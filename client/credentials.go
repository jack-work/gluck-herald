package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ClientCredentials is a TokenSource for a *machine* caller: a service that
// authenticates as itself rather than on behalf of a person.
//
// This is the OAuth client_credentials grant, and it is what service identity
// on spain is made of. The service holds a client secret delivered by systemd
// (LoadCredential, a per-unit tmpfs at 0400) and exchanges it for a
// short-lived access token. Herald then verifies that token's signature and
// authorizes on its client_id.
//
// The distinction that matters: the long-lived secret never leaves the box
// and never reaches herald. Herald and the caller share nothing — herald
// checks a signature made by Authelia. Compare a permanent bearer token,
// where both ends hold the same bytes and either can leak it.
type ClientCredentials struct {
	// TokenURL is the OIDC token endpoint.
	TokenURL string
	// ClientID doubles as the service's identity at every peer.
	ClientID string
	// ClientSecret is the machine's own credential. Prefer SecretFile.
	ClientSecret string
	// SecretFile reads the secret from disk at first use — normally
	// $CREDENTIALS_DIRECTORY/<name>, so the value never appears in a unit
	// file (world-readable in /nix/store, forever) or in argv
	// (world-readable in /proc).
	SecretFile string
	// Scopes requested. Authelia permits arbitrary scopes for
	// client_credentials clients; they are the service's own vocabulary.
	Scopes string

	HTTP *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
	secret  string
}

// EarlyRefresh is how long before expiry a token is considered stale.
// Refreshing early costs one cheap request and avoids the far more annoying
// failure of a token expiring mid-flight.
const EarlyRefresh = 2 * time.Minute

func (c *ClientCredentials) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *ClientCredentials) loadSecret() (string, error) {
	if c.secret != "" {
		return c.secret, nil
	}
	if c.ClientSecret != "" {
		c.secret = c.ClientSecret
		return c.secret, nil
	}
	path := c.SecretFile
	if path == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			path = filepath.Join(dir, "client_secret")
		}
	}
	if path == "" {
		return "", fmt.Errorf("no client secret: set SecretFile or run under systemd with LoadCredential")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read client secret: %w", err)
	}
	c.secret = strings.TrimSpace(string(b))
	if c.secret == "" {
		return "", fmt.Errorf("client secret at %s is empty", path)
	}
	return c.secret, nil
}

// Token returns a cached access token, minting one when it is missing or
// close to expiry.
func (c *ClientCredentials) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expires.Add(-EarlyRefresh)) {
		return c.token, nil
	}
	return c.mintLocked(ctx)
}

// Refresh discards the cached token and mints a new one. Called after a 401:
// a token can be valid by the clock and still rejected — revoked, or signed
// by a rotated key — and only the 401 knows.
func (c *ClientCredentials) Refresh(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token, c.expires = "", time.Time{}
	return c.mintLocked(ctx)
}

func (c *ClientCredentials) mintLocked(ctx context.Context) (string, error) {
	secret, err := c.loadSecret()
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if c.Scopes != "" {
		form.Set("scope", c.Scopes)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// client_secret_basic: the secret goes in the Authorization header, not
	// in the body and never in a URL — URLs end up in logs and referrers.
	req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(secret))

	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("mint token: %w", err)
	}
	defer resp.Body.Close()

	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("mint token: HTTP %d: %w", resp.StatusCode, err)
	}
	if body.Error != "" {
		return "", fmt.Errorf("mint token: %s: %s", body.Error, body.ErrorDesc)
	}
	if resp.StatusCode != http.StatusOK || body.AccessToken == "" {
		return "", fmt.Errorf("mint token: HTTP %d and no access_token", resp.StatusCode)
	}

	ttl := time.Duration(body.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	c.token = body.AccessToken
	c.expires = time.Now().Add(ttl)
	return c.token, nil
}
