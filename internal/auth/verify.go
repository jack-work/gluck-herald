// Package auth verifies Authelia-issued JWTs against its JWKS.
//
// The service binds loopback, so Caddy is the only thing that can reach it.
// Caddy strips client Remote-* headers and then either forward-auths a
// browser session to Authelia, or — when the request carries
// `Authorization: Bearer` — passes it straight through. That bearer path is
// what a CLI uses, and it is why herald must verify the token itself: on
// that path nothing upstream has checked it.
package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Identity is what a verified token asserts about its caller.
type Identity struct {
	Subject  string
	ClientID string
	Username string
	Groups   []string
	Scopes   []string
}

// HasGroup reports membership. Coarse authorization is a group name; fine
// authorization is the service's own business.
func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func (i *Identity) HasGroup(name string) bool {
	for _, g := range i.Groups {
		if g == name {
			return true
		}
	}
	return false
}

// Verifier checks bearer tokens against a JWKS endpoint.
type Verifier struct {
	JWKSURL string
	// ClientIDs is the allowlist of OIDC clients whose tokens are accepted.
	//
	// This — not the audience — is the gate that keeps one service's token
	// from opening another. Authelia issues access tokens with an EMPTY aud
	// claim (verified against a live token, not assumed), so an aud check
	// would either reject everything or, written permissively, pass
	// everything: a control that looks real and does nothing. The client_id
	// claim is populated and is what kfin already gates on.
	ClientIDs []string
	Issuer    string

	HTTP *http.Client

	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

// ErrNoToken means the request carried no bearer credential at all.
var ErrNoToken = errors.New("no bearer token")

func (v *Verifier) client() *http.Client {
	if v.HTTP != nil {
		return v.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Verify parses and checks an Authorization header value.
func (v *Verifier) Verify(ctx context.Context, header string) (*Identity, error) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return nil, ErrNoToken
	}
	return v.VerifyToken(ctx, strings.TrimSpace(header[len(prefix):]))
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Iss              string   `json:"iss"`
	Sub              string   `json:"sub"`
	Aud              audience `json:"aud"`
	Exp              int64    `json:"exp"`
	Nbf              int64    `json:"nbf"`
	Iat              int64    `json:"iat"`
	Scope            string   `json:"scope"`
	ScopeAlt         []string `json:"scp"`
	ClientID         string   `json:"client_id"`
	PreferredUser    string   `json:"preferred_username"`
	Groups           []string `json:"groups"`
	AutheliaGroupAlt []string `json:"grp"`
}

// audience is a JWT aud claim, which RFC 7519 permits to be either a string
// or an array of strings.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func (a audience) has(want string) bool {
	for _, s := range a {
		if s == want {
			return true
		}
	}
	return false
}

func (v *Verifier) VerifyToken(ctx context.Context, token string) (*Identity, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}

	headerBytes, err := b64(parts[0])
	if err != nil {
		return nil, fmt.Errorf("token header: %w", err)
	}
	var h jwtHeader
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return nil, fmt.Errorf("token header: %w", err)
	}
	// Only RSA signatures are accepted. Refusing to switch on the token's
	// own alg is what closes the "alg: none" and HMAC-confusion families:
	// the token must not get to choose how it is checked.
	if h.Alg != "RS256" && h.Alg != "RS512" {
		return nil, fmt.Errorf("unsupported signing algorithm %q", h.Alg)
	}

	key, err := v.key(ctx, h.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := b64(parts[2])
	if err != nil {
		return nil, fmt.Errorf("token signature: %w", err)
	}
	if err := verifyRSA(h.Alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}

	claimBytes, err := b64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("token claims: %w", err)
	}
	var c jwtClaims
	if err := json.Unmarshal(claimBytes, &c); err != nil {
		return nil, fmt.Errorf("token claims: %w", err)
	}

	now := time.Now()
	const skew = 60 * time.Second
	if c.Exp != 0 && now.After(time.Unix(c.Exp, 0).Add(skew)) {
		return nil, errors.New("token expired")
	}
	if c.Nbf != 0 && now.Add(skew).Before(time.Unix(c.Nbf, 0)) {
		return nil, errors.New("token not yet valid")
	}
	if v.Issuer != "" && c.Iss != v.Issuer {
		return nil, fmt.Errorf("wrong issuer %q", c.Iss)
	}
	// The load-bearing check: a token minted for another CLI must not open
	// this one.
	if len(v.ClientIDs) > 0 {
		if c.ClientID == "" {
			return nil, errors.New("token carries no client_id")
		}
		if !contains(v.ClientIDs, c.ClientID) {
			return nil, fmt.Errorf("token was issued for client %q, not for herald", c.ClientID)
		}
	}

	groups := c.Groups
	if len(groups) == 0 {
		groups = c.AutheliaGroupAlt
	}
	scopes := strings.Fields(c.Scope)
	if len(scopes) == 0 {
		scopes = c.ScopeAlt
	}
	return &Identity{
		Subject:  c.Sub,
		ClientID: c.ClientID,
		Username: c.PreferredUser,
		Groups:   groups,
		Scopes:   scopes,
	}, nil
}

// key returns the public key for a kid, refetching the JWKS at most once per
// minute when the kid is unknown — so a signing-key rotation recovers
// without a restart, and an unknown kid cannot become a fetch loop.
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	k, ok := v.keys[kid]
	fetched := v.fetched
	v.mu.RUnlock()
	if ok {
		return k, nil
	}
	if time.Since(fetched) < time.Minute {
		return nil, fmt.Errorf("unknown signing key %q", kid)
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
}

type jwks struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (v *Verifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client().Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: HTTP %d", resp.StatusCode)
	}
	var set jwks
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("parse jwks: %w", err)
	}

	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nb, err := b64(k.N)
		if err != nil {
			continue
		}
		eb, err := b64(k.E)
		if err != nil {
			continue
		}
		e := 0
		if len(eb) > 8 {
			continue
		}
		padded := make([]byte, 8)
		copy(padded[8-len(eb):], eb)
		e = int(binary.BigEndian.Uint64(padded))
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
	}

	v.mu.Lock()
	v.keys = keys
	v.fetched = time.Now()
	v.mu.Unlock()
	return nil
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
