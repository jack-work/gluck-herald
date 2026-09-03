// Package client talks to a herald server.
//
// This is the public surface other programs build on: the figaro bridge, the
// calendar notifier, anything that wants to send you a message. Herald itself
// knows nothing about them, which is the point — it is the Telegram API with
// names and an inbox, and everything domain-specific is a caller.
//
// Credentials arrive through a TokenSource. The bundled EnvTokenSource reads
// $HERALD_TOKEN, which is how hush brokers one; a service on spain uses
// ClientCredentials instead. Nothing here knows what a vault is.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TokenSource yields a bearer token, and is asked to refresh when the
// server rejects one. hush is the usual implementation; the default reads
// the environment and cannot refresh.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
	// Refresh is called once after a 401. It should obtain a new token, or
	// return an error if it cannot.
	Refresh(ctx context.Context) (string, error)
}

type Client struct {
	BaseURL string
	Tokens  TokenSource
	HTTP    *http.Client
}

func New(baseURL string, tokens TokenSource) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Tokens:  tokens,
		// A finite timeout, longer than the longest poll we ask for. The
		// default http.Client has NO timeout, which on a long-polling client
		// is a goroutine that can hang forever.
		HTTP: &http.Client{Timeout: 2 * time.Minute},
	}
}

// APIError carries the server's status so callers can distinguish an
// expired token from a refused action.
type APIError struct {
	Status int
	Msg    string
}

func (e *APIError) Error() string {
	if e.Msg == "" {
		return fmt.Sprintf("herald: HTTP %d", e.Status)
	}
	return fmt.Sprintf("herald: %s (HTTP %d)", e.Msg, e.Status)
}

// do issues a request, retrying once on 401 with a refreshed token.
//
// retryOnUnauthorized is deliberately a parameter rather than always true.
// Re-issuing a long poll is not free: the first attempt may already have
// been handed messages the server considers delivered. Idempotent calls opt
// in; the inbox poll does not.
func (c *Client) do(ctx context.Context, method, path string, body any, out any, retryOnUnauthorized bool) error {
	send := func(tok string) (*http.Response, error) {
		var r io.Reader
		if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			r = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, r)
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		return c.HTTP.Do(req)
	}

	// A missing token is not fatal here: some routes (health) need none,
	// and the server is the authority on what requires credentials. Send
	// without the header and let it answer 401 if it cares.
	tok, tokErr := c.Tokens.Token(ctx)
	resp, err := send(tok)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		if tokErr != nil {
			resp.Body.Close()
			return &APIError{Status: http.StatusUnauthorized, Msg: tokErr.Error()}
		}
		if retryOnUnauthorized {
			resp.Body.Close()
			// A token can be valid by the clock and still rejected — revoked,
			// or signed by a rotated key. Only the 401 knows this; expiry
			// math does not.
			fresh, rerr := c.Tokens.Refresh(ctx)
			if rerr != nil {
				return &APIError{
					Status: http.StatusUnauthorized,
					Msg:    "token rejected by the server and could not be refreshed: " + rerr.Error(),
				}
			}
			if resp, err = send(fresh); err != nil {
				return err
			}
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(raw))
		}
		return &APIError{Status: resp.StatusCode, Msg: e.Error}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Say sends a markdown message to a named recipient.
//
// The name is resolved by the server against its declared routes, so a
// caller never carries a chat id — and cannot reach a chat the deployment
// has not declared.
func (c *Client) Say(ctx context.Context, to, text string) error {
	return c.do(ctx, http.MethodPost, "/v1/say",
		map[string]any{"to": to, "text": text}, nil, true)
}

// Routes lists the recipient names this server will accept.
func (c *Client) Routes(ctx context.Context) ([]string, error) {
	var out struct {
		Routes []string `json:"routes"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/routes", nil, &out, true)
	return out.Routes, err
}

type Message struct {
	ID       int64     `json:"id"`
	Chat     int64     `json:"chat"`
	From     string    `json:"from"`
	Text     string    `json:"text"`
	Received time.Time `json:"received"`
}

// Inbox long-polls for messages newer than after.
//
// No retry on 401: a re-issued poll may double-deliver. An expired token
// surfaces as an error and the caller polls again, which is the same
// recovery a network blip gets.
func (c *Client) Inbox(ctx context.Context, after int64, wait time.Duration) ([]Message, error) {
	q := url.Values{}
	q.Set("after", strconv.FormatInt(after, 10))
	q.Set("wait", wait.String())

	var out struct {
		Messages []Message `json:"messages"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/inbox?"+q.Encode(), nil, &out, false)
	return out.Messages, err
}

// Ack drops messages through id. Delivery is at-least-once: acknowledge
// only after the message has been durably acted upon.
func (c *Client) Ack(ctx context.Context, through int64) error {
	return c.do(ctx, http.MethodPost, "/v1/inbox/ack",
		map[string]any{"through": through}, nil, true)
}

type WhoAmI struct {
	Subject  string   `json:"subject"`
	ClientID string   `json:"client_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
}

func (c *Client) WhoAmI(ctx context.Context) (*WhoAmI, error) {
	var w WhoAmI
	err := c.do(ctx, http.MethodGet, "/v1/whoami", nil, &w, true)
	return &w, err
}

func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	var m map[string]any
	err := c.do(ctx, http.MethodGet, "/v1/health", nil, &m, false)
	return m, err
}
