package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gauthz "github.com/jack-work/gluck-authz"
	"github.com/jack-work/gluck-herald/internal/authz"
	"github.com/jack-work/gluck-herald/internal/route"
	"github.com/jack-work/gluck-herald/internal/store"
)

// stubVerify accepts "Bearer <client_id>", so server tests exercise routing
// and authorization rather than re-testing the crypto that auth's own tests
// cover.
func stubVerify(ctx context.Context, header string) (*gauthz.Identity, error) {
	const p = "Bearer "
	if !strings.HasPrefix(header, p) {
		return nil, gauthz.ErrNoToken
	}
	id := strings.TrimSpace(header[len(p):])
	if id == "" || id == "bad" {
		return nil, errBadToken
	}
	return &gauthz.Identity{Subject: "s-" + id, ClientID: id, Username: ""}, nil
}

type badToken struct{}

func (badToken) Error() string { return "bad token" }

var errBadToken = badToken{}

func newTestServer(t *testing.T, policy map[string][]string) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := authz.NewPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := route.NewTable(map[string]string{"gluck": "487734915"})
	if err != nil {
		t.Fatal(err)
	}

	s := New(Config{Store: st, Policy: pol, Routes: routes})
	s.verify = stubVerify
	s.send = func(context.Context, int64, string) error { return nil }

	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, st
}

func req(t *testing.T, srv *httptest.Server, method, path, token, body string) *http.Response {
	t.Helper()
	var r *http.Request
	var err error
	if body == "" {
		r, err = http.NewRequest(method, srv.URL+path, nil)
	} else {
		r, err = http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	}
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestUnauthenticatedRequestsAreRefused(t *testing.T) {
	srv, _ := newTestServer(t, map[string][]string{"herald": {"say", "inbox", "admin"}})
	for _, path := range []string{"/v1/inbox", "/v1/whoami", "/v1/routes"} {
		resp := req(t, srv, http.MethodGet, path, "", "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without a token = %d, want 401", path, resp.StatusCode)
		}
		if resp.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("GET %s should advertise the bearer scheme", path)
		}
	}
}

func TestHealthNeedsNoAuth(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	resp := req(t, srv, http.MethodGet, "/v1/health", "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d, want 200", resp.StatusCode)
	}
}

// The role model's whole point: a notifier that announces events must not be
// able to read the replies to them.
func TestRolesAreEnforcedPerEndpoint(t *testing.T) {
	srv, _ := newTestServer(t, map[string][]string{
		"kcal-notify": {"say"},                   // may send, may not read
		"figaro":      {"say", "inbox"},          // the bridge: both
		"admin-cli":   {"say", "inbox", "admin"}, // everything
	})

	cases := []struct {
		client, method, path, body string
		want                       int
	}{
		{"kcal-notify", http.MethodPost, "/v1/say", `{"to":"gluck","text":"hi"}`, http.StatusOK},
		{"kcal-notify", http.MethodGet, "/v1/inbox?wait=0", "", http.StatusForbidden},
		{"kcal-notify", http.MethodPost, "/v1/inbox/ack", `{"through":1}`, http.StatusForbidden},
		{"kcal-notify", http.MethodGet, "/v1/whoami", "", http.StatusForbidden},
		{"figaro", http.MethodGet, "/v1/inbox?wait=0", "", http.StatusNoContent},
		{"figaro", http.MethodGet, "/v1/whoami", "", http.StatusForbidden},
		{"admin-cli", http.MethodGet, "/v1/whoami", "", http.StatusOK},
		{"admin-cli", http.MethodGet, "/v1/inbox?wait=0", "", http.StatusNoContent},
	}
	for _, c := range cases {
		resp := req(t, srv, c.method, c.path, c.client, c.body)
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s %s as %q = %d, want %d", c.method, c.path, c.client, resp.StatusCode, c.want)
		}
	}
}

// A client herald has never heard of is a 401 (fix: register it); a known
// client lacking a role is a 403 (fix: policy). Different problems.
func TestUnknownClientIs401AndUnprivilegedIs403(t *testing.T) {
	srv, _ := newTestServer(t, map[string][]string{"known": {"say"}})

	resp := req(t, srv, http.MethodGet, "/v1/routes", "stranger", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unregistered client = %d, want 401", resp.StatusCode)
	}

	resp2 := req(t, srv, http.MethodGet, "/v1/inbox?wait=0", "known", "")
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("known client without the role = %d, want 403", resp2.StatusCode)
	}
}

// The caller names a recipient; the server resolves it. An undeclared
// destination is refused however it is spelled — a gateway whose caller may
// name any destination is an open relay that signs its own requests.
func TestSayRefusesUndeclaredRecipients(t *testing.T) {
	srv, _ := newTestServer(t, map[string][]string{"c": {"say"}})

	for _, body := range []string{
		`{"to":"stranger","text":"hi"}`,
		`{"chat":999,"text":"hi"}`,
		`{"to":"999","text":"hi"}`,
		`{"text":"hi"}`,
	} {
		resp := req(t, srv, http.MethodPost, "/v1/say", "c", body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("say %s = %d, want 400", body, resp.StatusCode)
		}
	}
}

func TestRoutesListsNames(t *testing.T) {
	srv, _ := newTestServer(t, map[string][]string{"c": {"say"}})
	resp := req(t, srv, http.MethodGet, "/v1/routes", "c", "")
	defer resp.Body.Close()

	var out struct {
		Routes []string `json:"routes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Routes) != 1 || out.Routes[0] != "gluck" {
		t.Errorf("routes = %v", out.Routes)
	}
}

func TestInboxLongPollReturns204WhenIdle(t *testing.T) {
	srv, _ := newTestServer(t, map[string][]string{"c": {"inbox"}})
	start := time.Now()
	resp := req(t, srv, http.MethodGet, "/v1/inbox?wait=300ms", "c", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("idle poll = %d, want 204", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Errorf("returned after %s — it did not actually wait", elapsed)
	}
}

// A message arriving mid-poll must wake the waiter, not wait for the timeout.
func TestInboxLongPollWakesOnArrival(t *testing.T) {
	srv, st := newTestServer(t, map[string][]string{"c": {"inbox"}})

	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = st.Append(43, []store.Message{{ID: 42, Chat: 487734915, Text: "ping"}})
	}()

	start := time.Now()
	resp := req(t, srv, http.MethodGet, "/v1/inbox?wait=10s", "c", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll = %d, want 200", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("woke after %s — it slept through the arrival", elapsed)
	}
	var out struct{ Messages []store.Message }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Messages) != 1 || out.Messages[0].Text != "ping" {
		t.Errorf("messages = %+v", out.Messages)
	}
}

// Cloudflare kills a held request at ~100s, so the cap must sit well under.
func TestInboxWaitIsCappedBelowCloudflaresLimit(t *testing.T) {
	if MaxWait >= 100*time.Second {
		t.Fatalf("MaxWait = %s; Cloudflare returns 524 at about 100s", MaxWait)
	}
}

func TestAckDropsDeliveredMessages(t *testing.T) {
	srv, st := newTestServer(t, map[string][]string{"c": {"inbox"}})
	if err := st.Append(3, []store.Message{{ID: 1, Text: "a"}, {ID: 2, Text: "b"}}); err != nil {
		t.Fatal(err)
	}
	resp := req(t, srv, http.MethodPost, "/v1/inbox/ack", "c", `{"through":1}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ack = %d", resp.StatusCode)
	}
	if got := st.Peek(0, 10); len(got) != 1 || got[0].ID != 2 {
		t.Errorf("after ack through 1, pending = %+v", got)
	}
}
