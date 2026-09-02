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

	"github.com/jack-work/gluck-herald/internal/auth"
	"github.com/jack-work/gluck-herald/internal/store"
)

// stubVerifier accepts a fixed token, so server tests exercise routing and
// authorization rather than re-testing crypto (which auth's own tests do).
type stubVerifier struct{ groups []string }

func (s *stubVerifier) verify(ctx context.Context, header string) (*auth.Identity, error) {
	if header == "Bearer good" {
		return &auth.Identity{Subject: "u", Username: "gluck", ClientID: "herald", Groups: s.groups}, nil
	}
	if header == "" {
		return nil, auth.ErrNoToken
	}
	return nil, errBad
}

var errBad = &stubErr{}

type stubErr struct{}

func (*stubErr) Error() string { return "bad token" }

func newTestServer(t *testing.T, groups []string, requiredGroup string) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	sv := &stubVerifier{groups: groups}
	s := New(Config{Store: st, RequiredGroup: requiredGroup})
	s.verify = sv.verify

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
		r.Header.Set("Authorization", token)
	}
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestUnauthenticatedRequestsAreRefused(t *testing.T) {
	srv, _ := newTestServer(t, nil, "")
	for _, path := range []string{"/v1/inbox", "/v1/whoami"} {
		resp := req(t, srv, http.MethodGet, path, "", "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without a token = %d, want 401", path, resp.StatusCode)
		}
		if resp.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("GET %s should advertise the bearer scheme", path)
		}
	}
	resp := req(t, srv, http.MethodPost, "/v1/say", "Bearer nonsense", `{"chat":1,"text":"x"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad token = %d, want 401", resp.StatusCode)
	}
}

func TestHealthNeedsNoAuth(t *testing.T) {
	srv, _ := newTestServer(t, nil, "")
	resp := req(t, srv, http.MethodGet, "/v1/health", "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d, want 200", resp.StatusCode)
	}
}

func TestGroupGate(t *testing.T) {
	srv, _ := newTestServer(t, []string{"other"}, "herald-admin")
	resp := req(t, srv, http.MethodGet, "/v1/whoami", "Bearer good", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing group = %d, want 403", resp.StatusCode)
	}

	srv2, _ := newTestServer(t, []string{"herald-admin"}, "herald-admin")
	resp2 := req(t, srv2, http.MethodGet, "/v1/whoami", "Bearer good", "")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("with group = %d, want 200", resp2.StatusCode)
	}
}

// The caller may name a chat, but only from a fixed set: a gateway whose
// caller can name any destination is an open relay that signs its requests.
func TestSayRefusesChatsOutsideTheAllowlist(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.json"))
	if err != nil {
		t.Fatal(err)
	}
	sv := &stubVerifier{}
	s := New(Config{Store: st, AllowedChats: map[int64]bool{111: true}})
	s.verify = sv.verify
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp := req(t, srv, http.MethodPost, "/v1/say", "Bearer good", `{"chat":999,"text":"hi"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unlisted chat = %d, want 403", resp.StatusCode)
	}
}

func TestInboxLongPollReturns204WhenIdle(t *testing.T) {
	srv, _ := newTestServer(t, nil, "")
	start := time.Now()
	resp := req(t, srv, http.MethodGet, "/v1/inbox?wait=300ms", "Bearer good", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("idle poll = %d, want 204", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Errorf("returned after %s — it did not actually wait", elapsed)
	}
}

// A message arriving mid-poll must wake the waiter, not wait for the
// timeout: that is the difference between a gateway and a polling loop.
func TestInboxLongPollWakesOnArrival(t *testing.T) {
	srv, st := newTestServer(t, nil, "")

	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = st.Append(43, []store.Message{{ID: 42, Chat: 7, Text: "ping"}})
	}()

	start := time.Now()
	resp := req(t, srv, http.MethodGet, "/v1/inbox?wait=10s", "Bearer good", "")
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

// Cloudflare kills a held request at ~100s, so the server must cap the wait
// well under that no matter what the client asks for.
func TestInboxWaitIsCappedBelowCloudflaresLimit(t *testing.T) {
	if MaxWait >= 100*time.Second {
		t.Fatalf("MaxWait = %s; Cloudflare returns 524 at about 100s", MaxWait)
	}
}

func TestAckDropsDeliveredMessages(t *testing.T) {
	srv, st := newTestServer(t, nil, "")
	if err := st.Append(3, []store.Message{{ID: 1, Text: "a"}, {ID: 2, Text: "b"}}); err != nil {
		t.Fatal(err)
	}
	resp := req(t, srv, http.MethodPost, "/v1/inbox/ack", "Bearer good", `{"through":1}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ack = %d", resp.StatusCode)
	}
	if got := st.Peek(0, 10); len(got) != 1 || got[0].ID != 2 {
		t.Errorf("after ack through 1, pending = %+v", got)
	}
}
