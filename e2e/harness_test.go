//go:build !windows

// Package e2e drives the real herald binary end to end: a fake Authelia
// issuing real RS256 tokens, a fake Telegram API, the actual server process,
// and the actual CLI talking to it over HTTP.
//
// Nothing here stubs herald's own code — the binary under test is the one
// that ships.
package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var heraldBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "herald-e2e-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	heraldBin = filepath.Join(dir, "herald")
	out, err := exec.Command("go", "build", "-o", heraldBin, "..").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build herald: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// ---------- fake Authelia ----------

type idp struct {
	key    *rsa.PrivateKey
	kid    string
	issuer string
	srv    *httptest.Server
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i := &idp{key: k, kid: "e2e", issuer: "https://auth.test"}
	i.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e := big.NewInt(int64(k.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": i.kid,
				"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(e),
			}},
		})
	}))
	t.Cleanup(i.srv.Close)
	return i
}

func (i *idp) mint(t *testing.T, clientID string, groups []string) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	now := time.Now()
	signing := enc(map[string]any{"alg": "RS256", "typ": "JWT", "kid": i.kid}) + "." +
		enc(map[string]any{
			"iss": i.issuer, "sub": "u-1", "client_id": clientID,
			"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
			"nbf": now.Add(-time.Minute).Unix(),
			"scp": []string{"openid", "groups"}, "groups": groups,
		})
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, 5, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// ---------- fake Telegram ----------

type fakeTelegram struct {
	mu       sync.Mutex
	sent     []map[string]string
	pending  []map[string]any
	srv      *httptest.Server
	polls    int
	nextID   int64
	blockFor time.Duration
}

func newTelegram(t *testing.T) *fakeTelegram {
	f := &fakeTelegram{nextID: 100}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		switch method {
		case "getMe":
			writeOK(w, map[string]any{"username": "e2e_bot", "id": 1})
		case "getUpdates":
			f.mu.Lock()
			f.polls++
			ups := f.pending
			f.pending = nil
			f.mu.Unlock()
			if len(ups) == 0 {
				// Emulate a long poll without actually holding for 30s.
				time.Sleep(120 * time.Millisecond)
			}
			writeOK(w, ups)
		case "sendMessage":
			f.mu.Lock()
			f.sent = append(f.sent, map[string]string{
				"chat_id":    r.FormValue("chat_id"),
				"text":       r.FormValue("text"),
				"parse_mode": r.FormValue("parse_mode"),
			})
			f.mu.Unlock()
			writeOK(w, map[string]any{"message_id": 1})
		default:
			writeOK(w, map[string]any{})
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func writeOK(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
}

// deliver queues an inbound message for the next getUpdates.
func (f *fakeTelegram) deliver(chat int64, from, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	f.pending = append(f.pending, map[string]any{
		"update_id": f.nextID,
		"message": map[string]any{
			"message_id": f.nextID,
			"text":       text,
			"date":       time.Now().Unix(),
			"chat":       map[string]any{"id": chat, "type": "private"},
			"from":       map[string]any{"id": chat, "username": from},
		},
	})
}

func (f *fakeTelegram) messages() []map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]string{}, f.sent...)
}

// ---------- the herald process ----------

type herald struct {
	url   string
	cmd   *exec.Cmd
	log   *strings.Builder
	logMu sync.Mutex
}

func startHerald(t *testing.T, i *idp, tel *fakeTelegram, extraEnv ...string) *herald {
	t.Helper()
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	state := filepath.Join(t.TempDir(), "state.json")

	cmd := exec.Command(heraldBin, "serve",
		"--addr", addr,
		"--state", state,
		"--jwks", i.srv.URL,
		"--issuer", i.issuer,
		"--client-ids", "herald",
	)
	cmd.Env = append(os.Environ(),
		"HERALD_TELEGRAM_TOKEN=fake-token",
		// Point the telegram client at the fake API.
		"HERALD_TELEGRAM_BASE="+tel.srv.URL,
	)
	cmd.Env = append(cmd.Env, extraEnv...)

	h := &herald{url: "http://" + addr, cmd: cmd, log: &strings.Builder{}}
	cmd.Stdout = &syncWriter{b: h.log, mu: &h.logMu}
	cmd.Stderr = &syncWriter{b: h.log, mu: &h.logMu}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(h.url + "/v1/health")
		if err == nil {
			resp.Body.Close()
			return h
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.logMu.Lock()
	defer h.logMu.Unlock()
	t.Fatalf("herald never became healthy; log:\n%s", h.log.String())
	return nil
}

func (h *herald) logs() string {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	return h.log.String()
}

type syncWriter struct {
	b  *strings.Builder
	mu *sync.Mutex
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// cli runs the herald CLI against this server with a token in the
// environment, exactly as hush would broker it.
func (h *herald) cli(t *testing.T, token string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(heraldBin, args...)
	cmd.Env = append(os.Environ(),
		"HERALD_API="+h.url,
		"HERALD_TOKEN="+token,
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
