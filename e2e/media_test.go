//go:build !windows

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"

	"github.com/jack-work/gluck-herald/client"
	"strings"
	"testing"
	"time"
)

// The bug this whole feature exists to fix: a photo sent with no caption had
// an empty body, and the poller dropped every message with an empty body. It
// did not arrive late or arrive broken. It never arrived at all.
func TestUncaptionedPhotoArrivesInsteadOfVanishing(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)
	token := idp.mint(t, "herald", []string{"admins"})

	tel.deliverPhoto(487734915, "underiraq", "", pixels(64<<10))

	msgs := inbox(t, h, token)
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1 — the uncaptioned photo was dropped\nlog:\n%s",
			len(msgs), h.logs())
	}
	if len(msgs[0].Media) != 1 {
		t.Fatalf("message carries %d media, want 1: %+v", len(msgs[0].Media), msgs[0])
	}
	if msgs[0].Media[0].Error != "" {
		t.Fatalf("media reported an error: %q\nlog:\n%s", msgs[0].Media[0].Error, h.logs())
	}
}

// The bytes must survive the whole path unchanged, and must be the LARGEST
// rendition: Telegram sends one photo at several scales, and a thumbnail is
// not what an aria needs to read a screenshot.
func TestPhotoBytesRoundTripAndAreTheLargestRendition(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)
	token := idp.mint(t, "herald", []string{"admins"})

	original := pixels(128 << 10)
	tel.deliverPhoto(487734915, "underiraq", "look at this", original)

	msgs := inbox(t, h, token)
	if len(msgs) != 1 || len(msgs[0].Media) != 1 {
		t.Fatalf("unexpected inbox: %+v\nlog:\n%s", msgs, h.logs())
	}
	m := msgs[0].Media[0]

	if msgs[0].Text != "look at this" {
		t.Errorf("caption did not become the body: %q", msgs[0].Text)
	}
	if m.Kind != "photo" || m.Width != 1280 || m.Height != 853 {
		t.Errorf("media describes the wrong rendition: %+v", m)
	}

	status, body := get(t, h, token, "/v1/media/"+m.ID)
	if status != 200 {
		t.Fatalf("GET media = %d, want 200\nlog:\n%s", status, h.logs())
	}
	if !bytes.Equal(body, original) {
		t.Fatalf("bytes differ: got %d bytes (sha %s), sent %d bytes (sha %s)",
			len(body), sha(body), len(original), sha(original))
	}
	if int64(len(body)) != m.Size {
		t.Errorf("declared size %d, served %d bytes", m.Size, len(body))
	}
}

// The endpoint is behind the same bearer auth as the inbox. This is the
// property the whole design leans on: herald verifies the token itself,
// because on the bearer path nothing upstream has verified anything.
func TestMediaRefusesTheUnauthenticatedAndTheWrongRole(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)
	token := idp.mint(t, "herald", []string{"admins"})

	tel.deliverPhoto(487734915, "underiraq", "", pixels(4<<10))
	msgs := inbox(t, h, token)
	if len(msgs) != 1 || len(msgs[0].Media) != 1 {
		t.Fatalf("unexpected inbox: %+v", msgs)
	}
	id := msgs[0].Media[0].ID

	if status, _ := get(t, h, "", "/v1/media/"+id); status != 401 {
		t.Errorf("no token: got %d, want 401", status)
	}
	// The exact request that walks past Caddy's bypass on hosts whose
	// backend verifies nothing. Herald is not one of those backends.
	if status, _ := get(t, h, "not-a-real-token", "/v1/media/"+id); status != 401 {
		t.Errorf("bogus bearer: got %d, want 401", status)
	}
	// "say" is not "inbox": a notifier may announce events without being
	// able to read what the phone sent back, attachments included.
	notifier := idp.mint(t, "notifier", []string{"admins"})
	if status, _ := get(t, h, notifier, "/v1/media/"+id); status != 403 {
		t.Errorf("say-only client: got %d, want 403", status)
	}
}

// An id is 32 hex characters and a short extension. Anything else cannot
// name a file, so traversal is refused by construction rather than cleaned
// up after.
func TestMediaIDCannotNameAPathOutsideTheStore(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)
	token := idp.mint(t, "herald", []string{"admins"})

	for _, bad := range []string{
		"..%2f..%2f..%2f..%2fetc%2fpasswd",
		"..%2fstate.json",
		"state.json",
		"%2Fetc%2Fpasswd",
		strings.Repeat("a", 32) + ".jpg", // well-formed, simply not held
	} {
		status, body := get(t, h, token, "/v1/media/"+bad)
		if status != 404 {
			t.Errorf("GET /v1/media/%s = %d, want 404 (body %.120q)", bad, status, body)
		}
		if bytes.Contains(body, []byte("root:")) || bytes.Contains(body, []byte("offset")) {
			t.Fatalf("SERVED SOMETHING IT SHOULD NOT HAVE for %q: %.200q", bad, body)
		}
	}
}

// Lifetime is tied to the message: acknowledging releases the bytes. A
// deleted id answers 404 rather than pretending, and the disk of the machine
// that routes the house does not accumulate screenshots nobody came back for.
func TestAckReleasesTheBytes(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)
	token := idp.mint(t, "herald", []string{"admins"})

	tel.deliverPhoto(487734915, "underiraq", "", pixels(8<<10))
	msgs := inbox(t, h, token)
	if len(msgs) != 1 || len(msgs[0].Media) != 1 {
		t.Fatalf("unexpected inbox: %+v", msgs)
	}
	id := msgs[0].Media[0].ID

	if status, _ := get(t, h, token, "/v1/media/"+id); status != 200 {
		t.Fatalf("before ack: got %d, want 200", status)
	}
	if out, err := h.cli(t, token, "ack", "--through", "999999"); err != nil {
		t.Fatalf("ack: %v\n%s", err, out)
	}
	// Give the rename-then-unlink a moment; the ack itself is synchronous,
	// so this should not need to wait, and it fails loudly if it does.
	deadline := time.Now().Add(2 * time.Second)
	for {
		status, _ := get(t, h, token, "/v1/media/"+id)
		if status == 404 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after ack: still %d, want 404 — the bytes outlived the message\nlog:\n%s",
				status, h.logs())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// An attachment Telegram announces but will not hand over must be reported,
// not swallowed. Silence looks like nothing was sent; an error an aria can
// see is something it can ask about.
func TestFailedDownloadIsReportedRatherThanSwallowed(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)
	token := idp.mint(t, "herald", []string{"admins"})

	tel.deliverBrokenPhoto(487734915, "underiraq", "this one will fail")

	msgs := inbox(t, h, token)
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1: the message must survive a failed attachment", len(msgs))
	}
	if msgs[0].Text != "this one will fail" {
		t.Errorf("text lost: %q", msgs[0].Text)
	}
	if len(msgs[0].Media) != 1 || msgs[0].Media[0].Error == "" {
		t.Fatalf("expected one media carrying an error, got %+v", msgs[0].Media)
	}
	if msgs[0].Media[0].ID != "" {
		t.Errorf("a failed download must not claim an id: %+v", msgs[0].Media[0])
	}
}

// ---------- helpers ----------

type inboxMedia struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	MimeType string `json:"mime_type"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	Size     int64  `json:"size"`
	Error    string `json:"error"`
}

type inboxMessage struct {
	ID    int64        `json:"id"`
	From  string       `json:"from"`
	Text  string       `json:"text"`
	Media []inboxMedia `json:"media"`
}

func inbox(t *testing.T, h *herald, token string) []inboxMessage {
	t.Helper()
	out, err := h.cli(t, token, "inbox", "--wait", "10s")
	if err != nil {
		t.Fatalf("inbox: %v\n%s\nserver log:\n%s", err, out, h.logs())
	}
	var msgs []inboxMessage
	if strings.TrimSpace(out) == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(out), &msgs); err != nil {
		t.Fatalf("parse inbox output %q: %v", out, err)
	}
	return msgs
}

func get(t *testing.T, h *herald, token, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.url+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// pixels is deterministic pseudo-random content: real enough that a truncated
// or re-encoded copy cannot pass, cheap enough to generate.
func pixels(n int) []byte {
	b := make([]byte, n)
	r := rand.New(rand.NewSource(int64(n)))
	r.Read(b)
	return b
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

var _ = fmt.Sprintf

// The bridge does not speak raw HTTP: it calls the client package. This
// exercises that exact path, because a working endpoint and a working client
// are two claims, and only one of them was tested above.
func TestClientFetchesMediaTheWayTheBridgeDoes(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)
	token := idp.mint(t, "herald", []string{"admins"})

	original := pixels(32 << 10)
	tel.deliverPhoto(487734915, "underiraq", "", original)

	c := client.New(h.url, staticToken(token))
	var msgs []client.Message
	deadline := time.Now().Add(15 * time.Second)
	for {
		var err error
		msgs, err = c.Inbox(context.Background(), 0, 5*time.Second)
		if err != nil {
			t.Fatalf("client inbox: %v", err)
		}
		if len(msgs) > 0 || time.Now().After(deadline) {
			break
		}
	}
	if len(msgs) != 1 || len(msgs[0].Media) != 1 {
		t.Fatalf("client saw %+v\nlog:\n%s", msgs, h.logs())
	}
	md := msgs[0].Media[0]
	if !strings.HasSuffix(md.ID, ".jpg") {
		t.Errorf("id %q lost its extension: the local copy must be recognizable to the read tool", md.ID)
	}

	var buf bytes.Buffer
	n, err := c.Media(context.Background(), md.ID, &buf)
	if err != nil {
		t.Fatalf("client media: %v\nlog:\n%s", err, h.logs())
	}
	if int(n) != len(original) || !bytes.Equal(buf.Bytes(), original) {
		t.Fatalf("client got %d bytes (sha %s), want %d (sha %s)",
			n, sha(buf.Bytes()), len(original), sha(original))
	}
}

type staticToken string

func (s staticToken) Token(context.Context) (string, error)   { return string(s), nil }
func (s staticToken) Refresh(context.Context) (string, error) { return string(s), nil }

// Telegram stores the command menu on its own side, so it outlives whatever
// registered it. This bot token carried a previous tenant's commands for
// months because nothing overwrote them. Herald replaces the menu at every
// start, which makes it a property of the running code.
func TestStaleCommandMenuIsReplacedAtStartup(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	tel.stale = []map[string]string{
		{"command": "clear", "description": "openclaw: clear the session"},
		{"command": "model", "description": "openclaw: switch model"},
	}
	startHerald(t, idp, tel)

	deadline := time.Now().Add(10 * time.Second)
	for {
		tel.mu.Lock()
		n := len(tel.setCmds)
		var last []map[string]string
		if n > 0 {
			last = tel.setCmds[n-1]
		}
		tel.mu.Unlock()
		if n > 0 {
			names := map[string]bool{}
			for _, c := range last {
				names[c["command"]] = true
			}
			if names["clear"] || names["model"] {
				t.Fatalf("the previous tenant's commands survived: %+v", last)
			}
			for _, want := range []string{"hup", "cut", "arias", "bind"} {
				if !names[want] {
					t.Errorf("menu is missing /%s: %+v", want, last)
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("herald never registered a command menu")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Setting the menu on every start would be noise if it never changed, so it
// is written only when it differs. A restart against a correct menu must be
// silent.
func TestCommandMenuIsNotRewrittenWhenAlreadyCorrect(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	startHerald(t, idp, tel)
	waitForCommands(t, tel, 1)

	// A second herald sees the menu the first one left, which is correct,
	// and must leave it alone.
	startHerald(t, idp, tel)
	time.Sleep(2 * time.Second)

	tel.mu.Lock()
	n := len(tel.setCmds)
	tel.mu.Unlock()
	if n != 1 {
		t.Fatalf("menu was written %d times; a matching menu must not be rewritten", n)
	}
}

func waitForCommands(t *testing.T, tel *fakeTelegram, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		tel.mu.Lock()
		n := len(tel.setCmds)
		tel.mu.Unlock()
		if n >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d command registrations, want %d", n, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
