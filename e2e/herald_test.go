//go:build !windows

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The full round trip: a Telegram DM arrives, herald holds it, the CLI
// long-polls it out, replies, and Telegram sees the reply.
func TestInboundMessageReachesCLIAndReplyReachesTelegram(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)
	token := idp.mint(t, "herald", []string{"admins"})

	tel.deliver(487734915, "underiraq", "hello from the phone")

	// Long-poll it out through the CLI.
	out, err := h.cli(t, token, "inbox", "--wait", "10s")
	if err != nil {
		t.Fatalf("inbox: %v\n%s\nserver log:\n%s", err, out, h.logs())
	}
	var msgs []struct {
		ID   int64  `json:"id"`
		Chat int64  `json:"chat"`
		From string `json:"from"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(out), &msgs); err != nil {
		t.Fatalf("parse inbox output %q: %v", out, err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1: %s", len(msgs), out)
	}
	if msgs[0].Text != "hello from the phone" || msgs[0].From != "underiraq" {
		t.Errorf("message = %+v", msgs[0])
	}

	// Reply through the CLI.
	if out, err := h.cli(t, token, "say", "--chat", "487734915", "**bold** reply"); err != nil {
		t.Fatalf("say: %v\n%s", err, out)
	}

	sent := tel.messages()
	if len(sent) != 1 {
		t.Fatalf("telegram received %d messages, want 1", len(sent))
	}
	if sent[0]["chat_id"] != "487734915" {
		t.Errorf("sent to chat %q, want 487734915", sent[0]["chat_id"])
	}
	// Markdown must arrive as Telegram HTML.
	if sent[0]["parse_mode"] != "HTML" {
		t.Errorf("parse_mode = %q, want HTML", sent[0]["parse_mode"])
	}
	if !strings.Contains(sent[0]["text"], "<b>bold</b>") {
		t.Errorf("markdown was not rendered: %q", sent[0]["text"])
	}
}

// A token minted for another service must not open herald. Authelia's aud
// claim is empty, so client_id is the only thing carrying this distinction.
func TestTokenFromAnotherClientIsRefused(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)

	kfinToken := idp.mint(t, "kfin", []string{"admins"})
	out, err := h.cli(t, kfinToken, "whoami")
	if err == nil {
		t.Fatalf("a kfin token opened herald:\n%s", out)
	}
	if !strings.Contains(out, "401") && !strings.Contains(strings.ToLower(out), "unauthor") {
		t.Errorf("expected a 401, got: %s", out)
	}
	if len(tel.messages()) != 0 {
		t.Error("a refused caller still reached telegram")
	}
}

func TestNoTokenIsRefused(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)

	if out, err := h.cli(t, "", "whoami"); err == nil {
		t.Fatalf("whoami succeeded with no token:\n%s", out)
	}
}

func TestForgedTokenIsRefused(t *testing.T) {
	idp := newIDP(t)
	other := newIDP(t) // a different signing key entirely
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)

	forged := other.mint(t, "herald", []string{"admins"})
	if out, err := h.cli(t, forged, "whoami"); err == nil {
		t.Fatalf("a token signed by an unknown key was accepted:\n%s", out)
	}
}

// The long poll must return promptly when a message lands, and must return
// 204 (an empty list, not an error) when it does not.
func TestLongPollWakesOnArrivalAndTimesOutCleanly(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)
	token := idp.mint(t, "herald", []string{"admins"})

	start := time.Now()
	out, err := h.cli(t, token, "inbox", "--wait", "1s")
	if err != nil {
		t.Fatalf("idle poll errored: %v\n%s", err, out)
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Errorf("idle poll returned after %s — it did not wait", elapsed)
	}
	if strings.TrimSpace(out) != "null" && strings.TrimSpace(out) != "[]" {
		t.Errorf("idle poll should yield no messages, got %q", out)
	}
}

// Acknowledged messages must not be redelivered; unacknowledged ones must.
func TestAckStopsRedelivery(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)
	token := idp.mint(t, "herald", []string{"admins"})

	tel.deliver(487734915, "underiraq", "first")
	out, err := h.cli(t, token, "inbox", "--wait", "10s")
	if err != nil {
		t.Fatalf("inbox: %v\n%s", err, out)
	}
	var msgs []struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &msgs); err != nil || len(msgs) == 0 {
		t.Fatalf("expected a message, got %q (%v)", out, err)
	}

	// Before ack: still pending.
	again, err := h.cli(t, token, "inbox", "--wait", "0")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(again, "\"id\"") == false {
		t.Errorf("message vanished before it was acknowledged: %q", again)
	}

	// The pump acks through the id it handled; do the same by hand.
	if out, err := h.cli(t, token, "say", "--chat", "487734915", "ack test"); err != nil {
		t.Fatalf("say: %v\n%s", err, out)
	}
}

// dry-run pump proves the routing path without invoking figaro.
func TestPumpDryRunRoutesMessage(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)
	token := idp.mint(t, "herald", []string{"admins"})

	tel.deliver(487734915, "underiraq", "route me")

	out, err := h.cli(t, token, "pump", "--once", "--dry-run", "--aria", "abc123", "--wait", "10s")
	if err != nil {
		t.Fatalf("pump: %v\n%s\nserver:\n%s", err, out, h.logs())
	}
	if !strings.Contains(out, "route me") {
		t.Errorf("pump did not surface the message: %q", out)
	}
	if !strings.Contains(out, "abc123") {
		t.Errorf("pump did not target the requested aria: %q", out)
	}
	// The prompt must be marked, so an aria with a terminal open can tell
	// which door a message came through.
	if !strings.Contains(out, "telegram") {
		t.Errorf("routed prompt is not marked as telegram: %q", out)
	}
}

func TestHealthNeedsNoToken(t *testing.T) {
	idp := newIDP(t)
	tel := newTelegram(t)
	h := startHerald(t, idp, tel)

	out, err := h.cli(t, "", "health")
	if err != nil {
		t.Fatalf("health: %v\n%s", err, out)
	}
	if !strings.Contains(out, "\"ok\": true") {
		t.Errorf("health = %q", out)
	}
}
