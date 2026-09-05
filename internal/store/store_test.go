package store

import (
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestOpenMissingFileIsEmpty(t *testing.T) {
	s, _ := open(t)
	if off, pending := s.Stats(); off != 0 || pending != 0 {
		t.Errorf("fresh store = offset %d, pending %d", off, pending)
	}
}

// The offset is the whole state: it must survive a restart, or Telegram
// replays or drops every message since the last write.
func TestOffsetAndInboxSurviveReopen(t *testing.T) {
	s, path := open(t)
	msgs := []Message{
		{ID: 10, Chat: 1, From: "a", Text: "one", Received: time.Now().UTC().Truncate(time.Second)},
		{ID: 11, Chat: 1, From: "a", Text: "two", Received: time.Now().UTC().Truncate(time.Second)},
	}
	if err := s.Append(12, msgs); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	off, pending := reopened.Stats()
	if off != 12 {
		t.Errorf("offset after reopen = %d, want 12", off)
	}
	if pending != 2 {
		t.Errorf("pending after reopen = %d, want 2", pending)
	}
	if got := reopened.Peek(0, 10); len(got) != 2 || got[0].Text != "one" {
		t.Errorf("messages did not survive: %+v", got)
	}
}

func TestPeekFiltersAndOrders(t *testing.T) {
	s, _ := open(t)
	if err := s.Append(5, []Message{{ID: 3, Text: "c"}, {ID: 1, Text: "a"}, {ID: 2, Text: "b"}}); err != nil {
		t.Fatal(err)
	}
	got := s.Peek(1, 10)
	if len(got) != 2 || got[0].ID != 2 || got[1].ID != 3 {
		t.Fatalf("Peek(after=1) = %+v, want ids 2,3 in order", got)
	}
	if limited := s.Peek(0, 1); len(limited) != 1 || limited[0].ID != 1 {
		t.Errorf("limit ignored: %+v", limited)
	}
}

func TestAckIsIdempotentAndKeepsNewer(t *testing.T) {
	s, _ := open(t)
	if err := s.Append(4, []Message{{ID: 1}, {ID: 2}, {ID: 3}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.Ack(2); err != nil {
			t.Fatal(err)
		}
	}
	got := s.Peek(0, 10)
	if len(got) != 1 || got[0].ID != 3 {
		t.Errorf("after repeated Ack(2), pending = %+v; want only id 3", got)
	}
	// Acking a message that is already gone must not resurrect or panic.
	if err := s.Ack(99); err != nil {
		t.Fatal(err)
	}
	if got := s.Peek(0, 10); len(got) != 0 {
		t.Errorf("pending after Ack(99) = %+v", got)
	}
}

// A client that never polls must not grow the state file without bound.
func TestInboxIsBoundedDroppingOldestFirst(t *testing.T) {
	s, _ := open(t)
	s.MaxInbox = 3
	for i := int64(1); i <= 6; i++ {
		if err := s.Append(i+1, []Message{{ID: i}}); err != nil {
			t.Fatal(err)
		}
	}
	got := s.Peek(0, 100)
	if len(got) != 3 {
		t.Fatalf("retained %d messages, want 3", len(got))
	}
	if got[0].ID != 4 || got[2].ID != 6 {
		t.Errorf("wrong messages retained: %+v: oldest should be dropped", got)
	}
}

func TestWaitIsWokenByAppend(t *testing.T) {
	s, _ := open(t)
	woken := s.Wait()

	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = s.Append(2, []Message{{ID: 1, Text: "hi"}})
	}()

	select {
	case <-woken:
	case <-time.After(5 * time.Second):
		t.Fatal("waiter was never woken by an arriving message")
	}
}

// An empty Append (a poll that returned nothing) must not wake waiters:
// a spurious wake turns every long poll into a busy loop.
func TestEmptyAppendDoesNotWake(t *testing.T) {
	s, _ := open(t)
	woken := s.Wait()
	if err := s.Append(7, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-woken:
		t.Fatal("an empty append woke a long poll")
	case <-time.After(100 * time.Millisecond):
	}
	if off := s.Offset(); off != 7 {
		t.Errorf("offset = %d, want 7: an empty batch still advances it", off)
	}
}

func TestConcurrentAppendsAreSerialized(t *testing.T) {
	s, _ := open(t)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			_ = s.Append(int64(i), []Message{{ID: int64(i)}})
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if _, pending := s.Stats(); pending != 8 {
		t.Errorf("pending = %d after 8 concurrent appends, want 8", pending)
	}
}
