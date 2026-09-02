// Package store is herald's durable state: the Telegram update offset and
// the inbox of messages not yet claimed by a client.
//
// The offset is the whole state that matters. Telegram delivers an update
// exactly once per offset advance, so it must be persisted *before* the
// message is acknowledged, or a restart silently drops DMs. Single writer,
// one file, fsync on write.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Message is one inbound Telegram message held for delivery.
type Message struct {
	ID       int64     `json:"id"` // the Telegram update_id: monotonic, unique
	Chat     int64     `json:"chat"`
	From     string    `json:"from"`
	Text     string    `json:"text"`
	Received time.Time `json:"received"`
}

type state struct {
	Offset int64     `json:"offset"`
	Inbox  []Message `json:"inbox"`
}

type Store struct {
	mu    sync.Mutex
	st    state
	path  string
	waits []chan struct{}

	// MaxInbox bounds retention: a client that never polls must not grow
	// the file without limit. Oldest messages are dropped first.
	MaxInbox int
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, MaxInbox: 500}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(data, &s.st); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	return s, nil
}

// saveLocked writes the state atomically. The caller holds the mutex.
func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	// fsync before rename: the offset must survive a hard power loss, since
	// spain is the house router and is not always shut down politely.
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) Offset() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Offset
}

// Append records new messages and advances the offset in one durable write,
// then wakes any long-pollers. Offset and inbox move together: persisting
// them separately is how a crash between the two loses or repeats a message.
func (s *Store) Append(offset int64, msgs []Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.st.Offset = offset
	s.st.Inbox = append(s.st.Inbox, msgs...)
	if n := len(s.st.Inbox) - s.MaxInbox; n > 0 {
		s.st.Inbox = append([]Message{}, s.st.Inbox[n:]...)
	}
	if err := s.saveLocked(); err != nil {
		return err
	}
	if len(msgs) > 0 {
		s.wakeLocked()
	}
	return nil
}

// Peek returns messages with ID greater than after, oldest first.
func (s *Store) Peek(after int64, limit int) []Message {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Message, 0, limit)
	for _, m := range s.st.Inbox {
		if m.ID > after {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Ack drops messages up to and including id. Delivery is at-least-once: the
// client acknowledges only after it has durably acted, so a crash between
// receipt and ack replays rather than loses.
func (s *Store) Ack(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	kept := s.st.Inbox[:0]
	for _, m := range s.st.Inbox {
		if m.ID > id {
			kept = append(kept, m)
		}
	}
	s.st.Inbox = append([]Message{}, kept...)
	return s.saveLocked()
}

// Wait returns a channel closed when new messages arrive, for long polling.
func (s *Store) Wait() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := make(chan struct{})
	s.waits = append(s.waits, ch)
	return ch
}

func (s *Store) wakeLocked() {
	for _, ch := range s.waits {
		close(ch)
	}
	s.waits = nil
}

// Stats reports queue depth for /v1/health.
func (s *Store) Stats() (offset int64, pending int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Offset, len(s.st.Inbox)
}
