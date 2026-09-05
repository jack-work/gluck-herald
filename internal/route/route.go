// Package route resolves recipient names to Telegram chat ids.
//
// This is herald's one piece of vocabulary on top of the Telegram API.
// Callers name a person, "gluck", rather than carrying 487734915 around in
// their configuration, argv and logs. Names are declared centrally, so a chat
// id appears exactly once on the whole estate.
//
// It is also the security control: a gateway whose caller may name any
// destination is an open relay that signs its own requests. Because a caller
// can only name routes that exist, the set of reachable chats is a property
// of the deployment rather than of the request.
package route

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Table maps names to chat ids.
type Table struct {
	byName map[string]int64
}

// NewTable builds a route table from a name -> chat-id mapping.
func NewTable(spec map[string]string) (*Table, error) {
	t := &Table{byName: map[string]int64{}}
	for name, raw := range spec {
		n := strings.ToLower(strings.TrimSpace(name))
		if n == "" {
			return nil, fmt.Errorf("routes: empty name")
		}
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("routes: %q is not a chat id: %q", name, raw)
		}
		t.byName[n] = id
	}
	return t, nil
}

// Resolve turns a recipient name into a chat id.
//
// A numeric literal is accepted only if it matches a declared route, so
// "--to 487734915" keeps working for anyone who knows the id, while an
// undeclared id is still refused. The allowlist is not bypassable by
// spelling the destination differently.
func (t *Table) Resolve(name string) (int64, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return 0, fmt.Errorf("no recipient given")
	}
	if id, ok := t.byName[n]; ok {
		return id, nil
	}
	if id, err := strconv.ParseInt(n, 10, 64); err == nil {
		for _, known := range t.byName {
			if known == id {
				return id, nil
			}
		}
		return 0, fmt.Errorf("chat %d is not a declared route", id)
	}
	return 0, fmt.Errorf("unknown recipient %q (known: %s)", name, strings.Join(t.Names(), ", "))
}

// NameFor returns the route name for a chat id, or "", used to label
// inbound messages with something a human recognises.
func (t *Table) NameFor(chat int64) string {
	for n, id := range t.byName {
		if id == chat {
			return n
		}
	}
	return ""
}

// Allowed reports whether a chat id is a declared route. Inbound messages
// from anywhere else are refused.
func (t *Table) Allowed(chat int64) bool {
	return t.NameFor(chat) != ""
}

// Names lists declared route names, sorted.
func (t *Table) Names() []string {
	out := make([]string, 0, len(t.byName))
	for n := range t.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Empty reports whether any routes are declared. An empty table refuses
// everything, which is the correct posture for a misconfigured gateway.
func (t *Table) Empty() bool { return len(t.byName) == 0 }
