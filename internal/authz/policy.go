// Package authz decides what a verified caller may do.
//
// Herald deliberately keys authorization on the OIDC client_id rather than on
// a user. A machine caller: a timer on spain minting a client_credentials
// token: has no user at all: no preferred_username, no groups. Any model
// built on "which person is this" cannot express it, so herald asks "which
// program is this, and what is it allowed to do".
package authz

import (
	"fmt"
	"sort"
	"strings"
)

// Role is one capability herald exposes. They are deliberately coarse and
// few: a capability nobody can name is a capability nobody can reason about.
type Role string

const (
	// RoleSay permits sending messages.
	RoleSay Role = "say"
	// RoleInbox permits reading and acknowledging inbound messages.
	//
	// Separate from RoleSay on purpose. A notifier that announces calendar
	// events has no business reading the replies to them, and saying so in
	// configuration is cheaper than trusting it not to.
	RoleInbox Role = "inbox"
	// RoleAdmin permits introspection (whoami, routes).
	RoleAdmin Role = "admin"
)

var known = map[Role]bool{RoleSay: true, RoleInbox: true, RoleAdmin: true}

// Policy maps a client_id to the roles it holds. A client absent from the
// policy holds nothing: the default is deny, and it is not configurable.
type Policy struct {
	clients map[string]map[Role]bool
}

// NewPolicy builds a policy from a client_id -> roles mapping, rejecting
// unknown role names so a typo in configuration fails at startup rather than
// silently granting nothing (or, worse, being read as a grant).
func NewPolicy(spec map[string][]string) (*Policy, error) {
	p := &Policy{clients: map[string]map[Role]bool{}}
	for client, roles := range spec {
		if strings.TrimSpace(client) == "" {
			return nil, fmt.Errorf("policy: empty client_id")
		}
		set := map[Role]bool{}
		for _, r := range roles {
			role := Role(strings.TrimSpace(r))
			if !known[role] {
				return nil, fmt.Errorf("policy: client %q has unknown role %q (known: %s)",
					client, r, strings.Join(KnownRoles(), ", "))
			}
			set[role] = true
		}
		p.clients[client] = set
	}
	return p, nil
}

// KnownRoles lists every role herald understands, for error messages.
func KnownRoles() []string {
	out := make([]string, 0, len(known))
	for r := range known {
		out = append(out, string(r))
	}
	sort.Strings(out)
	return out
}

// Allows reports whether a client holds a role.
func (p *Policy) Allows(clientID string, role Role) bool {
	if p == nil {
		return false
	}
	return p.clients[clientID][role]
}

// Known reports whether the client appears in the policy at all. Used to
// distinguish "not registered here" (401) from "registered but not permitted
// this" (403), a distinction worth keeping, because they call for different
// fixes.
func (p *Policy) Known(clientID string) bool {
	if p == nil {
		return false
	}
	_, ok := p.clients[clientID]
	return ok
}

// Roles returns a client's roles, sorted.
func (p *Policy) Roles(clientID string) []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.clients[clientID]))
	for r := range p.clients[clientID] {
		out = append(out, string(r))
	}
	sort.Strings(out)
	return out
}

// Clients lists every client_id in the policy, sorted.
func (p *Policy) Clients() []string {
	out := make([]string, 0, len(p.clients))
	for c := range p.clients {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
