package authz

import (
	"strings"
	"testing"
)

func TestPolicyGrantsOnlyWhatIsDeclared(t *testing.T) {
	p, err := NewPolicy(map[string][]string{
		"kcal-notify": {"say"},
		"figaro":      {"say", "inbox"},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		client string
		role   Role
		want   bool
	}{
		{"kcal-notify", RoleSay, true},
		{"kcal-notify", RoleInbox, false}, // the notifier must not read replies
		{"kcal-notify", RoleAdmin, false},
		{"figaro", RoleSay, true},
		{"figaro", RoleInbox, true},
		{"figaro", RoleAdmin, false},
		{"stranger", RoleSay, false}, // absent means nothing, always
	}
	for _, c := range cases {
		if got := p.Allows(c.client, c.role); got != c.want {
			t.Errorf("Allows(%q, %q) = %v, want %v", c.client, c.role, got, c.want)
		}
	}
}

// A typo in configuration must fail at startup, not silently grant nothing —
// or, worse, be mistaken for a grant.
func TestUnknownRoleIsRejectedAtLoad(t *testing.T) {
	_, err := NewPolicy(map[string][]string{"svc": {"say", "delete-everything"}})
	if err == nil {
		t.Fatal("an unknown role must be refused")
	}
	if !strings.Contains(err.Error(), "delete-everything") {
		t.Errorf("error should name the offending role: %v", err)
	}
}

func TestEmptyClientIDIsRejected(t *testing.T) {
	if _, err := NewPolicy(map[string][]string{"": {"say"}}); err == nil {
		t.Fatal("an empty client_id must be refused")
	}
}

// Known and Allows answer different questions: registration versus
// permission. The server maps them to 401 and 403.
func TestKnownDistinguishesRegistrationFromPermission(t *testing.T) {
	p, _ := NewPolicy(map[string][]string{"registered": {}})
	if !p.Known("registered") {
		t.Error("a client with no roles is still registered")
	}
	if p.Allows("registered", RoleSay) {
		t.Error("no roles means no permissions")
	}
	if p.Known("stranger") {
		t.Error("an undeclared client is not registered")
	}
}

func TestNilPolicyDeniesEverything(t *testing.T) {
	var p *Policy
	if p.Allows("anyone", RoleSay) || p.Known("anyone") {
		t.Error("a nil policy must deny, not panic or permit")
	}
}
