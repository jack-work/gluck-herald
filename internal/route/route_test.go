package route

import (
	"strings"
	"testing"
)

func table(t *testing.T) *Table {
	t.Helper()
	tb, err := NewTable(map[string]string{"gluck": "487734915", "ops": "111222"})
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func TestResolveByName(t *testing.T) {
	tb := table(t)
	id, err := tb.Resolve("gluck")
	if err != nil || id != 487734915 {
		t.Fatalf("Resolve(gluck) = %d, %v", id, err)
	}
	// Names are a human convenience, so case should not matter.
	if id, err := tb.Resolve("  GLUCK "); err != nil || id != 487734915 {
		t.Errorf("Resolve is case/space sensitive: %d, %v", id, err)
	}
}

// The security property: a caller may only reach declared destinations,
// however it spells them. A gateway whose caller can name any destination is
// an open relay that signs its own requests.
func TestUndeclaredDestinationsAreRefused(t *testing.T) {
	tb := table(t)
	for _, bad := range []string{"stranger", "999999", "-100123", ""} {
		if id, err := tb.Resolve(bad); err == nil {
			t.Errorf("Resolve(%q) returned %d; it should be refused", bad, id)
		}
	}
}

// A numeric literal is accepted only when it matches a declared route, so
// existing callers that know an id keep working without opening a hole.
func TestDeclaredChatIDResolvesNumerically(t *testing.T) {
	tb := table(t)
	id, err := tb.Resolve("487734915")
	if err != nil || id != 487734915 {
		t.Fatalf("a declared id must resolve: %d, %v", id, err)
	}
}

func TestUnknownNameErrorListsChoices(t *testing.T) {
	tb := table(t)
	_, err := tb.Resolve("nobody")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "gluck") || !strings.Contains(err.Error(), "ops") {
		t.Errorf("error should list known names: %v", err)
	}
}

func TestAllowedAndNameForCoverInbound(t *testing.T) {
	tb := table(t)
	if !tb.Allowed(487734915) || tb.Allowed(999) {
		t.Error("Allowed must mirror the declared set")
	}
	if tb.NameFor(487734915) != "gluck" || tb.NameFor(999) != "" {
		t.Error("NameFor must label declared chats and only those")
	}
}

func TestBadChatIDIsRejectedAtLoad(t *testing.T) {
	if _, err := NewTable(map[string]string{"x": "not-a-number"}); err == nil {
		t.Fatal("a non-numeric chat id must be refused at load")
	}
	if _, err := NewTable(map[string]string{"": "123"}); err == nil {
		t.Fatal("an empty route name must be refused")
	}
}

func TestEmptyTableRefusesEverything(t *testing.T) {
	tb, err := NewTable(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !tb.Empty() {
		t.Error("a table with no routes is empty")
	}
	if _, err := tb.Resolve("gluck"); err == nil {
		t.Error("an empty table must resolve nothing")
	}
}
