package ids

import "testing"

func TestNewProducesValidDistinctIDs(t *testing.T) {
	seen := map[string]bool{}

	for range 1000 {
		id := New()
		if !Valid(id) {
			t.Fatalf("New() = %q, not valid", id)
		}
		if seen[id] {
			t.Fatalf("New() repeated %q", id)
		}
		seen[id] = true
	}
}

func TestValidRejectsOtherShapes(t *testing.T) {
	for _, id := range []string{"", "abc", "ABCDEFGHIJKL", "abcdefghijk1", "abcdefghijklm", "abcdef-hijkl", "../etc/pass"} {
		if Valid(id) {
			t.Errorf("Valid(%q) = true", id)
		}
	}
}
