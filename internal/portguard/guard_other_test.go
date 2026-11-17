//go:build !linux

package portguard

import (
	"errors"
	"testing"
)

func TestTheGuardNeedsLinux(t *testing.T) {
	g := Default()

	if err := g.Ensure(); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Ensure = %v, want ErrUnsupported", err)
	}
	if g.Attached() {
		t.Error("attached without Linux")
	}
	if err := g.Sync(map[uint16]uint32{20000: 1000}); !errors.Is(err, ErrNotAttached) {
		t.Errorf("Sync = %v, want ErrNotAttached", err)
	}
}
