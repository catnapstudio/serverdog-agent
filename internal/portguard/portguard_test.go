package portguard

import (
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/state"
)

func TestDefaultGuardsTheNodePortsOnTheRootCgroup(t *testing.T) {
	g := Default()

	if g.First != state.FirstNodePort || g.Last != state.LastNodePort {
		t.Errorf("range = %d-%d, want %d-%d", g.First, g.Last, state.FirstNodePort, state.LastNodePort)
	}
	if g.Cgroup != "/sys/fs/cgroup" || g.PinDir != "/sys/fs/bpf/serverdog" {
		t.Errorf("guard = %+v", g)
	}
}
