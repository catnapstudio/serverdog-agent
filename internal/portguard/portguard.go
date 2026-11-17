// Package portguard keeps Node sites' ports for their own users. A cgroup bind4 and bind6 program on the root cgroup
// lets a bind() to a port in the Node range through only for root or for the uid a pinned map records for that port.
// Every other bind in the range fails with EPERM, including binds to ports no site has yet. Ports outside the range,
// and binds in any network namespace but the host's (containers), are left alone.
//
// The program, its map and its links are pinned under PinDir, so the guard outlives the process that attached it.
// The serverdog-port-guard unit attaches it at boot, before any login or site starts; the agent attaches it again at
// startup, which replaces the program in place, and keeps the map in step with the store (Syncer).
package portguard

import (
	"errors"

	"github.com/catnapstudio/serverdog-agent/internal/state"
)

const (
	// DefaultPinDir holds the pinned map ("ports") and links ("bind4", "bind6"). Removing it detaches the guard.
	DefaultPinDir = "/sys/fs/bpf/serverdog"
	// DefaultCgroup is the root cgroup: a program attached there runs for every process on the server.
	DefaultCgroup = "/sys/fs/cgroup"
)

// ErrNotAttached is a guard whose links or map aren't pinned.
var ErrNotAttached = errors.New("the port guard isn't attached")

// Guard is the bind program for one port range, attached to one cgroup and pinned in one directory.
type Guard struct {
	PinDir string
	Cgroup string
	// First and Last bound the guarded ports, inclusive.
	First, Last uint16
}

// Default guards the Node port range for every process on the server.
func Default() Guard {
	return Guard{PinDir: DefaultPinDir, Cgroup: DefaultCgroup, First: state.FirstNodePort, Last: state.LastNodePort}
}
