package portguard

import (
	"context"
	"fmt"

	"github.com/catnapstudio/serverdog-agent/internal/lock"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// Target is the guard a Syncer fills: Guard in production.
type Target interface {
	Attached() bool
	Sync(allowed map[uint16]uint32) error
}

// PortUsers lists the Linux user of every allocated Node port (state.Store in production).
type PortUsers interface {
	NodePortUsers() (map[int]string, error)
}

// Syncer keeps the guard's map in step with the store. The agent, its deploys and the boot unit run in different
// processes, so each sync reads the store and writes the map under one file lock: the last sync always wrote the
// latest ports.
type Syncer struct {
	Guard      Target
	Store      PortUsers
	LookupUser func(name string) (system.User, error)
	LockPath   string
}

// Sync lets each site's user bind its site's ports, and nobody else but root. A port whose user doesn't exist is left
// out, so only root can bind it. It returns ErrNotAttached when the guard isn't attached.
func (s Syncer) Sync(ctx context.Context) error {
	release, err := lock.Acquire(ctx, s.LockPath)
	if err != nil {
		return err
	}
	defer release()

	if !s.Guard.Attached() {
		return ErrNotAttached
	}

	users, err := s.Store.NodePortUsers()
	if err != nil {
		return fmt.Errorf("read the Node ports: %w", err)
	}

	allowed := make(map[uint16]uint32, len(users))
	for port, name := range users {
		if port < state.FirstNodePort || port > state.LastNodePort {
			continue
		}

		user, err := s.LookupUser(name)
		if err != nil {
			continue
		}

		allowed[uint16(port)] = user.UID
	}

	return s.Guard.Sync(allowed)
}
