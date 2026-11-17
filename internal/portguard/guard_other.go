//go:build !linux

package portguard

import "errors"

// ErrUnsupported is the guard on a system without Linux's cgroup BPF hooks.
var ErrUnsupported = errors.New("the port guard needs Linux")

func (g Guard) Ensure() error { return ErrUnsupported }

func (g Guard) Attached() bool { return false }

func (g Guard) Sync(map[uint16]uint32) error { return ErrNotAttached }

func (g Guard) Remove() error { return nil }
