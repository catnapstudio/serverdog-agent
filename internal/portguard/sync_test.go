package portguard

import (
	"context"
	"errors"
	"maps"
	"path/filepath"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/system"
)

type fakeTarget struct {
	attached bool
	allowed  map[uint16]uint32
	synced   int
}

func (f *fakeTarget) Attached() bool { return f.attached }

func (f *fakeTarget) Sync(allowed map[uint16]uint32) error {
	f.allowed, f.synced = allowed, f.synced+1

	return nil
}

type portUsers map[int]string

func (p portUsers) NodePortUsers() (map[int]string, error) { return p, nil }

func lookupUser(name string) (system.User, error) {
	uids := map[string]uint32{"serverdog": 1000, "bob": 1002}
	uid, ok := uids[name]
	if !ok {
		return system.User{}, errors.New("unknown user " + name)
	}

	return system.User{Name: name, UID: uid}, nil
}

func TestSyncAllowsEachPortToItsSitesUser(t *testing.T) {
	target := &fakeTarget{attached: true}
	syncer := Syncer{
		Guard:      target,
		Store:      portUsers{20000: "serverdog", 20001: "serverdog", 20002: "bob", 20003: "gone", 19999: "serverdog"},
		LookupUser: lookupUser,
		LockPath:   filepath.Join(t.TempDir(), "port-guard.lock"),
	}

	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	want := map[uint16]uint32{20000: 1000, 20001: 1000, 20002: 1002}
	if !maps.Equal(target.allowed, want) {
		t.Errorf("allowed = %v, want %v (a missing user's port and a port outside the range stay root-only)", target.allowed, want)
	}
}

func TestSyncFailsWhenTheGuardIsNotAttached(t *testing.T) {
	target := &fakeTarget{}
	syncer := Syncer{Guard: target, Store: portUsers{20000: "serverdog"}, LookupUser: lookupUser, LockPath: filepath.Join(t.TempDir(), "port-guard.lock")}

	if err := syncer.Sync(context.Background()); !errors.Is(err, ErrNotAttached) {
		t.Errorf("Sync = %v, want ErrNotAttached", err)
	}
	if target.synced != 0 {
		t.Error("synced a guard that isn't attached")
	}
}
