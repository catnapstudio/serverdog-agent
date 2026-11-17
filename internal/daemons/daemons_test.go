package daemons

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

func newManager(t *testing.T) (*Manager, *systemtest.Fake, string) {
	t.Helper()

	root := t.TempDir()
	store, err := state.Open(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	fake := &systemtest.Fake{}
	m := &Manager{
		Store: store, Paths: paths.Paths{Root: root}, System: fake,
		Applier: apply.Applier{Runner: fake, LockPath: filepath.Join(root, "apply.lock")},
		LookupUser: func(name string) (system.User, error) {
			if name == "root" || name == "serverdog" {
				return system.User{Name: name}, nil
			}
			return system.User{}, errors.New("unknown user")
		},
	}

	return m, fake, root
}

var reverb = Daemon{ID: "reverbreverb", Name: "Reverb", Command: "php8.4 artisan reverb:start --port=8080", User: "serverdog", Count: 2}

func TestDaemonsAreSavedWrittenAndStarted(t *testing.T) {
	m, fake, root := newManager(t)

	revision, err := m.Put(context.Background(), []Daemon{reverb}, 0)
	if err != nil || revision != 1 {
		t.Fatalf("Put = %d, %v", revision, err)
	}

	unit, _ := os.ReadFile(filepath.Join(root, paths.SystemdUnit(Template(reverb.ID))))
	for _, want := range []string{"User=serverdog\n", "WorkingDirectory=~\n", "ExecStart=/etc/serverdog/daemons/reverbreverb.sh\n", "Restart=always\n"} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}

	script, _ := os.ReadFile(filepath.Join(root, StartScript(reverb.ID)))
	if string(script) != "#!/bin/sh\n# Managed by ServerDog.\nexec "+reverb.Command+"\n" {
		t.Errorf("start script = %q", script)
	}

	commands := fake.Commands()
	for _, want := range []string{
		"systemctl daemon-reload",
		"systemctl enable serverdog-daemon-reverbreverb@1.service serverdog-daemon-reverbreverb@2.service",
		"systemctl restart --no-block serverdog-daemon-reverbreverb@1.service serverdog-daemon-reverbreverb@2.service",
	} {
		if !slices.Contains(commands, want) {
			t.Errorf("commands %q lack %q", commands, want)
		}
	}

	list, listed, err := m.List()
	if err != nil || listed != 1 || len(list) != 1 || list[0] != reverb {
		t.Errorf("List = %v, %d, %v", list, listed, err)
	}
}

func TestShrinkingAndRemovingStopsCopies(t *testing.T) {
	m, fake, root := newManager(t)
	ctx := context.Background()

	if _, err := m.Put(ctx, []Daemon{reverb}, 0); err != nil {
		t.Fatal(err)
	}

	shrunk := reverb
	shrunk.Count = 1
	if _, err := m.Put(ctx, []Daemon{shrunk}, 1); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(fake.Commands(), "systemctl disable --now serverdog-daemon-reverbreverb@2.service") {
		t.Errorf("the second copy didn't stop: %q", fake.Commands())
	}

	if _, err := m.Put(ctx, nil, 2); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(fake.Commands(), "systemctl disable --now serverdog-daemon-reverbreverb@1.service") {
		t.Errorf("the removed daemon didn't stop: %q", fake.Commands())
	}
	if _, err := os.Stat(filepath.Join(root, paths.SystemdUnit(Template(reverb.ID)))); !os.IsNotExist(err) {
		t.Errorf("the unit is still there: %v", err)
	}
}

func TestUnchangedDaemonsDontRestart(t *testing.T) {
	m, fake, _ := newManager(t)
	ctx := context.Background()

	if _, err := m.Put(ctx, []Daemon{reverb}, 0); err != nil {
		t.Fatal(err)
	}
	before := len(fake.Commands())

	if _, err := m.Put(ctx, []Daemon{reverb}, 1); err != nil {
		t.Fatal(err)
	}
	for _, command := range fake.Commands()[before:] {
		if strings.HasPrefix(command, "systemctl restart") {
			t.Errorf("an unchanged daemon restarted: %s", command)
		}
	}
}

func TestInvalidDaemonsAreRefused(t *testing.T) {
	m, _, root := newManager(t)
	os.MkdirAll(filepath.Join(root, "srv/app"), 0o755)

	valid := reverb
	valid.Directory = "/srv/app"
	if _, err := m.Put(context.Background(), []Daemon{valid}, 0); err != nil {
		t.Fatalf("an existing folder was refused: %v", err)
	}

	for name, change := range map[string]func(*Daemon){
		"no command":        func(d *Daemon) { d.Command = " " },
		"two lines":         func(d *Daemon) { d.Command = "a\nb" },
		"no copies":         func(d *Daemon) { d.Count = 0 },
		"too many copies":   func(d *Daemon) { d.Count = 17 },
		"unknown user":      func(d *Daemon) { d.User = "nobody2" },
		"relative folder":   func(d *Daemon) { d.Directory = "srv/app" },
		"folder with space": func(d *Daemon) { d.Directory = "/srv/my app" },
		"missing folder":    func(d *Daemon) { d.Directory = "/srv/missing" },
		"bad id":            func(d *Daemon) { d.ID = "x" },
	} {
		d := reverb
		change(&d)
		if _, err := m.Put(context.Background(), []Daemon{d}, 1); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStaleRevisionIsRefused(t *testing.T) {
	m, _, _ := newManager(t)

	if _, err := m.Put(context.Background(), []Daemon{reverb}, 5); !errors.Is(err, state.ErrStaleDocument) {
		t.Errorf("Put = %v, want a stale document", err)
	}
}

func TestAStoppedDaemonStaysOffAndRefusesRestart(t *testing.T) {
	m, fake, root := newManager(t)
	ctx := context.Background()

	stopped := reverb
	stopped.Stopped = true
	stopped.StopSeconds = 300
	if _, err := m.Put(ctx, []Daemon{stopped}, 0); err != nil {
		t.Fatal(err)
	}

	instances := "serverdog-daemon-reverbreverb@1.service serverdog-daemon-reverbreverb@2.service"
	if !slices.Contains(fake.Commands(), "systemctl disable --now --no-block "+instances) {
		t.Errorf("the daemon didn't stop: %q", fake.Commands())
	}
	for _, command := range fake.Commands() {
		if strings.HasPrefix(command, "systemctl restart") || strings.HasPrefix(command, "systemctl enable") {
			t.Errorf("a stopped daemon started: %s", command)
		}
	}

	unit, _ := os.ReadFile(filepath.Join(root, paths.SystemdUnit(Template(reverb.ID))))
	if !strings.Contains(string(unit), "TimeoutStopSec=300\n") {
		t.Errorf("unit ignores the stop timeout:\n%s", unit)
	}

	if err := m.Restart(ctx, reverb.ID); !errors.Is(err, ErrStopped) {
		t.Errorf("Restart of a stopped daemon = %v", err)
	}

	if _, err := m.Put(ctx, []Daemon{reverb}, 1); err != nil {
		t.Fatal(err)
	}
	fake.Reset()
	if err := m.Restart(ctx, reverb.ID); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fake.Commands(), []string{"systemctl restart --no-block " + instances}) {
		t.Errorf("Restart ran %q", fake.Commands())
	}
	if err := m.Restart(ctx, "missingmissi"); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("Restart of a missing daemon = %v", err)
	}
}
