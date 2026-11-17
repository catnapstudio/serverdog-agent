package servicectl

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

const unitFiles = `cron.service enabled enabled
mariadb.service enabled enabled
mysql.service alias -
mysqld.service alias -
nginx.service enabled enabled
php8.4-fpm.service enabled enabled
php8.5-fpm.service enabled enabled
redis-server.service enabled enabled
ssh.service enabled enabled
`

func setup() (*Manager, *systemtest.Fake) {
	fake := &systemtest.Fake{}
	fake.Handle("systemctl", func(c system.Command) (system.Result, error) {
		switch c.Args[0] {
		case "list-unit-files":
			return system.Result{Output: []byte(unitFiles)}, nil
		case "show":
			states := []string{"active", "inactive", "active", "active", "failed"}
			return system.Result{Output: []byte(strings.Join(states[:len(c.Args)-3], "\n") + "\n")}, nil
		}
		return system.Result{}, nil
	})

	return &Manager{Runner: fake}, fake
}

func TestListKeepsKnownUnitsWithTheirState(t *testing.T) {
	m, _ := setup()

	services, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := []Service{
		{Unit: "mariadb", State: "active"},
		{Unit: "nginx", State: "inactive", Reloadable: true},
		{Unit: "php8.4-fpm", State: "active", Reloadable: true},
		{Unit: "php8.5-fpm", State: "active", Reloadable: true},
		{Unit: "redis-server", State: "failed"},
	}
	if !slices.Equal(services, want) {
		t.Errorf("services = %+v", services)
	}
}

func TestControlRunsOnlyKnownUnitsAndActions(t *testing.T) {
	m, fake := setup()
	ctx := context.Background()

	if err := m.Control(ctx, "php8.5-fpm", Reload); err != nil {
		t.Fatal(err)
	}
	if got := fake.Commands(); !slices.Contains(got, "systemctl reload php8.5-fpm") {
		t.Errorf("commands = %v", got)
	}

	var invalid *site.InvalidError
	for _, c := range []struct {
		unit   string
		action Action
	}{
		{"ssh", Restart},
		{"cron", Restart},
		{"mysql", Restart},
		{"redis-server", Reload},
		{"nginx", "kill"},
		{"nginx; reboot", Restart},
	} {
		if err := m.Control(ctx, c.unit, c.action); !errors.As(err, &invalid) {
			t.Errorf("%s %s: err = %v", c.action, c.unit, err)
		}
	}
}

func TestControlFailureCarriesTheJournal(t *testing.T) {
	m, fake := setup()
	fake.Handle("journalctl", func(system.Command) (system.Result, error) {
		return system.Result{Output: []byte(`{"MESSAGE":"Reloading nginx.service...","_PID":"1"}
{"MESSAGE":"nginx: [emerg] unknown directive \"oops\"","_PID":"812"}
{"MESSAGE":"Reload failed for nginx.service.","_PID":"1"}
`)}, nil
	})
	base := &systemtest.Fake{}
	base.Fail("systemctl", 1, "Job for nginx.service failed.")
	m.Runner = runnerFunc(func(ctx context.Context, c system.Command) (system.Result, error) {
		if c.Name == "systemctl" && c.Args[0] == "restart" {
			return base.Run(ctx, c)
		}
		return fake.Run(ctx, c)
	})

	err := m.Control(context.Background(), "nginx", Restart)

	var failed *Error
	if !errors.As(err, &failed) || failed.Summary != "nginx didn't restart." || failed.Detail != `nginx: [emerg] unknown directive "oops"` {
		t.Errorf("err = %v", err)
	}
}

func TestRebootWaitsThenReboots(t *testing.T) {
	fake := &systemtest.Fake{}
	m := &Manager{Runner: fake, RebootDelay: 10 * time.Millisecond}

	m.Reboot()
	if len(fake.Commands()) != 0 {
		t.Fatal("rebooted before the delay")
	}

	deadline := time.Now().Add(2 * time.Second)
	for !slices.Contains(fake.Commands(), "systemctl reboot") {
		if time.Now().After(deadline) {
			t.Fatal("never rebooted")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type runnerFunc func(context.Context, system.Command) (system.Result, error)

func (f runnerFunc) Run(ctx context.Context, c system.Command) (system.Result, error) {
	return f(ctx, c)
}

func TestServiceLinesFallsBackToSystemdWhenTheServiceSaidNothing(t *testing.T) {
	journal := []byte(`{"MESSAGE":"Failed to start redis-server.service.","_PID":"1"}
{"MESSAGE":[1,2,3],"_PID":"40"}
`)

	if got := serviceLines(journal); got != "Failed to start redis-server.service." {
		t.Errorf("lines = %q", got)
	}
}

func TestRestartingAFailedServiceClearsItsStartCount(t *testing.T) {
	m, fake := setup()
	ctx := context.Background()

	services, err := m.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	failed := services[slices.IndexFunc(services, func(s Service) bool { return s.State == "failed" })].Unit
	running := services[slices.IndexFunc(services, func(s Service) bool { return s.State == "active" })].Unit

	for _, unit := range []string{failed, running} {
		if err := m.Control(ctx, unit, Restart); err != nil {
			t.Fatal(err)
		}
	}

	commands := fake.Commands()
	reset, restart := slices.Index(commands, "systemctl reset-failed "+failed), slices.Index(commands, "systemctl restart "+failed)
	if reset < 0 || restart < reset {
		t.Errorf("commands = %v", commands)
	}
	if slices.Contains(commands, "systemctl reset-failed "+running) {
		t.Errorf("reset a running service: %v", commands)
	}
}
