package sites

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

const (
	workerUnit   = "/etc/systemd/system/serverdog-process-abcdefghijkl-workerid2345@.service"
	workerScript = "/etc/serverdog/sites/abcdefghijkl/process-workerid2345.sh"
	schedulerTab = "/etc/cron.d/serverdog-abcdefghijkl"
)

func withWorker(s site.Site, count int) site.Site {
	s.Processes = []site.Process{{ID: "workerid2345", Name: "Queue worker", Command: "php8.4 artisan queue:work --tries=3", Count: count}}
	return s
}

func worker(n string) string { return "serverdog-process-abcdefghijkl-workerid2345@" + n + ".service" }

func TestPutStartsANewProcessInTheLiveRelease(t *testing.T) {
	f := newFixture(t)

	if _, _, err := f.manager.Put(ctx, withWorker(laravel(), 2), 0, "Mac"); err != nil {
		t.Fatal(err)
	}

	unit, _ := os.ReadFile(f.file(workerUnit))
	for _, line := range []string{"User=serverdog", "WorkingDirectory=/home/serverdog/orchard.com/current", "ConditionPathExists=/home/serverdog/orchard.com/current", "ExecStart=" + workerScript, "Restart=always"} {
		if !strings.Contains(string(unit), line+"\n") {
			t.Errorf("unit lacks %q:\n%s", line, unit)
		}
	}

	script, _ := os.ReadFile(f.file(workerScript))
	if string(script) != "#!/bin/sh\n# Managed by ServerDog.\nexec php8.4 artisan queue:work --tries=3\n" {
		t.Errorf("script = %q", script)
	}

	commands := f.system.Commands()
	for _, want := range []string{
		"systemctl daemon-reload",
		"systemctl enable " + worker("1") + " " + worker("2"),
		"systemctl restart --no-block " + worker("1") + " " + worker("2"),
	} {
		if !slices.Contains(commands, want) {
			t.Errorf("commands lack %q:\n%v", want, commands)
		}
	}
}

func TestAnUnchangedProcessIsNotRestarted(t *testing.T) {
	f := newFixture(t)
	saved, _, _ := f.manager.Put(ctx, withWorker(laravel(), 1), 0, "Mac")
	f.system.Reset()

	saved.ForceHTTPS = true
	if _, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil {
		t.Fatal(err)
	}

	for _, command := range f.system.Commands() {
		if strings.Contains(command, "serverdog-process-") {
			t.Errorf("unchanged process touched: %q", command)
		}
	}
}

func TestShrinkingAProcessStopsItsExtraCopiesFirst(t *testing.T) {
	f := newFixture(t)
	saved, _, _ := f.manager.Put(ctx, withWorker(laravel(), 3), 0, "Mac")
	f.system.Reset()

	saved.Processes[0].Count = 1
	if _, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil {
		t.Fatal(err)
	}

	commands := f.system.Commands()
	stop := slices.Index(commands, "systemctl disable --now "+worker("2")+" "+worker("3"))
	restart := slices.Index(commands, "systemctl restart --no-block "+worker("1"))
	if stop < 0 || restart < stop {
		t.Errorf("commands = %v", commands)
	}
}

func TestRemovingAProcessStopsItAndRemovesItsUnit(t *testing.T) {
	f := newFixture(t)
	saved, _, _ := f.manager.Put(ctx, withWorker(laravel(), 2), 0, "Mac")
	f.system.Reset()

	saved.Processes = nil
	if _, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil {
		t.Fatal(err)
	}

	commands := f.system.Commands()
	stop := slices.Index(commands, "systemctl disable --now "+worker("1")+" "+worker("2"))
	reload := slices.Index(commands, "systemctl daemon-reload")
	if stop < 0 || reload < stop {
		t.Errorf("the copies didn't stop before their unit went: %v", commands)
	}
	for _, logical := range []string{workerUnit, workerScript} {
		if f.exists(logical) {
			t.Errorf("%s still exists", logical)
		}
	}
}

func TestAFailedStopKeepsTheProcessAndTheSite(t *testing.T) {
	f := newFixture(t)
	saved, _, _ := f.manager.Put(ctx, withWorker(laravel(), 1), 0, "Mac")
	f.system.Handle("systemctl", func(c system.Command) (system.Result, error) {
		if c.Args[0] == "disable" {
			return system.Result{ExitCode: 1, Output: []byte("Failed to stop")}, &system.ExitError{Command: "systemctl", ExitCode: 1}
		}
		return system.Result{}, nil
	})

	changed := saved
	changed.Processes = nil
	if _, _, err := f.manager.Put(ctx, changed, saved.Revision, "Mac"); err == nil || !strings.Contains(err.Error(), "Failed to stop") {
		t.Fatalf("err = %v", err)
	}

	stored, _ := f.store.GetSite("abcdefghijkl")
	if len(stored.Processes) != 1 || !f.exists(workerUnit) {
		t.Errorf("process lost after a failed stop: %+v", stored.Processes)
	}
}

func TestTheSchedulerRunsEveryMinuteUntilTurnedOff(t *testing.T) {
	f := newFixture(t)
	s := laravel()
	s.Scheduler = true

	saved, _, err := f.manager.Put(ctx, s, 0, "Mac")
	if err != nil {
		t.Fatal(err)
	}

	tab, _ := os.ReadFile(f.file(schedulerTab))
	if !strings.Contains(string(tab), "* * * * * serverdog cd '/home/serverdog/orchard.com/current' && /usr/bin/php8.4 artisan schedule:run >> /dev/null 2>&1\n") {
		t.Errorf("cron = %q", tab)
	}

	saved.Scheduler = false
	if _, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil {
		t.Fatal(err)
	}
	if f.exists(schedulerTab) {
		t.Error("scheduler still installed")
	}
}

func TestDeletingASiteStopsItsProcessesAndScheduler(t *testing.T) {
	f := newFixture(t)
	s := withWorker(laravel(), 1)
	s.Scheduler = true
	f.manager.Put(ctx, s, 0, "Mac")
	f.system.Reset()

	if err := f.manager.Delete(ctx, "abcdefghijkl", false, "Mac"); err != nil {
		t.Fatal(err)
	}

	if !slices.Contains(f.system.Commands(), "systemctl disable --now "+worker("1")) {
		t.Errorf("commands = %v", f.system.Commands())
	}
	for _, logical := range []string{workerUnit, workerScript, schedulerTab} {
		if f.exists(logical) {
			t.Errorf("%s still exists", logical)
		}
	}
}

func TestProcessesReportRunningCopiesAndWaitForTheFirstRelease(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, withWorker(laravel(), 2), 0, "Mac")
	f.system.Handle("systemctl", func(c system.Command) (system.Result, error) {
		return system.Result{Output: []byte("active\n\nactivating\n")}, nil
	})
	f.system.Handle("journalctl", func(c system.Command) (system.Result, error) {
		if !slices.Contains(c.Args, "--unit=serverdog-process-abcdefghijkl-workerid2345@*") || !slices.Contains(c.Args, "--lines=50") {
			t.Errorf("journalctl %v", c.Args)
		}
		return system.Result{Output: []byte("Processing jobs\n")}, nil
	})

	statuses, err := f.manager.Processes(ctx, "abcdefghijkl", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].Running != 1 || !statuses[0].WaitingForRelease || statuses[0].Log != "Processing jobs\n" {
		t.Errorf("statuses = %+v", statuses)
	}

	if err := os.Symlink("releases", f.file("/home/serverdog/orchard.com/current")); err != nil {
		t.Fatal(err)
	}
	if statuses, _ := f.manager.Processes(ctx, "abcdefghijkl", 50); statuses[0].WaitingForRelease {
		t.Error("still waiting with a live release")
	}
}

func TestAStoppedProcessStaysOffUntilStarted(t *testing.T) {
	f := newFixture(t)
	saved, _, _ := f.manager.Put(ctx, withWorker(laravel(), 2), 0, "Mac")
	f.system.Reset()

	saved.Processes[0].Stopped = true
	saved, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac")
	if err != nil {
		t.Fatal(err)
	}

	commands := f.system.Commands()
	if !slices.Contains(commands, "systemctl disable --now --no-block "+worker("1")+" "+worker("2")) {
		t.Errorf("the process didn't stop: %v", commands)
	}
	for _, command := range commands {
		if strings.HasPrefix(command, "systemctl restart") {
			t.Errorf("a stopped process restarted: %s", command)
		}
	}
	if err := f.manager.RestartProcess(ctx, saved.ID, "workerid2345", "Mac"); !errors.Is(err, ErrProcessStopped) {
		t.Errorf("RestartProcess of a stopped process = %v", err)
	}

	f.system.Reset()
	saved.Processes[0].Stopped = false
	if _, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.system.Commands(), "systemctl restart --no-block "+worker("1")+" "+worker("2")) {
		t.Errorf("the process didn't start again: %v", f.system.Commands())
	}
}

func TestRestartProcessRestartsEveryCopy(t *testing.T) {
	f := newFixture(t)
	saved, _, _ := f.manager.Put(ctx, withWorker(laravel(), 2), 0, "Mac")
	f.system.Reset()

	if err := f.manager.RestartProcess(ctx, saved.ID, "workerid2345", "Mac"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.system.Commands(), []string{"systemctl restart --no-block " + worker("1") + " " + worker("2")}) {
		t.Errorf("commands = %v", f.system.Commands())
	}
	if err := f.manager.RestartProcess(ctx, saved.ID, "missingmissi", "Mac"); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("RestartProcess of a missing process = %v", err)
	}
}

func TestAProcessStopTimeoutReachesItsUnit(t *testing.T) {
	f := newFixture(t)
	s := withWorker(laravel(), 1)
	s.Processes[0].StopSeconds = 900
	if _, _, err := f.manager.Put(ctx, s, 0, "Mac"); err != nil {
		t.Fatal(err)
	}

	unit, _ := os.ReadFile(f.file(workerUnit))
	if !strings.Contains(string(unit), "TimeoutStopSec=900\n") {
		t.Errorf("unit ignores the stop timeout:\n%s", unit)
	}

	s.Processes[0].StopSeconds = 3601
	if _, _, err := f.manager.Put(ctx, s, 1, "Mac"); err == nil {
		t.Error("a stop timeout over an hour was accepted")
	}
}

func TestAReverbDomainGetsAPortAndKeepsIt(t *testing.T) {
	f := newFixture(t)
	s := laravel()
	s.Domains = append(s.Domains, site.Domain{Name: "ws.orchard.com", Redirect: site.NoRedirect, Reverb: true})

	saved, _, err := f.manager.Put(ctx, s, 0, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if saved.ReverbPort != state.FirstNodePort {
		t.Fatalf("ReverbPort = %d", saved.ReverbPort)
	}
	config, _ := os.ReadFile(f.file(paths.NginxSiteAvailable(saved.ID)))
	if !strings.Contains(string(config), "proxy_pass http://127.0.0.1:20000;") {
		t.Errorf("Nginx doesn't forward to Reverb:\n%s", config)
	}

	// The app never sends the port; an unchanged site stays unchanged.
	saved.ReverbPort = 0
	again, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac")
	if err != nil || again.Revision != saved.Revision || again.ReverbPort != state.FirstNodePort {
		t.Errorf("Put again = revision %d port %d, %v", again.Revision, again.ReverbPort, err)
	}

	again.Domains = again.Domains[:1]
	without, _, err := f.manager.Put(ctx, again, again.Revision, "Mac")
	if err != nil || without.ReverbPort != 0 {
		t.Errorf("without its domain, ReverbPort = %d, %v", without.ReverbPort, err)
	}
}
