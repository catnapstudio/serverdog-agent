package nginx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"log/slog"

	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

// fakeProc is a /proc with an Nginx master (pid 100) and its processes.
type fakeProc struct {
	t       *testing.T
	root    string
	pidFile string
}

func newFakeProc(t *testing.T) *fakeProc {
	root := t.TempDir()
	p := &fakeProc{t: t, root: filepath.Join(root, "proc"), pidFile: filepath.Join(root, "nginx.pid")}
	os.WriteFile(p.pidFile, []byte("100\n"), 0o644)
	p.process(100, 1, "nginx: master process /usr/sbin/nginx")

	return p
}

func (p *fakeProc) process(pid, ppid int, title string) {
	dir := filepath.Join(p.root, fmt.Sprint(pid))
	os.MkdirAll(dir, 0o755)
	if err := os.WriteFile(filepath.Join(dir, "stat"), fmt.Appendf(nil, "%d (nginx) S %d %d 0 0", pid, ppid, pid), 0o644); err != nil {
		p.t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "cmdline"), []byte(title+"\x00\x00\x00"), 0o644)
}

func (p *fakeProc) exit(pid int) { os.RemoveAll(filepath.Join(p.root, fmt.Sprint(pid))) }

func (p *fakeProc) title(pid int) string {
	content, _ := os.ReadFile(filepath.Join(p.root, fmt.Sprint(pid), "cmdline"))
	return strings.TrimRight(string(content), "\x00")
}

func (p *fakeProc) reloader(runner system.Runner, timeout time.Duration) Reloader {
	return Reloader{Runner: runner, PIDFile: p.pidFile, Proc: p.root, Timeout: timeout, Every: 5 * time.Millisecond}
}

// The reload must not return while old workers still accept requests with the old configuration:
// systemctl reload nginx only signals the master, which switches workers moments later.
func TestReloadWaitsUntilOldWorkersShutDown(t *testing.T) {
	proc := newFakeProc(t)
	proc.process(101, 100, "nginx: worker process")
	proc.process(102, 100, "nginx: worker process")
	proc.process(103, 100, "nginx: cache manager process")
	proc.process(200, 1, "sshd: worker process")

	fake := &systemtest.Fake{}
	fake.Handle("systemctl", func(system.Command) (system.Result, error) {
		go func() {
			time.Sleep(50 * time.Millisecond)
			proc.process(111, 100, "nginx: worker process")
			proc.process(101, 100, "nginx: worker process is shutting down")
			proc.exit(102)
			time.Sleep(50 * time.Millisecond)
			proc.exit(103)
		}()
		return system.Result{}, nil
	})

	if err := proc.reloader(fake, 5*time.Second).Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(fake.Commands(), "\n"); got != "systemctl reload nginx" {
		t.Errorf("commands = %q", got)
	}
	if proc.title(101) != "nginx: worker process is shutting down" || proc.title(103) != "" {
		t.Error("Reload returned before every old worker stopped taking requests")
	}
}

func TestReloadFailsWhenNginxKeepsTheOldWorkers(t *testing.T) {
	proc := newFakeProc(t)
	proc.process(101, 100, "nginx: worker process")

	err := proc.reloader(&systemtest.Fake{}, 50*time.Millisecond).Reload(context.Background())
	if err == nil || !strings.Contains(err.Error(), "error.log") {
		t.Errorf("err = %v", err)
	}
}

func TestReloadReportsSystemctlFailures(t *testing.T) {
	proc := newFakeProc(t)
	proc.process(101, 100, "nginx: worker process")

	fake := &systemtest.Fake{}
	fake.Fail("systemctl", 1, "Job for nginx.service failed.")

	err := proc.reloader(fake, time.Second).Reload(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Job for nginx.service failed.") {
		t.Errorf("err = %v", err)
	}
}

func TestReloadWithoutARunningMasterOnlyReloads(t *testing.T) {
	proc := newFakeProc(t)
	os.Remove(proc.pidFile)

	var log bytes.Buffer
	fake := &systemtest.Fake{}
	reloader := proc.reloader(fake, time.Second)
	reloader.Logger = slog.New(slog.NewTextHandler(&log, nil))

	if err := reloader.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fake.Commands(), "\n"); got != "systemctl reload nginx" {
		t.Errorf("commands = %q", got)
	}
	if !strings.Contains(log.String(), "level=WARN") || !strings.Contains(log.String(), "nginx.pid") {
		t.Errorf("log = %q", log.String())
	}
}

func TestReloadWithoutProcWarnsAndOnlyReloads(t *testing.T) {
	proc := newFakeProc(t)

	var log bytes.Buffer
	fake := &systemtest.Fake{}
	reloader := proc.reloader(fake, time.Second)
	reloader.Proc = filepath.Join(t.TempDir(), "missing")
	reloader.Logger = slog.New(slog.NewTextHandler(&log, nil))

	if err := reloader.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "level=WARN") || !strings.Contains(log.String(), "missing") {
		t.Errorf("log = %q", log.String())
	}
}

func TestReloadCommandRunsTheAgentHelper(t *testing.T) {
	if got := strings.Join(append([]string{Reload.Name}, Reload.Args...), " "); got != "/usr/local/bin/serverdog-agent reload-nginx" {
		t.Errorf("Reload = %q", got)
	}
	if Reload.Description != "systemctl reload nginx" {
		t.Errorf("Reload.Description = %q", Reload.Description)
	}
}
