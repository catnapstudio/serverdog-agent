package nginx

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// Reloader reloads Nginx and returns once the new configuration answers requests. systemctl reload nginx only
// signals the master, which starts new workers and tells the old ones to stop taking requests moments later.
type Reloader struct {
	Runner system.Runner
	// PIDFile holds the master's pid; Proc is the proc filesystem.
	PIDFile string
	Proc    string
	// Timeout bounds the wait for the old workers; Every is the polling interval.
	Timeout time.Duration
	Every   time.Duration
	// Logger receives a warning when the wait can't happen; nil uses slog.Default().
	Logger *slog.Logger
}

// SystemReloader is the server's Nginx, as Ubuntu's package runs it.
func SystemReloader(runner system.Runner) Reloader {
	return Reloader{Runner: runner, PIDFile: "/run/nginx.pid", Proc: "/proc", Timeout: 10 * time.Second, Every: 20 * time.Millisecond}
}

// Reload reloads Nginx and waits until every process the master ran before has exited or is shutting down.
func (r Reloader) Reload(ctx context.Context) error {
	master := r.masterPID()
	old := r.children(master)

	if result, err := r.Runner.Run(ctx, system.Command{Name: "systemctl", Args: []string{"reload", "nginx"}}); err != nil {
		return fmt.Errorf("systemctl reload nginx: %w: %s", err, strings.TrimSpace(string(result.Output)))
	}

	deadline := time.Now().Add(r.Timeout)
	for {
		if !r.anyServing(master, old) {
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("Nginx didn't switch to the new configuration within %s; see /var/log/nginx/error.log.", r.Timeout)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.Every):
		}
	}
}

func (r Reloader) masterPID() int {
	content, err := os.ReadFile(r.PIDFile)
	if err != nil {
		r.warn("read nginx pid file", err)
		return 0
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil {
		r.warn("parse nginx pid file", err)
		return 0
	}

	return pid
}

func (r Reloader) warn(step string, err error) {
	logger := r.Logger
	if logger == nil {
		logger = slog.Default()
	}

	logger.Warn("reloading nginx without waiting for the new configuration", "step", step, "error", err)
}

// children lists the processes whose parent is master.
func (r Reloader) children(master int) []int {
	if master == 0 {
		return nil
	}

	entries, err := os.ReadDir(r.Proc)
	if err != nil {
		r.warn("list processes", err)
		return nil
	}

	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		if r.parent(pid) == master {
			pids = append(pids, pid)
		}
	}

	return pids
}

// parent reads the parent pid from /proc/<pid>/stat, whose fourth field follows the command name in parentheses.
func (r Reloader) parent(pid int) int {
	content, err := os.ReadFile(filepath.Join(r.Proc, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0
	}

	stat := string(content)
	fields := strings.Fields(stat[strings.LastIndex(stat, ")")+1:])
	if len(fields) < 2 {
		return 0
	}

	ppid, _ := strconv.Atoi(fields[1])

	return ppid
}

// anyServing reports whether one of the old processes is still a child of master and not shutting down.
// A worker renames itself "worker process is shutting down" when it stops accepting connections.
func (r Reloader) anyServing(master int, old []int) bool {
	for _, pid := range old {
		if r.parent(pid) != master {
			continue
		}

		title, err := os.ReadFile(filepath.Join(r.Proc, strconv.Itoa(pid), "cmdline"))
		if err != nil || len(title) == 0 {
			continue
		}

		if !strings.Contains(string(title), "shutting down") {
			return true
		}
	}

	return false
}

// Reload runs the installed agent's reload-nginx helper (paths.AgentBinary, see Reloader), so reloads in Apply
// plans finish only once Nginx serves the new configuration.
var Reload = system.Command{Name: paths.AgentBinary, Args: []string{"reload-nginx"}, Description: "systemctl reload nginx"}
