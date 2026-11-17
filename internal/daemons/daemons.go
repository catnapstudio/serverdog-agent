// Package daemons keeps the server's background processes: commands systemd keeps running as a user, apart from any
// site, such as a Reverb server shared by several apps or a custom worker.
package daemons

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

type Daemon struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Command string `json:"command"`
	User    string `json:"user"`
	// Absolute; empty is the user's home.
	Directory string `json:"directory,omitempty"`
	Count     int    `json:"count"`
	// Stopped daemons stay disabled until the user starts them again.
	Stopped bool `json:"stopped,omitempty"`
	// How long a copy may take to stop before systemd kills it; 0 is site.DefaultStopSeconds.
	StopSeconds int `json:"stop_seconds,omitempty"`
}

// Status is how many copies of a daemon run, with their recent output.
type Status struct {
	Running int
	Log     string
}

const (
	MaxDaemons = 50
	MaxCount   = 16
	document   = "daemons"
)

// ErrStopped refuses to restart a daemon the user stopped: Start brings it back.
var ErrStopped = errors.New("The background process is stopped. Start it instead.")

var userPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var daemonReload = system.Command{Name: "systemctl", Args: []string{"daemon-reload"}}

// Manager validates, saves and applies the daemons. Each is a template unit with one instance per copy.
type Manager struct {
	Store      *state.Store
	Paths      paths.Paths
	Applier    apply.Applier
	System     system.Runner
	LookupUser func(string) (system.User, error)

	mu sync.Mutex
}

// List returns the daemons and their revision, the one Put expects.
func (m *Manager) List() ([]Daemon, uint64, error) {
	encoded, revision, err := m.Store.Document(document)
	if err != nil || encoded == nil {
		return nil, revision, err
	}

	var daemons []Daemon

	return daemons, revision, json.Unmarshal(encoded, &daemons)
}

// Put replaces the daemons: copies that went away stop, units are rewritten, and new or changed daemons restart.
func (m *Manager) Put(ctx context.Context, daemons []Daemon, expectedRevision uint64) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.validate(daemons); err != nil {
		return 0, err
	}

	previous, current, err := m.List()
	if err != nil {
		return 0, err
	}
	if current != expectedRevision {
		return 0, state.ErrStaleDocument
	}

	// Their unit must stay until they stopped, or systemd forgets how long they were given and kills them early.
	for _, old := range previous {
		if site.StopTimeout(old.StopSeconds) <= site.StopPatience {
			continue
		}

		names := Instances(old.ID, 1, old.Count)
		if current, kept := find(daemons, old.ID); kept {
			names = Instances(old.ID, current.Count+1, old.Count)
		}
		if system.AnyActive(ctx, m.System, names) {
			return 0, site.TooSlowToRemove(old.Name, site.StopTimeout(old.StopSeconds))
		}
	}

	if err := m.systemctl(ctx, "Couldn't stop the removed background processes.", "disable", "--now", Retired(daemons, previous)...); err != nil {
		return 0, err
	}

	var files []apply.File
	for _, d := range daemons {
		files = append(files,
			apply.File{Path: m.Paths.File(paths.SystemdUnit(Template(d.ID))), Content: RenderUnit(d)},
			apply.File{Path: m.Paths.File(StartScript(d.ID)), Content: RenderStartScript(d.Command), Mode: 0o755})
	}
	for _, d := range removed(daemons, previous) {
		files = append(files,
			apply.File{Path: m.Paths.File(paths.SystemdUnit(Template(d.ID))), Remove: true},
			apply.File{Path: m.Paths.File(StartScript(d.ID)), Remove: true})
	}
	if _, err := m.Applier.Apply(ctx, apply.Plan{Files: files, Reloads: []system.Command{daemonReload}}); err != nil {
		return 0, err
	}

	var started, stopped []string
	for _, d := range changed(daemons, previous) {
		if d.Stopped {
			stopped = append(stopped, Instances(d.ID, 1, d.Count)...)
		} else {
			started = append(started, Instances(d.ID, 1, d.Count)...)
		}
	}
	if err := m.systemctl(ctx, "Couldn't stop the background processes.", "disable", "--now --no-block", stopped...); err != nil {
		return 0, err
	}
	if err := m.systemctl(ctx, "Couldn't start the background processes.", "enable", "", started...); err != nil {
		return 0, err
	}
	if err := m.systemctl(ctx, "Couldn't start the background processes.", "restart", "--no-block", started...); err != nil {
		return 0, err
	}

	encoded, err := json.Marshal(daemons)
	if err != nil {
		return 0, err
	}

	return m.Store.PutDocument(document, encoded, expectedRevision)
}

func (m *Manager) systemctl(ctx context.Context, failure, verb, flag string, names ...string) error {
	if len(names) == 0 {
		return nil
	}

	args := append([]string{verb}, strings.Fields(flag)...)

	if result, err := m.System.Run(ctx, system.Command{Name: "systemctl", Args: append(args, names...)}); err != nil {
		return fmt.Errorf("%s\n\n%s", failure, system.Tail(result.Output, 5))
	}

	return nil
}

// Restart restarts every copy of a daemon without waiting for them to stop.
func (m *Manager) Restart(ctx context.Context, id string) error {
	daemons, _, err := m.List()
	if err != nil {
		return err
	}

	d, found := find(daemons, id)
	if !found {
		return state.ErrNotFound
	}
	if d.Stopped {
		return ErrStopped
	}

	return m.systemctl(ctx, fmt.Sprintf("Couldn't restart %s.", d.Name), "restart", "--no-block", Instances(d.ID, 1, d.Count)...)
}

// Status reports how many copies of d run and the last lines of their journal.
func (m *Manager) Status(ctx context.Context, d Daemon, lines int) Status {
	var status Status

	if result, err := m.System.Run(ctx, system.Command{Name: "systemctl", Args: append([]string{"show", "--property=ActiveState", "--value"}, Instances(d.ID, 1, d.Count)...)}); err == nil {
		for _, state := range strings.Fields(string(result.Output)) {
			if state == "active" {
				status.Running++
			}
		}
	}

	pattern := strings.TrimSuffix(Template(d.ID), ".service") + "*"
	if lines == 0 {
		return status
	}
	if result, err := m.System.Run(ctx, system.Command{Name: "journalctl", Args: []string{"--no-pager", "--quiet", "--output=short-iso", "--lines=" + strconv.Itoa(lines), "--unit=" + pattern}}); err == nil {
		status.Log = strings.TrimSpace(string(result.Output))
	}

	return status
}

// Template is the unit file name of a daemon.
func Template(id string) string { return "serverdog-daemon-" + id + "@.service" }

// Instances names copies from through to of a daemon.
func Instances(id string, from, to int) []string {
	var names []string
	for n := from; n <= to; n++ {
		names = append(names, fmt.Sprintf("serverdog-daemon-%s@%d.service", id, n))
	}

	return names
}

func StartScript(id string) string { return path.Join(paths.DaemonsEtcDir, id+".sh") }

// RenderUnit keeps every copy running, restarting it 5 seconds after it exits. Stopping waits for the daemon's stop
// timeout, a minute by default, so a worker sent SIGTERM can finish what it is doing.
func RenderUnit(d Daemon) []byte {
	directory := d.Directory
	if directory == "" {
		directory = "~"
	}

	return []byte(fmt.Sprintf(`# Managed by ServerDog: a background process of the server.
[Unit]
Description=ServerDog background process %[1]s (copy %%i)
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=%[2]s
WorkingDirectory=%[3]s
ExecStart=%[4]s
Restart=always
RestartSec=5
TimeoutStopSec=%[5]d

[Install]
WantedBy=multi-user.target
`, oneLine(d.Name), d.User, directory, StartScript(d.ID), site.StopTimeout(d.StopSeconds)))
}

func RenderStartScript(command string) []byte {
	return []byte("#!/bin/sh\n# Managed by ServerDog.\nexec " + command + "\n")
}

// Retired names the copies that stop when previous becomes daemons: every copy of a removed daemon, and those beyond
// the new count of one that shrank.
func Retired(daemons, previous []Daemon) []string {
	var names []string
	for _, old := range previous {
		current, kept := find(daemons, old.ID)
		if !kept {
			names = append(names, Instances(old.ID, 1, old.Count)...)
			continue
		}
		names = append(names, Instances(old.ID, current.Count+1, old.Count)...)
	}

	return names
}

func removed(daemons, previous []Daemon) []Daemon {
	var list []Daemon
	for _, old := range previous {
		if _, kept := find(daemons, old.ID); !kept {
			list = append(list, old)
		}
	}

	return list
}

func changed(daemons, previous []Daemon) []Daemon {
	var list []Daemon
	for _, d := range daemons {
		if old, found := find(previous, d.ID); found && old == d {
			continue
		}
		list = append(list, d)
	}

	return list
}

func find(list []Daemon, id string) (Daemon, bool) {
	for _, d := range list {
		if d.ID == id {
			return d, true
		}
	}

	return Daemon{}, false
}

func (m *Manager) validate(daemons []Daemon) error {
	if len(daemons) > MaxDaemons {
		return invalid("A server can have at most %d background processes.", MaxDaemons)
	}

	seen := map[string]bool{}

	for _, d := range daemons {
		if !ids.Valid(d.ID) || seen[d.ID] {
			return invalid("The background process id %q isn't valid or is listed twice.", d.ID)
		}
		seen[d.ID] = true

		if strings.TrimSpace(d.Name) == "" || strings.ContainsAny(d.Name, "\r\n") || len(d.Name) > 60 {
			return invalid("A background process needs a single-line name of at most 60 characters.")
		}
		if strings.TrimSpace(d.Command) == "" || strings.ContainsAny(d.Command, "\r\n") || len(d.Command) > 1000 {
			return invalid("%s needs a command on a single line of at most 1000 characters.", d.Name)
		}
		if d.Count < 1 || d.Count > MaxCount {
			return invalid("%s can run 1 to %d copies.", d.Name, MaxCount)
		}
		if d.StopSeconds < 0 || d.StopSeconds > site.MaxStopSeconds {
			return invalid("%s can take between 1 and %d seconds to stop.", d.Name, site.MaxStopSeconds)
		}
		if !userPattern.MatchString(d.User) {
			return invalid("%s's user %q isn't a valid user name.", d.Name, d.User)
		}
		if _, err := m.LookupUser(d.User); err != nil {
			return invalid("%s runs as %s, but this server has no such user.", d.Name, d.User)
		}
		if err := m.checkDirectory(d); err != nil {
			return err
		}
	}

	return nil
}

// checkDirectory accepts an existing absolute folder written plainly, since systemd won't start a unit whose working
// directory is missing, and a path with spaces or specifiers would need escaping in the unit.
func (m *Manager) checkDirectory(d Daemon) error {
	if d.Directory == "" {
		return nil
	}

	if !path.IsAbs(d.Directory) || path.Clean(d.Directory) != d.Directory || strings.ContainsAny(d.Directory, " %\\\"'\r\n\t") {
		return invalid("%s's folder %q must be an absolute path without spaces, like /home/serverdog/app.", d.Name, d.Directory)
	}

	info, err := os.Stat(m.Paths.File(d.Directory))
	if errors.Is(err, fs.ErrNotExist) || (err == nil && !info.IsDir()) {
		return invalid("%s runs in %s, but that folder doesn't exist on the server.", d.Name, d.Directory)
	}

	return err
}

// oneLine makes a name safe in a unit's Description: no line breaks or continuations, and % escaped.
func oneLine(value string) string {
	return strings.NewReplacer("\n", " ", "\r", " ", "\\", " ", "%", "%%").Replace(value)
}

func invalid(format string, args ...any) error {
	return &site.InvalidError{Field: "daemons", Reason: fmt.Sprintf(format, args...)}
}
