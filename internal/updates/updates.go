// Package updates keeps the server's automatic updates. Provisioning turns on unattended-upgrades, which installs
// Ubuntu's security updates only; the agent adds the vendor archives provisioning set up (PHP, Node.js and, unless
// turned off, the database's) and can restart the server when an update needs it. It also reports what's pending.
package updates

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

type Settings struct {
	// Databases also updates MariaDB, MySQL or PostgreSQL from its vendor's archive, which restarts it for a moment.
	Databases bool `json:"databases"`
	// AutomaticReboot restarts the server at RebootTime when an installed update needs it.
	AutomaticReboot bool   `json:"automatic_reboot"`
	RebootTime      string `json:"reboot_time"`
}

var Defaults = Settings{Databases: true, RebootTime: "04:00"}

// Each vendor archive is locked to one major version by its source line (node_24.x, mariadb-server/11.8,
// mysql-8.4-lts, versioned PostgreSQL packages), so these are patch updates.
var (
	alwaysSites   = []string{"packages.sury.org", "deb.nodesource.com"}
	databaseSites = []string{"dlm.mariadb.com", "repo.mysql.com", "apt.postgresql.org"}
)

const (
	document = "update_settings"
	// ConfFile is read after Ubuntu's 50unattended-upgrades; apt adds its list entries to that file's.
	ConfFile = "/etc/apt/apt.conf.d/52serverdog-updates"

	stampFile      = "/var/lib/apt/periodic/unattended-upgrades-stamp"
	rebootFile     = "/var/run/reboot-required"
	rebootPkgsFile = "/var/run/reboot-required.pkgs"
)

var clock = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

type Manager struct {
	Store   *state.Store
	Paths   paths.Paths
	Applier apply.Applier
	Runner  system.Runner

	mu sync.Mutex
}

// Status is what unattended-upgrades did and what's waiting.
type Status struct {
	// LastRun is zero when unattended-upgrades never ran.
	LastRun time.Time
	// Pending counts the packages with an update; SecurityPending those from Ubuntu's security archive.
	Pending         int
	SecurityPending int
	// RebootRequiredSince is zero when no installed update waits for a restart.
	RebootRequiredSince time.Time
	RebootPackages      []string
}

// Get returns the settings and their revision, the one Put expects; Defaults with revision 0 before the first save.
func (m *Manager) Get() (Settings, uint64, error) {
	encoded, revision, err := m.Store.Document(document)
	if err != nil || encoded == nil {
		return Defaults, revision, err
	}

	settings := Defaults

	return settings, revision, json.Unmarshal(encoded, &settings)
}

// Put saves the settings once apt reads the file they're written to.
func (m *Manager) Put(ctx context.Context, settings Settings, expectedRevision uint64) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !clock.MatchString(settings.RebootTime) {
		return 0, &site.InvalidError{Field: "reboot_time", Reason: "Enter the restart time as HH:MM, like 04:00."}
	}

	if _, current, err := m.Store.Document(document); err != nil {
		return 0, err
	} else if current != expectedRevision {
		return 0, state.ErrStaleDocument
	}

	if err := m.write(ctx, settings); err != nil {
		return 0, err
	}

	encoded, err := json.Marshal(settings)
	if err != nil {
		return 0, err
	}

	return m.Store.PutDocument(document, encoded, expectedRevision)
}

// Apply writes the saved settings, or the defaults, so servers provisioned before the agent managed the file get it.
func (m *Manager) Apply(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	settings, _, err := m.Get()
	if err != nil {
		return err
	}

	return m.write(ctx, settings)
}

func (m *Manager) write(ctx context.Context, settings Settings) error {
	conf := m.Paths.File(ConfFile)
	if current, err := os.ReadFile(conf); err == nil && bytes.Equal(current, Render(settings)) {
		return nil
	}

	_, err := m.Applier.Apply(ctx, apply.Plan{
		Files:  []apply.File{{Path: conf, Content: Render(settings)}},
		Checks: []system.Command{{Name: "apt-config", Args: []string{"dump"}}},
	})

	return err
}

// Render is the apt configuration for the settings.
func Render(s Settings) []byte {
	sites := alwaysSites
	if s.Databases {
		sites = slices.Concat(alwaysSites, databaseSites)
	}

	var b strings.Builder
	b.WriteString("// Managed by ServerDog: the vendor archives unattended-upgrades also updates from, and restarts.\nUnattended-Upgrade::Origins-Pattern {\n")
	for _, name := range sites {
		fmt.Fprintf(&b, "\t\"site=%s\";\n", name)
	}
	b.WriteString("};\n")
	fmt.Fprintf(&b, "Unattended-Upgrade::Automatic-Reboot \"%t\";\n", s.AutomaticReboot)
	fmt.Fprintf(&b, "Unattended-Upgrade::Automatic-Reboot-Time \"%s\";\n", s.RebootTime)

	return []byte(b.String())
}

// Status reads unattended-upgrades' last run and the restart flag, and asks apt what it would upgrade from the
// package lists it has (it doesn't refresh them; apt's daily timer does).
func (m *Manager) Status(ctx context.Context) (Status, error) {
	var s Status

	if info, err := os.Stat(m.Paths.File(stampFile)); err == nil {
		s.LastRun = info.ModTime()
	}

	if since, packages, ok := m.RebootRequired(); ok {
		s.RebootRequiredSince, s.RebootPackages = since, packages
	}

	result, err := m.Runner.Run(ctx, system.Command{
		Name: "apt-get", Args: []string{"--simulate", "--quiet", "-o", "Debug::NoLocking=true", "dist-upgrade"},
		Env: []string{"LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"},
	})
	if err != nil {
		return s, err
	}

	s.Pending, s.SecurityPending = CountPending(result.Output)

	return s, nil
}

// RebootRequired reports since when an installed update has waited for a restart, and which packages asked for it.
func (m *Manager) RebootRequired() (time.Time, []string, bool) {
	info, err := os.Stat(m.Paths.File(rebootFile))
	if err != nil {
		return time.Time{}, nil, false
	}

	var packages []string
	if content, err := os.ReadFile(m.Paths.File(rebootPkgsFile)); err == nil {
		for line := range strings.FieldsSeq(string(content)) {
			if !slices.Contains(packages, line) {
				packages = append(packages, line)
			}
		}
	}

	return info.ModTime(), packages, true
}

// CountPending reads apt-get --simulate's "Inst" lines: "Inst libc6 [2.39-0ubuntu8.3] (2.39-0ubuntu8.4 Ubuntu:24.04/noble-security [arm64])".
func CountPending(output []byte) (pending, security int) {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}

		pending++
		if strings.Contains(line, "-security") {
			security++
		}
	}

	return pending, security
}

// RebootWait is how long an update may wait for a restart before the webhook hears about it.
const RebootWait = 3 * 24 * time.Hour

const warnedDocument = "reboot_warning"

// RebootWatcher posts to the server's webhook once per pending restart that waited RebootWait. What was posted is kept
// in the store, so an agent restart doesn't repeat it.
type RebootWatcher struct {
	Updates *Manager
	Post    func(ctx context.Context, text string) error
	Host    func() string
	Now     func() time.Time
	Logger  *slog.Logger
}

// Run checks every interval until ctx ends.
func (w *RebootWatcher) Run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		w.Check(ctx)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *RebootWatcher) Check(ctx context.Context) {
	since, packages, required := w.Updates.RebootRequired()
	if !required || w.Now().Sub(since) < RebootWait {
		return
	}

	store := w.Updates.Store
	encoded, revision, err := store.Document(warnedDocument)
	if err != nil {
		w.Logger.Warn("could not read the restart warning", "error", err)
		return
	}

	// The flag file's time tells one pending restart from the next.
	key := []byte(fmt.Sprint(since.Unix()))
	if bytes.Equal(encoded, key) {
		return
	}

	if err := w.Post(ctx, RebootText(w.Host(), since, packages)); err != nil {
		w.Logger.Warn("could not post the restart warning", "error", err)
		return
	}

	if _, err := store.PutDocument(warnedDocument, key, revision); err != nil {
		w.Logger.Warn("could not save the restart warning", "error", err)
	}
}

// RebootText is the webhook's message for a restart pending since since.
func RebootText(host string, since time.Time, packages []string) string {
	updates := "Updates"
	if len(packages) > 0 {
		shown := packages[:min(len(packages), 3)]
		updates = "Updates to " + strings.Join(shown, ", ")
		if len(packages) > 3 {
			updates += fmt.Sprintf(" and %d more", len(packages)-3)
		}
	}

	return fmt.Sprintf("🔄 %s on %s have waited for a restart since %s, so they aren't in effect yet. Restart the server in ServerDog, or turn on automatic restarts.", updates, host, since.Format("2 Jan"))
}
