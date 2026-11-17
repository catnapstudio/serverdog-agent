package deploy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/lock"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// Manager starts deployments as systemd units and keeps their records honest when units disappear.
type Manager struct {
	Store  *state.Store
	Paths  paths.Paths
	System system.Runner
	// Executable is the agent binary the unit runs as "run-deploy".
	Executable string
	StateDir   string
	Now        func() time.Time
	NewID      func() string
	// Locks is shared with the sites manager, so a site isn't changed or deleted while a deploy starts.
	Locks *lock.Keyed
	// Exec runs commands as the site user, so root never touches files inside a site's home.
	Exec       system.Runner
	LookupUser func(name string) (system.User, error)
	// AsUser runs Exec commands with the site user's ids. Tests leave it false and run as themselves.
	AsUser bool
}

// startGrace is how long a new deployment may run before Recover may judge its unit gone.
const startGrace = 30 * time.Second

// startTimeout bounds systemd-run creating a deploy's unit.
const startTimeout = 30 * time.Second

// removeTimeout bounds deleting an unfinished release.
const removeTimeout = time.Minute

// unitNotLoaded is the exit code of "systemctl stop" for a unit systemd doesn't have.
const unitNotLoaded = 5

var releaseNamePattern = regexp.MustCompile(`^\d{8}-\d{6}(-\d+)?$`)

// ErrNoRepository is a deploy of a zero-downtime site that has no repository yet: its releases are checkouts. Nothing
// is recorded or started. A site without zero downtime deploys by running its script in current/ (protocol 7).
var ErrNoRepository = errors.New("This site has no repository yet. Add one in its settings, then deploy.")

// Unit is the systemd unit a deployment runs in.
func Unit(deploymentID string) string { return "serverdog-deploy-" + deploymentID }

// Deploy starts a deploy of the site's branch, or returns the deploy already running (true).
func (m *Manager) Deploy(ctx context.Context, siteID, actor string) (state.Deployment, bool, error) {
	defer m.Locks.Lock(siteID)()

	s, err := m.Store.GetSite(siteID)
	if err != nil {
		return state.Deployment{}, false, err
	}

	if running, ok, err := m.Store.RunningDeployment(siteID); err != nil || ok {
		return running, ok, err
	}

	if !s.HasRepository() && s.ZeroDowntime {
		return state.Deployment{}, false, ErrNoRepository
	}

	// The runner runs this script, not the site's at the time its unit starts: the phases are planned from it.
	d := m.newDeployment(s, state.KindDeploy, actor)
	d.Script = s.DeployScript

	return d, false, m.start(ctx, s, d)
}

// Rollback makes a kept release live again without running any script.
func (m *Manager) Rollback(ctx context.Context, siteID, release, actor string) (state.Deployment, error) {
	defer m.Locks.Lock(siteID)()

	s, err := m.Store.GetSite(siteID)
	if err != nil {
		return state.Deployment{}, err
	}

	if !releaseNamePattern.MatchString(release) {
		return state.Deployment{}, &site.InvalidError{Field: "release", Reason: fmt.Sprintf("%q isn't a release name.", release)}
	}
	if info, err := os.Lstat(filepath.Join(m.Paths.File(s.Directory), "releases", release)); err != nil || !info.IsDir() {
		return state.Deployment{}, &site.InvalidError{Field: "release", Reason: fmt.Sprintf("Release %s isn't kept on the server any more.", release)}
	}

	// A release whose deploy failed before going live was never tested in production; it may not even be built.
	wentLive, err := m.Store.ReleasesThatWentLive(siteID)
	if err != nil {
		return state.Deployment{}, err
	}
	if !wentLive[release] {
		return state.Deployment{}, &site.InvalidError{Field: "release", Reason: fmt.Sprintf("Release %s never went live, so it can't be rolled back to.", release)}
	}

	if _, ok, err := m.Store.RunningDeployment(siteID); err != nil {
		return state.Deployment{}, err
	} else if ok {
		return state.Deployment{}, state.ErrDeployRunning
	}

	d := m.newDeployment(s, state.KindRollback, actor)
	d.Release = release
	d.Commit, d.CommitMessage, _ = m.Store.ReleaseCommit(siteID, release)

	return d, m.start(ctx, s, d)
}

func (m *Manager) newDeployment(s site.Site, kind, actor string) state.Deployment {
	return state.Deployment{
		ID:        m.NewID(),
		SiteID:    s.ID,
		Kind:      kind,
		State:     state.Running,
		Actor:     actor,
		Branch:    s.Branch,
		Phases:    PlannedPhases(s, kind),
		Marker:    ids.New(),
		StartedAt: m.Now(),
	}
}

func (m *Manager) start(ctx context.Context, s site.Site, d state.Deployment) error {
	if err := m.Store.CreateDeployment(d); err != nil {
		return err
	}

	logical := paths.DeployLog(s.ID, d.ID)
	log := m.Paths.File(logical)
	if err := os.MkdirAll(filepath.Dir(log), 0o700); err != nil {
		return m.failToStart(d, err)
	}
	if err := os.WriteFile(log, nil, 0o600); err != nil {
		return m.failToStart(d, err)
	}

	// A client that leaves mid-call mustn't kill systemd-run after it created the unit: the deployment would be
	// marked failed while it runs.
	startCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), startTimeout)
	defer cancel()

	limit := strconv.Itoa((s.DeployTimeoutMinutes + 1) * 60)
	result, err := m.System.Run(startCtx, system.Command{Name: "systemd-run", Args: []string{
		"--unit", Unit(d.ID), "--collect", "--quiet",
		"--property=RuntimeMaxSec=" + limit,
		// systemctl stop signals only the runner, which cancels its own commands and still finishes the switch it started.
		"--property=KillMode=mixed",
		"--property=StandardOutput=append:" + logical,
		"--property=StandardError=append:" + logical,
		m.Executable, "run-deploy", "--state-dir", m.StateDir, d.ID,
	}})
	if err != nil {
		return m.failToStart(d, fmt.Errorf("%w: %s", err, system.Tail(result.Output, 3)))
	}

	return nil
}

func (m *Manager) failToStart(d state.Deployment, cause error) error {
	m.Store.UpdateDeployment(d.ID, func(d *state.Deployment) {
		d.State, d.Error, d.FinishedAt = state.Failed, "The deploy couldn't start on the server.", m.Now()
	})

	return fmt.Errorf("start deploy: %w", cause)
}

// Cancel stops a running deployment's unit. The runner records the cancellation; if it couldn't, Cancel does.
func (m *Manager) Cancel(ctx context.Context, id, actor string) (state.Deployment, error) {
	d, err := m.Store.GetDeployment(id)
	if err != nil || d.Finished() {
		return d, err
	}

	if result, err := m.System.Run(ctx, system.Command{Name: "systemctl", Args: []string{"stop", Unit(id)}}); err != nil {
		if code, ok := system.ExitCode(err); !ok || code != unitNotLoaded {
			return d, fmt.Errorf("stop deploy: %w: %s", err, system.Tail(result.Output, 3))
		}
	}

	m.abandon(ctx, id, state.Cancelled, "The deploy was cancelled.")

	d, err = m.Store.GetDeployment(id)
	if err != nil {
		return d, err
	}

	m.Store.AddActivity(d.SiteID, state.Activity{At: m.Now(), Kind: "deploy.cancelled", Actor: actor, Summary: "Cancelled the deploy of " + short(d.Commit) + "."})

	return d, nil
}

// Recover marks running deployments whose unit systemd reports gone as interrupted. A unit is gone when is-active
// exits 3 or 4 and prints inactive, failed, unknown or nothing; "deactivating" also exits 3 but the runner is still cleaning up.
// Any other failure — such as systemctl losing the bus while apt reloads systemd — says nothing about the deploy.
func (m *Manager) Recover(ctx context.Context) {
	running, err := m.Store.RunningDeployments()
	if err != nil {
		return
	}

	for _, d := range running {
		if m.Now().Sub(d.StartedAt) < startGrace {
			continue
		}

		result, err := m.System.Run(ctx, system.Command{Name: "systemctl", Args: []string{"is-active", Unit(d.ID)}})
		if err == nil {
			continue
		}

		code, ok := system.ExitCode(err)
		if !ok || (code != 3 && code != 4) {
			continue
		}

		if !slices.Contains([]string{"", "inactive", "failed", "unknown"}, strings.TrimSpace(string(result.Output))) {
			continue
		}

		if m.abandon(ctx, d.ID, state.Interrupted, "The deploy stopped before it finished. The server may have restarted.") {
			m.Store.AddActivity(d.SiteID, state.Activity{At: m.Now(), Kind: "deploy.interrupted", Actor: "ServerDog", Summary: "A deploy stopped before it finished."})
		}
	}
}

// RecoverEvery runs Recover now and then every interval until ctx ends.
func (m *Manager) RecoverEvery(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		m.Recover(ctx)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// abandon records a final state for a deployment whose runner is gone, and deletes a release that never went live.
// It returns false when the deployment had already finished.
func (m *Manager) abandon(ctx context.Context, id, final, message string) bool {
	changed := false
	now := m.Now()

	d, err := m.Store.UpdateDeployment(id, func(d *state.Deployment) {
		if d.Finished() {
			return
		}

		changed = true
		d.State, d.Error, d.FinishedAt = final, message, now
		for i := range d.Phases {
			switch d.Phases[i].State {
			case state.PhaseRunning:
				d.Phases[i].State, d.Phases[i].FinishedAt = state.PhaseFailed, now
			case state.PhasePending:
				d.Phases[i].State = state.PhaseSkipped
			}
		}
	})
	if err != nil || !changed {
		return false
	}

	if d.Kind == state.KindDeploy && !d.WentLive && releaseNamePattern.MatchString(d.Release) {
		m.removeRelease(ctx, d)
	}

	return true
}

// removeRelease deletes an unfinished release as the site user, best effort.
// A release in use (see releaseInUse) is never removed: the runner switches before it records that the deploy went live.
func (m *Manager) removeRelease(ctx context.Context, d state.Deployment) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), removeTimeout)
	defer cancel()

	s, err := m.Store.GetSite(d.SiteID)
	if err != nil {
		return
	}

	dir := m.Paths.File(s.Directory)
	if reason := releaseInUse(m.Paths, dir, s.ID, d.Release); reason != "" {
		slog.Default().Info("kept an unfinished release", "site", s.ID, "release", d.Release, "reason", reason)

		return
	}

	user, err := m.LookupUser(s.User)
	if err != nil {
		slog.Default().Warn("look up site user to remove an unfinished release", "site", s.ID, "user", s.User, "error", err)

		return
	}

	command := system.Command{Name: "rm", Args: []string{"-rf", "--", filepath.Join(dir, "releases", d.Release)}}
	if m.AsUser {
		command.User = &user
	}

	if _, err := m.Exec.Run(ctx, command); err != nil {
		slog.Default().Warn("remove an unfinished release", "site", s.ID, "release", d.Release, "error", err)
	}
}
