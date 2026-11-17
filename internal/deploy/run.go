package deploy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/deployscript"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/processes"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/userfs"
)

// historyKept is how many deployments each site keeps, with their logs.
const historyKept = 50

// Run performs deployment id to the end and records its outcome. Cancelling ctx (SIGTERM from systemctl stop) cancels the deploy.
func (r *Runner) Run(ctx context.Context, id string) error {
	d, err := r.Store.GetDeployment(id)
	if err != nil {
		return err
	}

	// Cancel or Recover may have finished it before its unit started; running it now could put a release live.
	if d.Finished() {
		fmt.Fprintf(r.Out, "The deployment isn't running (it is %s), so there is nothing to do.\n", d.State)
		return nil
	}

	j, err := r.load(d)
	if err != nil {
		_, updateErr := r.Store.UpdateDeployment(id, func(d *state.Deployment) {
			d.State, d.Error, d.FinishedAt = state.Failed, err.Error(), r.Now()
		})
		if updateErr != nil {
			fmt.Fprintf(r.Out, "Couldn't record the failure: %v\n", updateErr)
		}

		return err
	}

	timeout := r.Timeout
	if timeout == 0 {
		timeout = time.Duration(j.s.DeployTimeoutMinutes) * time.Minute
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch {
	case d.Kind == state.KindRollback:
		err = j.rollback(runCtx)
	case j.s.ZeroDowntime:
		err = j.deploy(runCtx)
	default:
		err = j.deployInPlace(runCtx)
	}

	if err == nil {
		err = j.healthCheck(runCtx)
	}

	final, message := outcome(ctx, runCtx, err, timeout)
	j.finish(final, message)

	return nil
}

func (j *job) deploy(ctx context.Context) error {
	segments, err := deployscript.Split(j.s.DeployScript)
	if err != nil {
		return err
	}

	steps := []struct {
		phase string
		run   func() error
	}{
		{state.PhasePrepare, func() error { return j.script(ctx, segments.Before, j.dir, "") }},
		{state.PhaseFetch, func() error { return j.fetch(ctx) }},
		{state.PhaseCheckOut, func() error { return j.checkOut(ctx) }},
		{state.PhaseLinkShared, func() error { return j.linkShared(ctx) }},
		{state.PhaseBuild, func() error { return j.script(ctx, segments.Build, j.release, j.release) }},
		{state.PhaseActivate, func() error { return j.activate(ctx, j.releaseName) }},
		{state.PhaseAfterActivation, func() error {
			return j.script(ctx, segments.After, filepath.Join(j.dir, "current"), filepath.Join(j.releasesDir(), j.releaseName))
		}},
		{state.PhaseCleanUp, func() error { return j.prune(ctx) }},
	}

	for _, step := range steps {
		if !j.planned(step.phase) {
			continue
		}
		if err := j.phase(ctx, step.phase, step.run); err != nil {
			return err
		}
	}

	return nil
}

func (j *job) deployInPlace(ctx context.Context) error {
	current := filepath.Join(j.dir, "current")

	if !j.s.HasRepository() {
		return j.phase(ctx, state.PhaseBuild, func() error {
			if err := (userfs.FS{Runner: j.r.Exec, User: j.asUser()}).MkdirAll(ctx, "0750", current); err != nil {
				return err
			}
			j.logf("This site has no repository, so the script runs on the files already in current/.\n")

			// The script changes the files being served, unless the site is still on its placeholder page.
			if !j.placeholder {
				j.update(func(d *state.Deployment) { d.WentLive = true })
			}

			return j.buildInPlace(ctx, current)
		})
	}

	err := j.phase(ctx, state.PhaseFetch, func() error {
		if _, err := os.Stat(filepath.Join(current, ".git")); err != nil {
			if err := (userfs.FS{Runner: j.r.Exec, User: j.asUser()}).MkdirAll(ctx, "0750", current); err != nil {
				return err
			}
			if err := j.run(ctx, current, "git", "init", "--quiet"); err != nil {
				return err
			}
			if err := j.run(ctx, current, "git", "remote", "add", "origin", j.s.RepositoryURL); err != nil {
				return err
			}
		} else if err := j.run(ctx, current, "git", "remote", "set-url", "origin", j.s.RepositoryURL); err != nil {
			return err
		}

		if err := j.run(ctx, current, "git", "fetch", "--prune", "--quiet", "origin"); err != nil {
			return fmt.Errorf("Couldn't fetch the repository. Check the deploy key with Test Access.")
		}
		if err := j.resolve(ctx, current, "refs/remotes/origin/"+j.s.Branch); err != nil {
			return err
		}
		if err := j.run(ctx, current, "git", "reset", "--hard", "--quiet", j.d.Commit); err != nil {
			return err
		}

		// The code being served changed now, whatever happens next. A site on its placeholder page serves nothing from
		// current yet, so it goes live once the script succeeded.
		if !j.placeholder {
			j.update(func(d *state.Deployment) { d.WentLive = true })
		}

		return nil
	})
	if err != nil {
		return err
	}

	return j.phase(ctx, state.PhaseBuild, func() error { return j.buildInPlace(ctx, current) })
}

// buildInPlace runs the script in current/, then takes a site on its placeholder page to current/.
func (j *job) buildInPlace(ctx context.Context, current string) error {
	if err := j.script(ctx, deployscript.InPlace(j.s.DeployScript), current, ""); err != nil {
		return err
	}
	if !j.placeholder {
		return nil
	}

	background := context.WithoutCancel(ctx)

	return j.leavePlaceholder(background, func(applier apply.Applier) error {
		if err := j.serveReleases(background, applier); err != nil {
			return err
		}
		j.update(func(d *state.Deployment) { d.WentLive = true })

		return j.removePlaceholder(background)
	})
}

func (j *job) rollback(ctx context.Context) error {
	commit, message, _ := j.r.Store.ReleaseCommit(j.s.ID, j.d.Release)
	j.update(func(d *state.Deployment) {
		d.Commit, d.CommitMessage = commit, message
		setNote(d, state.PhaseActivate, "releases/"+j.d.Release)
	})

	return j.phase(ctx, state.PhaseActivate, func() error {
		if j.d.Release == j.liveRelease() {
			return fmt.Errorf("Release %s is already live.", j.d.Release)
		}

		return j.activate(ctx, j.d.Release)
	})
}

func (j *job) planned(phase string) bool {
	for _, p := range j.d.Phases {
		if p.Name == phase {
			return true
		}
	}

	return false
}

func outcome(parent, run context.Context, err error, timeout time.Duration) (string, string) {
	switch {
	case err == nil:
		return state.Succeeded, ""
	case parent.Err() != nil:
		return state.Cancelled, "The deploy was cancelled."
	case errors.Is(run.Err(), context.DeadlineExceeded):
		return state.TimedOut, fmt.Sprintf("The deploy didn't finish within %s.", describeDuration(timeout))
	default:
		message, _, _ := strings.Cut(err.Error(), "\n")
		return state.Failed, message
	}
}

func describeDuration(d time.Duration) string {
	if d >= time.Minute && d%time.Minute == 0 {
		minutes := int(d / time.Minute)
		if minutes == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", minutes)
	}

	return d.String()
}

// finish removes a release that never went live, records the outcome, prunes history and adds an activity entry.
func (j *job) finish(final, message string) {
	if j.release != "" && !j.d.WentLive {
		j.removeUnfinished()
	}

	// Whatever happened after, the live code changed: the site's processes move to it.
	if j.d.WentLive {
		j.restartProcesses()
		j.reloadPHP()
	}

	if final == state.Succeeded {
		j.logf("\n==> Finished.\n")
	} else {
		j.logf("\n==> %s\n", message)
	}

	now := j.r.Now()
	j.update(func(d *state.Deployment) {
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

	j.pruneHistory()

	// The manager records cancellations itself, with who cancelled.
	if final == state.Cancelled {
		return
	}

	if j.r.Notify != nil {
		if err := j.r.Notify(context.Background(), j.s, j.d); err != nil {
			j.logf("Couldn't post to the webhook: %v\n", err)
		}
	}

	j.r.Store.AddActivity(j.s.ID, state.Activity{At: now, Kind: activityKind(j.d.Kind, final), Actor: j.d.Actor, Summary: j.summary(final, message)})
}

// restartProcesses restarts every copy of the site's processes that isn't stopped, without waiting, so a queue worker
// can finish its job (its unit's stop timeout) while the deploy completes.
func (j *job) restartProcesses() {
	// Read again: a process stopped or removed while the deploy ran must stay that way.
	current := j.s
	if stored, err := j.r.Store.GetSite(j.s.ID); err == nil {
		current = stored
	}
	names := processes.Running(current)
	if len(names) == 0 {
		return
	}

	j.logf("Restarting the site's processes.\n")
	if err := j.systemctl(context.Background(), append([]string{"restart", "--no-block"}, names...)...); err != nil {
		j.logf("Couldn't restart the site's processes: %v\n", err)
	}
}

// reloadPHP clears OPcache when it no longer checks files for changes, so the live code is the code that runs.
func (j *job) reloadPHP() {
	if j.s.Runtime != site.PHP || j.r.OPcacheFrozen == nil || !j.r.OPcacheFrozen() {
		return
	}

	j.logf("Reloading PHP-FPM %s to clear OPcache.\n", j.s.PHPVersion)
	if err := j.systemctl(context.Background(), "reload", "php"+j.s.PHPVersion+"-fpm"); err != nil {
		j.logf("Couldn't reload PHP-FPM: %v\n", err)
	}
}

// pruneHistory deletes the oldest deployments beyond historyKept, with their logs. A release still on the server keeps
// the deployment that put it live, so it stays on the rollback list.
func (j *job) pruneHistory() {
	var kept []string
	entries, err := os.ReadDir(j.releasesDir())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		j.logf("Couldn't list the releases, so the deployment history wasn't pruned: %v\n", err)
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			kept = append(kept, entry.Name())
		}
	}

	removed, err := j.r.Store.PruneDeployments(j.s.ID, historyKept, kept)
	if err != nil {
		j.logf("Couldn't prune the deployment history: %v\n", err)
	}
	for _, id := range removed {
		os.Remove(j.r.Paths.File(paths.DeployLog(j.s.ID, id)))
	}
}

// removeUnfinished deletes the release this deploy created, unless something already uses it.
func (j *job) removeUnfinished() {
	if reason := releaseInUse(j.r.Paths, j.dir, j.s.ID, j.releaseName); reason != "" {
		j.logf("Kept release %s: %s.\n", j.releaseName, reason)
		return
	}

	// The deploy may have been cancelled or timed out, so removing needs a context of its own.
	cleanUp, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if err := j.remove(cleanUp, j.release); err != nil {
		j.logf("Couldn't remove the unfinished release %s: %v\n", j.releaseName, err)
		return
	}

	j.logf("Removed the unfinished release %s. The site is untouched.\n", j.releaseName)
}

func activityKind(kind, final string) string {
	prefix := "deploy"
	if kind == state.KindRollback {
		prefix = "rollback"
	}

	return prefix + "." + final
}

func (j *job) summary(final, message string) string {
	commitMessage, _, _ := strings.Cut(j.d.CommitMessage, "\n")

	switch {
	case j.d.Kind == state.KindRollback && final == state.Succeeded:
		return "Rolled back to release " + j.d.Release + "."
	case j.d.Kind == state.KindRollback:
		return "Rollback to release " + j.d.Release + " failed: " + message
	case final == state.Succeeded && j.d.Commit == "":
		return "Deployed."
	case final == state.Succeeded:
		return fmt.Sprintf("Deployed %s: %s", short(j.d.Commit), commitMessage)
	case j.d.Commit == "":
		return "Deploy failed: " + message
	default:
		return fmt.Sprintf("Deploy of %s failed: %s", short(j.d.Commit), message)
	}
}
