package backups

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/lock"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

// Runner runs one plan: each database dumped and gzipped to a file, the files uploaded to one folder, old folders
// deleted. The outcome is recorded as a run.
type Runner struct {
	Store *state.Store
	Paths paths.Paths
	Plans *Manager
	// Engine is the installed database: "mysql", "mariadb" or "postgres".
	Engine func(context.Context) string
	Now    func() time.Time
	// Notify posts a failed run to the server's webhook (notify.Manager.BackupFailed). Nil sends nothing.
	Notify func(ctx context.Context, planName, message string) error
}

// Start records a new run of the plan and runs it in the background, for "run now".
func (r *Runner) Start(planID string) (state.BackupRun, error) {
	plan, err := r.Plans.Get(planID)
	if err != nil {
		return state.BackupRun{}, err
	}

	run, err := r.begin(plan)
	if err != nil {
		return state.BackupRun{}, err
	}

	go r.finish(context.Background(), plan, run)

	return run, nil
}

// Run runs the plan and waits, for cron's run-backup.
func (r *Runner) Run(ctx context.Context, planID string) error {
	plan, err := r.Plans.Get(planID)
	if err != nil {
		return err
	}

	run, err := r.begin(plan)
	if err != nil {
		return err
	}

	return r.finish(ctx, plan, run)
}

func (r *Runner) begin(plan Plan) (state.BackupRun, error) {
	now := r.Now().UTC()
	run := state.BackupRun{ID: ids.New(), PlanID: plan.ID, State: state.BackupRunning, StartedAt: now, Folder: now.Format("20060102T150405Z")}

	return run, r.Store.StartBackupRun(run)
}

func (r *Runner) finish(ctx context.Context, plan Plan, run state.BackupRun) error {
	size, err := r.backup(ctx, plan, run)

	outcome, message := state.BackupSucceeded, ""
	if err != nil {
		outcome, message = state.BackupFailed, err.Error()
	}

	if recordErr := r.Store.FinishBackupRun(run.ID, outcome, size, message, r.Now()); recordErr != nil {
		return errors.Join(err, recordErr)
	}

	if err != nil && r.Notify != nil {
		_ = r.Notify(context.WithoutCancel(ctx), plan.Name, message) // shortcut: a failed post is dropped; the run's own error is what is recorded
	}

	return err
}

// shortcut: a run waits for the plan's previous one, so runs pile up if they take longer than the schedule's interval;
// skip a run that finds the lock taken if that turns out to happen.
func (r *Runner) backup(ctx context.Context, plan Plan, run state.BackupRun) (int64, error) {
	release, err := lock.Acquire(ctx, r.Paths.File(paths.BackupLock(plan.ID)))
	if err != nil {
		return 0, err
	}
	defer release()

	engine := r.Engine(ctx)
	if engine == "" {
		return 0, errors.New("This server has no database to back up.")
	}

	dir := filepath.Join(r.Paths.File(paths.BackupsDir), run.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)

	b, err := open(plan.Storage)
	if err != nil {
		return 0, err
	}

	var size int64
	for _, database := range plan.Databases {
		file := filepath.Join(dir, database+".sql.gz")
		if err := dump(ctx, engine, database, file); err != nil {
			return size, err
		}

		info, err := os.Stat(file)
		if err != nil {
			return size, err
		}
		size += info.Size()

		if err := b.upload(ctx, b.key(plan.ID, run.Folder, database+".sql.gz"), file); err != nil {
			return size, err
		}
	}

	return size, b.prune(ctx, plan.ID, plan.Keep)
}

// dumpCommand is how the engine's own tool dumps one database as root, the way the agent creates databases.
func dumpCommand(engine, database string) (string, []string, error) {
	switch engine {
	case "mysql":
		return "mysqldump", []string{"--defaults-extra-file=/root/.my.cnf", "--single-transaction", "--quick", "--routines", "--triggers", "--events", database}, nil
	case "mariadb":
		return "mariadb-dump", []string{"--single-transaction", "--quick", "--routines", "--triggers", "--events", database}, nil
	case "postgres":
		return "runuser", []string{"-u", "postgres", "--", "pg_dump", "--clean", "--if-exists", database}, nil
	default:
		return "", nil, fmt.Errorf("ServerDog can't back up %s databases.", engine)
	}
}

func dump(ctx context.Context, engine, database, file string) error {
	name, args, err := dumpCommand(engine, database)
	if err != nil {
		return err
	}

	out, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	compressed := gzip.NewWriter(out)
	var stderr bytes.Buffer

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = compressed
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Couldn't dump %s: %s", database, firstLine(stderr.String(), err))
	}

	if err := compressed.Close(); err != nil {
		return err
	}

	return out.Close()
}

func firstLine(output string, fallback error) string {
	if line, _, _ := strings.Cut(strings.TrimSpace(output), "\n"); line != "" {
		return line
	}

	return fallback.Error()
}
