package state

import "time"

// Backup run states.
const (
	BackupRunning   = "running"
	BackupSucceeded = "succeeded"
	BackupFailed    = "failed"
)

// BackupRun is one run of a backup plan: its databases dumped and uploaded to Folder.
type BackupRun struct {
	ID         string
	PlanID     string
	State      string
	StartedAt  time.Time
	FinishedAt time.Time
	// Folder is where the run's dumps are in the bucket.
	Folder string
	Size   int64
	Error  string
}

func (s *Store) StartBackupRun(run BackupRun) error {
	_, err := s.db.Exec(`INSERT INTO backup_runs(id, plan_id, state, started_at, folder) VALUES (?, ?, ?, ?, ?)`,
		run.ID, run.PlanID, BackupRunning, run.StartedAt.UTC().Format(time.RFC3339), run.Folder)

	return err
}

func (s *Store) FinishBackupRun(id, state string, size int64, errorText string, at time.Time) error {
	_, err := s.db.Exec(`UPDATE backup_runs SET state = ?, size = ?, error = ?, finished_at = ? WHERE id = ?`,
		state, size, errorText, at.UTC().Format(time.RFC3339), id)

	return err
}

// ListBackupRuns returns a plan's latest runs, newest first.
func (s *Store) ListBackupRuns(planID string, limit int) ([]BackupRun, error) {
	rows, err := s.db.Query(`SELECT id, plan_id, state, started_at, finished_at, folder, size, error FROM backup_runs WHERE plan_id = ? ORDER BY started_at DESC, rowid DESC LIMIT ?`, planID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []BackupRun
	for rows.Next() {
		var run BackupRun
		var started, finished string
		if err := rows.Scan(&run.ID, &run.PlanID, &run.State, &started, &finished, &run.Folder, &run.Size, &run.Error); err != nil {
			return nil, err
		}
		run.StartedAt, _ = time.Parse(time.RFC3339, started)
		run.FinishedAt, _ = time.Parse(time.RFC3339, finished)
		runs = append(runs, run)
	}

	return runs, rows.Err()
}
