package state

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

var ErrDeployRunning = errors.New("a deploy is already running for this site")

const (
	KindDeploy   = "deploy"
	KindRollback = "rollback"

	Running     = "running"
	Succeeded   = "succeeded"
	Failed      = "failed"
	Cancelled   = "cancelled"
	TimedOut    = "timedOut"
	Interrupted = "interrupted"

	PhasePrepare         = "prepare"
	PhaseFetch           = "fetch"
	PhaseCheckOut        = "checkOut"
	PhaseLinkShared      = "linkShared"
	PhaseBuild           = "build"
	PhaseActivate        = "activate"
	PhaseAfterActivation = "afterActivation"
	PhaseCleanUp         = "cleanUp"

	PhasePending = "pending"
	PhaseRunning = "running"
	PhaseDone    = "done"
	PhaseFailed  = "failed"
	PhaseSkipped = "skipped"
)

type Phase struct {
	Name       string    `json:"name"`
	State      string    `json:"state"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	Note       string    `json:"note"`
}

type Deployment struct {
	ID            string
	SiteID        string
	Kind          string
	State         string
	WentLive      bool
	Actor         string
	Branch        string
	Commit        string
	CommitAuthor  string
	CommitMessage string
	// Release is the directory the deploy created, or the rollback's target.
	Release string
	Phases  []Phase
	Error   string
	// Marker is the random nonce in this deploy's progress lines.
	Marker string
	// Script is the site's deploy script when the deploy was started, which its phases were planned from. Empty for a
	// rollback, and for deployments recorded before agent v0.2.0-rc.4.
	Script     string
	StartedAt  time.Time
	FinishedAt time.Time
}

// Finished reports whether the deployment reached a final state.
func (d Deployment) Finished() bool { return d.State != Running }

const deploymentColumns = `id, site_id, kind, state, went_live, actor, branch, commit_hash, commit_author, commit_message, release, phases, error, marker, script, started_at, finished_at`

// CreateDeployment stores a new deployment. A second running deployment for the same site fails with ErrDeployRunning.
func (s *Store) CreateDeployment(d Deployment) error {
	phases, err := json.Marshal(d.Phases)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`INSERT INTO deployments(`+deploymentColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.SiteID, d.Kind, d.State, d.WentLive, d.Actor, d.Branch, d.Commit, d.CommitAuthor, d.CommitMessage,
		d.Release, string(phases), d.Error, d.Marker, d.Script, formatTime(d.StartedAt), formatTime(d.FinishedAt))
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: deployments.site_id") {
		return ErrDeployRunning
	}

	return err
}

// GetDeployment returns a deployment or ErrNotFound.
func (s *Store) GetDeployment(id string) (Deployment, error) {
	return readDeployment(s.db.QueryRow(`SELECT `+deploymentColumns+` FROM deployments WHERE id = ?`, id))
}

// UpdateDeployment applies change inside one transaction and stores the result.
func (s *Store) UpdateDeployment(id string, change func(*Deployment)) (Deployment, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Deployment{}, err
	}
	defer tx.Rollback()

	d, err := readDeployment(tx.QueryRow(`SELECT `+deploymentColumns+` FROM deployments WHERE id = ?`, id))
	if err != nil {
		return Deployment{}, err
	}

	change(&d)

	phases, err := json.Marshal(d.Phases)
	if err != nil {
		return Deployment{}, err
	}

	_, err = tx.Exec(`UPDATE deployments SET state = ?, went_live = ?, branch = ?, commit_hash = ?, commit_author = ?, commit_message = ?,
release = ?, phases = ?, error = ?, finished_at = ? WHERE id = ?`,
		d.State, d.WentLive, d.Branch, d.Commit, d.CommitAuthor, d.CommitMessage, d.Release, string(phases), d.Error, formatTime(d.FinishedAt), id)
	if err != nil {
		return Deployment{}, err
	}

	return d, tx.Commit()
}

// RunningDeployment returns the site's running deployment, if any.
func (s *Store) RunningDeployment(siteID string) (Deployment, bool, error) {
	d, err := readDeployment(s.db.QueryRow(`SELECT `+deploymentColumns+` FROM deployments WHERE site_id = ? AND state = 'running'`, siteID))
	if errors.Is(err, ErrNotFound) {
		return Deployment{}, false, nil
	}

	return d, err == nil, err
}

// RunningDeployments returns every running deployment on the server.
func (s *Store) RunningDeployments() ([]Deployment, error) {
	return s.queryDeployments(`SELECT ` + deploymentColumns + ` FROM deployments WHERE state = 'running' ORDER BY started_at`)
}

// ListDeployments returns a site's newest deployments first.
func (s *Store) ListDeployments(siteID string, limit int) ([]Deployment, error) {
	return s.queryDeployments(`SELECT `+deploymentColumns+` FROM deployments WHERE site_id = ? ORDER BY started_at DESC, rowid DESC LIMIT ?`, siteID, limit)
}

// DeployedBefore reports whether commit went live for the site in another deployment.
func (s *Store) DeployedBefore(siteID, commit, exceptID string) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM deployments WHERE site_id = ? AND commit_hash = ? AND id != ? AND went_live = 1`, siteID, commit, exceptID).Scan(&count)

	return count > 0, err
}

// ReleaseCommit returns the commit a deploy put in release.
func (s *Store) ReleaseCommit(siteID, release string) (string, string, error) {
	var commit, message string
	err := s.db.QueryRow(`SELECT commit_hash, commit_message FROM deployments WHERE site_id = ? AND release = ? AND kind = 'deploy' ORDER BY started_at DESC LIMIT 1`, siteID, release).Scan(&commit, &message)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}

	return commit, message, err
}

// ReleasesThatWentLive returns the releases that went live in some deployment of the site: deployed or rolled back to.
func (s *Store) ReleasesThatWentLive(siteID string) (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT DISTINCT release FROM deployments WHERE site_id = ? AND went_live = 1 AND release != ''`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	releases := map[string]bool{}
	for rows.Next() {
		var release string
		if err := rows.Scan(&release); err != nil {
			return nil, err
		}
		releases[release] = true
	}

	return releases, rows.Err()
}

// PruneDeployments deletes all but the newest keep finished deployments of a site and returns their ids. A deployment
// that put one of releases live is kept however old it is: releases are the folders still on the server, and a row that
// went live is what lets the rollback list offer one.
func (s *Store) PruneDeployments(siteID string, keep int, releases []string) ([]string, error) {
	rows, err := s.db.Query(`SELECT id, went_live, release FROM deployments WHERE site_id = ? AND state != 'running' ORDER BY started_at DESC, rowid DESC LIMIT -1 OFFSET ?`, siteID, keep)
	if err != nil {
		return nil, err
	}

	var removed []string
	for rows.Next() {
		var id, release string
		var wentLive bool
		if err := rows.Scan(&id, &wentLive, &release); err != nil {
			rows.Close()
			return nil, err
		}
		if wentLive && slices.Contains(releases, release) {
			continue
		}
		removed = append(removed, id)
	}
	rows.Close()

	for _, id := range removed {
		if _, err := s.db.Exec(`DELETE FROM deployments WHERE id = ?`, id); err != nil {
			return nil, err
		}
	}

	return removed, nil
}

func (s *Store) queryDeployments(query string, args ...any) ([]Deployment, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Deployment
	for rows.Next() {
		d, err := readDeployment(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, d)
	}

	return list, rows.Err()
}

func readDeployment(row scanner) (Deployment, error) {
	var d Deployment
	var phases, startedAt, finishedAt string

	err := row.Scan(&d.ID, &d.SiteID, &d.Kind, &d.State, &d.WentLive, &d.Actor, &d.Branch, &d.Commit, &d.CommitAuthor, &d.CommitMessage,
		&d.Release, &phases, &d.Error, &d.Marker, &d.Script, &startedAt, &finishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Deployment{}, ErrNotFound
	}
	if err != nil {
		return Deployment{}, err
	}

	if err := json.Unmarshal([]byte(phases), &d.Phases); err != nil {
		return Deployment{}, fmt.Errorf("decode phases: %w", err)
	}
	if d.StartedAt, err = parseTime(startedAt); err != nil {
		return Deployment{}, err
	}
	if d.FinishedAt, err = parseTime(finishedAt); err != nil {
		return Deployment{}, err
	}

	return d, nil
}

// storedTime is fixed-width, so stored timestamps sort correctly as strings.
const storedTime = "2006-01-02T15:04:05.000000000Z07:00"

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}

	return t.UTC().Format(storedTime)
}

func parseTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}

	return time.Parse(time.RFC3339Nano, value)
}
