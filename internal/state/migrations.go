package state

import (
	"database/sql"
	"fmt"
)

// migrations[i] moves the schema from user_version i to i+1. Never edit a shipped migration; append a new one.
var migrations = []string{
	// 1: Foundation. IF NOT EXISTS because Foundation databases have these tables at user_version 0.
	`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agent_versions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	version TEXT NOT NULL,
	started_at TEXT NOT NULL
);`,

	// 2: Sites and deploys.
	`CREATE TABLE sites (
	id TEXT PRIMARY KEY,
	revision INTEGER NOT NULL,
	spec TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE site_domains (
	name TEXT PRIMARY KEY,
	site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE
);
CREATE TABLE deployments (
	id TEXT PRIMARY KEY,
	site_id TEXT NOT NULL,
	kind TEXT NOT NULL,
	state TEXT NOT NULL,
	went_live INTEGER NOT NULL DEFAULT 0,
	actor TEXT NOT NULL,
	branch TEXT NOT NULL DEFAULT '',
	commit_hash TEXT NOT NULL DEFAULT '',
	commit_author TEXT NOT NULL DEFAULT '',
	commit_message TEXT NOT NULL DEFAULT '',
	release TEXT NOT NULL DEFAULT '',
	phases TEXT NOT NULL DEFAULT '[]',
	error TEXT NOT NULL DEFAULT '',
	marker TEXT NOT NULL DEFAULT '',
	started_at TEXT NOT NULL,
	finished_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX deployments_by_site ON deployments(site_id, started_at);
CREATE UNIQUE INDEX deployments_one_running ON deployments(site_id) WHERE state = 'running';
CREATE TABLE activity (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	site_id TEXT NOT NULL,
	at TEXT NOT NULL,
	kind TEXT NOT NULL,
	actor TEXT NOT NULL,
	summary TEXT NOT NULL
);
CREATE INDEX activity_by_site ON activity(site_id, id);
CREATE TABLE host_keys (
	site_id TEXT NOT NULL,
	line TEXT NOT NULL,
	PRIMARY KEY (site_id, line)
);
CREATE TABLE node_ports (
	port INTEGER PRIMARY KEY,
	site_id TEXT NOT NULL,
	live INTEGER NOT NULL DEFAULT 0
);`,

	// 3: Certificates.
	`CREATE TABLE certificates (
	id TEXT PRIMARY KEY,
	site_id TEXT NOT NULL,
	domain TEXT NOT NULL,
	source TEXT NOT NULL,
	key_type TEXT NOT NULL DEFAULT '',
	names TEXT NOT NULL DEFAULT '[]',
	status TEXT NOT NULL,
	active INTEGER NOT NULL DEFAULT 0,
	issuer TEXT NOT NULL DEFAULT '',
	not_before TEXT NOT NULL DEFAULT '',
	not_after TEXT NOT NULL DEFAULT '',
	error TEXT NOT NULL DEFAULT '',
	next_attempt TEXT NOT NULL DEFAULT '',
	waiting_since TEXT NOT NULL DEFAULT '',
	failures INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL
);
CREATE INDEX certificates_by_site ON certificates(site_id, domain);
CREATE UNIQUE INDEX certificates_one_active ON certificates(site_id, domain) WHERE active = 1;
CREATE INDEX certificates_due ON certificates(next_attempt) WHERE next_attempt != '';`,

	// 4: The deploy script a deployment was planned from.
	`ALTER TABLE deployments ADD COLUMN script TEXT NOT NULL DEFAULT '';`,

	// 5: Database backup runs.
	`CREATE TABLE backup_runs (
	id TEXT PRIMARY KEY,
	plan_id TEXT NOT NULL,
	state TEXT NOT NULL,
	started_at TEXT NOT NULL,
	finished_at TEXT NOT NULL DEFAULT '',
	folder TEXT NOT NULL DEFAULT '',
	size INTEGER NOT NULL DEFAULT 0,
	error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX backup_runs_by_plan ON backup_runs(plan_id, started_at);`,

	// 6: Ports for a site's Reverb and Octane servers, next to its Node ports and guarded the same way.
	`ALTER TABLE node_ports ADD COLUMN purpose TEXT NOT NULL DEFAULT 'node';`,
}

func migrate(db *sql.DB) error {
	for {
		migrated, err := migrateOnce(db)
		if err != nil {
			return err
		}
		if !migrated {
			return nil
		}
	}
}

// migrateOnce applies the next pending migration. It reads user_version inside the write transaction,
// so a second process migrating the same file waits and then finds nothing left to do.
func migrateOnce(db *sql.DB) (bool, error) {
	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var version int
	if err := tx.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return false, fmt.Errorf("read schema version: %w", err)
	}

	if version >= len(migrations) {
		return false, nil
	}

	if _, err := tx.Exec(migrations[version]); err != nil {
		return false, fmt.Errorf("migration %d: %w", version+1, err)
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, version+1)); err != nil {
		return false, fmt.Errorf("set schema version %d: %w", version+1, err)
	}

	return true, tx.Commit()
}
