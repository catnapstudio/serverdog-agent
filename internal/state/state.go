// Package state stores the agent's metadata, sites and deployments in SQLite.
package state

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// VersionRecord is one agent version that has run on this server.
type VersionRecord struct {
	Version   string
	StartedAt time.Time
}

// Store is the agent's state database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) state.db inside dir and applies pending migrations.
// The deploy runner opens the same file from another process, so the database uses WAL and waits up to 5 s for locks.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	dsn := "file:" + filepath.Join(dir, "state.db") +
		"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}

	db.SetMaxOpenConns(1)

	if err := enableWAL(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable wal: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate state db: %w", err)
	}

	return &Store{db: db}, nil
}

// enableWAL switches the database to WAL mode. SQLite reports SQLITE_BUSY for the switch without consulting
// busy_timeout when another process is opening the same file, so it is retried here instead of set in the DSN.
func enableWAL(db *sql.DB) error {
	deadline := time.Now().Add(walTimeout)

	for {
		var mode string
		err := db.QueryRow(`PRAGMA journal_mode = WAL`).Scan(&mode)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) || !strings.Contains(err.Error(), "SQLITE_BUSY") {
			return err
		}

		time.Sleep(10 * time.Millisecond)
	}
}

const walTimeout = 5 * time.Second

// RecordStart stores the install time on first start and appends version when it differs from the last one recorded.
func (s *Store) RecordStart(version string, now time.Time) error {
	timestamp := now.UTC().Format(time.RFC3339)

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`INSERT OR IGNORE INTO meta(key, value) VALUES ('installed_at', ?)`, timestamp); err != nil {
		return err
	}

	var last string
	err = tx.QueryRow(`SELECT version FROM agent_versions ORDER BY id DESC LIMIT 1`).Scan(&last)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	if errors.Is(err, sql.ErrNoRows) || last != version {
		if _, err := tx.Exec(`INSERT INTO agent_versions(version, started_at) VALUES (?, ?)`, version, timestamp); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// InstalledAt returns when the agent first started on this server.
func (s *Store) InstalledAt() (time.Time, error) {
	var value string
	if err := s.db.QueryRow(`SELECT value FROM meta WHERE key = 'installed_at'`).Scan(&value); err != nil {
		return time.Time{}, err
	}

	return time.Parse(time.RFC3339, value)
}

// Versions returns every recorded version, oldest first.
func (s *Store) Versions() ([]VersionRecord, error) {
	rows, err := s.db.Query(`SELECT version, started_at FROM agent_versions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []VersionRecord
	for rows.Next() {
		var record VersionRecord
		var startedAt string
		if err := rows.Scan(&record.Version, &startedAt); err != nil {
			return nil, err
		}

		record.StartedAt, err = time.Parse(time.RFC3339, startedAt)
		if err != nil {
			return nil, err
		}

		records = append(records, record)
	}

	return records, rows.Err()
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}
