package state

import (
	"database/sql"
	"errors"
	"strconv"
)

// ErrStaleDocument is a change based on a document, such as the scheduled jobs, that changed since it was read.
var ErrStaleDocument = errors.New("the list changed since it was read")

// Document returns a document another package encoded, such as the scheduled jobs, and its revision: 0 and nil
// before the first save.
func (s *Store) Document(name string) ([]byte, uint64, error) {
	return document(s.db, name)
}

type queryRower interface {
	QueryRow(query string, args ...any) *sql.Row
}

func document(db queryRower, name string) ([]byte, uint64, error) {
	var encoded, revision string

	err := db.QueryRow(`SELECT value FROM meta WHERE key = ?`, name).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}

	if err := db.QueryRow(`SELECT value FROM meta WHERE key = ?`, name+"_revision").Scan(&revision); err != nil {
		return nil, 0, err
	}

	number, err := strconv.ParseUint(revision, 10, 64)

	return []byte(encoded), number, err
}

// PutDocument replaces the document if it is still at expectedRevision, and returns the new revision.
func (s *Store) PutDocument(name string, encoded []byte, expectedRevision uint64) (uint64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	_, current, err := document(tx, name)
	if err != nil {
		return 0, err
	}
	if current != expectedRevision {
		return 0, ErrStaleDocument
	}

	revision := current + 1
	for key, value := range map[string]string{name: string(encoded), name + "_revision": strconv.FormatUint(revision, 10)} {
		if _, err := tx.Exec(`INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value); err != nil {
			return 0, err
		}
	}

	return revision, tx.Commit()
}
