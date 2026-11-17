package state

import "time"

// Activity is one entry in a site's activity feed.
type Activity struct {
	At      time.Time
	Kind    string
	Actor   string
	Summary string
}

const activityKept = 200

// AddActivity records an entry and keeps only the site's newest 200.
func (s *Store) AddActivity(siteID string, entry Activity) error {
	if _, err := s.db.Exec(`INSERT INTO activity(site_id, at, kind, actor, summary) VALUES (?, ?, ?, ?, ?)`,
		siteID, formatTime(entry.At), entry.Kind, entry.Actor, entry.Summary); err != nil {
		return err
	}

	_, err := s.db.Exec(`DELETE FROM activity WHERE site_id = ? AND id NOT IN (SELECT id FROM activity WHERE site_id = ? ORDER BY id DESC LIMIT ?)`,
		siteID, siteID, activityKept)

	return err
}

// ListActivity returns a site's newest entries first.
func (s *Store) ListActivity(siteID string, limit int) ([]Activity, error) {
	rows, err := s.db.Query(`SELECT at, kind, actor, summary FROM activity WHERE site_id = ? ORDER BY id DESC LIMIT ?`, siteID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Activity
	for rows.Next() {
		var entry Activity
		var at string
		if err := rows.Scan(&at, &entry.Kind, &entry.Actor, &entry.Summary); err != nil {
			return nil, err
		}
		if entry.At, err = parseTime(at); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	return entries, rows.Err()
}
