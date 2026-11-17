package state

// AddHostKey stores a known_hosts line the user trusted for a site (or a site being created).
func (s *Store) AddHostKey(siteID, line string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO host_keys(site_id, line) VALUES (?, ?)`, siteID, line)

	return err
}

// HostKeys returns the known_hosts lines trusted for a site.
func (s *Store) HostKeys(siteID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT line FROM host_keys WHERE site_id = ? ORDER BY line`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var lines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, err
		}
		lines = append(lines, line)
	}

	return lines, rows.Err()
}

// RemoveHostKeys deletes the given known_hosts lines from a site's trusted keys, all or none.
func (s *Store) RemoveHostKeys(siteID string, lines []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, line := range lines {
		if _, err := tx.Exec(`DELETE FROM host_keys WHERE site_id = ? AND line = ?`, siteID, line); err != nil {
			return err
		}
	}

	return tx.Commit()
}
