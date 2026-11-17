package state

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/site"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrStaleRevision = errors.New("the site changed since it was read")
)

// DomainTakenError is a domain another site already uses.
type DomainTakenError struct {
	Name   string
	SiteID string
}

func (e *DomainTakenError) Error() string {
	return fmt.Sprintf("%s already belongs to another site on this server", e.Name)
}

// PutSite creates (expectedRevision 0) or replaces a site, giving it revision expectedRevision+1.
func (s *Store) PutSite(spec site.Site, expectedRevision uint64, now time.Time) (site.Site, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return site.Site{}, err
	}
	defer tx.Rollback()

	var current uint64
	var createdAt string
	err = tx.QueryRow(`SELECT revision, created_at FROM sites WHERE id = ?`, spec.ID).Scan(&current, &createdAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if expectedRevision != 0 {
			return site.Site{}, ErrStaleRevision
		}
		spec.CreatedAt = now.UTC()
	case err != nil:
		return site.Site{}, err
	default:
		if current != expectedRevision {
			return site.Site{}, ErrStaleRevision
		}
		spec.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			return site.Site{}, err
		}
	}

	for _, domain := range spec.Domains {
		var owner string
		err := tx.QueryRow(`SELECT site_id FROM site_domains WHERE name = ?`, domain.Name).Scan(&owner)
		if err == nil && owner != spec.ID {
			return site.Site{}, &DomainTakenError{Name: domain.Name, SiteID: owner}
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return site.Site{}, err
		}
	}

	spec.Revision = expectedRevision + 1
	if err := writeSite(tx, spec, now); err != nil {
		return site.Site{}, err
	}

	if _, err := tx.Exec(`DELETE FROM site_domains WHERE site_id = ?`, spec.ID); err != nil {
		return site.Site{}, err
	}
	for _, domain := range spec.Domains {
		if _, err := tx.Exec(`INSERT INTO site_domains(name, site_id) VALUES (?, ?)`, domain.Name, spec.ID); err != nil {
			return site.Site{}, err
		}
	}

	return spec, tx.Commit()
}

// UpdateSite changes a stored site in place (agent-owned fields such as NginxCustomised) and bumps its revision.
func (s *Store) UpdateSite(id string, change func(*site.Site), now time.Time) (site.Site, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return site.Site{}, err
	}
	defer tx.Rollback()

	spec, err := readSite(tx.QueryRow(`SELECT spec FROM sites WHERE id = ?`, id))
	if err != nil {
		return site.Site{}, err
	}

	change(&spec)
	spec.ID = id
	spec.Revision++

	if err := writeSite(tx, spec, now); err != nil {
		return site.Site{}, err
	}

	return spec, tx.Commit()
}

// GetSite returns a site or ErrNotFound.
func (s *Store) GetSite(id string) (site.Site, error) {
	return readSite(s.db.QueryRow(`SELECT spec FROM sites WHERE id = ?`, id))
}

// ListSites returns every site, oldest first.
func (s *Store) ListSites() ([]site.Site, error) {
	rows, err := s.db.Query(`SELECT spec FROM sites ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sites []site.Site
	for rows.Next() {
		spec, err := readSite(rows)
		if err != nil {
			return nil, err
		}
		sites = append(sites, spec)
	}

	return sites, rows.Err()
}

// DomainOwner returns the id of the site that uses name.
func (s *Store) DomainOwner(name string) (string, bool, error) {
	var owner string
	err := s.db.QueryRow(`SELECT site_id FROM site_domains WHERE name = ?`, name).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}

	return owner, err == nil, err
}

// DeleteSiteData removes a site and everything recorded about it.
func (s *Store) DeleteSiteData(siteID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, statement := range []string{
		`DELETE FROM site_domains WHERE site_id = ?`,
		`DELETE FROM sites WHERE id = ?`,
		`DELETE FROM deployments WHERE site_id = ?`,
		`DELETE FROM activity WHERE site_id = ?`,
		`DELETE FROM host_keys WHERE site_id = ?`,
		`DELETE FROM node_ports WHERE site_id = ?`,
		`DELETE FROM certificates WHERE site_id = ?`,
	} {
		if _, err := tx.Exec(statement, siteID); err != nil {
			return err
		}
	}

	return tx.Commit()
}

type scanner interface {
	Scan(dest ...any) error
}

func readSite(row scanner) (site.Site, error) {
	var raw string
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return site.Site{}, ErrNotFound
		}
		return site.Site{}, err
	}

	var spec site.Site
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		return site.Site{}, fmt.Errorf("decode site: %w", err)
	}

	return spec, nil
}

func writeSite(tx *sql.Tx, spec site.Site, now time.Time) error {
	raw, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("encode site: %w", err)
	}

	_, err = tx.Exec(`INSERT INTO sites(id, revision, spec, created_at, updated_at) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET revision = excluded.revision, spec = excluded.spec, updated_at = excluded.updated_at`,
		spec.ID, spec.Revision, string(raw), spec.CreatedAt.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))

	return err
}
