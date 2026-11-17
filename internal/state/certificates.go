package state

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	CertLetsEncrypt    = "letsencrypt"
	CertSigningRequest = "signingRequest"
	CertUploaded       = "uploaded"
	CertCloned         = "cloned"

	CertWaitingForDNS       = "waitingForDns"
	CertIssuing             = "issuing"
	CertIssued              = "issued"
	CertRenewalFailing      = "renewalFailing"
	CertFailed              = "failed"
	CertAwaitingCertificate = "awaitingCertificate"
)

// Certificate is one certificate of a domain. Its files live in /etc/serverdog/certs/<site-id>/<id>/.
type Certificate struct {
	ID       string
	SiteID   string
	Domain   string
	Source   string
	KeyType  string
	Names    []string
	Status   string
	Active   bool
	Issuer   string
	Error    string
	Failures int

	NotBefore    time.Time
	NotAfter     time.Time
	NextAttempt  time.Time
	WaitingSince time.Time
	CreatedAt    time.Time
}

// Usable reports whether the certificate has files Nginx can serve.
func (c Certificate) Usable() bool {
	return c.Status == CertIssued || c.Status == CertRenewalFailing
}

const certificateColumns = `id, site_id, domain, source, key_type, names, status, active, issuer, error, failures, not_before, not_after, next_attempt, waiting_since, created_at`

func (s *Store) CreateCertificate(c Certificate) error {
	names, err := json.Marshal(c.Names)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`INSERT INTO certificates(`+certificateColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.SiteID, c.Domain, c.Source, c.KeyType, string(names), c.Status, c.Active, c.Issuer, c.Error, c.Failures,
		formatTime(c.NotBefore), formatTime(c.NotAfter), formatTime(c.NextAttempt), formatTime(c.WaitingSince), formatTime(c.CreatedAt))

	return err
}

func (s *Store) GetCertificate(id string) (Certificate, error) {
	return readCertificate(s.db.QueryRow(`SELECT `+certificateColumns+` FROM certificates WHERE id = ?`, id))
}

// UpdateCertificate applies change in one transaction. The callback must not call the Store (single connection).
// Active is not changed here; use SetActiveCertificate.
func (s *Store) UpdateCertificate(id string, change func(*Certificate)) (Certificate, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Certificate{}, err
	}
	defer tx.Rollback()

	c, err := readCertificate(tx.QueryRow(`SELECT `+certificateColumns+` FROM certificates WHERE id = ?`, id))
	if err != nil {
		return Certificate{}, err
	}

	active := c.Active
	change(&c)
	c.Active = active

	names, err := json.Marshal(c.Names)
	if err != nil {
		return Certificate{}, err
	}

	_, err = tx.Exec(`UPDATE certificates SET key_type = ?, names = ?, status = ?, issuer = ?, error = ?, failures = ?,
not_before = ?, not_after = ?, next_attempt = ?, waiting_since = ? WHERE id = ?`,
		c.KeyType, string(names), c.Status, c.Issuer, c.Error, c.Failures,
		formatTime(c.NotBefore), formatTime(c.NotAfter), formatTime(c.NextAttempt), formatTime(c.WaitingSince), id)
	if err != nil {
		return Certificate{}, err
	}

	return c, tx.Commit()
}

// ListCertificates returns a site's certificates by domain, oldest first.
func (s *Store) ListCertificates(siteID string) ([]Certificate, error) {
	return s.queryCertificates(`SELECT `+certificateColumns+` FROM certificates WHERE site_id = ? ORDER BY domain, created_at, id`, siteID)
}

// CertificatesWithStatus returns every certificate on the server in a status.
func (s *Store) CertificatesWithStatus(status string) ([]Certificate, error) {
	return s.queryCertificates(`SELECT `+certificateColumns+` FROM certificates WHERE status = ? ORDER BY created_at, id`, status)
}

// DueCertificates returns certificates whose next attempt is at or before now, earliest first.
func (s *Store) DueCertificates(now time.Time) ([]Certificate, error) {
	return s.queryCertificates(`SELECT `+certificateColumns+` FROM certificates WHERE next_attempt != '' AND next_attempt <= ? ORDER BY next_attempt, id`, formatTime(now))
}

// SetActiveCertificate makes id the domain's only active certificate; an empty id leaves the domain with none.
func (s *Store) SetActiveCertificate(siteID, domain, id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`UPDATE certificates SET active = 0 WHERE site_id = ? AND domain = ?`, siteID, domain); err != nil {
		return err
	}

	if id != "" {
		result, err := tx.Exec(`UPDATE certificates SET active = 1 WHERE id = ? AND site_id = ? AND domain = ?`, id, siteID, domain)
		if err != nil {
			return err
		}
		if count, _ := result.RowsAffected(); count != 1 {
			return fmt.Errorf("certificate %s isn't one of %s's", id, domain)
		}
	}

	return tx.Commit()
}

func (s *Store) DeleteCertificate(id string) error {
	_, err := s.db.Exec(`DELETE FROM certificates WHERE id = ?`, id)

	return err
}

func (s *Store) queryCertificates(query string, args ...any) ([]Certificate, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Certificate
	for rows.Next() {
		c, err := readCertificate(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, c)
	}

	return list, rows.Err()
}

func readCertificate(row scanner) (Certificate, error) {
	var c Certificate
	var names, notBefore, notAfter, nextAttempt, waitingSince, createdAt string

	err := row.Scan(&c.ID, &c.SiteID, &c.Domain, &c.Source, &c.KeyType, &names, &c.Status, &c.Active, &c.Issuer, &c.Error, &c.Failures,
		&notBefore, &notAfter, &nextAttempt, &waitingSince, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Certificate{}, ErrNotFound
	}
	if err != nil {
		return Certificate{}, err
	}

	if err := json.Unmarshal([]byte(names), &c.Names); err != nil {
		return Certificate{}, fmt.Errorf("decode names: %w", err)
	}

	for _, field := range []struct {
		raw    string
		target *time.Time
	}{{notBefore, &c.NotBefore}, {notAfter, &c.NotAfter}, {nextAttempt, &c.NextAttempt}, {waitingSince, &c.WaitingSince}, {createdAt, &c.CreatedAt}} {
		if *field.target, err = parseTime(field.raw); err != nil {
			return Certificate{}, err
		}
	}

	return c, nil
}
