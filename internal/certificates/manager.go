// Package certificates keeps each domain's certificates: signing requests, uploads, clones and activation, and the
// scheduler that issues and renews Let's Encrypt certificates on its own (schedule.go).
package certificates

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"slices"
	"sync"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/acmeclient"
	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/certs"
	"github.com/catnapstudio/serverdog-agent/internal/nginx"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/sites"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

// Reachability is the DNS self-check (domains.Checker): whether every name reaches this server, and why not.
type Reachability interface {
	Reachable(ctx context.Context, names []string) (bool, string)
}

// Manager changes certificates under the site's lock (shared with sites.Manager, whose Nginx config it rewrites).
type Manager struct {
	Store   *state.Store
	Paths   paths.Paths
	Sites   *sites.Manager
	Applier apply.Applier
	Domains Reachability
	ACME    acmeclient.Client
	Now     func() time.Time
	NewID   func() string

	kickOnce sync.Once
	kick     chan struct{}
}

// Upload is a pasted certificate (optionally followed by its chain), its chain, and its private key.
type Upload struct {
	Certificate []byte
	Chain       []byte
	PrivateKey  []byte
}

// Active returns the domains of the site that have an active certificate, as Nginx references them.
func (m *Manager) Active(siteID string) (map[string]nginx.Certificate, error) {
	list, err := m.Store.ListCertificates(siteID)
	if err != nil {
		return nil, err
	}

	active := map[string]nginx.Certificate{}
	for _, c := range list {
		if c.Active && c.Usable() {
			active[c.Domain] = certs.Nginx(siteID, c.Domain)
		}
	}

	return active, nil
}

// SyncSite follows a saved site (sites.Manager.AfterPut, which holds the site's lock). Added domains get a Let's Encrypt
// request, removed domains lose their certificates, and Let's Encrypt certificates whose names changed are requested again.
func (m *Manager) SyncSite(ctx context.Context, saved site.Site, previous *site.Site) {
	if err := m.syncSite(saved, previous); err != nil {
		slog.Warn("could not update the site's certificates", "site", saved.ID, "error", err)
	}

	m.Kick()
}

func (m *Manager) syncSite(saved site.Site, previous *site.Site) error {
	existing, err := m.Store.ListCertificates(saved.ID)
	if err != nil {
		return err
	}

	byDomain := map[string][]state.Certificate{}
	for _, c := range existing {
		byDomain[c.Domain] = append(byDomain[c.Domain], c)
	}

	before := map[string]bool{}
	if previous != nil {
		for _, domain := range previous.Domains {
			before[domain.Name] = true
		}
	}

	now := m.Now()
	var failures []error

	for _, domain := range saved.Domains {
		names := certs.Names(domain)
		list := byDomain[domain.Name]
		delete(byDomain, domain.Name)

		if !before[domain.Name] && len(list) == 0 {
			failures = append(failures, m.Store.CreateCertificate(m.letsEncrypt(saved.ID, domain.Name, names, certs.ECDSAP256)))
			continue
		}

		for _, c := range list {
			if c.Source != state.CertLetsEncrypt || slices.Equal(c.Names, names) {
				continue
			}

			_, err := m.Store.UpdateCertificate(c.ID, func(c *state.Certificate) {
				c.Names, c.NextAttempt, c.Failures = names, now, 0
			})
			failures = append(failures, err)
		}
	}

	for domain, list := range byDomain {
		for _, c := range list {
			failures = append(failures, m.Store.DeleteCertificate(c.ID), os.RemoveAll(m.Paths.File(paths.CertificateDir(saved.ID, c.ID))))
		}
		failures = append(failures, os.RemoveAll(m.Paths.File(path.Dir(paths.ActiveCertificateDir(saved.ID, domain)))))
	}

	return errors.Join(failures...)
}

func (m *Manager) letsEncrypt(siteID, domain string, names []string, keyType certs.KeyType) state.Certificate {
	now := m.Now()

	return state.Certificate{
		ID: m.NewID(), SiteID: siteID, Domain: domain, Source: state.CertLetsEncrypt, KeyType: string(keyType), Names: names,
		Status: state.CertWaitingForDNS, NextAttempt: now, WaitingSince: now, CreatedAt: now,
	}
}

// RequestLetsEncrypt queues a Let's Encrypt certificate for the domain and wakes the scheduler, which checks DNS at once
// ("Request Now"). A request that is waiting, failed or failing to renew is retried instead of adding another, and an
// issued certificate with the same key type is left alone; only a different key type adds a certificate beside it.
func (m *Manager) RequestLetsEncrypt(ctx context.Context, siteID, domain string, keyType certs.KeyType, actor string) (state.Certificate, error) {
	defer m.Sites.Locks.Lock(siteID)()
	defer m.Kick()

	d, err := m.domain(siteID, domain)
	if err != nil {
		return state.Certificate{}, err
	}

	list, err := m.Store.ListCertificates(siteID)
	if err != nil {
		return state.Certificate{}, err
	}

	now := m.Now()

	for _, c := range list {
		if c.Domain != domain || c.Source != state.CertLetsEncrypt {
			continue
		}

		// A retry starts over: no failures to stretch its backoff, and no error from the attempt before.
		switch c.Status {
		case state.CertIssuing:
			return c, nil
		case state.CertWaitingForDNS, state.CertFailed:
			return m.Store.UpdateCertificate(c.ID, func(c *state.Certificate) {
				c.KeyType, c.NextAttempt, c.Failures, c.Error = string(keyType), now, 0, ""
			})
		case state.CertRenewalFailing:
			return m.Store.UpdateCertificate(c.ID, func(c *state.Certificate) { c.NextAttempt, c.Failures, c.Error = now, 0, "" })
		case state.CertIssued:
			if c.KeyType == string(keyType) {
				return c, nil
			}
		}
	}

	c := m.letsEncrypt(siteID, domain, certs.Names(d), keyType)
	if err := m.Store.CreateCertificate(c); err != nil {
		return state.Certificate{}, err
	}
	m.Store.AddActivity(siteID, state.Activity{At: now, Kind: "certificate.requested", Actor: actor, Summary: "Requested a Let's Encrypt certificate for " + domain + "."})

	return m.Store.GetCertificate(c.ID)
}

// CreateSigningRequest creates a private key on the server (it never leaves) and returns a CSR for the domain's names.
func (m *Manager) CreateSigningRequest(ctx context.Context, siteID, domain string, keyType certs.KeyType, actor string) (state.Certificate, []byte, error) {
	defer m.Sites.Locks.Lock(siteID)()

	d, err := m.domain(siteID, domain)
	if err != nil {
		return state.Certificate{}, nil, err
	}

	key, keyPEM, err := certs.GenerateKey(keyType)
	if err != nil {
		return state.Certificate{}, nil, err
	}

	names := certs.Names(d)
	csr, err := certs.CreateCSR(key, names)
	if err != nil {
		return state.Certificate{}, nil, err
	}

	now := m.Now()
	c := state.Certificate{
		ID: m.NewID(), SiteID: siteID, Domain: domain, Source: state.CertSigningRequest, KeyType: string(keyType), Names: names,
		Status: state.CertAwaitingCertificate, CreatedAt: now,
	}

	if err := m.certificateDir(siteID, c.ID); err != nil {
		return state.Certificate{}, nil, err
	}
	if _, err := m.Applier.Apply(ctx, apply.Plan{Files: []apply.File{
		{Path: certs.KeyFile(m.Paths, siteID, c.ID), Content: keyPEM, Mode: 0o600},
		{Path: certs.RequestFile(m.Paths, siteID, c.ID), Content: csr, Mode: 0o644},
	}}); err != nil {
		return state.Certificate{}, nil, err
	}

	if err := m.Store.CreateCertificate(c); err != nil {
		os.RemoveAll(m.Paths.File(paths.CertificateDir(siteID, c.ID)))
		return state.Certificate{}, nil, err
	}
	m.Store.AddActivity(siteID, state.Activity{At: now, Kind: "certificate.requested", Actor: actor, Summary: "Created a certificate signing request for " + domain + "."})

	return c, csr, nil
}

// Install installs the certificate for a signing request (certificateID set; its key is already on the server) or an
// existing certificate with its private key.
func (m *Manager) Install(ctx context.Context, siteID, domain, certificateID string, upload Upload, actor string) (state.Certificate, error) {
	defer m.Sites.Locks.Lock(siteID)()

	d, err := m.domain(siteID, domain)
	if err != nil {
		return state.Certificate{}, err
	}

	now := m.Now()
	var c state.Certificate
	var keyPEM []byte

	if certificateID != "" {
		if c, err = m.Store.GetCertificate(certificateID); err != nil {
			return state.Certificate{}, err
		}
		if c.SiteID != siteID || c.Domain != domain || c.Source != state.CertSigningRequest || c.Status != state.CertAwaitingCertificate {
			return state.Certificate{}, &site.InvalidError{Field: "certificateId", Reason: "That certificate isn't a signing request waiting for its certificate."}
		}
		if keyPEM, err = os.ReadFile(certs.KeyFile(m.Paths, siteID, c.ID)); err != nil {
			return state.Certificate{}, fmt.Errorf("read the signing request's key: %w", err)
		}
	} else {
		if len(bytes.TrimSpace(upload.PrivateKey)) == 0 {
			return state.Certificate{}, &site.InvalidError{Field: "privateKey", Reason: "Paste the certificate's private key."}
		}
		keyPEM = upload.PrivateKey
		c = state.Certificate{ID: m.NewID(), SiteID: siteID, Domain: domain, Source: state.CertUploaded, CreatedAt: now}
	}

	parsed, err := certs.ParseBundle(upload.Certificate, upload.Chain, keyPEM, now)
	if err != nil {
		return state.Certificate{}, err
	}
	if err := parsed.Covers(certs.Names(d)); err != nil {
		return state.Certificate{}, err
	}

	return m.save(ctx, c, parsed, certificateID == "", "Installed a certificate for "+domain+".", actor)
}

// Clone copies an issued certificate of any site on this server to the domain. The copy isn't renewed with its source.
func (m *Manager) Clone(ctx context.Context, siteID, domain, fromID, actor string) (state.Certificate, error) {
	defer m.Sites.Locks.Lock(siteID)()

	d, err := m.domain(siteID, domain)
	if err != nil {
		return state.Certificate{}, err
	}

	from, err := m.Store.GetCertificate(fromID)
	if err != nil {
		return state.Certificate{}, err
	}
	if !from.Usable() {
		return state.Certificate{}, &site.InvalidError{Field: "fromCertificateId", Reason: "Only an issued certificate can be cloned."}
	}

	fullchain, err := os.ReadFile(certs.FullchainFile(m.Paths, from.SiteID, from.ID))
	if err != nil {
		return state.Certificate{}, fmt.Errorf("read the certificate to clone: %w", err)
	}
	key, err := os.ReadFile(certs.KeyFile(m.Paths, from.SiteID, from.ID))
	if err != nil {
		return state.Certificate{}, fmt.Errorf("read the certificate to clone: %w", err)
	}

	now := m.Now()
	parsed, err := certs.ParseBundle(fullchain, nil, key, now)
	if err != nil {
		return state.Certificate{}, err
	}
	if err := parsed.Covers(certs.Names(d)); err != nil {
		return state.Certificate{}, err
	}

	c := state.Certificate{ID: m.NewID(), SiteID: siteID, Domain: domain, Source: state.CertCloned, CreatedAt: now}

	return m.save(ctx, c, parsed, true, "Cloned a certificate for "+domain+".", actor)
}

// save writes a usable certificate's files and row, then activates it when its domain has none active.
func (m *Manager) save(ctx context.Context, c state.Certificate, parsed certs.Parsed, create bool, summary, actor string) (state.Certificate, error) {
	if err := m.certificateDir(c.SiteID, c.ID); err != nil {
		return state.Certificate{}, err
	}
	if _, err := m.Applier.Apply(ctx, apply.Plan{Files: certs.Files(m.Paths, c.SiteID, c.ID, parsed.Fullchain, parsed.Key)}); err != nil {
		return state.Certificate{}, err
	}

	var err error
	if create {
		describe(&c, parsed.Leaf)
		if err = m.Store.CreateCertificate(c); err != nil {
			os.RemoveAll(m.Paths.File(paths.CertificateDir(c.SiteID, c.ID)))
		}
	} else {
		c, err = m.Store.UpdateCertificate(c.ID, func(stored *state.Certificate) { describe(stored, parsed.Leaf) })
	}
	if err != nil {
		return state.Certificate{}, err
	}

	m.Store.AddActivity(c.SiteID, state.Activity{At: m.Now(), Kind: "certificate.installed", Actor: actor, Summary: summary})

	if err := m.activateIfFirst(ctx, c); err != nil {
		return state.Certificate{}, err
	}

	return m.Store.GetCertificate(c.ID)
}

// describe records what an installed certificate is. Let's Encrypt certificates keep the names they were requested
// for, which SyncSite compares with the domain's.
func describe(c *state.Certificate, leaf *x509.Certificate) {
	c.Status = state.CertIssued
	if c.Source != state.CertLetsEncrypt {
		c.Names = leaf.DNSNames
		c.KeyType = keyTypeOf(leaf)
	}
	c.Issuer = certs.IssuerName(leaf)
	c.NotBefore, c.NotAfter = leaf.NotBefore, leaf.NotAfter
	c.Error, c.Failures, c.WaitingSince = "", 0, time.Time{}
	if c.Source != state.CertLetsEncrypt {
		c.NextAttempt = time.Time{}
	}
}

// keyTypeOf names the leaf's key when it is one of the two ServerDog creates; anything else stays unnamed.
func keyTypeOf(leaf *x509.Certificate) string {
	switch key := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if key.Curve == elliptic.P256() {
			return string(certs.ECDSAP256)
		}
	case *rsa.PublicKey:
		if key.N.BitLen() == 2048 {
			return string(certs.RSA2048)
		}
	}

	return ""
}

func (m *Manager) activateIfFirst(ctx context.Context, c state.Certificate) error {
	active, err := m.Active(c.SiteID)
	if err != nil {
		return err
	}
	if _, has := active[c.Domain]; has {
		return nil
	}

	return m.activate(ctx, c, active, nil)
}

// activate serves c for its domain: extra files, the active link and the regenerated config in one validated change.
// The caller holds the site's lock.
func (m *Manager) activate(ctx context.Context, c state.Certificate, active map[string]nginx.Certificate, extra []apply.File) error {
	active[c.Domain] = certs.Nginx(c.SiteID, c.Domain)
	files := append(extra, certs.ActiveLink(m.Paths, c.SiteID, c.Domain, c.ID))

	return m.Sites.ApplyCertificates(ctx, c.SiteID, files, active, func() error {
		return m.Store.SetActiveCertificate(c.SiteID, c.Domain, c.ID)
	})
}

// Activate makes the certificate its domain's active one, without downtime.
func (m *Manager) Activate(ctx context.Context, id, actor string) (state.Certificate, error) {
	c, err := m.Store.GetCertificate(id)
	if err != nil {
		return state.Certificate{}, err
	}
	defer m.Sites.Locks.Lock(c.SiteID)()

	if c, err = m.Store.GetCertificate(id); err != nil {
		return state.Certificate{}, err
	}
	if !c.Usable() {
		return state.Certificate{}, &site.InvalidError{Field: "certificateId", Reason: "This certificate has nothing to serve yet."}
	}
	if c.Active {
		return c, nil
	}

	active, err := m.Active(c.SiteID)
	if err != nil {
		return state.Certificate{}, err
	}
	if err := m.activate(ctx, c, active, nil); err != nil {
		return state.Certificate{}, err
	}
	m.Store.AddActivity(c.SiteID, state.Activity{At: m.Now(), Kind: "certificate.activated", Actor: actor, Summary: "Activated another certificate for " + c.Domain + "."})

	return m.Store.GetCertificate(id)
}

// Delete removes the certificate. Deleting the active one turns HTTPS off for its domain first.
func (m *Manager) Delete(ctx context.Context, id, actor string) error {
	c, err := m.Store.GetCertificate(id)
	if err != nil {
		return err
	}
	defer m.Sites.Locks.Lock(c.SiteID)()

	if c, err = m.Store.GetCertificate(id); err != nil {
		return err
	}

	if c.Active {
		active, err := m.Active(c.SiteID)
		if err != nil {
			return err
		}
		delete(active, c.Domain)

		if err := m.Sites.ApplyCertificates(ctx, c.SiteID, []apply.File{certs.RemoveActiveLink(m.Paths, c.SiteID, c.Domain)}, active, func() error {
			return m.Store.SetActiveCertificate(c.SiteID, c.Domain, "")
		}); err != nil {
			return err
		}
	}

	if err := m.Store.DeleteCertificate(id); err != nil {
		return err
	}
	if err := os.RemoveAll(m.Paths.File(paths.CertificateDir(c.SiteID, id))); err != nil {
		return err
	}
	m.Store.AddActivity(c.SiteID, state.Activity{At: m.Now(), Kind: "certificate.deleted", Actor: actor, Summary: "Deleted a certificate for " + c.Domain + "."})

	return nil
}

// Kick wakes the scheduler.
func (m *Manager) Kick() {
	select {
	case m.kicks() <- struct{}{}:
	default:
	}
}

func (m *Manager) kicks() chan struct{} {
	m.kickOnce.Do(func() { m.kick = make(chan struct{}, 1) })

	return m.kick
}

// certificateDir creates a certificate's directory 0700, like the tree above it (apply would create it 0755).
func (m *Manager) certificateDir(siteID, certID string) error {
	dir := m.Paths.File(paths.CertificateDir(siteID, certID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create the certificate's directory: %w", err)
	}

	return os.Chmod(dir, 0o700)
}

func (m *Manager) domain(siteID, name string) (site.Domain, error) {
	s, err := m.Store.GetSite(siteID)
	if err != nil {
		return site.Domain{}, err
	}

	for _, domain := range s.Domains {
		if domain.Name == name {
			return domain, nil
		}
	}

	return site.Domain{}, &site.InvalidError{Field: "domain", Reason: fmt.Sprintf("%s isn't one of this site's domains.", name)}
}
