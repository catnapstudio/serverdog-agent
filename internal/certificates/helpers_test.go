package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/acmeclient"
	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/capabilities"
	"github.com/catnapstudio/serverdog-agent/internal/certs"
	"github.com/catnapstudio/serverdog-agent/internal/gitsource"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/lock"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/sites"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

var ctx = context.Background()

type fixture struct {
	t       *testing.T
	root    string
	store   *state.Store
	system  *systemtest.Fake
	sites   *sites.Manager
	manager *Manager
	acme    *fakeACME
	dns     *fakeDNS

	mu  sync.Mutex
	now time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	root := t.TempDir()
	store, err := state.Open(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	current, _ := system.CurrentUser()
	p := paths.Paths{Root: root}
	fake := &systemtest.Fake{}
	applier := apply.Applier{Runner: fake, LockPath: filepath.Join(root, "apply.lock")}

	f := &fixture{t: t, root: root, store: store, system: fake, now: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	f.acme = &fakeACME{now: f.clock}
	f.dns = &fakeDNS{reachable: true}

	f.sites = &sites.Manager{
		Store: store, Paths: p, System: fake, Exec: system.Exec{}, Applier: applier, Keys: gitsource.Keys{Paths: p},
		Capabilities: func(context.Context) capabilities.Capabilities {
			return capabilities.Capabilities{PHPVersions: []string{"8.4"}, NginxVersion: "1.24.0"}
		},
		LookupUser: func(name string) (system.User, error) { u := current; u.Name = name; return u, nil },
		Now:        f.clock, Locks: &lock.Keyed{},
	}
	f.manager = &Manager{Store: store, Paths: p, Sites: f.sites, Applier: applier, Domains: f.dns, ACME: f.acme, Now: f.clock, NewID: ids.New}
	f.sites.ActiveCertificates = f.manager.Active
	f.sites.AfterPut = f.manager.SyncSite

	return f
}

func (f *fixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.now
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.now = f.now.Add(d)
}

func (f *fixture) file(logical string) string { return filepath.Join(f.root, logical) }

// put saves s, creating it or applying it over the stored revision.
func (f *fixture) put(s site.Site) site.Site {
	f.t.Helper()

	var revision uint64
	if stored, err := f.store.GetSite(s.ID); err == nil {
		revision = stored.Revision
	}

	saved, _, err := f.sites.Put(ctx, s, revision, "Mac")
	if err != nil {
		f.t.Fatal(err)
	}

	return saved
}

func (f *fixture) certificates(siteID string) []state.Certificate {
	f.t.Helper()

	list, err := f.store.ListCertificates(siteID)
	if err != nil {
		f.t.Fatal(err)
	}

	return list
}

func laravel() site.Site {
	return site.Site{
		ID:              "abcdefghijkl",
		Preset:          "laravel",
		Runtime:         site.PHP,
		Domains:         []site.Domain{{Name: "orchard.com", Redirect: site.FromWWW, Primary: true}},
		RepositoryURL:   "git@github.com:morgan/orchard.git",
		Branch:          "main",
		PHPVersion:      "8.4",
		WebDirectory:    "public",
		EnvironmentFile: ".env",
		DeployScript:    "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\n",
		ZeroDowntime:    true,
		User:            "serverdog",
	}
}

// selfSigned returns a certificate for names valid from notBefore for lifetime, with its PKCS#8 key.
func selfSigned(t *testing.T, names []string, notBefore time.Time, lifetime time.Duration) (fullchain, key []byte, leaf *x509.Certificate) {
	t.Helper()

	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(lifetime),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(der)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(private)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), leaf
}

// upload installs a self-signed certificate for names on the site's domain.
func (f *fixture) upload(siteID, domain string, names ...string) state.Certificate {
	f.t.Helper()

	fullchain, key, _ := selfSigned(f.t, names, f.clock().Add(-time.Hour), 90*24*time.Hour)
	c, err := f.manager.Install(ctx, siteID, domain, "", Upload{Certificate: fullchain, PrivateKey: key}, "Mac")
	if err != nil {
		f.t.Fatal(err)
	}

	return c
}

// fakeACME issues self-signed 90-day certificates (or fails with err) and renews when a third of the lifetime is left.
type fakeACME struct {
	now func() time.Time

	mu       sync.Mutex
	err      error
	obtained [][]string
	keyTypes []certs.KeyType

	// afterObtain and onRenewalTime run while the scheduler works from its snapshot of the row.
	afterObtain   func()
	onRenewalTime func()
}

func (a *fakeACME) Obtain(_ context.Context, names []string, keyType certs.KeyType) (acmeclient.Issued, error) {
	a.mu.Lock()
	hook := a.afterObtain
	a.mu.Unlock()
	if hook != nil {
		defer hook()
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.obtained = append(a.obtained, append([]string(nil), names...))
	a.keyTypes = append(a.keyTypes, keyType)
	if a.err != nil {
		return acmeclient.Issued{}, a.err
	}

	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	start := a.now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: start, NotAfter: start.Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		return acmeclient.Issued{}, err
	}
	leaf, _ := x509.ParseCertificate(der)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(private)

	return acmeclient.Issued{
		Fullchain:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		Leaf:       leaf,
	}, nil
}

func (a *fakeACME) RenewalTime(_ context.Context, leaf *x509.Certificate, _ time.Time) (time.Time, error) {
	a.mu.Lock()
	hook := a.onRenewalTime
	a.mu.Unlock()
	if hook != nil {
		hook()
	}

	return acmeclient.Fallback(leaf), nil
}

func (a *fakeACME) calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return len(a.obtained)
}

func (a *fakeACME) fail(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.err = err
}

type fakeDNS struct {
	mu        sync.Mutex
	reachable bool
	onCheck   func()
}

func (d *fakeDNS) Reachable(_ context.Context, names []string) (bool, string) {
	d.mu.Lock()
	hook := d.onCheck
	d.mu.Unlock()
	if hook != nil {
		hook()
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.reachable {
		return false, names[0] + " doesn't point at this server yet."
	}

	return true, ""
}

func (d *fakeDNS) set(reachable bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.reachable = reachable
}
