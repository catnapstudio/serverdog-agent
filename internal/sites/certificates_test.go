package sites

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/nginx"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
)

const certDir = "/etc/serverdog/certs/abcdefghijkl/c1"

func certificateFiles(f *fixture, fullchain string) []apply.File {
	return []apply.File{
		{Path: f.file(certDir + "/fullchain.pem"), Content: []byte(fullchain), Mode: 0o600},
		{Path: f.file(certDir + "/privkey.pem"), Content: []byte("key"), Mode: 0o600},
		{Path: f.file("/etc/serverdog/certs/abcdefghijkl/orchard.com/active"), Link: "../c1"},
	}
}

var activeOrchard = map[string]nginx.Certificate{"orchard.com": {
	Fullchain: "/etc/serverdog/certs/abcdefghijkl/orchard.com/active/fullchain.pem",
	Key:       "/etc/serverdog/certs/abcdefghijkl/orchard.com/active/privkey.pem",
}}

func TestApplyCertificatesServesHTTPS(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, laravel(), 0, "Mac")
	f.system.Reset()

	if err := f.manager.ApplyCertificates(ctx, "abcdefghijkl", certificateFiles(f, "chain"), activeOrchard, nil); err != nil {
		t.Fatal(err)
	}

	config, _ := os.ReadFile(f.file(paths.NginxSiteAvailable("abcdefghijkl")))
	if !strings.Contains(string(config), "ssl_certificate /etc/serverdog/certs/abcdefghijkl/orchard.com/active/fullchain.pem;") {
		t.Errorf("config has no certificate:\n%s", config)
	}
	if target, _ := os.Readlink(f.file("/etc/serverdog/certs/abcdefghijkl/orchard.com/active")); target != "../c1" {
		t.Errorf("active link = %q", target)
	}
	if commands := strings.Join(f.system.Commands(), "\n"); !strings.Contains(commands, "nginx -t") || !strings.Contains(commands, "reload-nginx") {
		t.Errorf("commands = %s", commands)
	}
}

func TestApplyCertificatesLeavesACustomisedConfigAlone(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, laravel(), 0, "Mac")
	_, sum, _, _ := f.manager.NginxConfig(ctx, "abcdefghijkl")
	f.manager.PutNginxConfig(ctx, "abcdefghijkl", []byte("# mine\n"), sum, "Mac")
	f.system.Reset()

	if err := f.manager.ApplyCertificates(ctx, "abcdefghijkl", certificateFiles(f, "chain"), activeOrchard, nil); err != nil {
		t.Fatal(err)
	}

	if config, _ := os.ReadFile(f.file(paths.NginxSiteAvailable("abcdefghijkl"))); string(config) != "# mine\n" {
		t.Errorf("customised config was rewritten:\n%s", config)
	}
	if commands := strings.Join(f.system.Commands(), "\n"); !strings.Contains(commands, "reload-nginx") {
		t.Errorf("renewed files need a reload; commands = %s", commands)
	}
}

func TestApplyCertificatesRestoresEverythingWhenNginxRejectsIt(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, laravel(), 0, "Mac")
	f.manager.ApplyCertificates(ctx, "abcdefghijkl", certificateFiles(f, "old chain"), activeOrchard, nil)
	f.system.Fail("nginx", 1, "nginx: [emerg] cannot load certificate")

	err := f.manager.ApplyCertificates(ctx, "abcdefghijkl", certificateFiles(f, "new chain"), activeOrchard, nil)

	var applyErr *apply.Error
	if !errors.As(err, &applyErr) {
		t.Fatalf("err = %v", err)
	}
	if content, _ := os.ReadFile(f.file(certDir + "/fullchain.pem")); string(content) != "old chain" {
		t.Errorf("fullchain = %q, want the previous file", content)
	}
}

func TestActiveCertificatesErrorStopsThePut(t *testing.T) {
	f := newFixture(t)
	f.manager.ActiveCertificates = func(string) (map[string]nginx.Certificate, error) { return nil, errors.New("database is locked") }

	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err == nil {
		t.Fatal("a Put that can't read the certificates must fail instead of dropping HTTPS")
	}
	if f.exists(paths.NginxSiteAvailable("abcdefghijkl")) {
		t.Error("config was written")
	}
}

func TestAfterPutGetsTheSavedSiteAndThePreviousOne(t *testing.T) {
	f := newFixture(t)
	type call struct {
		saved    site.Site
		previous *site.Site
	}
	var calls []call
	f.manager.AfterPut = func(_ context.Context, saved site.Site, previous *site.Site) {
		calls = append(calls, call{saved, previous})
	}

	saved, _, _ := f.manager.Put(ctx, laravel(), 0, "Mac")
	f.manager.Put(ctx, laravel(), saved.Revision, "Mac")

	changed := laravel()
	changed.Domains = append(changed.Domains, site.Domain{Name: "orchard.dev", Redirect: site.NoRedirect})
	f.manager.Put(ctx, changed, saved.Revision, "Mac")

	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2 (an identical Put saves nothing)", len(calls))
	}
	if calls[0].previous != nil || calls[0].saved.Revision != 1 {
		t.Errorf("create call = %+v", calls[0])
	}
	if calls[1].previous == nil || len(calls[1].previous.Domains) != 1 || len(calls[1].saved.Domains) != 2 {
		t.Errorf("update call = %+v", calls[1])
	}
}

func TestDeleteRemovesTheSitesCertificates(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, laravel(), 0, "Mac")
	f.manager.ApplyCertificates(ctx, "abcdefghijkl", certificateFiles(f, "chain"), activeOrchard, nil)

	if err := f.manager.Delete(ctx, "abcdefghijkl", false, "Mac"); err != nil {
		t.Fatal(err)
	}

	if f.exists("/etc/serverdog/certs/abcdefghijkl") {
		t.Error("certificates were left behind")
	}
}

func TestMergeEnvSetsKeysAndKeepsTheRest(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, laravel(), 0, "Mac")
	_, sum, _ := f.manager.Env(ctx, "abcdefghijkl")
	f.manager.PutEnv(ctx, "abcdefghijkl", []byte("APP_KEY=x\nDB_HOST=localhost\n"), sum, "Mac")

	err := f.manager.MergeEnv(ctx, "abcdefghijkl", [][2]string{{"DB_HOST", "127.0.0.1"}, {"DB_PASSWORD", "s3cretPassw0rdXYZ"}}, "Set the database settings in .env.", "Mac")
	if err != nil {
		t.Fatal(err)
	}

	content, _, _ := f.manager.Env(ctx, "abcdefghijkl")
	if string(content) != "APP_KEY=x\nDB_HOST=127.0.0.1\nDB_PASSWORD=s3cretPassw0rdXYZ\n" {
		t.Errorf("content = %q", content)
	}

	info, _ := os.Stat(filepath.Join(f.root, "home/serverdog/orchard.com/shared/.env"))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode())
	}

	activity, _ := f.store.ListActivity("abcdefghijkl", 1)
	if activity[0].Summary != "Set the database settings in .env." || strings.Contains(activity[0].Summary, "s3cret") {
		t.Errorf("activity = %+v", activity[0])
	}
}

func TestMergeEnvNeedsAnEnvironmentFile(t *testing.T) {
	f := newFixture(t)
	s := laravel()
	s.EnvironmentFile = ""
	f.manager.Put(ctx, s, 0, "Mac")

	var invalid *site.InvalidError
	if err := f.manager.MergeEnv(ctx, "abcdefghijkl", [][2]string{{"A", "b"}}, "x", "Mac"); !errors.As(err, &invalid) {
		t.Errorf("err = %v", err)
	}
}

func TestCheckEnvWritable(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, laravel(), 0, "Mac")

	if err := f.manager.CheckEnvWritable(ctx, "abcdefghijkl"); err != nil {
		t.Fatalf("with the file in place: %v", err)
	}

	os.Remove(filepath.Join(f.root, "home/serverdog/orchard.com/shared/.env"))

	var invalid *site.InvalidError
	if err := f.manager.CheckEnvWritable(ctx, "abcdefghijkl"); !errors.As(err, &invalid) || invalid.Field != "environmentFile" || !strings.Contains(invalid.Reason, ".env is missing") {
		t.Errorf("without the file: %v", err)
	}

	delete(f.users, "serverdog")

	if err := f.manager.CheckEnvWritable(ctx, "abcdefghijkl"); !errors.As(err, &invalid) || invalid.Field != "user" {
		t.Errorf("without the user: %v", err)
	}
}

func TestCheckEnvWritableNeedsAnEnvironmentFile(t *testing.T) {
	f := newFixture(t)
	s := laravel()
	s.EnvironmentFile = ""
	f.manager.Put(ctx, s, 0, "Mac")

	var invalid *site.InvalidError
	if err := f.manager.CheckEnvWritable(ctx, "abcdefghijkl"); !errors.As(err, &invalid) || invalid.Field != "environmentFile" {
		t.Errorf("err = %v", err)
	}
}
