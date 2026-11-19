package advisories

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

var now = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func notice(id string, daysAgo int, cves []string, sources ...Source) Notice {
	return Notice{ID: id, Title: id + " title", Published: now.Add(-time.Duration(daysAgo) * 24 * time.Hour), CVEs: cves, Sources: sources}
}

var installed = []Package{
	{Name: "nginx", Version: "1.28.3-2ubuntu1.12", Source: "nginx", SourceVersion: "1.28.3-2ubuntu1.12"},
	{Name: "nginx-common", Version: "1.28.3-2ubuntu1.12", Source: "nginx", SourceVersion: "1.28.3-2ubuntu1.12"},
	{Name: "libssl3t64", Version: "3.5.5-1ubuntu3.7", Source: "openssl", SourceVersion: "3.5.5-1ubuntu3.7"},
	{Name: "linux-image-7.0.0-30-generic", Version: "7.0.0-30.30", Source: "linux-signed", SourceVersion: "7.0.0-30.30"},
	{Name: "linux-modules-7.0.0-30-generic", Version: "7.0.0-30.30", Source: "linux", SourceVersion: "7.0.0-30.30"},
	{Name: "linux-image-virtual", Version: "7.0.0-30.30", Source: "linux-meta", SourceVersion: "7.0.0-30.30"},
	{Name: "linux-virtual", Version: "7.0.0-30.30", Source: "linux-meta", SourceVersion: "7.0.0-30.30"},
	{Name: "swupdate", Version: "2025.12+dfsg-4", Source: "swupdate", SourceVersion: "2025.12+dfsg-4"},
}

func TestMatchFindsUnpatchedPackagesByTheirSource(t *testing.T) {
	notices := []Notice{
		notice("USN-9159-1", 0, []string{"CVE-2026-1", "CVE-2026-2"}, Source{"nginx", "1.28.3-2ubuntu1.13"}),
		notice("USN-9150-1", 2, []string{"CVE-2026-3"}, Source{"swupdate", "2025.12+dfsg-4ubuntu1+esm1"}),
		notice("USN-9100-1", 5, []string{"CVE-2026-4"}, Source{"openssl", "3.5.5-1ubuntu3.7"}),
		notice("USN-9090-1", 7, []string{"CVE-2026-5"}, Source{"apache2", "2.4.66-2ubuntu2.8"}),
		notice("USN-9080-1", 9, []string{"CVE-2026-2", "CVE-2026-6"}, Source{"nginx", "1.28.3-2ubuntu1.12"}, Source{"linux-aws", "7.0.0-1017.18"}),
	}

	findings := Match(notices, installed, "")
	if len(findings) != 2 {
		t.Fatalf("findings = %+v", findings)
	}

	nginx := findings[0]
	if nginx.Source != "nginx" || nginx.Restart || nginx.Pro || strings.Join(nginx.Packages, " ") != "nginx nginx-common" || len(nginx.Notices) != 1 {
		t.Errorf("nginx = %+v", nginx)
	}
	if got := strings.Join(nginx.CVEs(), " "); got != "CVE-2026-1 CVE-2026-2" {
		t.Errorf("cves = %s", got)
	}

	if swupdate := findings[1]; swupdate.Source != "swupdate" || !swupdate.Pro {
		t.Errorf("swupdate = %+v", swupdate)
	}
}

func TestMatchTellsAKernelFixThatWaitsForARestartFromOneNotInstalled(t *testing.T) {
	notices := []Notice{
		notice("USN-9018-1", 9, []string{"CVE-2026-10", "CVE-2026-11"}, Source{"linux", "7.0.0-43.43"}, Source{"linux-aws", "7.0.0-1017.18"}),
		notice("USN-8959-1", 16, []string{"CVE-2026-11", "CVE-2026-12"}, Source{"linux", "7.0.0-42.42"}),
		notice("USN-8659-1", 90, []string{"CVE-2026-13"}, Source{"linux", "7.0.0-30.30"}),
	}

	findings := Match(notices, installed, "7.0.0-30-generic")
	if len(findings) != 1 || findings[0].Source != "linux" || findings[0].Restart || strings.Join(findings[0].Packages, " ") != "linux-image-virtual linux-virtual" {
		t.Fatalf("not installed = %+v", findings)
	}
	if got := strings.Join(findings[0].CVEs(), " "); got != "CVE-2026-10 CVE-2026-11 CVE-2026-12" {
		t.Errorf("cves = %s", got)
	}

	updated := append(installed, Package{Name: "linux-image-7.0.0-43-generic", Version: "7.0.0-43.43", Source: "linux-signed", SourceVersion: "7.0.0-43.43"})
	findings = Match(notices, updated, "7.0.0-30-generic")
	if len(findings) != 1 || !findings[0].Restart || findings[0].Packages != nil || len(findings[0].Notices) != 2 {
		t.Fatalf("installed = %+v", findings)
	}

	if findings := Match(notices, updated, "7.0.0-43-generic"); len(findings) != 0 {
		t.Errorf("running the fixed kernel = %+v", findings)
	}
}

func TestInstalledReadsDpkgsDatabase(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/var/lib/dpkg/status", `Package: libssl3t64
Status: install ok installed
Architecture: amd64
Source: openssl
Version: 3.5.5-1ubuntu3.7
Description: Secure Sockets Layer toolkit
 continued description: with a colon

Package: removed-thing
Status: deinstall ok config-files
Version: 1.0

Package: libfoo1
Status: install ok installed
Source: foo (2.0-1)
Version: 2.0-1build1
`)

	got, err := Installed(paths.Paths{Root: root})
	if err != nil {
		t.Fatal(err)
	}

	want := []Package{
		{Name: "libssl3t64", Version: "3.5.5-1ubuntu3.7", Source: "openssl", SourceVersion: "3.5.5-1ubuntu3.7"},
		{Name: "libfoo1", Version: "2.0-1build1", Source: "foo", SourceVersion: "2.0-1"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("installed = %+v", got)
	}
}

func TestReleaseAndRunningKernel(t *testing.T) {
	root := t.TempDir()
	p := paths.Paths{Root: root}

	write(t, root, "/etc/os-release", "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_CODENAME=resolute\n")
	write(t, root, "/proc/sys/kernel/osrelease", "7.0.0-30-generic\n")
	if Release(p) != "resolute" || RunningKernel(p) != "7.0.0-30-generic" {
		t.Errorf("release %q, kernel %q", Release(p), RunningKernel(p))
	}

	write(t, root, "/etc/os-release", "ID=debian\nVERSION_CODENAME=trixie\n")
	if Release(p) != "" {
		t.Errorf("release %q", Release(p))
	}
}

func TestMatchFollowsACloudKernelAndOtherLinuxPackages(t *testing.T) {
	aws := []Package{
		{Name: "linux-image-7.0.0-1016-aws", Version: "7.0.0-1016.17", Source: "linux-signed-aws", SourceVersion: "7.0.0-1016.17"},
		{Name: "linux-modules-7.0.0-1016-aws", Version: "7.0.0-1016.17", Source: "linux-aws", SourceVersion: "7.0.0-1016.17"},
		{Name: "linux-aws", Version: "7.0.0-1016.17", Source: "linux-meta-aws", SourceVersion: "7.0.0-1016.17"},
		{Name: "linux-image-aws", Version: "7.0.0-1016.17", Source: "linux-meta-aws", SourceVersion: "7.0.0-1016.17"},
		// A generic kernel left from before the switch to AWS's.
		{Name: "linux-modules-7.0.0-30-generic", Version: "7.0.0-30.30", Source: "linux", SourceVersion: "7.0.0-30.30"},
		{Name: "linux-firmware", Version: "20260901.git1-0ubuntu1", Source: "linux-firmware", SourceVersion: "20260901.git1-0ubuntu1"},
	}
	notices := []Notice{
		notice("USN-9018-1", 9, []string{"CVE-2026-10"}, Source{"linux", "7.0.0-43.43"}, Source{"linux-aws", "7.0.0-1017.18"}),
		notice("USN-9010-1", 10, []string{"CVE-2026-20"}, Source{"linux-firmware", "20260901.git1-0ubuntu2"}),
	}

	findings := Match(notices, aws, "7.0.0-1016-aws")
	if len(findings) != 2 {
		t.Fatalf("findings = %+v", findings)
	}
	if k := findings[0]; k.Source != "linux" || k.Restart || strings.Join(k.Packages, " ") != "linux-aws linux-image-aws" {
		t.Errorf("kernel = %+v", k)
	}
	if f := findings[1]; f.Source != "linux-firmware" || strings.Join(f.Packages, " ") != "linux-firmware" {
		t.Errorf("firmware = %+v", f)
	}

	installedFix := append(aws, Package{Name: "linux-image-7.0.0-1017-aws", Version: "7.0.0-1017.18", Source: "linux-signed-aws", SourceVersion: "7.0.0-1017.18"})
	if findings := Match(notices, installedFix, "7.0.0-1016-aws"); len(findings) != 2 || !findings[0].Restart {
		t.Errorf("installed, not running = %+v", findings)
	}
}

// ubuntu serves pages of notices for resolute, newest first, and counts the requests.
func ubuntu(t *testing.T, notices []Notice) (*httptest.Server, *int) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ubuntu's CVE pages and CISA's catalogue: CVE-2026-1 is rated high, CVE-2026-2 is exploited.
		if cve, ok := strings.CutPrefix(r.URL.Path, "/cves/"); ok {
			priority := "medium"
			if cve == "CVE-2026-1.json" {
				priority = "high"
			}
			json.NewEncoder(w).Encode(map[string]string{"id": strings.TrimSuffix(cve, ".json"), "priority": priority})
			return
		}
		if r.URL.Path == "/kev" {
			json.NewEncoder(w).Encode(map[string]any{"vulnerabilities": []map[string]string{{"cveID": "CVE-2026-2"}, {"cveID": "CVE-2020-9"}}})
			return
		}

		requests++
		query := r.URL.Query()
		if query.Get("release") != "resolute" || query.Get("order") != "newest" {
			t.Errorf("query %v", query)
		}
		offset, _ := strconv.Atoi(query.Get("offset"))
		limit, _ := strconv.Atoi(query.Get("limit"))

		type pkg struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			IsSource bool   `json:"is_source"`
		}
		var page []map[string]any
		for _, n := range notices[min(offset, len(notices)):min(offset+limit, len(notices))] {
			packages := []pkg{}
			for _, s := range n.Sources {
				packages = append(packages, pkg{s.Name, s.Version, true}, pkg{s.Name + "-bin", s.Version, false})
			}
			page = append(page, map[string]any{
				"id": n.ID, "title": n.Title, "published": n.Published.Format("2006-01-02T15:04:05.999999"), "cves_ids": n.CVEs,
				"description": "long", "release_packages": map[string]any{"resolute": packages, "noble": []pkg{{"x", "1", true}}},
			})
		}
		json.NewEncoder(w).Encode(map[string]any{"notices": page})
	}))
	t.Cleanup(server.Close)

	return server, &requests
}

func newFeed(t *testing.T, url string) *Feed {
	root := t.TempDir()
	store, err := state.Open(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	write(t, root, "/etc/os-release", "ID=ubuntu\nVERSION_CODENAME=resolute\n")

	return &Feed{Store: store, Paths: paths.Paths{Root: root}, Client: http.DefaultClient, URL: url, CVEURL: url + "/cves/", ExploitedURL: url + "/kev", Now: func() time.Time { return now }}
}

func TestRefreshKeepsNoticesWithinTheWindowAndFetchesOnlyNewOnes(t *testing.T) {
	var notices []Notice
	for day := range 120 {
		notices = append(notices, notice(fmt.Sprintf("USN-%d-1", 9000-day), day, []string{"CVE-1"}, Source{"nginx", "1.0"}))
	}
	notices = append(notices[:3], append([]Notice{notice("USN-LSN", 3, nil)}, notices[3:]...)...)

	server, requests := ubuntu(t, notices)
	feed := newFeed(t, server.URL)

	if err := feed.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	kept, _ := feed.Notices()
	// Days 0 to 90, without the notice that fixes nothing on this release.
	if len(kept) != 91 || kept[0].ID != "USN-9000-1" || kept[90].ID != "USN-8910-1" || kept[0].Sources[0] != (Source{"nginx", "1.0"}) || *requests != 5 {
		t.Fatalf("kept %d (%s…%s), %d requests", len(kept), kept[0].ID, kept[len(kept)-1].ID, *requests)
	}

	*requests = 0
	server2, requests2 := ubuntu(t, append([]Notice{notice("USN-9001-1", 0, nil, Source{"openssl", "2"})}, notices...))
	feed.URL = server2.URL
	if err := feed.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	kept, _ = feed.Notices()
	if len(kept) != 92 || kept[0].ID != "USN-9001-1" || *requests2 != 1 {
		t.Errorf("kept %d, first %s, %d requests", len(kept), kept[0].ID, *requests2)
	}
}

func TestWatcherPostsEachExposureOnce(t *testing.T) {
	server, _ := ubuntu(t, []Notice{notice("USN-9159-1", 0, []string{"CVE-2026-1", "CVE-2026-2", "CVE-2026-3", "CVE-2026-4"}, Source{"nginx", "1.28.3-2ubuntu1.13"})})
	feed := newFeed(t, server.URL)
	write(t, feed.Paths.Root, "/var/lib/dpkg/status", "Package: nginx\nStatus: install ok installed\nVersion: 1.28.3-2ubuntu1.12\n")

	var posted []string
	watcher := &Watcher{
		Feed: feed, Host: func() string { return "web-1" }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Post: func(_ context.Context, text string) error { posted = append(posted, text); return nil },
	}

	watcher.Check(context.Background())
	watcher.Check(context.Background())

	want := "🛡️ web-1 is missing security fixes from Ubuntu:\n• ⚠️ nginx (high): USN-9159-1 (CVE-2026-1, CVE-2026-2, CVE-2026-3 and 1 more). Exploited in the wild: CVE-2026-2. Install the update in ServerDog's Security tab."
	if len(posted) != 1 || posted[0] != want {
		t.Fatalf("posted %q", posted)
	}

	write(t, feed.Paths.Root, "/var/lib/dpkg/status", "Package: nginx\nStatus: install ok installed\nVersion: 1.28.3-2ubuntu1.13\n")
	watcher.Check(context.Background())
	if len(posted) != 1 {
		t.Errorf("posted again after the fix: %q", posted)
	}
}

func TestEnrichRatesOnlyNewCVEsAndKeepsTheExploitedListADay(t *testing.T) {
	cves := []string{"CVE-2026-1", "CVE-2026-2"}
	server, _ := ubuntu(t, []Notice{
		notice("USN-9159-1", 0, cves, Source{"nginx", "1.28.3-2ubuntu1.13"}),
		notice("USN-9018-1", 1, []string{"CVE-2026-7"}, Source{"linux", "7.0.0-43.43"}),
	})
	asked := map[string]int{}
	feed := newFeed(t, server.URL)
	feed.Client = &http.Client{Transport: counting{asked}}
	write(t, feed.Paths.Root, "/var/lib/dpkg/status", "Package: nginx\nStatus: install ok installed\nVersion: 1.28.3-2ubuntu1.12\n\nPackage: linux-image-virtual\nStatus: install ok installed\nSource: linux-meta\nVersion: 7.0.0-30.30\n\nPackage: linux-image-7.0.0-30-generic\nStatus: install ok installed\nSource: linux-signed\nVersion: 7.0.0-30.30\n")
	write(t, feed.Paths.Root, "/proc/sys/kernel/osrelease", "7.0.0-30-generic\n")

	for range 2 {
		if err := feed.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := feed.Enrich(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	// Each nginx CVE once, none of the kernel's, and the exploited list once a day.
	if asked["/cves/CVE-2026-1.json"] != 1 || asked["/cves/CVE-2026-2.json"] != 1 || asked["/cves/CVE-2026-7.json"] != 0 || asked["/kev"] != 1 {
		t.Errorf("asked %v", asked)
	}

	findings, err := feed.Exposure()
	if err != nil || len(findings) != 2 {
		t.Fatalf("findings %+v, %v", findings, err)
	}
	if nginx := findings[0]; nginx.Priority != "high" || strings.Join(nginx.Exploited, " ") != "CVE-2026-2" {
		t.Errorf("nginx = %+v", nginx)
	}
	if kernel := findings[1]; kernel.Priority != "" || kernel.Exploited != nil {
		t.Errorf("kernel = %+v", kernel)
	}

	feed.Now = func() time.Time { return now.Add(25 * time.Hour) }
	if err := feed.Enrich(context.Background()); err != nil || asked["/kev"] != 2 {
		t.Errorf("a day later: %v, asked %v", err, asked)
	}
}

// counting passes requests through and counts them by path.
type counting struct{ asked map[string]int }

func (c counting) RoundTrip(r *http.Request) (*http.Response, error) {
	c.asked[r.URL.Path]++

	return http.DefaultTransport.RoundTrip(r)
}

func TestUpgradeRefreshesListsThenUpgradesOnlyThePackages(t *testing.T) {
	fake := &systemtest.Fake{}
	if err := Upgrade(context.Background(), fake, []string{"nginx", "nginx-common"}); err != nil {
		t.Fatal(err)
	}

	got := fake.Commands()
	if len(got) != 2 || !strings.HasPrefix(got[0], "apt-get update") || !strings.HasPrefix(got[1], "apt-get install --only-upgrade --yes") || !strings.HasSuffix(got[1], "-- nginx nginx-common") {
		t.Errorf("ran %q", got)
	}
	if env := strings.Join(fake.Calls()[1].Env, " "); !strings.Contains(env, "DEBIAN_FRONTEND=noninteractive") {
		t.Errorf("env %s", env)
	}

	fake.Fail("apt-get", 100, "E: Could not get lock")
	if err := Upgrade(context.Background(), fake, []string{"nginx"}); err == nil || !strings.Contains(err.Error(), "Could not get lock") {
		t.Errorf("failure = %v", err)
	}
}

func write(t *testing.T, root, logical, content string) {
	t.Helper()

	file := filepath.Join(root, logical)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
