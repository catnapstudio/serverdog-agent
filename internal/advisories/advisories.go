// Package advisories keeps Ubuntu's security notices for this server's release and finds the ones it is still exposed
// to: a fix that isn't installed, or a kernel fix installed but not running yet. The notices come from ubuntu.com, which
// learns only the release asked for, as apt's mirrors do; nothing about the server's packages leaves it.
package advisories

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	neturl "net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// DefaultURL is Ubuntu's notice list, CVEURL its page for one CVE, and ExploitedURL CISA's catalogue of
// vulnerabilities known to be exploited (KEV). The catalogue comes from CISA's own GitHub repository: cisa.gov answers
// 403 to datacenter addresses.
const (
	DefaultURL   = "https://ubuntu.com/security/notices.json"
	CVEURL       = "https://ubuntu.com/security/cves/"
	ExploitedURL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
)

const (
	document          = "security_notices"
	notifiedDocument  = "security_notices_notified"
	priorityDocument  = "security_cve_priorities"
	exploitedDocument = "security_exploited"
	// exploitedEvery is how often CISA's catalogue is downloaded again; CISA adds to it a few times a week.
	exploitedEvery = 24 * time.Hour
	// shortcut: at most this many CVE ratings are asked for each refresh, and none for the kernel, whose notices fix
	// thousands; the rest are asked on later refreshes, and kernel findings rely on the exploited list.
	priorityLimit = 100
	exploitedSize = 32 << 20
	// shortcut: a server whose kernel or packages are older than Window misses the notices before it, which is rare on
	// a server with automatic updates; keep more if a server is found further behind.
	Window = 90 * 24 * time.Hour
	// Ubuntu answers at most 20 a page; a few hundred notices cover Window.
	pageSize = 20
	maxPages = 40
	// StatusLimit bounds the read of dpkg's database, a few megabytes on a full server.
	StatusLimit  = 64 << 20
	responseSize = 8 << 20
	kernel       = "linux"
	// UpgradeLimit bounds an upgrade, waiting for apt's lock included.
	UpgradeLimit = 15 * time.Minute
)

type Source struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Notice is an Ubuntu Security Notice (USN) for this release, kept without its long description.
type Notice struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Published time.Time `json:"published"`
	CVEs      []string  `json:"cves"`
	// Sources are the source packages it fixes, at the first version with the fix.
	Sources []Source `json:"sources"`
}

// Feed fetches and keeps the notices.
type Feed struct {
	Store  *state.Store
	Paths  paths.Paths
	Client *http.Client
	// URL is the notice list; CVEURL and ExploitedURL default to Ubuntu's and CISA's.
	URL          string
	CVEURL       string
	ExploitedURL string
	Now          func() time.Time
}

// Notices returns the kept notices, newest first; none before the first Refresh.
func (f *Feed) Notices() ([]Notice, error) {
	encoded, _, err := f.Store.Document(document)
	if err != nil || encoded == nil {
		return nil, err
	}

	var notices []Notice

	return notices, json.Unmarshal(encoded, &notices)
}

// Refresh adds the notices published since the newest one kept, and forgets those older than Window. A server that
// isn't Ubuntu has none.
func (f *Feed) Refresh(ctx context.Context) error {
	release := Release(f.Paths)
	if release == "" {
		return nil
	}

	encoded, revision, err := f.Store.Document(document)
	if err != nil {
		return err
	}

	var kept []Notice
	if encoded != nil {
		if err := json.Unmarshal(encoded, &kept); err != nil {
			return err
		}
	}

	known := map[string]bool{}
	for _, notice := range kept {
		known[notice.ID] = true
	}
	cutoff := f.Now().Add(-Window)

	var added []Notice
	for page := range maxPages {
		notices, err := f.page(ctx, release, page*pageSize)
		if err != nil {
			return err
		}

		done := len(notices) < pageSize
		for _, notice := range notices {
			if known[notice.ID] || notice.Published.Before(cutoff) {
				done = true
				break
			}
			if len(notice.Sources) > 0 {
				added = append(added, notice)
			}
		}
		if done {
			break
		}
	}

	all := slices.DeleteFunc(append(added, kept...), func(n Notice) bool { return n.Published.Before(cutoff) })
	if encoded != nil && len(added) == 0 && len(all) == len(kept) {
		return nil
	}

	updated, err := json.Marshal(all)
	if err != nil {
		return err
	}

	_, err = f.Store.PutDocument(document, updated, revision)

	return err
}

type pageResponse struct {
	Notices []struct {
		ID        string                         `json:"id"`
		Title     string                         `json:"title"`
		Published string                         `json:"published"`
		CVEs      []string                       `json:"cves_ids"`
		Packages  map[string][]packageInResponse `json:"release_packages"`
	} `json:"notices"`
}

type packageInResponse struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	IsSource bool   `json:"is_source"`
}

func (f *Feed) page(ctx context.Context, release string, offset int) ([]Notice, error) {
	query := neturl.Values{"release": {release}, "order": {"newest"}, "limit": {strconv.Itoa(pageSize)}, "offset": {strconv.Itoa(offset)}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}

	response, err := f.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ubuntu.com answered %s", response.Status)
	}

	var decoded pageResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, responseSize)).Decode(&decoded); err != nil {
		return nil, err
	}

	var notices []Notice
	for _, entry := range decoded.Notices {
		// "2026-11-19T05:21:17.692963", in UTC.
		published, err := time.Parse("2006-01-02T15:04:05.999999", entry.Published)
		if err != nil {
			return nil, fmt.Errorf("notice %s: %w", entry.ID, err)
		}

		notice := Notice{ID: entry.ID, Title: entry.Title, Published: published, CVEs: entry.CVEs}
		for _, p := range entry.Packages[release] {
			if p.IsSource {
				notice.Sources = append(notice.Sources, Source{Name: p.Name, Version: p.Version})
			}
		}
		notices = append(notices, notice)
	}

	return notices, nil
}

// Release is the server's Ubuntu codename ("resolute"), or "" on another system.
func Release(p paths.Paths) string {
	content, err := os.ReadFile(p.File("/etc/os-release"))
	if err != nil {
		return ""
	}

	values := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		if key, value, found := strings.Cut(line, "="); found {
			values[key] = strings.Trim(value, `"'`)
		}
	}
	if values["ID"] != "ubuntu" {
		return ""
	}

	return values["VERSION_CODENAME"]
}

// Package is an installed binary package and the source package it was built from.
type Package struct {
	Name          string
	Version       string
	Source        string
	SourceVersion string
}

// Installed reads dpkg's database for the installed packages.
func Installed(p paths.Paths) ([]Package, error) {
	opened, err := os.Open(p.File("/var/lib/dpkg/status"))
	if err != nil {
		return nil, err
	}
	defer opened.Close()

	var installed []Package
	var current Package
	ok := false
	flush := func() {
		if ok && current.Name != "" && current.Version != "" {
			if current.Source == "" {
				current.Source = current.Name
			}
			if current.SourceVersion == "" {
				current.SourceVersion = current.Version
			}
			installed = append(installed, current)
		}
		current, ok = Package{}, false
	}

	scanner := bufio.NewScanner(io.LimitReader(opened, StatusLimit))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}

		key, value, found := strings.Cut(line, ": ")
		if !found {
			continue
		}
		switch key {
		case "Package":
			current.Name = value
		case "Version":
			current.Version = value
		case "Status":
			ok = value == "install ok installed"
		case "Source":
			// "openssl" or "openssl (3.5.5-1ubuntu3.7)" when the binary's version differs.
			name, version, _ := strings.Cut(value, " ")
			current.Source, current.SourceVersion = name, strings.Trim(version, "()")
		}
	}
	flush()

	return installed, scanner.Err()
}

// RunningKernel is the running kernel's release, as uname -r has it ("7.0.0-30-generic", "7.0.0-1017-aws").
func RunningKernel(p paths.Paths) string {
	content, _ := os.ReadFile(p.File("/proc/sys/kernel/osrelease"))

	return strings.TrimSpace(string(content))
}

// kernelPackages are the prefixes of the packages each kernel installs under its own name. Old kernels stay installed
// beside new ones, so these are compared through the running kernel, never on their own.
var kernelPackages = []string{"linux-image-", "linux-modules-", "linux-main-modules-", "linux-headers-", "linux-buildinfo-", "linux-tools-", "linux-cloud-tools-", "linux-objects-"}

// isKernelPackage is one of a kernel's own packages, named with its ABI ("linux-image-7.0.0-30-generic"), unlike the
// metapackages that follow the newest kernel ("linux-image-virtual").
func isKernelPackage(name string) bool {
	for _, prefix := range kernelPackages {
		if rest, ok := strings.CutPrefix(name, prefix); ok && rest != "" && rest[0] >= '0' && rest[0] <= '9' {
			return true
		}
	}

	return false
}

// kernelSource is the source package a kernel image was built from: Ubuntu signs it in a "-signed" twin.
func kernelSource(p Package) string {
	return strings.Replace(p.Source, "linux-signed", "linux", 1)
}

// Finding is a source package the server is exposed through.
type Finding struct {
	Source string
	// Notices are the ones not in effect, newest first.
	Notices []Notice
	// Packages are the installed binary packages to upgrade; none when the fix only waits for a restart.
	Packages []string
	// Restart is a kernel fix that is installed but runs only after the server restarts. A finding about the running
	// kernel has Source "linux", whichever kernel source it came from.
	Restart bool
	// Pro is a fix published only to Ubuntu Pro's ESM archive, which this server can't install without it.
	Pro bool
	// Priority is Ubuntu's highest rating among the CVEs ("negligible" to "critical"); "" before any is known.
	Priority string
	// Exploited are the CVEs CISA lists as exploited in the wild.
	Exploited []string
}

// CVEs returns every CVE the finding's notices fix, without repeats.
func (f Finding) CVEs() []string {
	var cves []string
	seen := map[string]bool{}
	for _, notice := range f.Notices {
		for _, cve := range notice.CVEs {
			if !seen[cve] {
				seen[cve] = true
				cves = append(cves, cve)
			}
		}
	}

	return cves
}

// Match finds what the server is exposed to: notices whose fixed version is newer than what is installed, and notices
// for the running kernel's source (linux, linux-aws, linux-hwe-…) newer than it. Findings are by source package, in
// the order of their newest notice. runningKernel is uname -r.
func Match(notices []Notice, installed []Package, runningKernel string) []Finding {
	bySource := map[string][]Package{}
	var running Package
	for _, p := range installed {
		if isKernelPackage(p.Name) {
			if runningKernel != "" && p.Name == "linux-image-"+runningKernel {
				running = p
			}
			continue
		}
		bySource[p.Source] = append(bySource[p.Source], p)
	}

	// The newest image of the running kernel's source is what a restart runs.
	source := kernelSource(running)
	newestKernel := running.SourceVersion
	for _, p := range installed {
		if running.Name != "" && strings.HasPrefix(p.Name, "linux-image-") && kernelSource(p) == source && Compare(p.SourceVersion, newestKernel) > 0 {
			newestKernel = p.SourceVersion
		}
	}

	var findings []Finding
	add := func(source string, notice Notice, packages []string, restart, pro bool) {
		index := slices.IndexFunc(findings, func(f Finding) bool { return f.Source == source })
		if index < 0 {
			findings = append(findings, Finding{Source: source})
			index = len(findings) - 1
		}

		finding := &findings[index]
		finding.Notices = append(finding.Notices, notice)
		for _, name := range packages {
			if !slices.Contains(finding.Packages, name) {
				finding.Packages = append(finding.Packages, name)
			}
		}
		finding.Restart = finding.Restart || restart
		finding.Pro = finding.Pro || pro
	}

	for _, notice := range notices {
		for _, source := range notice.Sources {
			pro := strings.Contains(source.Version, "esm")

			if running.Name != "" && source.Name == kernelSource(running) {
				if Compare(running.SourceVersion, source.Version) >= 0 {
					continue
				}
				if Compare(newestKernel, source.Version) >= 0 {
					add(kernel, notice, nil, true, false)
					continue
				}

				// The kernel's metapackages (linux-image-virtual, linux-aws) pull in the fixed kernel; their source
				// is the kernel's with "-meta" (linux-meta, linux-meta-aws).
				var metapackages []string
				for _, p := range bySource[strings.Replace(source.Name, "linux", "linux-meta", 1)] {
					if Compare(p.Version, source.Version) < 0 {
						metapackages = append(metapackages, p.Name)
					}
				}
				add(kernel, notice, metapackages, false, pro)
				continue
			}

			var outdated []string
			for _, p := range bySource[source.Name] {
				if Compare(p.SourceVersion, source.Version) < 0 {
					outdated = append(outdated, p.Name)
				}
			}
			if len(outdated) > 0 {
				add(source.Name, notice, outdated, false, pro)
			}
		}
	}

	for i := range findings {
		slices.Sort(findings[i].Packages)
		// A kernel fix that is installed waits only for the restart, whatever older notices say.
		if findings[i].Restart {
			findings[i].Packages, findings[i].Pro = nil, false
		}
	}

	return findings
}

// Exposure is Match on what this server has installed and runs, with the ratings and exploited CVEs known so far.
func (f *Feed) Exposure() ([]Finding, error) {
	findings, err := f.match()
	if err != nil || len(findings) == 0 {
		return nil, err
	}

	priorities, err := readDocument[map[string]string](f.Store, priorityDocument)
	if err != nil {
		return nil, err
	}
	known, err := readDocument[exploitedList](f.Store, exploitedDocument)
	if err != nil {
		return nil, err
	}
	exploited := map[string]bool{}
	for _, cve := range known.CVEs {
		exploited[cve] = true
	}

	for i := range findings {
		for _, cve := range findings[i].CVEs() {
			if exploited[cve] {
				findings[i].Exploited = append(findings[i].Exploited, cve)
			}
			if rank(priorities[cve]) > rank(findings[i].Priority) {
				findings[i].Priority = priorities[cve]
			}
		}
	}

	return findings, nil
}

func (f *Feed) match() ([]Finding, error) {
	notices, err := f.Notices()
	if err != nil || len(notices) == 0 {
		return nil, err
	}

	installed, err := Installed(f.Paths)
	if err != nil {
		return nil, err
	}

	return Match(notices, installed, RunningKernel(f.Paths)), nil
}

var priorities = []string{"negligible", "low", "medium", "high", "critical"}

// rank orders Ubuntu's ratings; an unknown one ranks below them all.
func rank(priority string) int {
	return slices.Index(priorities, priority) + 1
}

type exploitedList struct {
	Fetched time.Time `json:"fetched"`
	CVEs    []string  `json:"cves"`
}

// Enrich keeps CISA's exploited list at most a day old and asks Ubuntu for the rating of the CVEs the server is
// exposed to that it doesn't know yet. Ratings are kept: Ubuntu rarely changes one once a fix is out. Either failing
// leaves the other done.
func (f *Feed) Enrich(ctx context.Context) error {
	return errors.Join(f.refreshExploited(ctx), f.rate(ctx))
}

func (f *Feed) refreshExploited(ctx context.Context) error {
	known, revision, err := documentRevision[exploitedList](f.Store, exploitedDocument)
	if err != nil || f.Now().Sub(known.Fetched) < exploitedEvery {
		return err
	}

	cves, err := f.exploited(ctx)
	if err != nil {
		return fmt.Errorf("CISA's exploited list: %w", err)
	}

	return putDocument(f.Store, exploitedDocument, exploitedList{Fetched: f.Now(), CVEs: cves}, revision)
}

func (f *Feed) rate(ctx context.Context) error {
	findings, err := f.match()
	if err != nil {
		return err
	}

	rated, revision, err := documentRevision[map[string]string](f.Store, priorityDocument)
	if err != nil {
		return err
	}
	if rated == nil {
		rated = map[string]string{}
	}

	asked := 0
	for _, finding := range findings {
		if finding.Source == kernel {
			continue
		}
		for _, cve := range finding.CVEs() {
			if _, ok := rated[cve]; ok || asked == priorityLimit {
				continue
			}

			asked++
			priority, err := f.priority(ctx, cve)
			if err != nil {
				return fmt.Errorf("rating of %s: %w", cve, err)
			}
			rated[cve] = priority
		}
	}

	if asked == 0 {
		return nil
	}

	return putDocument(f.Store, priorityDocument, rated, revision)
}

func (f *Feed) exploited(ctx context.Context) ([]string, error) {
	var catalogue struct {
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := f.get(ctx, or(f.ExploitedURL, ExploitedURL), exploitedSize, &catalogue); err != nil {
		return nil, err
	}

	var cves []string
	for _, v := range catalogue.Vulnerabilities {
		cves = append(cves, v.CVE)
	}
	slices.Sort(cves)

	return cves, nil
}

func (f *Feed) priority(ctx context.Context, cve string) (string, error) {
	var page struct {
		Priority string `json:"priority"`
	}
	if err := f.get(ctx, or(f.CVEURL, CVEURL)+neturl.PathEscape(cve)+".json", responseSize, &page); err != nil {
		return "", err
	}

	return page.Priority, nil
}

func (f *Feed) get(ctx context.Context, url string, limit int64, into any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	response, err := f.Client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", request.URL.Host, response.Status)
	}

	return json.NewDecoder(io.LimitReader(response.Body, limit)).Decode(into)
}

func or(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}

func readDocument[T any](store *state.Store, name string) (T, error) {
	value, _, err := documentRevision[T](store, name)

	return value, err
}

func documentRevision[T any](store *state.Store, name string) (T, uint64, error) {
	var value T

	encoded, revision, err := store.Document(name)
	if err != nil || encoded == nil {
		return value, revision, err
	}

	return value, revision, json.Unmarshal(encoded, &value)
}

func putDocument(store *state.Store, name string, value any, revision uint64) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}

	_, err = store.PutDocument(name, encoded, revision)

	return err
}

// Error is an upgrade that failed; Detail is apt's output.
type Error struct {
	Summary string
	Detail  string
}

func (e *Error) Error() string { return e.Summary + "\n\n" + e.Detail }

// Upgrade refreshes apt's package lists, which may not know a fix published since apt's daily run, then upgrades
// packages that are already installed and nothing else. It waits for unattended-upgrades to finish rather than failing.
// A caller that stops waiting doesn't stop apt: dpkg cut off halfway leaves packages broken.
func Upgrade(ctx context.Context, runner system.Runner, packages []string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), UpgradeLimit)
	defer cancel()

	env := []string{"LANG=C", "DEBIAN_FRONTEND=noninteractive", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	lock := "DPkg::Lock::Timeout=300"

	for _, command := range []system.Command{
		{Name: "apt-get", Args: []string{"update", "--quiet", "-o", lock}, Env: env},
		{Name: "apt-get", Args: append([]string{"install", "--only-upgrade", "--yes", "--quiet", "-o", lock, "-o", "Dpkg::Options::=--force-confold", "--"}, packages...), Env: env},
	} {
		result, err := runner.Run(ctx, command)
		if err != nil {
			return &Error{Summary: "Couldn't install the security update.", Detail: strings.TrimSpace(fmt.Sprintf("%s\n%s", err, tail(result.Output)))}
		}
	}

	return nil
}

func tail(output []byte) []byte {
	if len(output) > 4<<10 {
		output = output[len(output)-4<<10:]
	}

	return bytes.TrimSpace(output)
}

// Watcher refreshes the notices and posts to the server's webhook when the server is newly exposed. What was posted is
// kept in the store, so an agent restart doesn't repeat it.
type Watcher struct {
	Feed   *Feed
	Post   func(ctx context.Context, text string) error
	Host   func() string
	Logger *slog.Logger
}

// Run checks every interval until ctx ends.
func (w *Watcher) Run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		w.Check(ctx)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Watcher) Check(ctx context.Context) {
	if err := w.Feed.Refresh(ctx); err != nil {
		w.Logger.Warn("could not fetch Ubuntu's security notices", "error", err)
	}
	if err := w.Feed.Enrich(ctx); err != nil {
		w.Logger.Warn("could not rate the security notices", "error", err)
	}

	findings, err := w.Feed.Exposure()
	if err != nil {
		w.Logger.Warn("could not match Ubuntu's security notices", "error", err)
		return
	}

	store := w.Feed.Store
	encoded, revision, err := store.Document(notifiedDocument)
	if err != nil {
		w.Logger.Warn("could not read the security alerts sent", "error", err)
		return
	}

	var notified []string
	if encoded != nil {
		_ = json.Unmarshal(encoded, &notified)
	}

	// A finding is new when its newest notice, or its move from "install" to "restart", wasn't posted.
	var keys []string
	var fresh []Finding
	for _, finding := range findings {
		// Turning up in CISA's exploited list later is news too.
		key := finding.Source + "/" + finding.Notices[0].ID + "/" + strconv.FormatBool(finding.Restart) + "/" + strconv.FormatBool(len(finding.Exploited) > 0)
		keys = append(keys, key)
		if !slices.Contains(notified, key) {
			fresh = append(fresh, finding)
		}
	}

	if len(fresh) > 0 {
		if err := w.Post(ctx, Text(w.Host(), fresh)); err != nil {
			w.Logger.Warn("could not post the security alert", "error", err)
			return
		}
	}

	if slices.Equal(keys, notified) {
		return
	}

	updated, err := json.Marshal(keys)
	if err == nil {
		_, err = store.PutDocument(notifiedDocument, updated, revision)
	}
	if err != nil {
		w.Logger.Warn("could not save the security alerts sent", "error", err)
	}
}

// Text is the webhook's message for findings: one line each.
func Text(host string, findings []Finding) string {
	lines := []string{"🛡️ " + host + " is missing security fixes from Ubuntu:"}
	for _, finding := range findings {
		lines = append(lines, "• "+Line(finding))
	}

	return strings.Join(lines, "\n")
}

// Line describes one finding: what, which notices and CVEs, and what to do.
func Line(f Finding) string {
	name := f.Source
	if name == kernel {
		name = "Linux kernel"
	}

	var ids []string
	for _, notice := range f.Notices[:min(len(f.Notices), 3)] {
		ids = append(ids, notice.ID)
	}
	if len(f.Notices) > 3 {
		ids = append(ids, fmt.Sprintf("%d more", len(f.Notices)-3))
	}

	cves := f.CVEs()
	shown := strings.Join(cves[:min(len(cves), 3)], ", ")
	if len(cves) > 3 {
		shown += fmt.Sprintf(" and %d more", len(cves)-3)
	}

	what := name
	if f.Priority != "" {
		what += " (" + f.Priority + ")"
	}
	what += ": " + strings.Join(ids, ", ")
	if shown != "" {
		what += " (" + shown + ")"
	}
	if len(f.Exploited) > 0 {
		what = "⚠️ " + what + ". Exploited in the wild: " + strings.Join(f.Exploited[:min(len(f.Exploited), 3)], ", ")
	}

	switch {
	case f.Restart:
		return what + ". The fix is installed but runs only after the server restarts."
	case f.Pro:
		return what + ". The fix is only in Ubuntu Pro's ESM archive."
	default:
		return what + ". Install the update in ServerDog's Security tab."
	}
}
