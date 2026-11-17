package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

var f0 = time.Date(2026, 10, 16, 18, 0, 0, 0, time.UTC)

func TestFetchClonesThenFetchesAndRecordsTheCommit(t *testing.T) {
	f := newFixture(t, nil)
	first := git(t, f.work, "rev-parse", "HEAD")

	j := f.job(f.start(state.KindDeploy, ""))
	if err := j.fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if j.d.Commit != first || j.d.CommitMessage != "First" || j.d.CommitAuthor != "ServerDog Test" {
		t.Errorf("deployment = %+v", j.d)
	}
	if note := j.d.Phases[0].Note; note != "main at "+first[:7] {
		t.Errorf("fetch note = %q", note)
	}

	second := f.commit(map[string]string{"public/index.html": "v2"}, "Second")
	j = f.job(f.start(state.KindDeploy, ""))
	if err := j.fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if j.d.Commit != second {
		t.Errorf("commit = %s, want %s", j.d.Commit, second)
	}
}

func TestFetchReportsAMissingBranch(t *testing.T) {
	f := newFixture(t, func(s *site.Site) { s.Branch = "release" })

	err := f.job(f.start(state.KindDeploy, "")).fetch(ctx)
	if err == nil || !strings.Contains(err.Error(), "release") {
		t.Errorf("err = %v", err)
	}
}

func TestCheckOutCreatesAReleaseWithoutGit(t *testing.T) {
	f := newFixture(t, nil)
	j := f.job(f.start(state.KindDeploy, ""))

	if err := j.fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := j.checkOut(ctx); err != nil {
		t.Fatal(err)
	}

	if f.read(filepath.Join(j.release, "public/index.html")) != "v1" {
		t.Error("release content wrong")
	}
	if _, err := os.Stat(filepath.Join(j.release, ".git")); !os.IsNotExist(err) {
		t.Error("release has a .git directory")
	}
	if j.d.Release != filepath.Base(j.release) || !strings.HasPrefix(j.d.Release, "20261016-18000") {
		t.Errorf("release = %q", j.d.Release)
	}
}

func TestReleaseNamesNeverCollide(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "20261016-180000"), 0o755)
	os.Mkdir(filepath.Join(dir, "20261016-180000-2"), 0o755)

	if name := releaseName(f0, dir); name != "20261016-180000-3" {
		t.Errorf("name = %q", name)
	}
}

func TestLinkSharedSeedsNestedFileAndDirectory(t *testing.T) {
	f := newFixture(t, func(s *site.Site) {
		s.SharedPaths = []string{"storage", "var/log", "database/database.sqlite"}
	})
	f.commit(map[string]string{"database/database.sqlite": "seed", "var/log/.gitkeep": ""}, "Data")

	j := f.job(f.start(state.KindDeploy, ""))
	for _, step := range []func() error{func() error { return j.fetch(ctx) }, func() error { return j.checkOut(ctx) }, func() error { return j.linkShared(ctx) }} {
		if err := step(); err != nil {
			t.Fatalf("%v\n%s", err, f.out)
		}
	}

	shared := filepath.Join(f.dir(), "shared")
	if f.read(filepath.Join(shared, "database/database.sqlite")) != "seed" {
		t.Error("file not seeded into shared/")
	}

	links := map[string]string{
		"database/database.sqlite": "../../../shared/database/database.sqlite",
		"var/log":                  "../../../shared/var/log",
		"storage":                  "../../shared/storage",
		".env":                     "../../shared/.env",
	}
	for path, want := range links {
		if target, err := os.Readlink(filepath.Join(j.release, path)); err != nil || target != want {
			t.Errorf("%s -> %q (%v), want %q", path, target, err, want)
		}
	}
	if f.read(filepath.Join(j.release, "database/database.sqlite")) != "seed" {
		t.Error("link doesn't resolve")
	}

	if info, err := os.Stat(filepath.Join(shared, ".env")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("shared .env = %v %v", info, err)
	}

	// A later deploy keeps what's in shared/, even when the repository's copy changed.
	f.commit(map[string]string{"database/database.sqlite": "changed in git"}, "Change")
	j = f.job(f.start(state.KindDeploy, ""))
	j.fetch(ctx)
	j.checkOut(ctx)
	if err := j.linkShared(ctx); err != nil {
		t.Fatal(err)
	}
	if f.read(filepath.Join(j.release, "database/database.sqlite")) != "seed" {
		t.Error("shared file overwritten by the repository")
	}
}

func TestScriptGetsVariablesAndEmitsMarkers(t *testing.T) {
	f := newFixture(t, nil)
	j := f.job(f.start(state.KindDeploy, ""))
	j.fetch(ctx)

	if err := j.script(ctx, `echo "id=$SERVERDOG_SITE_ID commit=$SERVERDOG_DEPLOY_COMMIT"`+"\n", f.dir(), ""); err != nil {
		t.Fatal(err)
	}

	out := f.out.String()
	if !strings.Contains(out, "id=abcdefghijkl commit="+j.d.Commit) {
		t.Errorf("output = %q", out)
	}
	if !strings.Contains(out, "\x1eserverdog:"+j.d.Marker+`:echo "id=$SERVERDOG_SITE_ID commit=$SERVERDOG_DEPLOY_COMMIT"`) {
		t.Errorf("no marker for the command in %q", out)
	}
}

func TestScriptStopsAtTheFirstFailure(t *testing.T) {
	f := newFixture(t, nil)
	j := f.job(f.start(state.KindDeploy, ""))

	err := j.script(ctx, "echo one\nfalse | true\necho two\n", f.dir(), "")
	if err == nil || !strings.Contains(err.Error(), "exit code 1") {
		t.Fatalf("err = %v", err)
	}
	if out := f.out.String(); !strings.Contains(out, "one") || strings.Contains(out, "two") {
		t.Errorf("output = %q", out)
	}
}

func TestScriptSeesTheEnvironmentFileOnlyWhenAllowed(t *testing.T) {
	for allowed, want := range map[bool]string{true: "foo=bar id=abcdefghijkl", false: "foo= id=abcdefghijkl"} {
		f := newFixture(t, func(s *site.Site) { s.EnvironmentInScript = allowed })
		os.WriteFile(filepath.Join(f.dir(), "shared/.env"), []byte("FOO=bar\nSERVERDOG_SITE_ID=spoofed\n"), 0o600)

		j := f.job(f.start(state.KindDeploy, ""))
		if err := j.script(ctx, `echo "foo=$FOO id=$SERVERDOG_SITE_ID"`+"\n", f.dir(), ""); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(f.out.String(), want) {
			t.Errorf("allowed=%v: output = %q, want %q", allowed, f.out.String(), want)
		}
	}
}

func TestLinkSharedRefusesASymlinkedParent(t *testing.T) {
	victim := t.TempDir()
	os.MkdirAll(filepath.Join(victim, "log"), 0o755)
	os.WriteFile(filepath.Join(victim, "log", "keep"), []byte("precious"), 0o644)

	f := newFixture(t, func(s *site.Site) { s.SharedPaths = []string{"var/log"} })
	if err := os.Symlink(victim, filepath.Join(f.work, "var")); err != nil {
		t.Fatal(err)
	}
	git(t, f.work, "add", "-A")
	git(t, f.work, "commit", "--quiet", "-m", "Symlink")
	git(t, f.work, "push", "--quiet", "origin", "HEAD:main")

	j := f.job(f.start(state.KindDeploy, ""))
	if err := j.fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := j.checkOut(ctx); err != nil {
		t.Fatal(err)
	}

	err := j.linkShared(ctx)
	if err == nil {
		t.Fatal("linkShared followed a symlink out of the release")
	}
	if !strings.Contains(f.out.String(), "var/log goes through a symlink") {
		t.Errorf("output = %q", f.out.String())
	}

	entries, _ := os.ReadDir(victim)
	if len(entries) != 1 || f.read(filepath.Join(victim, "log", "keep")) != "precious" {
		t.Errorf("victim directory was changed: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(f.dir(), "shared", "var")); err == nil {
		if _, err := os.Stat(filepath.Join(f.dir(), "shared", "var", "log")); err == nil {
			t.Error("shared/var/log was created")
		}
	}
}

func TestScriptDropsServerDogAndBashEnvFromTheEnvironmentFile(t *testing.T) {
	f := newFixture(t, func(s *site.Site) { s.EnvironmentInScript = true })
	os.WriteFile(filepath.Join(f.dir(), "shared/.env"), []byte("SERVERDOG_RELEASE_DIRECTORY=/tmp/evil\nSERVERDOG_PHP=/tmp/evil\nBASH_ENV=/tmp/x\nKEPT=yes\n"), 0o600)

	j := f.job(f.start(state.KindDeploy, ""))
	if err := j.script(ctx, `echo "release=[$SERVERDOG_RELEASE_DIRECTORY] php=[$SERVERDOG_PHP] bash_env=[$BASH_ENV] kept=$KEPT"`+"\n", f.dir(), ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.out.String(), "release=[] php=[] bash_env=[] kept=yes") {
		t.Errorf("output = %q", f.out.String())
	}
}

func TestScriptExpandsReferencesInTheEnvironmentFileBeforeDroppingServerDogVariables(t *testing.T) {
	f := newFixture(t, func(s *site.Site) { s.EnvironmentInScript = true })
	env := "SERVERDOG_SECRET=hidden\nAPP=shop\nURL=\"https://${APP}.test/${SERVERDOG_SECRET}\"\nLITERAL='${APP}'\nLATER=\"${AFTER}\"\nAFTER=1\n"
	os.WriteFile(filepath.Join(f.dir(), "shared/.env"), []byte(env), 0o600)

	j := f.job(f.start(state.KindDeploy, ""))
	if err := j.script(ctx, `echo "url=[$URL] literal=[$LITERAL] later=[$LATER] secret=[$SERVERDOG_SECRET]"`+"\n", f.dir(), ""); err != nil {
		t.Fatal(err)
	}
	if want := "url=[https://shop.test/hidden] literal=[${APP}] later=[${AFTER}] secret=[]"; !strings.Contains(f.out.String(), want) {
		t.Errorf("output = %q, want it to contain %q", f.out.String(), want)
	}
}

func TestPlannedPhases(t *testing.T) {
	s := site.Site{ZeroDowntime: true, RepositoryURL: "git@github.com:a/b.git", DeployScript: "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\n"}
	if got := phaseNames(PlannedPhases(s, state.KindDeploy)); got != "fetch checkOut linkShared build activate cleanUp" {
		t.Errorf("minimal = %s", got)
	}

	s.DeployScript = "echo first\n$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\necho after\n"
	if got := phaseNames(PlannedPhases(s, state.KindDeploy)); got != "prepare fetch checkOut linkShared build activate afterActivation cleanUp" {
		t.Errorf("full = %s", got)
	}

	if got := phaseNames(PlannedPhases(s, state.KindRollback)); got != "activate" {
		t.Errorf("rollback = %s", got)
	}

	s.ZeroDowntime = false
	if got := phaseNames(PlannedPhases(s, state.KindDeploy)); got != "fetch build" {
		t.Errorf("in place = %s", got)
	}

	s.RepositoryURL = ""
	if got := phaseNames(PlannedPhases(s, state.KindDeploy)); got != "build" {
		t.Errorf("in place without a repository = %s", got)
	}
}

func phaseNames(phases []state.Phase) string {
	var names []string
	for _, phase := range phases {
		if phase.State != state.PhasePending {
			return "not pending: " + phase.Name
		}
		names = append(names, phase.Name)
	}

	return strings.Join(names, " ")
}

// /proc/<pid>/cmdline is world-readable, so the script (which may hold secrets) travels in the environment.
func TestScriptTextIsNotInTheCommandLine(t *testing.T) {
	f := newFixture(t, nil)
	recorder := &recordingRunner{}
	f.runner.Exec = recorder
	j := f.job(f.start(state.KindDeploy, ""))

	const text = "echo \"token=s3cret\"\necho \"script=[${SERVERDOG_SCRIPT-unset}]\"\n"
	if err := j.script(ctx, text, f.dir(), ""); err != nil {
		t.Fatalf("%v\n%s", err, f.out)
	}

	for _, command := range recorder.commands {
		for _, arg := range command {
			if strings.Contains(arg, "s3cret") {
				t.Errorf("argument %q holds the script", arg)
			}
		}
	}

	out := f.out.String()
	if !strings.Contains(out, "token=s3cret\n") || !strings.Contains(out, "script=[unset]\n") {
		t.Errorf("output = %q", out)
	}
	if strings.Contains(out, "__serverdog") || strings.Contains(out, ":eval ") {
		t.Errorf("the wrapper shows up as a command: %q", out)
	}
}
