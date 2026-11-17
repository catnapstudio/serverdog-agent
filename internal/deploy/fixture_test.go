package deploy

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

var ctx = context.Background()

type fixture struct {
	t      *testing.T
	root   string
	remote string
	work   string
	store  *state.Store
	system *systemtest.Fake
	out    *bytes.Buffer
	runner *Runner
	clock  time.Time
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=ServerDog Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=ServerDog Test", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_CONFIG_GLOBAL=/dev/null")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}

	return strings.TrimSpace(string(output))
}

// newFixture makes a repository with one commit, a static site pointing at it, and a Runner that runs as the current user.
func newFixture(t *testing.T, change func(*site.Site)) *fixture {
	t.Helper()

	root := t.TempDir()
	f := &fixture{t: t, root: root, out: &bytes.Buffer{}, system: &systemtest.Fake{}, clock: time.Date(2026, 10, 16, 18, 0, 0, 0, time.UTC)}

	f.remote = filepath.Join(root, "remote.git")
	git(t, root, "init", "--quiet", "--bare", "--initial-branch=main", f.remote)
	f.work = filepath.Join(root, "work")
	git(t, root, "clone", "--quiet", f.remote, f.work)
	f.commit(map[string]string{"public/index.html": "v1", "storage/app/.gitkeep": ""}, "First")

	current, err := system.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}

	s := site.Site{
		ID:              "abcdefghijkl",
		Runtime:         site.Static,
		Domains:         []site.Domain{{Name: "example.com", Redirect: site.FromWWW, Primary: true}},
		RepositoryURL:   f.remote,
		Branch:          "main",
		WebDirectory:    "public",
		EnvironmentFile: ".env",
		SharedPaths:     []string{"storage"},
		DeployScript:    "$CREATE_RELEASE()\n\ncd $SERVERDOG_RELEASE_DIRECTORY\necho built\n\n$ACTIVATE_RELEASE()\n",
		ZeroDowntime:    true,
		User:            current.Name,
		Directory:       paths.SiteDirectory(current.Name, "example.com"),
	}.WithDefaults()
	if change != nil {
		change(&s)
	}

	f.store, err = state.Open(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })

	if _, err := f.store.PutSite(s, 0, f.clock); err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{"releases", "shared"} {
		if err := os.MkdirAll(filepath.Join(f.dir(), dir), 0o750); err != nil {
			t.Fatal(err)
		}
	}

	f.runner = &Runner{
		Store:      f.store,
		Paths:      paths.Paths{Root: root},
		Exec:       system.Exec{},
		System:     f.system,
		Applier:    apply.Applier{Runner: f.system, LockPath: filepath.Join(root, "apply.lock")},
		Out:        f.out,
		Now:        f.tick,
		LookupUser: func(string) (system.User, error) { return current, nil },
		BasePath:   os.Getenv("PATH"),
		Probe:      func(context.Context, string) error { return nil },
		ProbeEvery: 10 * time.Millisecond,
		ProbeFor:   time.Second,
		PortGuard:  func(context.Context) error { return nil },
		Listener:   fakeListener{},
	}

	return f
}

// fakeListener answers for every port with err, or says the instance owns it.
type fakeListener struct{ err error }

func (l fakeListener) OwnedBy(context.Context, int, string) error { return l.err }

func (f *fixture) tick() time.Time {
	f.clock = f.clock.Add(time.Second)
	return f.clock
}

func (f *fixture) dir() string {
	s, err := f.store.GetSite("abcdefghijkl")
	if err != nil {
		f.t.Fatal(err)
	}

	return paths.Paths{Root: f.root}.File(s.Directory)
}

// commit writes files in the working copy, commits and pushes them, and returns the new commit.
func (f *fixture) commit(files map[string]string, message string) string {
	f.t.Helper()

	for name, content := range files {
		path := filepath.Join(f.work, name)
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}

	git(f.t, f.work, "add", "-A")
	git(f.t, f.work, "commit", "--quiet", "-m", message)
	git(f.t, f.work, "push", "--quiet", "origin", "HEAD:main")

	return git(f.t, f.work, "rev-parse", "HEAD")
}

// updateSite changes the stored site.
func (f *fixture) updateSite(change func(*site.Site)) {
	f.t.Helper()

	if _, err := f.store.UpdateSite("abcdefghijkl", change, f.clock); err != nil {
		f.t.Fatal(err)
	}
}

// start records a new running deployment (finishing any earlier one) and returns its id.
func (f *fixture) start(kind, release string) string {
	f.t.Helper()

	if running, ok, _ := f.store.RunningDeployment("abcdefghijkl"); ok {
		f.store.UpdateDeployment(running.ID, func(d *state.Deployment) { d.State = state.Succeeded })
	}

	s, _ := f.store.GetSite("abcdefghijkl")
	d := state.Deployment{
		ID: ids.New(), SiteID: s.ID, Kind: kind, State: state.Running, Actor: "Test Mac",
		Branch: s.Branch, Release: release, Phases: PlannedPhases(s, kind), Marker: "m" + ids.New(), StartedAt: f.clock,
	}
	if err := f.store.CreateDeployment(d); err != nil {
		f.t.Fatal(err)
	}

	return d.ID
}

func (f *fixture) job(id string) *job {
	f.t.Helper()

	d, err := f.store.GetDeployment(id)
	if err != nil {
		f.t.Fatal(err)
	}

	j, err := f.runner.load(d)
	if err != nil {
		f.t.Fatal(err)
	}

	return j
}

func (f *fixture) read(path string) string {
	f.t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatal(err)
	}

	return string(data)
}
