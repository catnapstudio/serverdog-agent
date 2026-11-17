package sites

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/capabilities"
	"github.com/catnapstudio/serverdog-agent/internal/lock"
	"github.com/catnapstudio/serverdog-agent/internal/nginx"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

func noRepository() site.Site {
	s := laravel()
	s.RepositoryURL, s.Branch = "", ""

	return s
}

func (f *fixture) config() string {
	f.t.Helper()

	content, err := os.ReadFile(f.file(paths.NginxSiteAvailable("abcdefghijkl")))
	if err != nil {
		f.t.Fatal(err)
	}

	return string(content)
}

func TestANewSiteServesItsPlaceholderPage(t *testing.T) {
	f := newFixture(t)

	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}

	page, err := os.ReadFile(f.file("/home/serverdog/orchard.com/placeholder/index.html"))
	if err != nil || !strings.Contains(string(page), "This site is set up on ServerDog.") || !strings.Contains(string(page), "Nothing is deployed here yet.") {
		t.Fatalf("placeholder page = %q %v", page, err)
	}

	if config := f.config(); !strings.Contains(config, "root /home/serverdog/orchard.com/placeholder;") || strings.Contains(config, "fastcgi_pass") {
		t.Errorf("config doesn't serve the placeholder:\n%s", config)
	}
}

func TestASiteWithoutARepositoryGetsAKeyButNoKnownHosts(t *testing.T) {
	f := newFixture(t)

	saved, _, err := f.manager.Put(ctx, noRepository(), 0, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if !f.exists("/home/serverdog/.ssh/serverdog-abcdefghijkl") {
		t.Error("no deploy key")
	}
	if f.exists("/home/serverdog/.ssh/serverdog-abcdefghijkl.known_hosts") {
		t.Error("known_hosts written for a site without a repository")
	}

	saved.RepositoryURL, saved.Branch = "git@github.com:morgan/orchard.git", "main"
	if _, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil {
		t.Fatal(err)
	}
	if !f.exists("/home/serverdog/.ssh/serverdog-abcdefghijkl.known_hosts") {
		t.Error("adding a repository didn't write known_hosts")
	}
	if !f.exists("/home/serverdog/orchard.com/placeholder/index.html") {
		t.Error("adding a repository removed the placeholder before any deploy")
	}
}

func TestReleaseConfigServesTheReleases(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}

	files, err := f.manager.ReleaseConfig(ctx, "abcdefghijkl", f.manager.Capabilities(ctx))
	if err != nil || len(files) != 1 || files[0].Path != f.file(paths.NginxSiteAvailable("abcdefghijkl")) {
		t.Fatalf("ReleaseConfig = %+v %v", files, err)
	}

	for _, line := range []string{"root /home/serverdog/orchard.com/current/public;", "fastcgi_pass unix:/run/php/serverdog-abcdefghijkl.sock;"} {
		if !strings.Contains(string(files[0].Content), line) {
			t.Errorf("release config lacks %q:\n%s", line, files[0].Content)
		}
	}
}

func TestReleaseConfigLeavesACustomisedConfigAlone(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}
	_, sum, _, _ := f.manager.NginxConfig(ctx, "abcdefghijkl")
	if _, err := f.manager.PutNginxConfig(ctx, "abcdefghijkl", []byte("# mine\n"), sum, "Mac"); err != nil {
		t.Fatal(err)
	}

	if files, err := f.manager.ReleaseConfig(ctx, "abcdefghijkl", f.manager.Capabilities(ctx)); err != nil || len(files) != 0 {
		t.Errorf("ReleaseConfig = %+v %v, want nothing for a customised config", files, err)
	}
	if config := f.config(); config != "# mine\n" {
		t.Errorf("customised config changed:\n%s", config)
	}
}

// Sites made by agents before protocol 3 have no placeholder page, and the first live deploy removes it: either way,
// every config ServerDog writes from then on serves the releases.
func TestWithoutAPlaceholderPageConfigsServeReleases(t *testing.T) {
	f := newFixture(t)
	saved, _, err := f.manager.Put(ctx, laravel(), 0, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(f.file("/home/serverdog/orchard.com/placeholder")); err != nil {
		t.Fatal(err)
	}

	saved.Branch = "develop"
	if _, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil {
		t.Fatal(err)
	}
	if config := f.config(); !strings.Contains(config, "root /home/serverdog/orchard.com/current/public;") || strings.Contains(config, "placeholder") {
		t.Errorf("Put brought the placeholder back:\n%s", config)
	}

	if err := f.manager.ApplyCertificates(ctx, "abcdefghijkl", certificateFiles(f, "chain"), activeOrchard, nil); err != nil {
		t.Fatal(err)
	}
	if config := f.config(); strings.Contains(config, "placeholder") {
		t.Errorf("a certificate change brought the placeholder back:\n%s", config)
	}

	if reset, _, err := f.manager.ResetNginxConfig(ctx, "abcdefghijkl", "Mac"); err != nil || strings.Contains(string(reset), "placeholder") {
		t.Errorf("Reset = %v:\n%s", err, reset)
	}
}

func TestThePlaceholderGetsHTTPSToo(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}

	if err := f.manager.ApplyCertificates(ctx, "abcdefghijkl", certificateFiles(f, "chain"), activeOrchard, nil); err != nil {
		t.Fatal(err)
	}
	if config := f.config(); !strings.Contains(config, "ssl_certificate /etc/serverdog/certs/abcdefghijkl/orchard.com/active/fullchain.pem;") || !strings.Contains(config, "root /home/serverdog/orchard.com/placeholder;") {
		t.Errorf("HTTPS placeholder config:\n%s", config)
	}
}

// applyLockHeld reports whether the apply lock is taken, as the deploy that leaves the placeholder page would find it.
func (f *fixture) applyLockHeld() bool {
	done, cancel := context.WithCancel(ctx)
	cancel()

	release, err := lock.Acquire(done, f.manager.Applier.LockPath)
	if err != nil {
		return true
	}
	release()

	return false
}

// The deploy that leaves the placeholder page renders, applies and removes the page under the apply lock. Every
// config the agent generates must be rendered under it too, so it sees the page either still there with the deploy
// yet to switch, or gone.
func TestTheAgentRendersASitesConfigUnderTheApplyLock(t *testing.T) {
	f := newFixture(t)

	var held []bool
	f.manager.ActiveCertificates = func(string) (map[string]nginx.Certificate, error) {
		held = append(held, f.applyLockHeld())

		return nil, nil
	}

	saved, _, err := f.manager.Put(ctx, laravel(), 0, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	saved.Branch = "develop"
	if _, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.manager.ResetNginxConfig(ctx, "abcdefghijkl", "Mac"); err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(held, []bool{true, true, true}) {
		t.Errorf("create, change and reset rendered with the apply lock held: %v", held)
	}
}

// switchFromPlaceholder does to Nginx what the deploy that makes the first release live does, from its own process:
// under the apply lock, it renders the release config with a lock-free sites manager, calls during, applies the
// config and removes the placeholder page. It returns the config it applied.
func (f *fixture) switchFromPlaceholder(certificates func(string) (map[string]nginx.Certificate, error), during func()) string {
	f.t.Helper()

	deploy := &Manager{Store: f.store, Paths: f.manager.Paths, Capabilities: f.manager.Capabilities, ActiveCertificates: certificates}

	caps := deploy.Capabilities(ctx)

	var config string
	err := f.manager.Applier.Hold(ctx, func(applier apply.Applier) error {
		files, err := deploy.ReleaseConfig(ctx, "abcdefghijkl", caps)
		if err != nil {
			return err
		}
		if during != nil {
			during()
		}

		if _, err := applier.Apply(ctx, apply.Plan{Files: files, Checks: []system.Command{nginx.Check}, Reloads: []system.Command{nginx.Reload}}); err != nil {
			return err
		}
		config = string(files[0].Content)

		return os.RemoveAll(f.file("/home/serverdog/orchard.com/placeholder"))
	})
	if err != nil {
		f.t.Error(err)
	}

	return config
}

// A Put that starts while the deploy switches renders once the deploy let go of the apply lock, when the page is gone,
// so it serves the releases rather than the folder the deploy removed.
func TestAConfigTheAgentWritesDuringTheSwitchServesTheReleases(t *testing.T) {
	f := newFixture(t)
	saved, _, err := f.manager.Put(ctx, laravel(), 0, "Mac")
	if err != nil {
		t.Fatal(err)
	}

	rendered := make(chan struct{}, 1)
	f.manager.ActiveCertificates = func(string) (map[string]nginx.Certificate, error) {
		select {
		case rendered <- struct{}{}:
		default:
		}

		return nil, nil
	}

	put := make(chan error, 1)
	f.switchFromPlaceholder(nil, func() {
		saved.Branch = "develop"
		go func() {
			_, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac")
			put <- err
		}()

		// Long enough for the Put to render, if it could while the deploy holds the lock.
		select {
		case <-rendered:
		case <-time.After(time.Second):
		}
	})

	if err := <-put; err != nil {
		t.Fatal(err)
	}
	if config := f.config(); !strings.Contains(config, "root /home/serverdog/orchard.com/current/public;") || strings.Contains(config, "placeholder") {
		t.Errorf("the Put brought the placeholder back:\n%s", config)
	}
}

// The deploy waits for the apply lock while the agent activates the site's first certificate. The agent saves the
// certificate before it lets go of the lock, however long that takes, so the release config the deploy renders and
// applies last still serves HTTPS.
func TestTheSwitchRendersTheCertificateTheAgentSavedWhileItWaited(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var stored map[string]nginx.Certificate
	certificates := func(string) (map[string]nginx.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()

		return stored, nil
	}
	f.manager.ActiveCertificates = certificates

	// The deploy starts its switch while the agent's change is in Nginx's hands.
	switched := make(chan string, 1)
	var once sync.Once
	f.system.Handle(nginx.Reload.Name, func(system.Command) (system.Result, error) {
		once.Do(func() { go func() { switched <- f.switchFromPlaceholder(certificates, nil) }() })

		return system.Result{}, nil
	})

	err := f.manager.ApplyCertificates(ctx, "abcdefghijkl", certificateFiles(f, "chain"), activeOrchard, func() error {
		time.Sleep(100 * time.Millisecond)

		mu.Lock()
		defer mu.Unlock()
		stored = activeOrchard

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	config := <-switched
	for _, line := range []string{"ssl_certificate /etc/serverdog/certs/abcdefghijkl/orchard.com/active/fullchain.pem;", "root /home/serverdog/orchard.com/current/public;"} {
		if !strings.Contains(config, line) {
			t.Errorf("the deploy's config lacks %q:\n%s", line, config)
		}
	}
	if f.config() != config {
		t.Errorf("Nginx serves:\n%s", f.config())
	}
}

// The deploy detects what the server runs before it takes the apply lock: detecting waits on version commands, and every
// config change on the server waits for that lock.
func TestReleaseConfigRendersForTheCapabilitiesItIsGiven(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}
	f.manager.Capabilities = func(context.Context) capabilities.Capabilities {
		t.Error("ReleaseConfig detected the capabilities itself")

		return capabilities.Capabilities{}
	}

	files, err := f.manager.ReleaseConfig(ctx, "abcdefghijkl", capabilities.Capabilities{PHPVersions: []string{"8.4"}, NginxVersion: "1.28.0"})
	if err != nil || len(files) != 1 || !strings.Contains(string(files[0].Content), "root /home/serverdog/orchard.com/current/public;") {
		t.Fatalf("ReleaseConfig = %+v %v", files, err)
	}
}

// lockedClock is a Now that records, each time the agent reads it, whether the apply lock is held. The agent stamps a
// site's saved settings with the time it reads just before saving them.
func (f *fixture) lockedClock() *[]bool {
	var held []bool
	now := f.manager.Now
	f.manager.Now = func() time.Time {
		held = append(held, f.applyLockHeld())

		return now()
	}

	return &held
}

// The deploy that leaves the placeholder page reads the site from the store under the apply lock. What the agent
// rendered from must be saved before it lets go of that lock: the site's settings, and that its config is customised.
func TestTheAgentSavesWhatItRenderedFromUnderTheApplyLock(t *testing.T) {
	t.Run("put", func(t *testing.T) {
		f := newFixture(t)
		saved, _, err := f.manager.Put(ctx, laravel(), 0, "Mac")
		if err != nil {
			t.Fatal(err)
		}

		held := f.lockedClock()
		saved.Branch = "develop"
		if _, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(*held, []bool{true, false}) {
			t.Errorf("site saved, then activity added, with the apply lock held: %v", *held)
		}
	})

	t.Run("customised config", func(t *testing.T) {
		f := newFixture(t)
		if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
			t.Fatal(err)
		}
		_, sum, _, err := f.manager.NginxConfig(ctx, "abcdefghijkl")
		if err != nil {
			t.Fatal(err)
		}

		held := f.lockedClock()
		if _, err := f.manager.PutNginxConfig(ctx, "abcdefghijkl", []byte("# mine\n"), sum, "Mac"); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(*held, []bool{true, false}) {
			t.Errorf("customisation saved, then activity added, with the apply lock held: %v", *held)
		}
	})
}

// A certificate the agent activates while the deploy switches is rendered once the deploy let go of the apply lock,
// when the page is gone, so the HTTPS config serves the releases rather than the folder the deploy removed.
func TestACertificateActivatedDuringTheSwitchServesTheReleases(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}

	applied := make(chan error, 1)
	f.switchFromPlaceholder(nil, func() {
		go func() {
			applied <- f.manager.ApplyCertificates(ctx, "abcdefghijkl", certificateFiles(f, "chain"), activeOrchard, nil)
		}()

		// Long enough for the agent to render, if it could while the deploy holds the lock.
		time.Sleep(200 * time.Millisecond)
	})

	if err := <-applied; err != nil {
		t.Fatal(err)
	}
	config := f.config()
	if !strings.Contains(config, "ssl_certificate /etc/serverdog/certs/abcdefghijkl/orchard.com/active/fullchain.pem;") || !strings.Contains(config, "root /home/serverdog/orchard.com/current/public;") || strings.Contains(config, "placeholder") {
		t.Errorf("the certificate brought the placeholder back:\n%s", config)
	}
}

// An edit made to the placeholder config, saved while the deploy switches, is compared once the deploy let go of the
// apply lock. The config changed under it, so it is refused rather than replacing the release config and freezing it.
func TestAnEditOfThePlaceholderConfigSavedDuringTheSwitchIsStale(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}
	_, sum, _, err := f.manager.NginxConfig(ctx, "abcdefghijkl")
	if err != nil {
		t.Fatal(err)
	}

	saved := make(chan error, 1)
	release := f.switchFromPlaceholder(nil, func() {
		go func() {
			_, err := f.manager.PutNginxConfig(ctx, "abcdefghijkl", []byte("# mine, still serving the placeholder\n"), sum, "Mac")
			saved <- err
		}()

		// Long enough for the agent to compare the sum, if it could while the deploy holds the lock.
		time.Sleep(200 * time.Millisecond)
	})

	if err := <-saved; !errors.Is(err, ErrStaleContent) {
		t.Fatalf("PutNginxConfig = %v, want ErrStaleContent", err)
	}
	if f.config() != release {
		t.Errorf("Nginx serves:\n%s", f.config())
	}
	if s, err := f.store.GetSite("abcdefghijkl"); err != nil || s.NginxCustomised {
		t.Errorf("site = %+v %v, want a config ServerDog still generates", s, err)
	}
}
