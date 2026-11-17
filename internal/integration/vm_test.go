//go:build vmtest

// Package integration drives the real agent as root on an Ubuntu VM. Run it with scripts/vm-test.sh.
package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const actor = "VM test"

var conn *grpc.ClientConn

func TestMain(m *testing.M) {
	var err error
	conn, err = grpc.NewClient("unix:///run/serverdog/agent.sock", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func sitesClient() agentv1.SiteServiceClient     { return agentv1.NewSiteServiceClient(conn) }
func deploysClient() agentv1.DeployServiceClient { return agentv1.NewDeployServiceClient(conn) }
func configClient() agentv1.ConfigServiceClient  { return agentv1.NewConfigServiceClient(conn) }

func timeout(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	return ctx
}

func sh(t *testing.T, dir, name string, args ...string) string {
	t.Helper()

	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=VM Test", "GIT_AUTHOR_EMAIL=vm@example.com",
		"GIT_COMMITTER_NAME=VM Test", "GIT_COMMITTER_EMAIL=vm@example.com")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, output)
	}

	return strings.TrimSpace(string(output))
}

type repo struct {
	t    *testing.T
	bare string
	work string
	URL  string
}

// newRepo makes a repository served over SSH by the git user, like a self-hosted Git server.
func newRepo(t *testing.T, files map[string]string) *repo {
	bare := "/srv/git/" + ids.New() + ".git"
	sh(t, "/", "git", "init", "--quiet", "--bare", "--initial-branch=main", bare)

	work := t.TempDir()
	sh(t, work, "git", "init", "--quiet", "--initial-branch=main")
	sh(t, work, "git", "remote", "add", "origin", bare)

	r := &repo{t: t, bare: bare, work: work, URL: "git@127.0.0.1:" + bare}
	r.push(files, "First")

	return r
}

func (r *repo) push(files map[string]string, message string) {
	r.t.Helper()

	for name, content := range files {
		path := filepath.Join(r.work, name)
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			r.t.Fatal(err)
		}
	}

	sh(r.t, r.work, "git", "add", "-A")
	sh(r.t, r.work, "git", "commit", "--quiet", "-m", message)
	sh(r.t, r.work, "git", "push", "--quiet", "origin", "HEAD:main")
	sh(r.t, "/", "chown", "-R", "git:git", r.bare)
}

func authorize(t *testing.T, publicKey string) {
	file, err := os.OpenFile("/home/git/.ssh/authorized_keys", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	// On a line of its own even when the file's last line is unfinished, as after a VM was stopped mid-write.
	fmt.Fprintf(file, "\n%s\n", publicKey)
}

func newSite(runtime agentv1.Runtime, preset, domain, url string) *agentv1.Site {
	return &agentv1.Site{
		Id:                   ids.New(),
		Preset:               preset,
		Runtime:              runtime,
		Domains:              []*agentv1.Domain{{Name: domain, Redirect: agentv1.Redirect_REDIRECT_FROM_WWW, Primary: true}},
		RepositoryUrl:        url,
		Branch:               "main",
		DeployScript:         "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\n",
		ZeroDowntime:         true,
		User:                 "serverdog",
		ReleasesToKeep:       5,
		DeployTimeoutMinutes: 10,
	}
}

// grantAccess does what the New Site sheet and Settings › Repository do before a repository is saved: show the deploy
// key (added to the Git server here), trust an unknown host, and test access.
func grantAccess(t *testing.T, s *agentv1.Site) {
	t.Helper()
	ctx := timeout(t)

	key, err := sitesClient().GetDeployKey(ctx, &agentv1.GetDeployKeyRequest{SiteId: s.Id})
	if err != nil {
		t.Fatal(err)
	}
	authorize(t, key.PublicKey)

	test := func() *agentv1.TestRepositoryResponse {
		result, err := sitesClient().TestRepository(ctx, &agentv1.TestRepositoryRequest{SiteId: s.Id, RepositoryUrl: s.RepositoryUrl, Branch: s.Branch})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}

	result := test()
	if result.Access == agentv1.RepositoryAccess_REPOSITORY_ACCESS_HOST_KEY_UNKNOWN {
		if _, err := sitesClient().TrustHostKey(ctx, &agentv1.TrustHostKeyRequest{SiteId: s.Id, RepositoryUrl: s.RepositoryUrl, Fingerprint: result.HostKeyFingerprint}); err != nil {
			t.Fatal(err)
		}
		result = test()
	}
	if result.Access != agentv1.RepositoryAccess_REPOSITORY_ACCESS_OK || result.Commit == "" {
		t.Fatalf("Test Access = %v", result)
	}
}

// createSite does what the New Site sheet does: show the key, trust the host, test access, create.
func createSite(t *testing.T, s *agentv1.Site) *agentv1.Site {
	t.Helper()

	grantAccess(t, s)

	put, err := sitesClient().PutSite(timeout(t), &agentv1.PutSiteRequest{Site: s, Actor: actor})
	if err != nil {
		t.Fatalf("PutSite: %v", err)
	}

	t.Cleanup(func() {
		sitesClient().DeleteSite(context.Background(), &agentv1.DeleteSiteRequest{Id: s.Id, RemoveFiles: true, Actor: actor})
	})

	return put.Site
}

func deploy(t *testing.T, siteID string) (*agentv1.Deployment, string) {
	t.Helper()

	started, err := deploysClient().Deploy(timeout(t), &agentv1.DeployRequest{SiteId: siteID, Actor: actor})
	if err != nil {
		t.Fatal(err)
	}

	return watch(t, started.Deployment.Id)
}

func watch(t *testing.T, id string) (*agentv1.Deployment, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	stream, err := deploysClient().WatchDeployment(ctx, &agentv1.WatchDeploymentRequest{Id: id})
	if err != nil {
		t.Fatal(err)
	}

	var log strings.Builder
	var last *agentv1.Deployment
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			return last, log.String()
		}
		if err != nil {
			t.Fatalf("watch: %v", err)
		}

		if d := response.GetDeployment(); d != nil {
			last = d
		}
		if chunk := response.GetLog(); chunk != nil {
			log.WriteString(chunk.Text)
		}
	}
}

func succeeded(t *testing.T, d *agentv1.Deployment, log string) {
	t.Helper()

	if d == nil || d.State != agentv1.DeploymentState_DEPLOYMENT_STATE_SUCCEEDED {
		t.Fatalf("deployment = %v\n%s", d, log)
	}
}

// mustDeploy deploys and fails the test, printing the log, unless the deploy succeeds.
func mustDeploy(t *testing.T, siteID string) *agentv1.Deployment {
	t.Helper()

	d, log := deploy(t, siteID)
	succeeded(t, d, log)

	return d
}

// mustWatch follows a deployment and fails the test unless it succeeds.
func mustWatch(t *testing.T, id string) *agentv1.Deployment {
	t.Helper()

	d, log := watch(t, id)
	succeeded(t, d, log)

	return d
}

var client = &http.Client{
	Timeout:       5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func get(host string) (int, string, http.Header, error) {
	request, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	request.Host = host

	response, err := client.Do(request)
	if err != nil {
		return 0, "", nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)

	return response.StatusCode, strings.TrimSpace(string(body)), response.Header, err
}

func expect(t *testing.T, host string, code int, body string) {
	t.Helper()

	gotCode, gotBody, _, err := get(host)
	if err != nil || gotCode != code || gotBody != body {
		t.Errorf("GET %s = %d %q (%v), want %d %q", host, gotCode, gotBody, err, code, body)
	}
}

// hammer requests host every 20 ms until stopped and returns every failure.
func hammer(host string) func() []string {
	var failures []string
	var mu sync.Mutex
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}

			code, body, _, err := get(host)
			if err != nil || code != http.StatusOK {
				mu.Lock()
				failures = append(failures, fmt.Sprintf("%d %q %v", code, body, err))
				mu.Unlock()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	return func() []string {
		close(stop)
		<-done
		return failures
	}
}

func phpVersion(t *testing.T) string {
	caps, err := agentv1.NewServerServiceClient(conn).GetCapabilities(timeout(t), &agentv1.GetCapabilitiesRequest{})
	if err != nil || len(caps.PhpVersions) == 0 {
		t.Fatalf("capabilities = %v %v", caps, err)
	}

	return caps.PhpVersions[0]
}

func waitForAgent(t *testing.T) {
	t.Helper()

	health := agentv1.NewAgentServiceClient(conn)
	for range 100 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := health.Health(ctx, &agentv1.HealthRequest{})
		cancel()
		if err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}

	t.Fatal("the agent didn't come back")
}

func TestStaticSite(t *testing.T) {
	r := newRepo(t, map[string]string{"index.html": "static v1\n"})
	s := createSite(t, newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "static.test", r.URL))

	mustDeploy(t, s.Id)
	expect(t, "static.test", 200, "static v1")

	code, _, header, err := get("www.static.test")
	if err != nil || code != 301 || header.Get("Location") != "http://static.test/" {
		t.Errorf("www = %d %v %v", code, header, err)
	}

	config := "/etc/nginx/sites-available/serverdog-" + s.Id + ".conf"
	before, _ := os.Stat(config)
	same, err := sitesClient().PutSite(timeout(t), &agentv1.PutSiteRequest{Site: s, ExpectedRevision: s.Revision, Actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	if same.Site.Revision != s.Revision || same.Created {
		t.Errorf("identical PutSite = revision %d (created %v), want revision %d", same.Site.Revision, same.Created, s.Revision)
	}
	after, _ := os.Stat(config)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("an identical PutSite rewrote the Nginx config")
	}
}

func TestPHPSite(t *testing.T) {
	version := phpVersion(t)
	r := newRepo(t, map[string]string{
		"VERSION":          "v1",
		"public/index.php": "<?php echo trim(file_get_contents(__DIR__ . '/../VERSION')), ' ', PHP_MAJOR_VERSION, '.', PHP_MINOR_VERSION;\n",
	})

	s := newSite(agentv1.Runtime_RUNTIME_PHP, "php", "php.test", r.URL)
	s.PhpVersion, s.WebDirectory, s.EnvironmentFile, s.SharedPaths = version, "public", ".env", []string{"storage"}
	s.DeployScript = "$CREATE_RELEASE()\n\ncd $SERVERDOG_RELEASE_DIRECTORY\n$SERVERDOG_PHP -l public/index.php\n\n$ACTIVATE_RELEASE()\n"
	s = createSite(t, s)

	first, log := deploy(t, s.Id)
	succeeded(t, first, log)
	expect(t, "php.test", 200, "v1 "+version)
	expectSocketOnlyForNginx(t, "/run/php/serverdog-"+s.Id+".sock")

	stop := hammer("php.test")
	r.push(map[string]string{"VERSION": "v2"}, "Second")
	mustDeploy(t, s.Id)
	if failures := stop(); len(failures) > 0 {
		t.Errorf("%d requests failed during the deploy, e.g. %s", len(failures), failures[0])
	}
	expect(t, "php.test", 200, "v2 "+version)

	r.push(map[string]string{"public/index.php": "<?php echo 'broken"}, "Broken")
	broken, log := deploy(t, s.Id)
	if broken.State != agentv1.DeploymentState_DEPLOYMENT_STATE_FAILED || broken.WentLive {
		t.Errorf("broken deploy = %v\n%s", broken, log)
	}
	expect(t, "php.test", 200, "v2 "+version)

	rollback, err := deploysClient().Rollback(timeout(t), &agentv1.RollbackRequest{SiteId: s.Id, Release: first.Release, Actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	mustWatch(t, rollback.Deployment.Id)
	expect(t, "php.test", 200, "v1 "+version)

	env, err := configClient().GetEnv(timeout(t), &agentv1.GetEnvRequest{SiteId: s.Id})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configClient().PutEnv(timeout(t), &agentv1.PutEnvRequest{SiteId: s.Id, Content: "APP_ENV=production\n", ExpectedSha256: env.Sha256, Actor: actor}); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat("/home/serverdog/php.test/shared/.env")
	if err != nil || info.Mode().Perm() != 0o600 || info.Sys().(*syscall.Stat_t).Uid == 0 {
		t.Errorf(".env = %v %v", info, err)
	}
}

// expectSocketOnlyForNginx checks only www-data can connect to an FPM socket: the shared serverdog user is in group
// www-data, so a group-writable socket would let it run code as any isolated site's user.
func expectSocketOnlyForNginx(t *testing.T, socket string) {
	t.Helper()

	nginx, err := user.Lookup("www-data")
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}

	owner := strconv.Itoa(int(info.Sys().(*syscall.Stat_t).Uid))
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || owner != nginx.Uid {
		t.Errorf("%s = %v owned by uid %s, want a socket with mode 0600 owned by www-data (%s)", socket, info.Mode(), owner, nginx.Uid)
	}
}

func TestNodeSite(t *testing.T) {
	r := newRepo(t, map[string]string{
		"VERSION": "v1",
		"server.js": `const fs = require('fs');
require('http').createServer((request, response) => {
  response.end(` + "`${fs.readFileSync('VERSION', 'utf8').trim()} ${process.env.GREETING} ${process.env.PORT}`" + `);
}).listen(Number(process.env.PORT), process.env.HOST);
`,
	})

	s := newSite(agentv1.Runtime_RUNTIME_NODE, "other", "node.test", r.URL)
	s.NodeStartCommand, s.EnvironmentFile = "node server.js", ".env"
	s = createSite(t, s)

	env, err := configClient().GetEnv(timeout(t), &agentv1.GetEnvRequest{SiteId: s.Id})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configClient().PutEnv(timeout(t), &agentv1.PutEnvRequest{SiteId: s.Id, Content: "GREETING=hello\nPORT=1\n", ExpectedSha256: env.Sha256, Actor: actor}); err != nil {
		t.Fatal(err)
	}

	mustDeploy(t, s.Id)
	expectNode(t, "v1")

	stop := hammer("node.test")
	r.push(map[string]string{"VERSION": "v2"}, "Second")
	mustDeploy(t, s.Id)
	if failures := stop(); len(failures) > 0 {
		t.Errorf("%d requests failed during the switch, e.g. %s", len(failures), failures[0])
	}
	expectNode(t, "v2")
}

// expectNode checks the Node site answers with its version, the greeting from .env, and the port ServerDog gave it rather than .env's PORT.
func expectNode(t *testing.T, version string) {
	t.Helper()

	code, body, _, err := get("node.test")
	fields := strings.Fields(body)
	if err != nil || code != 200 || len(fields) != 3 || fields[0] != version || fields[1] != "hello" {
		t.Errorf("GET node.test = %d %q (%v), want 200 %q", code, body, err, version+" hello <port>")
		return
	}

	port, err := strconv.Atoi(fields[2])
	if err != nil || port < 20000 || port > 29999 {
		t.Errorf("GET node.test port = %q, want the allocated port in 20000-29999, not .env's PORT", fields[2])
	}
}

func TestIsolatedSite(t *testing.T) {
	r := newRepo(t, map[string]string{"index.html": "isolated\n"})
	s := newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "iso.test", r.URL)
	s.Isolated, s.User = true, "iso"+ids.New()[:8]
	s = createSite(t, s)

	mustDeploy(t, s.Id)
	expect(t, "iso.test", 200, "isolated")

	info, err := os.Stat(s.Directory)
	if err != nil || info.Sys().(*syscall.Stat_t).Uid == 0 {
		t.Errorf("site directory = %v %v", info, err)
	}

	if _, err := sitesClient().DeleteSite(timeout(t), &agentv1.DeleteSiteRequest{Id: s.Id, RemoveFiles: true, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("id", s.User).Run(); err == nil {
		t.Error("the isolated user still exists")
	}
	if code, _, _, err := get("iso.test"); err == nil {
		t.Errorf("deleted site still answers %d", code)
	}
}

// www-data is in every site user's group, so Nginx could read another site's files through a symlink one site's
// repository contains. It must refuse links whose owner differs from their target's.
func TestASiteCannotServeAnotherSitesFilesThroughASymlink(t *testing.T) {
	victimRepo := newRepo(t, map[string]string{"index.html": "victim\n", "secret.html": "victim secret\n"})
	victim := newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "victim.test", victimRepo.URL)
	victim.Isolated, victim.User = true, "vic"+ids.New()[:8]
	victim = createSite(t, victim)
	mustDeploy(t, victim.Id)
	expect(t, "victim.test", 200, "victim")

	secret := filepath.Join(victim.Directory, "current", "secret.html")
	expectPath(t, "victim.test", "/secret.html", 200, "victim secret")

	r := newRepo(t, map[string]string{"index.html": "attacker\n"})
	if err := os.Symlink(secret, filepath.Join(r.work, "leak.html")); err != nil {
		t.Fatal(err)
	}
	r.push(nil, "Link to another site")

	attacker := createSite(t, newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "attacker.test", r.URL))
	mustDeploy(t, attacker.Id)
	expect(t, "attacker.test", 200, "attacker")

	code, body, err := getPath("attacker.test", "/leak.html")
	if err != nil || (code != 403 && code != 404) || strings.Contains(body, "secret") {
		t.Errorf("GET attacker.test/leak.html = %d %q (%v), want 403 or 404", code, body, err)
	}
}

// The web directory itself can be a link the repository commits; it must not lead into another site's files either.
func TestASiteCannotServeAnotherSitesFilesThroughItsWebDirectory(t *testing.T) {
	victimRepo := newRepo(t, map[string]string{"index.html": "victim\n", "secret.html": "victim secret\n"})
	victim := newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "webdir-victim.test", victimRepo.URL)
	victim.Isolated, victim.User = true, "vic"+ids.New()[:8]
	victim = createSite(t, victim)
	mustDeploy(t, victim.Id)
	expectPath(t, "webdir-victim.test", "/secret.html", 200, "victim secret")

	r := newRepo(t, map[string]string{"README.md": "attacker\n"})
	if err := os.Symlink(filepath.Join(victim.Directory, "current"), filepath.Join(r.work, "public")); err != nil {
		t.Fatal(err)
	}
	r.push(nil, "Serve another site's directory")

	s := newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "webdir-attacker.test", r.URL)
	s.WebDirectory = "public"
	attacker := createSite(t, s)
	mustDeploy(t, attacker.Id)

	code, body, err := getPath("webdir-attacker.test", "/secret.html")
	if err != nil || (code != 403 && code != 404) || strings.Contains(body, "secret") {
		t.Errorf("GET webdir-attacker.test/secret.html = %d %q (%v), want 403 or 404", code, body, err)
	}
}

func getPath(host, path string) (int, string, error) {
	request, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
	request.Host = host

	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)

	return response.StatusCode, strings.TrimSpace(string(body)), err
}

func expectPath(t *testing.T, host, path string, code int, body string) {
	t.Helper()

	gotCode, gotBody, err := getPath(host, path)
	if err != nil || gotCode != code || gotBody != body {
		t.Errorf("GET %s%s = %d %q (%v), want %d %q", host, path, gotCode, gotBody, err, code, body)
	}
}

func TestDeploySurvivesAnAgentRestartAndCanBeCancelled(t *testing.T) {
	r := newRepo(t, map[string]string{"index.html": "slow\n"})
	s := newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "slow.test", r.URL)
	s.DeployScript = "$CREATE_RELEASE()\nsleep 8\n$ACTIVATE_RELEASE()\n"
	s = createSite(t, s)

	started, err := deploysClient().Deploy(timeout(t), &agentv1.DeployRequest{SiteId: s.Id, Actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	sh(t, "/", "systemctl", "restart", "serverdog-agent")
	waitForAgent(t)

	mustWatch(t, started.Deployment.Id)
	expect(t, "slow.test", 200, "slow")

	second, err := deploysClient().Deploy(timeout(t), &agentv1.DeployRequest{SiteId: s.Id, Actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)

	cancelled, err := deploysClient().CancelDeployment(timeout(t), &agentv1.CancelDeploymentRequest{Id: second.Deployment.Id, Actor: actor})
	if err != nil || cancelled.Deployment.State != agentv1.DeploymentState_DEPLOYMENT_STATE_CANCELLED || cancelled.Deployment.WentLive {
		t.Fatalf("cancel = %v %v", cancelled, err)
	}

	releases, err := deploysClient().ListReleases(timeout(t), &agentv1.ListReleasesRequest{SiteId: s.Id})
	if err != nil || len(releases.Releases) != 1 || !releases.Releases[0].Live {
		t.Errorf("releases after cancel = %v %v", releases, err)
	}
	expect(t, "slow.test", 200, "slow")
}

func TestNginxCustomisation(t *testing.T) {
	r := newRepo(t, map[string]string{"index.html": "custom\n"})
	s := createSite(t, newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "custom.test", r.URL))
	mustDeploy(t, s.Id)

	config, err := configClient().GetNginxConfig(timeout(t), &agentv1.GetNginxConfigRequest{SiteId: s.Id})
	if err != nil {
		t.Fatal(err)
	}

	_, err = configClient().PutNginxConfig(timeout(t), &agentv1.PutNginxConfigRequest{SiteId: s.Id, Content: "bogus;\n", ExpectedSha256: config.Sha256, Actor: actor})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "nginx -t") {
		t.Errorf("invalid config err = %v", err)
	}
	expect(t, "custom.test", 200, "custom")

	edited := strings.Replace(config.Content, "    include /etc/nginx/serverdog/acme.conf;\n", "    include /etc/nginx/serverdog/acme.conf;\n    add_header X-ServerDog-Test yes;\n", 1)
	if _, err := configClient().PutNginxConfig(timeout(t), &agentv1.PutNginxConfigRequest{SiteId: s.Id, Content: edited, ExpectedSha256: config.Sha256, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	if _, _, header, _ := get("custom.test"); header.Get("X-ServerDog-Test") != "yes" {
		t.Error("customised config not served")
	}

	if _, err := configClient().ResetNginxConfig(timeout(t), &agentv1.ResetNginxConfigRequest{SiteId: s.Id, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	if _, _, header, _ := get("custom.test"); header.Get("X-ServerDog-Test") != "" {
		t.Error("reset kept the customisation")
	}
}
