package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/capabilities"
	"github.com/catnapstudio/serverdog-agent/internal/certificates"
	"github.com/catnapstudio/serverdog-agent/internal/databases"
	"github.com/catnapstudio/serverdog-agent/internal/deploy"
	"github.com/catnapstudio/serverdog-agent/internal/domains"
	"github.com/catnapstudio/serverdog-agent/internal/gitsource"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/listen"
	"github.com/catnapstudio/serverdog-agent/internal/lock"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/sites"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type fakeResolver map[string][]string

func (r fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	var addrs []net.IPAddr
	for _, address := range r[host] {
		addrs = append(addrs, net.IPAddr{IP: net.ParseIP(address)})
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	return addrs, nil
}

// offline fails every request, so the HTTP self-check never leaves the machine and CheckDns relies on the fake resolver.
type offline struct{}

func (offline) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("offline")
}

func startServices(t *testing.T) (*grpc.ClientConn, *Services) {
	t.Helper()

	root := t.TempDir()
	store, err := state.Open(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	current, _ := system.CurrentUser()
	fake := &systemtest.Fake{}
	p := paths.Paths{Root: root}
	applier := apply.Applier{Runner: fake, LockPath: filepath.Join(root, "apply.lock")}
	caps := func(context.Context) capabilities.Capabilities {
		return capabilities.Capabilities{PHPVersions: []string{"8.4"}, NginxVersion: "1.24.0"}
	}
	locks := &lock.Keyed{}

	siteManager := &sites.Manager{
		Store: store, Paths: p, System: fake, Exec: system.Exec{}, Applier: applier, Keys: gitsource.Keys{Paths: p}, Capabilities: caps,
		LookupUser: func(name string) (system.User, error) { u := current; u.Name = name; return u, nil },
		Now:        time.Now, Locks: locks,
	}
	checker := domains.Checker{
		Paths:     p,
		Resolver:  fakeResolver{"orchard.com": {"203.0.113.10"}, "www.orchard.com": {"198.51.100.7"}},
		HTTP:      &http.Client{Transport: offline{}},
		Addresses: func(context.Context) []string { return []string{"203.0.113.10"} },
	}
	certificateManager := &certificates.Manager{Store: store, Paths: p, Sites: siteManager, Applier: applier, Domains: checker, Now: time.Now, NewID: ids.New}
	siteManager.ActiveCertificates = certificateManager.Active
	siteManager.AfterPut = certificateManager.SyncSite

	services := &Services{
		Store: store,
		Paths: p,
		Sites: siteManager,
		Deploys: &deploy.Manager{
			Store: store, Paths: p, System: fake, Exec: system.Exec{}, Executable: "/usr/local/bin/serverdog-agent", StateDir: "/var/lib/serverdog",
			LookupUser: func(name string) (system.User, error) { u := current; u.Name = name; return u, nil },
			Now:        time.Now, NewID: ids.New, Locks: locks,
		},
		Watcher:      deploy.Watcher{Store: store, Paths: p, Poll: 10 * time.Millisecond},
		Tester:       gitsource.Tester{Runner: fake},
		Capabilities: caps,
		Domains:      checker,
		Certificates: certificateManager,
		Databases:    databases.Creator{Runner: fake, Engine: func(context.Context) string { return "" }},
	}

	dir, _ := os.MkdirTemp("/tmp", "cs")
	t.Cleanup(func() { os.RemoveAll(dir) })
	listener, err := listen.Unix(filepath.Join(dir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}

	g := grpc.NewServer()
	services.Register(g)
	go g.Serve(listener)
	t.Cleanup(g.Stop)

	conn, err := grpc.NewClient("unix://"+filepath.Join(dir, "agent.sock"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	return conn, services
}

func TestSiteAndDeployServicesEndToEnd(t *testing.T) {
	conn, _ := startServices(t)
	sitesClient := agentv1.NewSiteServiceClient(conn)
	deploys := agentv1.NewDeployServiceClient(conn)
	ctx := context.Background()

	key, err := sitesClient.GetDeployKey(ctx, &agentv1.GetDeployKeyRequest{SiteId: "abcdefghijkl"})
	if err != nil || key.Fingerprint == "" {
		t.Fatalf("GetDeployKey = %v %v", key, err)
	}

	put, err := sitesClient.PutSite(ctx, &agentv1.PutSiteRequest{Actor: "Mac", Site: &agentv1.Site{
		Id: "abcdefghijkl", Preset: "laravel", Runtime: agentv1.Runtime_RUNTIME_PHP,
		Domains:       []*agentv1.Domain{{Name: "orchard.com", Redirect: agentv1.Redirect_REDIRECT_FROM_WWW, Primary: true}},
		RepositoryUrl: "git@github.com:morgan/orchard.git", Branch: "main", PhpVersion: "8.4", WebDirectory: "public",
		EnvironmentFile: ".env", DeployScript: "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\n", ZeroDowntime: true, User: "serverdog",
	}})
	if err != nil || !put.Created || put.Site.Revision != 1 {
		t.Fatalf("PutSite = %v %v", put, err)
	}

	if _, err := sitesClient.PutSite(ctx, &agentv1.PutSiteRequest{Site: put.Site, ExpectedRevision: 0}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("stale PutSite code = %s", status.Code(err))
	}

	listed, err := sitesClient.ListSites(ctx, &agentv1.ListSitesRequest{})
	if err != nil || len(listed.Sites) != 1 {
		t.Fatalf("ListSites = %v %v", listed, err)
	}

	started, err := deploys.Deploy(ctx, &agentv1.DeployRequest{SiteId: "abcdefghijkl", Actor: "Mac"})
	if err != nil || started.Deployment.State != agentv1.DeploymentState_DEPLOYMENT_STATE_RUNNING || len(started.Deployment.Phases) == 0 {
		t.Fatalf("Deploy = %v %v", started, err)
	}

	cancelled, err := deploys.CancelDeployment(ctx, &agentv1.CancelDeploymentRequest{Id: started.Deployment.Id, Actor: "Mac"})
	if err != nil || cancelled.Deployment.State != agentv1.DeploymentState_DEPLOYMENT_STATE_CANCELLED {
		t.Fatalf("Cancel = %v %v", cancelled, err)
	}

	stream, err := deploys.WatchDeployment(ctx, &agentv1.WatchDeploymentRequest{Id: started.Deployment.Id})
	if err != nil {
		t.Fatal(err)
	}
	var last *agentv1.Deployment
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if d := response.GetDeployment(); d != nil {
			last = d
		}
	}
	if last == nil || last.State != agentv1.DeploymentState_DEPLOYMENT_STATE_CANCELLED {
		t.Errorf("watch ended with %v", last)
	}

	env, err := agentv1.NewConfigServiceClient(conn).GetEnv(ctx, &agentv1.GetEnvRequest{SiteId: "abcdefghijkl"})
	if err != nil || env.Content != "" {
		t.Errorf("GetEnv = %v %v", env, err)
	}

	if _, err := sitesClient.GetSite(ctx, &agentv1.GetSiteRequest{Id: "zzzzzzzzzzzz"}); status.Code(err) != codes.NotFound {
		t.Errorf("missing site code = %s", status.Code(err))
	}
}

func TestTextThatIsNotUTF8StillReachesTheApp(t *testing.T) {
	conn, services := startServices(t)
	ctx := context.Background()

	d := state.Deployment{
		ID: "dddddddddddd", SiteID: "abcdefghijkl", Kind: state.KindDeploy, State: state.Failed, Actor: "Mac",
		CommitAuthor: "J\xe9r\xf4me", CommitMessage: "Caf\xe9", Error: "bad \xff byte", Marker: "mmmmmmmmmmmm",
		Release: "20261016-180000", StartedAt: time.Now(), FinishedAt: time.Now(),
	}
	if err := services.Store.CreateDeployment(d); err != nil {
		t.Fatal(err)
	}

	log := services.Paths.File(paths.DeployLog(d.SiteID, d.ID))
	os.MkdirAll(filepath.Dir(log), 0o700)
	content := "before\n\x1eserverdog:mmmmmmmmmmmm:echo \xff\nLatin-1: caf\xe9\nafter\n"
	if err := os.WriteFile(log, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	stream, err := agentv1.NewDeployServiceClient(conn).WatchDeployment(ctx, &agentv1.WatchDeploymentRequest{Id: d.ID})
	if err != nil {
		t.Fatal(err)
	}

	var text string
	var command string
	var last *agentv1.Deployment
	var offset uint64
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("watch stopped at offset %d: %v", offset, err)
		}
		if chunk := response.GetLog(); chunk != nil {
			text += chunk.Text
			offset = chunk.NextOffset
		}
		if c := response.GetCommand(); c != nil {
			command = c.Text
			offset = c.NextOffset
		}
		if got := response.GetDeployment(); got != nil {
			last = got
		}
	}

	if text != "before\nLatin-1: caf\uFFFD\nafter\n" || command != "echo \uFFFD" || offset != uint64(len(content)) {
		t.Errorf("log = %q, command = %q, offset = %d of %d", text, command, offset, len(content))
	}
	if last == nil || last.CommitMessage != "Caf\uFFFD" || last.CommitAuthor != "J\uFFFDr\uFFFDme" || last.Error != "bad \uFFFD byte" {
		t.Errorf("deployment = %v", last)
	}

	services.Store.AddActivity("abcdefghijkl", state.Activity{At: time.Now(), Kind: "deploy.failed", Actor: "Mac", Summary: "Deploy failed: caf\xe9"})
	activity, err := agentv1.NewSiteServiceClient(conn).ListActivity(ctx, &agentv1.ListActivityRequest{SiteId: "abcdefghijkl"})
	if err != nil || len(activity.Entries) != 1 || activity.Entries[0].Summary != "Deploy failed: caf\uFFFD" {
		t.Errorf("ListActivity = %v %v", activity, err)
	}

	listed, err := agentv1.NewDeployServiceClient(conn).ListDeployments(ctx, &agentv1.ListDeploymentsRequest{SiteId: "abcdefghijkl"})
	if err != nil || len(listed.Deployments) != 1 {
		t.Errorf("ListDeployments = %v %v", listed, err)
	}
}

func TestGetEnvRefusesAFileThatIsNotUTF8(t *testing.T) {
	conn, services := startServices(t)
	ctx := context.Background()

	_, err := agentv1.NewSiteServiceClient(conn).PutSite(ctx, &agentv1.PutSiteRequest{Actor: "Mac", Site: &agentv1.Site{
		Id: "abcdefghijkl", Runtime: agentv1.Runtime_RUNTIME_STATIC,
		Domains:       []*agentv1.Domain{{Name: "example.com", Redirect: agentv1.Redirect_REDIRECT_NONE, Primary: true}},
		RepositoryUrl: "git@github.com:morgan/example.git", Branch: "main", WebDirectory: "public",
		EnvironmentFile: ".env", DeployScript: "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\n", ZeroDowntime: true, User: "serverdog",
	}})
	if err != nil {
		t.Fatal(err)
	}

	env := services.Paths.File("/home/serverdog/example.com/shared/.env")
	if err := os.WriteFile(env, []byte("NAME=caf\xe9\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = agentv1.NewConfigServiceClient(conn).GetEnv(ctx, &agentv1.GetEnvRequest{SiteId: "abcdefghijkl"})
	if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "The environment file isn't valid UTF-8, so ServerDog can't edit it safely." {
		t.Errorf("GetEnv err = %v", err)
	}
}

func TestGetNginxConfigRefusesAFileThatIsNotUTF8(t *testing.T) {
	conn, services := startServices(t)
	ctx := context.Background()

	_, err := agentv1.NewSiteServiceClient(conn).PutSite(ctx, &agentv1.PutSiteRequest{Actor: "Mac", Site: &agentv1.Site{
		Id: "abcdefghijkl", Runtime: agentv1.Runtime_RUNTIME_STATIC,
		Domains:       []*agentv1.Domain{{Name: "example.com", Redirect: agentv1.Redirect_REDIRECT_NONE, Primary: true}},
		RepositoryUrl: "git@github.com:morgan/example.git", Branch: "main", WebDirectory: "public",
		DeployScript: "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\n", ZeroDowntime: true, User: "serverdog",
	}})
	if err != nil {
		t.Fatal(err)
	}

	config := services.Paths.File(paths.NginxSiteAvailable("abcdefghijkl"))
	if err := os.WriteFile(config, []byte("# caf\xe9\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = agentv1.NewConfigServiceClient(conn).GetNginxConfig(ctx, &agentv1.GetNginxConfigRequest{SiteId: "abcdefghijkl"})
	if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "The Nginx configuration isn't valid UTF-8, so ServerDog can't edit it safely." {
		t.Errorf("GetNginxConfig err = %v", err)
	}
}

func TestTestRepositoryReportsDetailThatIsNotUTF8(t *testing.T) {
	conn, services := startServices(t)
	services.Tester.Runner.(*systemtest.Fake).Fail("ssh-keyscan", 1, "caf\xe9: connection refused")

	response, err := agentv1.NewSiteServiceClient(conn).TestRepository(context.Background(), &agentv1.TestRepositoryRequest{
		SiteId: "abcdefghijkl", RepositoryUrl: "git@git.example.com:morgan/example.git", Branch: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Access != agentv1.RepositoryAccess_REPOSITORY_ACCESS_HOST_UNREACHABLE || !strings.Contains(response.Detail, "caf\uFFFD: connection refused") {
		t.Errorf("response = %v", response)
	}
}

func TestTrustHostKeyIsOnlyForUnknownHosts(t *testing.T) {
	conn, services := startServices(t)
	ctx := context.Background()
	fake := services.Tester.Runner.(*systemtest.Fake)
	client := agentv1.NewSiteServiceClient(conn)

	github := gitsource.ParseKnownHosts(gitsource.ProviderKnownHosts)[0]
	trusted := strings.Replace(github.Line, "github.com", "[git.example.com]:2222", 1)
	if err := services.Store.AddHostKey("abcdefghijkl", trusted); err != nil {
		t.Fatal(err)
	}

	const refused = "This host already has a different trusted key.\n\nIf the host changed its key on purpose, remove the old key first, then trust the new one."
	for _, url := range []string{"ssh://git@git.example.com:2222/morgan/orchard.git", "git@github.com:morgan/orchard.git"} {
		_, err := client.TrustHostKey(ctx, &agentv1.TrustHostKeyRequest{SiteId: "abcdefghijkl", RepositoryUrl: url, Fingerprint: "SHA256:somethingelse"})
		if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != refused {
			t.Errorf("%s: err = %v", url, err)
		}
	}

	// Trusting a key that is trusted already changes nothing and succeeds.
	if _, err := client.TrustHostKey(ctx, &agentv1.TrustHostKeyRequest{SiteId: "abcdefghijkl", RepositoryUrl: "ssh://git@git.example.com:2222/morgan/orchard.git", Fingerprint: github.Fingerprint}); err != nil {
		t.Errorf("trusting the trusted key again: %v", err)
	}

	if commands := fake.Commands(); len(commands) != 0 {
		t.Errorf("contacted the host: %v", commands)
	}
	if lines, _ := services.Store.HostKeys("abcdefghijkl"); len(lines) != 1 {
		t.Errorf("host keys = %v", lines)
	}
}

func TestListReleasesOffersOnlyReleasesThatWentLive(t *testing.T) {
	conn, services := startServices(t)
	ctx := context.Background()

	_, err := agentv1.NewSiteServiceClient(conn).PutSite(ctx, &agentv1.PutSiteRequest{Actor: "Mac", Site: &agentv1.Site{
		Id: "abcdefghijkl", Runtime: agentv1.Runtime_RUNTIME_STATIC,
		Domains:       []*agentv1.Domain{{Name: "example.com", Redirect: agentv1.Redirect_REDIRECT_NONE, Primary: true}},
		RepositoryUrl: "git@github.com:morgan/example.git", Branch: "main", WebDirectory: "public",
		DeployScript: "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\n", ZeroDowntime: true, User: "serverdog",
	}})
	if err != nil {
		t.Fatal(err)
	}

	releases := services.Paths.File("/home/serverdog/example.com/releases")
	for i, release := range []struct {
		name string
		live bool
	}{{"20261016-170000", true}, {"20261016-170001", false}, {"20261016-170002", true}} {
		os.MkdirAll(filepath.Join(releases, release.name), 0o750)
		d := state.Deployment{
			ID: ids.New(), SiteID: "abcdefghijkl", Kind: state.KindDeploy, State: state.Failed, WentLive: release.live, Actor: "Mac",
			Release: release.name, StartedAt: time.Now().Add(time.Duration(i) * time.Second),
		}
		if err := services.Store.CreateDeployment(d); err != nil {
			t.Fatal(err)
		}
	}
	// current points at a release whose deploy crashed before recording that it went live: still listed, as live.
	os.MkdirAll(filepath.Join(releases, "20261016-170003"), 0o750)
	os.Symlink("releases/20261016-170003", services.Paths.File("/home/serverdog/example.com/current"))

	listed, err := agentv1.NewDeployServiceClient(conn).ListReleases(ctx, &agentv1.ListReleasesRequest{SiteId: "abcdefghijkl"})
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, release := range listed.Releases {
		names = append(names, fmt.Sprintf("%s live=%v", release.Name, release.Live))
	}
	if want := "20261016-170003 live=true, 20261016-170002 live=false, 20261016-170000 live=false"; strings.Join(names, ", ") != want {
		t.Errorf("releases = %s, want %s", strings.Join(names, ", "), want)
	}
}

func TestASiteWithoutARepositoryIsCreatedButNotDeployed(t *testing.T) {
	conn, _ := startServices(t)
	ctx := context.Background()

	put, err := agentv1.NewSiteServiceClient(conn).PutSite(ctx, &agentv1.PutSiteRequest{Actor: "Mac", Site: &agentv1.Site{
		Id: "abcdefghijkl", Preset: "html", Runtime: agentv1.Runtime_RUNTIME_STATIC,
		Domains:      []*agentv1.Domain{{Name: "orchard.com", Redirect: agentv1.Redirect_REDIRECT_FROM_WWW, Primary: true}},
		DeployScript: "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\n", ZeroDowntime: true, User: "serverdog",
	}})
	if err != nil || put.Site.RepositoryUrl != "" || put.Site.Branch != "" {
		t.Fatalf("PutSite = %v %v", put, err)
	}

	deploys := agentv1.NewDeployServiceClient(conn)
	_, err = deploys.Deploy(ctx, &agentv1.DeployRequest{SiteId: "abcdefghijkl", Actor: "Mac"})
	if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "This site has no repository yet. Add one in its settings, then deploy." {
		t.Errorf("Deploy err = %v", err)
	}

	listed, err := deploys.ListDeployments(ctx, &agentv1.ListDeploymentsRequest{SiteId: "abcdefghijkl"})
	if err != nil || len(listed.Deployments) != 0 {
		t.Errorf("ListDeployments = %v %v", listed, err)
	}
}

// providerKey returns one of the providers' published keys, as a stand-in for any host's key.
func providerKey(t *testing.T, name, keyType string) gitsource.HostKey {
	t.Helper()

	for _, key := range gitsource.ParseKnownHosts(gitsource.ProviderKnownHosts) {
		if key.Names(name) && key.Type == keyType {
			return key
		}
	}
	t.Fatalf("no %s key for %s", keyType, name)

	return gitsource.HostKey{}
}

// lineFor rewrites a provider's key line so it names host instead.
func lineFor(key gitsource.HostKey, host string) string {
	return host + " " + strings.SplitN(key.Line, " ", 2)[1]
}

func TestRemoveHostKeysThenTrustTheNewKey(t *testing.T) {
	conn, services := startServices(t)
	ctx := context.Background()
	fake := services.Tester.Runner.(*systemtest.Fake)
	client := agentv1.NewSiteServiceClient(conn)
	const url = "ssh://git@git.example.com:2222/morgan/orchard.git"

	old := providerKey(t, "github.com", "ssh-ed25519")
	rotated := providerKey(t, "gitlab.com", "ssh-ed25519")
	if err := services.Store.AddHostKey("abcdefghijkl", lineFor(old, "[git.example.com]:2222")); err != nil {
		t.Fatal(err)
	}

	refusals := map[string]struct {
		url, fingerprint, message string
	}{
		"wrong fingerprint": {url, "SHA256:somethingelse", "The trusted key changed since you looked. Test access again."},
		"a provider's key":  {"git@github.com:morgan/orchard.git", old.Fingerprint, "The site has no trusted key for this host.\n\nA key from the built-in list of GitHub, GitLab and Bitbucket keys can't be removed."},
	}
	for name, r := range refusals {
		_, err := client.RemoveHostKeys(ctx, &agentv1.RemoveHostKeysRequest{SiteId: "abcdefghijkl", RepositoryUrl: r.url, Fingerprint: r.fingerprint, Actor: "Mac"})
		if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != r.message {
			t.Errorf("%s: err = %v", name, err)
		}
	}

	response, err := client.RemoveHostKeys(ctx, &agentv1.RemoveHostKeysRequest{SiteId: "abcdefghijkl", RepositoryUrl: url, Fingerprint: old.Fingerprint, Actor: "Mac"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Host != "[git.example.com]:2222" || len(response.Fingerprints) != 1 || response.Fingerprints[0] != old.Fingerprint {
		t.Errorf("response = %v", response)
	}
	if commands := fake.Commands(); len(commands) != 0 {
		t.Errorf("contacted the host while removing: %v", commands)
	}

	// The host now offers its new key, and trusting it works like the first time.
	fake.Handle("ssh-keyscan", func(system.Command) (system.Result, error) {
		return system.Result{Output: []byte(lineFor(rotated, "[git.example.com]:2222") + "\n")}, nil
	})
	if _, err := client.TrustHostKey(ctx, &agentv1.TrustHostKeyRequest{SiteId: "abcdefghijkl", RepositoryUrl: url, Fingerprint: rotated.Fingerprint}); err != nil {
		t.Fatal(err)
	}
	if lines, _ := services.Store.HostKeys("abcdefghijkl"); len(lines) != 1 || lines[0] != lineFor(rotated, "[git.example.com]:2222") {
		t.Errorf("host keys = %v", lines)
	}
}

func TestRemoveHostKeysChecksTheRequest(t *testing.T) {
	conn, _ := startServices(t)
	client := agentv1.NewSiteServiceClient(conn)

	for name, request := range map[string]*agentv1.RemoveHostKeysRequest{
		"bad id":  {SiteId: "nope", RepositoryUrl: "git@github.com:morgan/orchard.git", Fingerprint: "SHA256:x"},
		"bad url": {SiteId: "abcdefghijkl", RepositoryUrl: "https://github.com/morgan/orchard", Fingerprint: "SHA256:x"},
	} {
		if _, err := client.RemoveHostKeys(context.Background(), request); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestTestRepositoryNamesTheTrustedKeyWhenTheHostKeyChanged(t *testing.T) {
	conn, services := startServices(t)
	fake := services.Tester.Runner.(*systemtest.Fake)
	client := agentv1.NewSiteServiceClient(conn)

	old := providerKey(t, "github.com", "ssh-ed25519")
	rotated := providerKey(t, "gitlab.com", "ssh-ed25519")
	if err := services.Store.AddHostKey("abcdefghijkl", lineFor(old, "[git.example.com]:2222")); err != nil {
		t.Fatal(err)
	}
	fake.Fail("git", 128, "@@@@@@@@@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\nHost key verification failed.\nfatal: Could not read from remote repository.\n")
	fake.Handle("ssh-keyscan", func(c system.Command) (system.Result, error) {
		host := c.Args[len(c.Args)-1]
		if host == "github.com" {
			return system.Result{Output: []byte(lineFor(rotated, "github.com") + "\n")}, nil
		}
		return system.Result{Output: []byte(lineFor(rotated, "[git.example.com]:2222") + "\n")}, nil
	})

	cases := map[string]string{
		"ssh://git@git.example.com:2222/morgan/orchard.git": old.Fingerprint,
		"git@github.com:morgan/orchard.git":                 "",
	}
	for url, want := range cases {
		response, err := client.TestRepository(context.Background(), &agentv1.TestRepositoryRequest{SiteId: "abcdefghijkl", RepositoryUrl: url, Branch: "main"})
		if err != nil {
			t.Fatal(err)
		}
		if response.Access != agentv1.RepositoryAccess_REPOSITORY_ACCESS_HOST_KEY_CHANGED || response.HostKeyFingerprint != rotated.Fingerprint || response.TrustedHostKeyFingerprint != want {
			t.Errorf("%s: response = %v", url, response)
		}
	}
}

func TestGetCapabilitiesReportsThePortGuard(t *testing.T) {
	conn, services := startServices(t)
	services.Capabilities = func(context.Context) capabilities.Capabilities {
		return capabilities.Capabilities{NodeVersion: "v24.22.0", PortGuard: true}
	}

	caps, err := agentv1.NewServerServiceClient(conn).GetCapabilities(context.Background(), &agentv1.GetCapabilitiesRequest{})
	if err != nil || !caps.PortGuard || caps.NodeVersion != "v24.22.0" {
		t.Errorf("GetCapabilities = %v %v", caps, err)
	}
}
