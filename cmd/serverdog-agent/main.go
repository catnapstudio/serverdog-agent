// Command serverdog-agent serves serverdog.agent.v1 on a root-only Unix socket.
// "serverdog-agent run-deploy <id>" performs one deployment inside its systemd unit.
// "serverdog-agent env-exports <file>" prints shell exports for an environment file, for Node sites' start scripts.
// "serverdog-agent reload-nginx" reloads Nginx and returns once the new configuration serves requests.
// "serverdog-agent port-guard" attaches the Node port guard and fills it from the store; the serverdog-port-guard unit
// runs it at boot. "serverdog-agent port-guard --remove" detaches it, for uninstalling.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/acmeclient"
	"github.com/catnapstudio/serverdog-agent/internal/agentconfig"
	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/backups"
	"github.com/catnapstudio/serverdog-agent/internal/capabilities"
	"github.com/catnapstudio/serverdog-agent/internal/certificates"
	"github.com/catnapstudio/serverdog-agent/internal/credentials"
	"github.com/catnapstudio/serverdog-agent/internal/daemons"
	"github.com/catnapstudio/serverdog-agent/internal/databases"
	"github.com/catnapstudio/serverdog-agent/internal/deploy"
	"github.com/catnapstudio/serverdog-agent/internal/domains"
	"github.com/catnapstudio/serverdog-agent/internal/dotenv"
	"github.com/catnapstudio/serverdog-agent/internal/firewall"
	"github.com/catnapstudio/serverdog-agent/internal/frankenphp"
	"github.com/catnapstudio/serverdog-agent/internal/gitsource"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/insights"
	"github.com/catnapstudio/serverdog-agent/internal/jobs"
	"github.com/catnapstudio/serverdog-agent/internal/listen"
	"github.com/catnapstudio/serverdog-agent/internal/listenowner"
	"github.com/catnapstudio/serverdog-agent/internal/lock"
	"github.com/catnapstudio/serverdog-agent/internal/logs"
	"github.com/catnapstudio/serverdog-agent/internal/meilisearch"
	"github.com/catnapstudio/serverdog-agent/internal/metrics"
	"github.com/catnapstudio/serverdog-agent/internal/monitor"
	"github.com/catnapstudio/serverdog-agent/internal/network"
	"github.com/catnapstudio/serverdog-agent/internal/nginx"
	"github.com/catnapstudio/serverdog-agent/internal/notify"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/phpfpm"
	"github.com/catnapstudio/serverdog-agent/internal/phpsettings"
	"github.com/catnapstudio/serverdog-agent/internal/phpversions"
	"github.com/catnapstudio/serverdog-agent/internal/portguard"
	"github.com/catnapstudio/serverdog-agent/internal/pushdeploy"
	"github.com/catnapstudio/serverdog-agent/internal/server"
	"github.com/catnapstudio/serverdog-agent/internal/serversettings"
	"github.com/catnapstudio/serverdog-agent/internal/serversetup"
	"github.com/catnapstudio/serverdog-agent/internal/servicectl"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/sites"
	"github.com/catnapstudio/serverdog-agent/internal/sshkeys"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/sysinfo"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/updates"
	"github.com/catnapstudio/serverdog-agent/internal/userfs"
	"github.com/catnapstudio/serverdog-agent/internal/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "env-exports" {
		os.Exit(envExports(os.Args[2:], os.Stdout, os.Stderr, os.LookupEnv))
	}

	if len(os.Args) > 1 && os.Args[1] == "reload-nginx" {
		if err := nginx.SystemReloader(system.Exec{}).Reload(context.Background()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "port-guard" {
		if err := portGuard(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "run-backup" {
		if err := runBackup(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "run-deploy" {
		if err := runDeploy(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	socket := flag.String("socket", "/run/serverdog/agent.sock", "Unix socket to serve gRPC on")
	stateDir := flag.String("state-dir", "/var/lib/serverdog", "directory for the agent's state database")
	root := flag.String("root", "/", "filesystem root the agent manages")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Version)
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*socket, *stateDir, *root, logger); err != nil {
		logger.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}

func run(socket, stateDir, root string, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := state.Open(stateDir)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := store.RecordStart(version.Version, time.Now()); err != nil {
		return fmt.Errorf("record start: %w", err)
	}

	p := paths.Paths{Root: root}
	exec := system.Exec{}
	applier := apply.Applier{Runner: exec, LockPath: p.File(paths.ApplyLock)}
	guard := portguard.Default()
	detector := capabilities.Detector{Root: root, Runner: exec, InterfaceAddrs: net.InterfaceAddrs, PortGuardAttached: guard.Attached}
	locks := &lock.Keyed{}

	if err := (serversetup.Setup{Paths: p, Applier: applier, Capabilities: detector.Detect(ctx)}).Ensure(ctx); err != nil {
		logger.Warn("server setup incomplete", "error", err)
	}

	portSync := portguard.Syncer{Guard: guard, Store: store, LookupUser: system.LookupUser, LockPath: p.File(paths.PortGuardLock)}
	ensurePortGuard(ctx, guard, portSync, root, logger)
	warnAboutStrayNodeListeners(p, store, logger)

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find agent binary: %w", err)
	}

	deploys := &deploy.Manager{
		Store: store, Paths: p, System: exec, Exec: exec, LookupUser: system.LookupUser, AsUser: true,
		Executable: executable, StateDir: stateDir, Now: time.Now, NewID: ids.New, Locks: locks,
	}
	// A settings file that can't be read must not turn a staging or test setup into real Let's Encrypt orders, so
	// the scheduler stays off until the file is fixed and the agent restarted. Everything else keeps working.
	config, configErr := agentconfig.Load(p.File(paths.AgentConfig))
	if configErr != nil {
		logger.Error("the agent's settings file is unusable, so certificates won't be issued or renewed automatically", "error", configErr)
		config = agentconfig.Config{ACMEDirectory: agentconfig.LetsEncrypt}
	}

	siteManager := &sites.Manager{
		Store: store, Paths: p, System: exec, Exec: exec, Applier: applier, Keys: gitsource.Keys{Paths: p},
		Capabilities: detector.Detect, LookupUser: system.LookupUser, AsUser: true, Now: time.Now, Locks: locks,
		SyncPorts: portSync.Sync,
	}
	resolver := domains.Authoritative{Fallback: net.DefaultResolver}
	checker := domains.Checker{
		Paths:         p,
		Resolver:      resolver,
		HTTP:          domains.NoRedirects(&http.Client{Transport: &http.Transport{DialContext: domains.DialVia(resolver)}}),
		Addresses:     func(ctx context.Context) []string { return detector.Detect(ctx).PublicAddresses },
		AllowLoopback: config.AllowLoopbackDomains,
	}
	certificateManager := &certificates.Manager{
		Store: store, Paths: p, Sites: siteManager, Applier: applier, Domains: checker,
		ACME: &acmeclient.Lego{
			Directory: config.ACMEDirectory, CABundle: config.ACMECABundle,
			AccountDir: p.File(paths.ACMEAccountDir), Webroot: p.File(paths.ACMERoot),
		},
		Now: time.Now, NewID: ids.New,
	}
	siteManager.ActiveCertificates = certificateManager.Active
	siteManager.AfterPut = certificateManager.SyncSite

	// Before serving: no site can be created or given a certificate while the sweep decides what is left over.
	if err := certificateManager.RemoveOrphanFiles(); err != nil {
		logger.Warn("could not remove the certificate files of deleted sites", "error", err)
	}

	if err := databases.SweepLoginFiles(p.File(paths.DatabaseLoginDir)); err != nil {
		logger.Warn("could not remove leftover database login files", "error", err)
	}

	backupPlans := &backups.Manager{Store: store, Paths: p, Applier: applier}
	notifications := &notify.Manager{Store: store}
	engine := func(ctx context.Context) string { return detector.Detect(ctx).DatabaseEngine }
	networking := &network.Manager{
		Store: store, Paths: p, System: exec, Links: network.SystemLinks, Engine: engine,
		Dial: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
	}
	phpSettings := &phpsettings.Manager{Store: store, Paths: p, Applier: applier}
	automaticUpdates := &updates.Manager{Store: store, Paths: p, Applier: applier, Runner: exec}
	recorder := &metrics.Recorder{
		File: p.File(paths.MetricsFile), NetDev: filepath.Join(root, "proc/net/dev"), Now: time.Now,
		Collect: func() (sysinfo.Info, error) { return sysinfo.Collect(root) },
	}
	scheduledJobs := &jobs.Manager{Store: store, Paths: p, Applier: applier, System: exec, LookupUser: system.LookupUser}
	serverSettings := &serversettings.Manager{Paths: p, Runner: exec}
	backgroundProcesses := &daemons.Manager{Store: store, Paths: p, Applier: applier, System: exec, LookupUser: system.LookupUser}
	systemServices := &servicectl.Manager{Runner: exec, RebootDelay: 2 * time.Second}
	services := &server.Services{
		Store:        store,
		Paths:        p,
		Sites:        siteManager,
		Deploys:      deploys,
		Watcher:      deploy.Watcher{Store: store, Paths: p, Poll: 250 * time.Millisecond},
		Tester:       gitsource.Tester{Runner: exec},
		Capabilities: detector.Detect,
		Domains:      checker,
		Certificates: certificateManager,
		Databases: databases.Creator{
			Runner: exec, Engine: func(ctx context.Context) string { return detector.Detect(ctx).DatabaseEngine },
			LoginDir: p.File(paths.DatabaseLoginDir), Network: networking.Network,
		},
		Jobs:          scheduledJobs,
		Daemons:       backgroundProcesses,
		Notifications: notifications,
		Logs:          &logs.Reader{Paths: p, System: exec, Sites: store.ListSites, LookupUser: system.LookupUser},
		Firewall:      &firewall.Manager{Store: store, Paths: p, System: exec},
		SSHKeys: &sshkeys.Manager{Store: store, Sites: store.ListSites, LookupUser: system.LookupUser, FS: func(account system.User) userfs.FS {
			if account.Name == "root" {
				return userfs.FS{Runner: exec}
			}
			return userfs.FS{Runner: exec, User: &account}
		}},
		PHP: &phpversions.Manager{Paths: p, System: exec, Sites: store.ListSites, AfterInstall: func(ctx context.Context, version string) error {
			if _, err := applier.Apply(ctx, phpfpm.LockStockPool(p, version)); err != nil {
				return err
			}

			return phpSettings.ApplyVersion(ctx, version)
		}},
		PHPSettings:    phpSettings,
		Metrics:        recorder,
		Settings:       serverSettings,
		Meilisearch:    &meilisearch.Manager{Paths: p, Runner: exec},
		SystemServices: systemServices,
		Credentials:    &credentials.Manager{Paths: p, Runner: exec, LookupUser: system.LookupUser, AsUser: true},
		Backups:        backupPlans,
		BackupRunner: &backups.Runner{
			Store: store, Paths: p, Plans: backupPlans, Now: time.Now, Notify: notifications.BackupFailed,
			Engine: func(ctx context.Context) string { return detector.Detect(ctx).DatabaseEngine },
		},
		Network: networking,
		Updates: automaticUpdates,
		Insights: &insights.Scanner{
			Paths: p, Runner: exec, Sites: store.ListSites, Now: time.Now, Disk: insights.RootDisk(root),
			Env: func(ctx context.Context, id string) ([]byte, error) {
				return siteManager.EnvHead(ctx, id, insights.EnvLimit)
			},
			SaveSite: func(ctx context.Context, s site.Site, actor string) error {
				_, _, err := siteManager.Put(ctx, s, s.Revision, actor)

				return err
			},
			BackgroundProcesses: func() map[string][2]string {
				processes := map[string][2]string{}
				list, _, _ := backgroundProcesses.List()
				for _, process := range list {
					processes[process.ID] = [2]string{process.Name, process.Command}
				}

				return processes
			},
			RestartService: func(ctx context.Context, unit string) error {
				return systemServices.Control(ctx, unit, servicectl.Restart)
			},
			RebootRequired: func() (time.Time, bool) {
				since, _, required := automaticUpdates.RebootRequired()

				return since, required
			},
		},
		FrankenPHP: &frankenphp.Installer{
			Paths: p, Client: &http.Client{Timeout: 15 * time.Minute}, Arch: runtime.GOARCH,
			ReleaseURL: "https://api.github.com/repos/php/frankenphp/releases/tags/v" + frankenphp.Version,
		},
	}

	listener, err := listen.Unix(socket)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(recoverPanic))
	agentv1.RegisterAgentServiceServer(grpcServer, server.New(root, time.Now))
	services.Register(grpcServer)

	// The background loops use the store, which closes when run returns, so they are stopped and waited for first.
	background, stopBackground := context.WithCancel(ctx)
	var running sync.WaitGroup
	defer running.Wait()
	defer stopBackground()

	running.Go(func() { deploys.RecoverEvery(background, 15*time.Second) })
	running.Go(func() {
		if err := services.FrankenPHP.Refresh(background); err != nil {
			slog.Warn("could not update FrankenPHP", "error", err)
		}
	})
	if configErr == nil {
		running.Go(func() { certificateManager.Run(background) })
	}

	pushDeploys := &pushdeploy.Poller{
		Store: store, Credentials: siteManager.RepositoryCredentials, Deploy: deploys.Deploy, Logger: logger,
		Head: func(ctx context.Context, rawURL, branch string, c gitsource.Credentials) (string, error) {
			return gitsource.Head(ctx, exec, rawURL, branch, c)
		},
	}
	running.Go(func() { pushDeploys.Run(background) })

	monitors := &monitor.Monitor{
		Collect: func() (sysinfo.Info, error) { return sysinfo.Collect(root) },
		Settings: func() (notify.Settings, error) {
			settings, _, err := notifications.Get()
			return settings, err
		},
		Post: notifications.Alert, Host: notify.Hostname, Logger: logger,
	}
	running.Go(func() { monitors.Run(background, time.Minute) })
	expiryWatcher := &certificates.ExpiryWatcher{
		Store: store, Post: notifications.Alert, Host: notify.Hostname, Now: time.Now, Logger: logger,
	}
	running.Go(func() { expiryWatcher.Run(background, time.Hour) })
	// Servers provisioned before the agent managed automatic updates get the vendor archives now.
	if err := automaticUpdates.Apply(background); err != nil {
		logger.Warn("could not write the automatic updates' settings", "error", err)
	}
	rebootWatcher := &updates.RebootWatcher{
		Updates: automaticUpdates, Post: notifications.Alert, Host: notify.Hostname, Now: time.Now, Logger: logger,
	}
	running.Go(func() { rebootWatcher.Run(background, time.Hour) })
	jobWatcher := &jobs.Watcher{
		Jobs: scheduledJobs,
		Enabled: func() bool {
			settings, _, err := notifications.Get()
			return err == nil && settings.WebhookURL != ""
		},
		Post: notifications.Alert, Host: notify.Hostname, Now: time.Now, Logger: logger,
		Location: func() *time.Location {
			if zone, err := time.LoadLocation(serverSettings.Timezone()); err == nil {
				return zone
			}
			return time.Local
		},
	}
	if err := scheduledJobs.Rewrite(background); err != nil {
		logger.Warn("could not rewrite the scheduled jobs' cron file", "error", err)
	}
	running.Go(func() { jobWatcher.Run(background, time.Minute) })
	running.Go(func() {
		recorder.Run(background, func(err error) { logger.Warn("record metrics", "error", err) })
	})

	go func() {
		<-ctx.Done()
		stopWithin(grpcServer, gracefulStopTimeout)
	}()

	logger.Info("agent listening", "socket", socket, "version", version.Version)

	return grpcServer.Serve(listener)
}

// runDeploy performs one deployment. The agent starts it with systemd-run, so it outlives agent restarts;
// systemctl stop sends SIGTERM, which cancels the deploy.
// runBackup runs one backup plan and waits; cron starts it on the plan's schedule. The run records its outcome.
func runBackup(args []string) error {
	flags := flag.NewFlagSet("run-backup", flag.ContinueOnError)
	stateDir := flags.String("state-dir", "/var/lib/serverdog", "directory of the agent's state database")
	root := flags.String("root", "/", "filesystem root the agent manages")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: serverdog-agent run-backup [--state-dir dir] [--root dir] <plan-id>")
	}

	store, err := state.Open(*stateDir)
	if err != nil {
		return err
	}
	defer store.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	p := paths.Paths{Root: *root}
	detector := capabilities.Detector{Root: *root, Runner: system.Exec{}, InterfaceAddrs: net.InterfaceAddrs}
	runner := &backups.Runner{
		Store: store, Paths: p, Plans: &backups.Manager{Store: store, Paths: p}, Now: time.Now,
		Notify: (&notify.Manager{Store: store}).BackupFailed,
		Engine: func(ctx context.Context) string { return detector.Detect(ctx).DatabaseEngine },
	}

	return runner.Run(ctx, flags.Arg(0))
}

func runDeploy(args []string) error {
	flags := flag.NewFlagSet("run-deploy", flag.ContinueOnError)
	stateDir := flags.String("state-dir", "/var/lib/serverdog", "directory of the agent's state database")
	root := flags.String("root", "/", "filesystem root the agent manages")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: serverdog-agent run-deploy [--state-dir dir] [--root dir] <deployment-id>")
	}

	store, err := state.Open(*stateDir)
	if err != nil {
		return err
	}
	defer store.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	p := paths.Paths{Root: *root}
	exec := system.Exec{}

	// The deploy that makes a site's first release live renders the site's config like the agent does.
	detector := capabilities.Detector{Root: *root, Runner: exec, InterfaceAddrs: net.InterfaceAddrs}
	siteConfigs := &sites.Manager{
		Store: store, Paths: p, Capabilities: detector.Detect,
		ActiveCertificates: (&certificates.Manager{Store: store, Paths: p}).Active,
	}

	runner := &deploy.Runner{
		Store:          store,
		Paths:          p,
		Exec:           exec,
		System:         exec,
		Applier:        apply.Applier{Runner: exec, LockPath: p.File(paths.ApplyLock)},
		Out:            os.Stdout,
		Notify:         (&notify.Manager{Store: store}).Deploy,
		Now:            time.Now,
		LookupUser:     system.LookupUser,
		AsUser:         true,
		BasePath:       deploy.DefaultPath,
		Probe:          deploy.HTTPProbe,
		ProbeEvery:     500 * time.Millisecond,
		ProbeFor:       time.Minute,
		HealthCheck:    deploy.SiteHealthCheck,
		HealthCheckFor: 30 * time.Second,
		DrainFor:       10 * time.Second,
		OPcacheFrozen:  (&phpsettings.Manager{Store: store, Paths: p}).OPcacheFrozen,

		ReleaseConfig: siteConfigs.ReleaseConfig,
		Capabilities:  detector.Detect,
		PortGuard: portguard.Syncer{
			Guard: portguard.Default(), Store: store, LookupUser: system.LookupUser, LockPath: p.File(paths.PortGuardLock),
		}.Sync,
		Listener: listenowner.Checker{Paths: p, System: exec},
	}

	return runner.Run(ctx, flags.Arg(0))
}

// ensurePortGuard attaches the Node port guard and fills it from the store. When the boot unit attached it first, the
// program is replaced in place and a failed fill keeps the map the boot unit wrote. Otherwise (an upgraded server, or
// a boot unit that failed) it attaches the way the boot unit does, and any failure leaves it detached. A failure is
// logged, not fatal: running sites don't need the guard, and Node deploys refuse to start without it.
func ensurePortGuard(ctx context.Context, guard bootGuard, syncer portguard.Syncer, root string, logger *slog.Logger) {
	if !guard.Attached() {
		if err := attachPortGuard(ctx, guard, syncer.Store, syncer); err != nil {
			logger.Warn("the Node port guard isn't attached, so Node deploys will fail", "error", err)
		}
	} else if err := guard.Ensure(); err != nil {
		logger.Warn("the Node port guard isn't attached, so Node deploys will fail", "error", err)
	} else if err := syncer.Sync(ctx); err != nil {
		logger.Warn("the Node port guard couldn't be filled from the store, so Node deploys will retry", "error", err)
	}

	if overlaps, portRange, err := capabilities.LocalPortRangeOverlaps(root); err == nil && overlaps {
		logger.Warn("ip_local_port_range overlaps the Node ports, so a listen() without bind() could take one of them",
			"ip_local_port_range", portRange, "node_ports", fmt.Sprintf("%d-%d", state.FirstNodePort, state.LastNodePort))
	}
}

// warnAboutStrayNodeListeners names each service on the host that listens on a Node port as a non-root user, on a port
// no site has. It keeps the socket it has, but the port guard stops it from binding again once it restarts. Only the
// agent's own network namespace is read, the host's: the guard leaves the others (containers) alone.
func warnAboutStrayNodeListeners(p paths.Paths, store portguard.PortUsers, logger *slog.Logger) {
	sockets, err := listenowner.Listening(p)
	if err != nil {
		logger.Warn("the services listening on the Node ports couldn't be listed", "error", err)

		return
	}

	users, err := store.NodePortUsers()
	if err != nil {
		logger.Warn("the services listening on the Node ports couldn't be checked", "error", err)

		return
	}

	for _, socket := range strayNodeListeners(sockets, users) {
		logger.Warn("a service listens on a Node port as a non-root user, and the port guard will stop it from binding there again after it restarts",
			"port", socket.Port, "uid", socket.UID)
	}
}

// strayNodeListeners returns the sockets on a Node port that aren't root's and whose port no site has.
func strayNodeListeners(sockets []listenowner.Socket, users map[int]string) []listenowner.Socket {
	var stray []listenowner.Socket
	for _, socket := range sockets {
		if socket.Port < state.FirstNodePort || socket.Port > state.LastNodePort {
			continue
		}
		if socket.UID == 0 {
			continue
		}
		if _, ok := users[socket.Port]; ok {
			continue
		}

		stray = append(stray, socket)
	}

	return stray
}

// portGuard attaches the Node port guard and fills it from the store, for the serverdog-port-guard boot unit. With
// --remove it detaches the guard instead.
func portGuard(args []string) error {
	flags := flag.NewFlagSet("port-guard", flag.ContinueOnError)
	stateDir := flags.String("state-dir", "/var/lib/serverdog", "directory of the agent's state database")
	root := flags.String("root", "/", "filesystem root the agent manages")
	remove := flags.Bool("remove", false, "detach the guard, for uninstalling")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: serverdog-agent port-guard [--state-dir dir] [--root dir] [--remove]")
	}

	guard := portguard.Default()
	if *remove {
		return guard.Remove()
	}

	store, err := state.Open(*stateDir)
	if err != nil {
		return err
	}
	defer store.Close()

	p := paths.Paths{Root: *root}
	syncer := portguard.Syncer{Guard: guard, Store: store, LookupUser: system.LookupUser, LockPath: p.File(paths.PortGuardLock)}

	return attachPortGuard(context.Background(), guard, store, syncer)
}

// bootGuard is the guard attachPortGuard and ensurePortGuard attach: portguard.Guard in production.
type bootGuard interface {
	Attached() bool
	Ensure() error
	Remove() error
}

// attachPortGuard attaches the guard and fills it, or leaves it detached. The store is read before the guard attaches:
// bpffs is empty after a reboot, so a guard attached and then left unfilled would stop every Node instance that
// starts at boot from binding its port. Serving fails open and deploys fail closed, so any failure detaches the
// guard, and the agent's next start tries again.
func attachPortGuard(ctx context.Context, guard bootGuard, store portguard.PortUsers, syncer portguard.Syncer) error {
	if _, err := store.NodePortUsers(); err != nil {
		return fmt.Errorf("read the Node ports: %w", err)
	}

	if err := guard.Ensure(); err != nil {
		return errors.Join(err, guard.Remove())
	}

	if err := syncer.Sync(ctx); err != nil {
		return errors.Join(err, guard.Remove())
	}

	return nil
}

// envExports prints "export" lines for an environment file, skipping variables the process already has.
// A missing file prints nothing. It returns the process exit code and never prints the file's content to stderr.
func envExports(args []string, stdout, stderr io.Writer, lookup func(string) (string, bool)) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: serverdog-agent env-exports <file>")

		return 2
	}

	content, err := os.ReadFile(args[0])
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "read environment file: %v\n", err)

		return 1
	}

	isSet := func(key string) bool {
		_, ok := lookup(key)

		return ok
	}
	fmt.Fprint(stdout, dotenv.Exports(dotenv.Parse(content), isSet))

	return 0
}

// gracefulStopTimeout bounds how long shutdown waits for open RPCs, such as a client watching a deploy.
const gracefulStopTimeout = 5 * time.Second

// stopWithin stops the server gracefully and forces it to stop if open RPCs keep it from finishing within d.
func stopWithin(server interface {
	GracefulStop()
	Stop()
}, d time.Duration) {
	done := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(d):
		server.Stop()
	}
}

// recoverPanic turns a panic in one request into that request's error. The agent also runs certificates, backups and
// monitors, which a crash would cut short.
func recoverPanic(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (response any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			slog.Error("panic in a request", "method", info.FullMethod, "panic", recovered)
			err = status.Error(codes.Internal, "ServerDog's agent hit an unexpected error.")
		}
	}()

	return handler(ctx, request)
}
