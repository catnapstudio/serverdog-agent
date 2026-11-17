// Package version holds build metadata injected with -ldflags.
package version

// ProtocolVersion is the serverdog.agent.v1 revision this build implements.
// 2 adds ServerService, SiteService, DeployService and ConfigService.
// 3 lets a site have no repository (PutSite with an empty URL and branch; Deploy refuses it) and serves a placeholder
// page until a site's first release is live. It also adds RemoveHostKeys, TestRepositoryResponse's
// trusted_host_key_fingerprint and the port_guard capability; 3 was unreleased when they joined it.
// 4 adds a site's processes and Laravel scheduler (Site.processes, Site.scheduler), ListProcesses, and deploy on
// push (Site.deploy_on_push).
// 5 adds a process's directory, a site's app directory and sites without a website (Process.directory,
// Site.app_directory, Site.name), the server's scheduled jobs (ListScheduledJobs, PutScheduledJobs), database backups
// (BackupService), the server's chat webhook (GetNotifications, PutNotifications, TestNotifications) and a site's
// health check (Site.health_check_path).
// 6 adds the server's logs (ListLogs, ReadLog), firewall rules, SSH keys, PHP versions and database management.
// 7 deploys a site without zero downtime and without a repository by running its script in current/ (WordPress).
// 8 adds the server's monitor thresholds (Notifications.disk_percent, memory_percent, load_percent).
// 9 adds private networking (GetNetwork, PutNetwork, CheckConnection) and CreateDatabaseRequest.allowed_from.
// 10 adds the server's background processes (ListBackgroundProcesses, PutBackgroundProcesses).
// 11 adds PHP settings (GetPHPSettings, PutPHPSettings) and Composer and npm credentials.
// 12 adds metric history (GetMetricHistory).
// 13 adds site redirects and basic auth (Site.redirects, Site.basic_auth_username, Site.basic_auth_password).
// 14 adds server settings (GetServerSettings, SetTimezone, SetRedisPassword) and read-only database users.
// 18 adds automatic updates (GetUpdates, PutUpdateSettings).
// 19 adds stopping a process until started again and its stop timeout (Process.stopped, Process.stop_seconds and the
// same on BackgroundProcess), RestartProcess and RestartBackgroundProcess, and Reverb on its own domain (Domain.reverb,
// Site.reverb_port), and Laravel Octane (Site.octane and its ports, InstallFrankenPHP), and insights (GetInsights,
// FixInsight) with a site's PHP worker limit (Site.php_workers).
// 20 added a single site webhook that no release shipped; 21 replaces it with a site's own deploy notifications
// (Site.deploy_notifications: Slack, Discord and a custom hook).
// 22 adds a site's own Nginx rules (Site.nginx_rules, Site.nginx_default_rules).
// 23 adds Meilisearch's settings and API keys (GetMeilisearchConfig, PutMeilisearchConfig, ListMeilisearchKeys) and
// its log.
const ProtocolVersion uint32 = 23

var (
	Version = "dev"
	Commit  = "none"
	BuiltAt = "unknown"
)
