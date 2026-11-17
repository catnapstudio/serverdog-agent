// Package paths names the files and directories the agent manages on a server.
//
// Functions return logical paths ("/etc/nginx/...") as they appear inside generated configs.
// Paths.File maps a logical path under a filesystem root, so tests can work in a temp directory.
package paths

import (
	"path"
	"path/filepath"
)

// Paths locates logical paths under Root ("/" in production).
type Paths struct {
	Root string
}

// File returns where logical lives under the root.
func (p Paths) File(logical string) string {
	return filepath.Join(p.Root, filepath.FromSlash(logical))
}

const (
	StateDir         = "/var/lib/serverdog"
	DeploysDir       = "/var/lib/serverdog/deploys"
	MetricsFile      = "/var/lib/serverdog/metrics.bin"
	KeysDir          = "/var/lib/serverdog/keys"
	LocksDir         = "/var/lib/serverdog/locks"
	ApplyLock        = "/var/lib/serverdog/locks/apply.lock"
	PortGuardLock    = "/var/lib/serverdog/locks/port-guard.lock"
	ACMERoot         = "/var/lib/serverdog-acme"
	CertsDir         = "/etc/serverdog/certs"
	ACMEAccountDir   = "/var/lib/serverdog/acme-account"
	AgentConfig      = "/etc/serverdog/agent.json"
	EtcDir           = "/etc/serverdog"
	SitesEtcDir      = "/etc/serverdog/sites"
	DaemonsEtcDir    = "/etc/serverdog/daemons"
	KnownHosts       = "/etc/serverdog/known_hosts"
	NginxSnippetsDir = "/etc/nginx/serverdog"
	NginxUpstreams   = "/etc/nginx/serverdog/upstreams"
	NginxACME        = "/etc/nginx/serverdog/acme.conf"
	NginxTLS         = "/etc/nginx/serverdog/tls.conf"
	NginxHTTPConf    = "/etc/nginx/conf.d/serverdog-http.conf"
	NginxCatchAll    = "/etc/nginx/sites-available/000-catch-all"
	PHPHelpersDir    = "/usr/local/lib/serverdog/php"
	SystemdDir       = "/etc/systemd/system"
	CronDir          = "/etc/cron.d"
	HomeDir          = "/home"
	// DatabaseLoginDir holds the short-lived option files of database login tests. /run/serverdog is root's, mode 0700.
	DatabaseLoginDir = "/run/serverdog/db-login"
	// AgentBinary is the installed agent. Node start scripts run its env-exports helper and Nginx reloads run
	// its reload-nginx helper.
	AgentBinary = "/usr/local/bin/serverdog-agent"
)

// SiteDirectory is where a site lives: /home/<user>/<first domain at creation>.
func SiteDirectory(user, domain string) string { return path.Join(HomeDir, user, domain) }

// Placeholder is the folder of the page a site serves until its first release is live. The site user owns it.
func Placeholder(siteDirectory string) string { return path.Join(siteDirectory, "placeholder") }

// UserHome is a site user's home directory.
func UserHome(user string) string { return path.Join(HomeDir, user) }

func DeployLogDir(siteID string) string { return path.Join(DeploysDir, siteID) }

func DeployLog(siteID, deploymentID string) string {
	return path.Join(DeploysDir, siteID, deploymentID+".log")
}

func PendingKeyDir(siteID string) string { return path.Join(KeysDir, siteID) }

func DeployKey(user, siteID string) string {
	return path.Join(HomeDir, user, ".ssh", "serverdog-"+siteID)
}

func SiteKnownHosts(user, siteID string) string {
	return path.Join(HomeDir, user, ".ssh", "serverdog-"+siteID+".known_hosts")
}

func SiteEtcDir(siteID string) string { return path.Join(SitesEtcDir, siteID) }

// NginxPasswords is the login file of a protected site, read by Nginx's www-data workers.
func NginxPasswords(siteID string) string {
	return "/etc/nginx/serverdog/passwords/" + siteID
}

func NginxSiteAvailable(siteID string) string {
	return "/etc/nginx/sites-available/serverdog-" + siteID + ".conf"
}

func NginxSiteEnabled(siteID string) string {
	return "/etc/nginx/sites-enabled/serverdog-" + siteID + ".conf"
}

func NginxUpstream(siteID string) string { return path.Join(NginxUpstreams, siteID+".conf") }

// FPMStockPool is the pool the distribution's package ships, and FPMStockPoolLock the file that tightens it. Pool
// files load in name order, so the lock's settings win.
func FPMStockPool(version string) string {
	return path.Join("/etc/php", version, "fpm/pool.d/www.conf")
}

func FPMStockPoolLock(version string) string {
	return path.Join("/etc/php", version, "fpm/pool.d/zz-serverdog-www.conf")
}

func FPMPool(version, siteID string) string {
	return path.Join("/etc/php", version, "fpm/pool.d", "serverdog-"+siteID+".conf")
}

func FPMSocket(siteID string) string { return "/run/php/serverdog-" + siteID + ".sock" }

func PHPHelperBin(version string) string { return path.Join(PHPHelpersDir, version, "bin") }

func SystemdUnit(name string) string { return path.Join(SystemdDir, name) }

// BackupsCron runs the database backup plans.
const BackupsCron = CronDir + "/serverdog-backups"

// BackupsDir holds a backup's dumps while they upload. Root only.
const BackupsDir = StateDir + "/backups"

// BackupLock is held while a plan's backup runs.
func BackupLock(planID string) string { return path.Join(StateDir, "locks", "backup-"+planID+".lock") }

// JobsCron holds the server's scheduled jobs, the ones that belong to no site.
const JobsCron = CronDir + "/serverdog-jobs"

// SchedulerCron is the site's Laravel scheduler entry. cron ignores files in cron.d whose names contain dots.
func SchedulerCron(siteID string) string { return path.Join(CronDir, "serverdog-"+siteID) }

// SiteCertificates holds every certificate of a site.
func SiteCertificates(siteID string) string { return path.Join(CertsDir, siteID) }

// CertificateDir holds one certificate's fullchain.pem and privkey.pem (and request.csr for signing requests).
func CertificateDir(siteID, certID string) string { return path.Join(CertsDir, siteID, certID) }

// ActiveCertificateDir is a symlink to the domain's active certificate; Nginx configs reference files through it.
func ActiveCertificateDir(siteID, domain string) string {
	return path.Join(CertsDir, siteID, domain, "active")
}
