// Package nodeservice renders the systemd template unit, start script and Nginx upstream of a Node site.
//
// Each Node site has two ports. A deploy starts the new release on the idle one, points the upstream at it
// and stops the old instance (see internal/deploy), so requests never hit a restarting process.
package nodeservice

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
)

func UpstreamName(siteID string) string { return "serverdog_" + siteID }

// Template is the unit file name; Instance is one running copy on a port.
func Template(siteID string) string { return "serverdog-site-" + siteID + "@.service" }

func Instance(siteID string, port int) string {
	return fmt.Sprintf("serverdog-site-%s@%d.service", siteID, port)
}

func StartScript(siteID string) string { return path.Join(paths.SiteEtcDir(siteID), "start.sh") }

func PortEnv(siteID string, port int) string {
	return path.Join(paths.SiteEtcDir(siteID), fmt.Sprintf("%d.env", port))
}

// RenderUnit returns the template unit. systemd reads EnvironmentFile= as root and follows symlinks, so the
// site's own .env is never listed here; the start script loads it as the site user instead. The per-port file
// is root-owned and comes last, so PORT and HOST can't be overridden by anything else.
func RenderUnit(siteID, user string) []byte {
	return []byte(fmt.Sprintf(`# Managed by ServerDog for site %[1]s.
[Unit]
Description=ServerDog site %[1]s on port %%i
After=network.target
# The server that answers the site never gives up starting: left failed, the site stays down until the next deploy.
StartLimitIntervalSec=0

[Service]
Type=simple
User=%[2]s
Group=%[2]s
EnvironmentFile=%[3]s/%%i.env
ExecStart=%[4]s
Restart=always
RestartSec=2
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
`, siteID, user, paths.SiteEtcDir(siteID), StartScript(siteID)))
}

// RenderStartScript runs the site's start command from the release the instance was started for.
// environmentFile is the site's .env (logical path) or "" for none. The script loads it as the site user, through
// the installed agent's env-exports helper (paths.AgentBinary), so the values never pass through systemd. If the
// helper fails, the script exits before starting the command, so the service never runs without its variables.
func RenderStartScript(command, environmentFile string) []byte {
	load := ""
	if environmentFile != "" {
		load = fmt.Sprintf("exports=\"$(%s env-exports %s)\" || exit 1\neval \"$exports\"\n", paths.AgentBinary, shellQuote(environmentFile))
	}

	return []byte("#!/bin/sh\n# Managed by ServerDog.\ncd \"${SERVERDOG_RELEASE_DIRECTORY:?}\" || exit 1\n" + load + "exec " + command + "\n")
}

// OctaneCaddyfile is where an Octane server keeps its copy of Octane's Caddyfile, in its release.
const OctaneCaddyfile = "bootstrap/cache/octane.Caddyfile"

// RenderOctaneStartScript runs a release's Laravel Octane server on the server-wide FrankenPHP, on the instance's
// port. appDirectory is where artisan is, inside the release ("" for its root).
//
// Octane's own Caddyfile makes FrankenPHP listen on every interface whatever --host says, and opens its admin API
// to every local user. The script starts Octane on a copy of the installed Octane's file that listens only to Nginx
// and has no admin API, and refuses to start when the copy isn't that: the deploy then fails and the previous
// release keeps serving. OCTANE_HTTPS makes Octane write https links when the site forces HTTPS, unless the .env
// already says.
func RenderOctaneStartScript(phpBinary, appDirectory string, forceHTTPS bool) []byte {
	https := ""
	if forceHTTPS {
		https = "grep -q '^OCTANE_HTTPS=' .env 2>/dev/null || export OCTANE_HTTPS=true\n"
	}

	return []byte(fmt.Sprintf(`#!/bin/sh
# Managed by ServerDog.
cd "${SERVERDOG_RELEASE_DIRECTORY:?}"/%[1]s || exit 1
stub=vendor/laravel/octane/src/Commands/stubs/Caddyfile
if [ ! -f "$stub" ]; then
  echo "This release has no laravel/octane. Add it with: composer require laravel/octane" >&2
  exit 1
fi
sed -e 's/^{$CADDY_SERVER_SERVER_NAME} {$/&\n\tbind 127.0.0.1/' -e 's/^\([[:space:]]*\)admin .*/\1admin off/' "$stub" > %[2]s || exit 1
if ! grep -q 'bind 127.0.0.1' %[2]s || ! grep -q 'admin off' %[2]s; then
  echo "ServerDog couldn't make Octane's Caddyfile listen only on this server; laravel/octane changed its format. Update the server's agent." >&2
  exit 1
fi
%[3]sexec %[4]s artisan octane:start --server=frankenphp --host=127.0.0.1 --port="${PORT:?}" --caddyfile=%[2]s --no-interaction
`, shellQuote(appDirectory), OctaneCaddyfile, https, phpBinary))
}

// RenderPortEnv is the environment of the instance on port: where it listens and which release it runs.
// HOST suits Nuxt and Astro; Next.js ignores it, so its start command passes -H 127.0.0.1.
func RenderPortEnv(port int, release string) []byte {
	return []byte(fmt.Sprintf("PORT=%d\nHOST=127.0.0.1\nHOSTNAME=127.0.0.1\nNODE_ENV=production\nPYTHONUNBUFFERED=1\nSERVERDOG_RELEASE_DIRECTORY=%s\n", port, release))
}

// RenderUpstream points the site's Nginx upstream at port.
func RenderUpstream(siteID string, port int) []byte {
	return []byte(fmt.Sprintf("# Managed by ServerDog for site %s.\nupstream %s {\n    server 127.0.0.1:%d;\n}\n", siteID, UpstreamName(siteID), port))
}

// UpstreamPort returns the port an upstream file sends traffic to, or false unless it names exactly one
// 127.0.0.1 server.
func UpstreamPort(content []byte) (int, bool) {
	port, found := 0, false

	for line := range strings.SplitSeq(string(content), "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "server 127.0.0.1:")
		if !ok {
			continue
		}

		number, err := strconv.Atoi(strings.TrimSuffix(value, ";"))
		if err != nil || found {
			return 0, false
		}
		port, found = number, true
	}

	return port, found
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
