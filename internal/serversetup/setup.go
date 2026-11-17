// Package serversetup prepares a server for sites each time the agent starts: directories, the Git hosts' keys,
// PHP helpers, and the Nginx snippets site configs include. Everything is idempotent.
package serversetup

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/capabilities"
	"github.com/catnapstudio/serverdog-agent/internal/gitsource"
	"github.com/catnapstudio/serverdog-agent/internal/nginx"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/phpfpm"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

const ACMESnippet = `# Managed by ServerDog. Let's Encrypt's HTTP-01 challenges.
location ^~ /.well-known/acme-challenge/ {
    auth_basic off;
    root ` + paths.ACMERoot + `;
    default_type text/plain;
    try_files $uri =404;
}
`

const TLSSnippet = `# Managed by ServerDog.
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:ServerDogTLS:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;
`

const HTTPSnippet = `# Managed by ServerDog.
map $http_upgrade $serverdog_connection_upgrade {
    default upgrade;
    ''      close;
}
`

// CatchAll replaces provisioning's catch-all: unknown names get no response on port 80 and no certificate on 443.
// ssl_reject_handshake was checked with nginx -t on Ubuntu 24.04 (1.24.0) and 26.04 (1.28.3). Before 1.25.1 the 443
// listen carries http2 like the sites' (nginx.Render), so Nginx doesn't warn that the protocol options differ.
func CatchAll(http2Directive bool) string {
	secure := "ssl http2 default_server"
	if http2Directive {
		secure = "ssl default_server"
	}

	return `# Managed by ServerDog. Requests for unknown hosts get no response.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}

server {
    listen 443 ` + secure + `;
    listen [::]:443 ` + secure + `;
    server_name _;
    ssl_reject_handshake on;
}
`
}

// PortGuardUnitName attaches the Node port guard at boot (serverdog-agent port-guard, see internal/portguard).
const PortGuardUnitName = "serverdog-port-guard.service"

// PortGuardUnit runs before sysinit.target, so the guard is attached before any login, cron job or site starts. No
// site unit requires it: a guard that fails to attach must not stop the sites, and Node deploys refuse to start a
// release until it is attached. deploy/serverdog-port-guard.service is a copy for reference.
const PortGuardUnit = `# Managed by ServerDog. Keeps Node sites' ports for their own users.
[Unit]
Description=ServerDog port guard
Documentation=https://github.com/catnapstudio/serverdog-agent
DefaultDependencies=no
After=local-fs.target
Before=sysinit.target

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=30
ExecStart=` + paths.AgentBinary + ` port-guard

[Install]
WantedBy=sysinit.target
`

type Setup struct {
	Paths        paths.Paths
	Applier      apply.Applier
	Capabilities capabilities.Capabilities
}

// Ensure prepares the server for sites and installs the port guard's boot unit. The unit doesn't depend on the rest,
// so a failure there (a hand-edited Nginx config that nginx -t rejects, say) doesn't keep the guard from attaching at
// boot; Ensure still returns that failure.
func (s Setup) Ensure(ctx context.Context) error {
	return errors.Join(s.prepareSites(ctx), s.installPortGuardUnit(ctx))
}

func (s Setup) prepareSites(ctx context.Context) error {
	for logical, mode := range map[string]os.FileMode{
		paths.DeploysDir:                0o700,
		paths.KeysDir:                   0o700,
		paths.CertsDir:                  0o700,
		paths.ACMEAccountDir:            0o700,
		paths.LocksDir:                  0o700,
		paths.ACMERoot:                  0o755,
		paths.ACMERoot + "/.well-known": 0o755,
		paths.ACMERoot + "/.well-known/acme-challenge": 0o755,
		paths.EtcDir:      0o755,
		paths.SitesEtcDir: 0o755,
	} {
		dir := s.Paths.File(logical)
		if err := os.MkdirAll(dir, mode); err != nil {
			return fmt.Errorf("create %s: %w", logical, err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			return fmt.Errorf("chmod %s: %w", logical, err)
		}
	}

	plan := apply.Plan{Files: []apply.File{{Path: s.Paths.File(paths.KnownHosts), Content: []byte(gitsource.ProviderKnownHosts)}}}
	for _, version := range s.Capabilities.PHPVersions {
		plan.Files = append(plan.Files, phpfpm.Helpers(s.Paths, version)...)
	}
	if _, err := s.Applier.Apply(ctx, plan); err != nil {
		return err
	}

	// Each version on its own, so one whose pools don't load doesn't leave the others' packaged pools open.
	var locks []error
	for _, version := range s.Capabilities.PHPVersions {
		if _, err := s.Applier.Apply(ctx, phpfpm.LockStockPool(s.Paths, version)); err != nil {
			locks = append(locks, fmt.Errorf("lock PHP %s's packaged pool: %w", version, err))
		}
	}
	if err := errors.Join(locks...); err != nil {
		return err
	}

	if s.Capabilities.NginxVersion != "" {
		_, err := s.Applier.Apply(ctx, apply.Plan{
			Files: []apply.File{
				{Path: s.Paths.File(paths.NginxACME), Content: []byte(ACMESnippet)},
				{Path: s.Paths.File(paths.NginxTLS), Content: []byte(TLSSnippet)},
				{Path: s.Paths.File(paths.NginxHTTPConf), Content: []byte(HTTPSnippet)},
				{Path: s.Paths.File(paths.NginxCatchAll), Content: []byte(CatchAll(s.Capabilities.NginxHTTP2Directive()))},
				{Path: s.Paths.File("/etc/nginx/sites-enabled/000-catch-all"), Link: s.Paths.File(paths.NginxCatchAll)},
			},
			Checks:  []system.Command{nginx.Check},
			Reloads: []system.Command{nginx.Reload},
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (s Setup) installPortGuardUnit(ctx context.Context) error {
	_, err := s.Applier.Apply(ctx, apply.Plan{
		Files: []apply.File{{Path: s.Paths.File(paths.SystemdUnit(PortGuardUnitName)), Content: []byte(PortGuardUnit)}},
		Reloads: []system.Command{
			{Name: "systemctl", Args: []string{"daemon-reload"}},
			{Name: "systemctl", Args: []string{"enable", PortGuardUnitName}},
		},
	})

	return err
}
