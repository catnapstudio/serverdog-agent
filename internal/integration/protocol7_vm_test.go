//go:build vmtest

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
)

// The app's WordPress preset: an in-place PHP site without a repository whose wp-config.php is its environment file,
// and whose script downloads WordPress the first time it runs.
const wordpressScript = "cd $SERVERDOG_SITE_PATH\n\nbash -eo pipefail -c '[ -f wp-load.php ] || curl -fsSL https://wordpress.org/latest.tar.gz | tar -xz --strip-components=1'\n"

func TestWordPressInstallsWithoutARepositoryAndKeepsItsConfig(t *testing.T) {
	if engine := serverEngine(t); engine == "postgres" {
		t.Skip("WordPress needs MySQL or MariaDB")
	}
	resolveHere(t, "blog.test", "www.blog.test")

	spec := newSite(agentv1.Runtime_RUNTIME_PHP, "wordpress", "blog.test", "")
	spec.Branch, spec.PhpVersion, spec.ZeroDowntime = "", phpVersion(t), false
	spec.EnvironmentFile, spec.DeployScript = "wp-config.php", wordpressScript
	put, err := sitesClient().PutSite(timeout(t), &agentv1.PutSiteRequest{Site: spec, Actor: actor})
	if err != nil {
		t.Fatalf("PutSite: %v", err)
	}
	t.Cleanup(func() {
		sitesClient().DeleteSite(context.Background(), &agentv1.DeleteSiteRequest{Id: spec.Id, RemoveFiles: true, Actor: actor})
	})
	s := put.Site

	name, password := "blog"+strings.ToLower(s.Id[:6]), "Wp1"+strings.ToLower(s.Id)+"x"
	if _, err := databasesClient().CreateDatabase(timeout(t), &agentv1.CreateDatabaseRequest{SiteId: s.Id, Name: name, User: name, Password: password, Actor: actor}); err != nil {
		t.Fatalf("CreateDatabase: %v", err)
	}
	t.Cleanup(func() {
		databasesClient().DeleteDatabase(context.Background(), &agentv1.DeleteDatabaseRequest{Name: name})
		databasesClient().DeleteDatabaseUser(context.Background(), &agentv1.DeleteDatabaseUserRequest{User: name})
	})

	env, err := configClient().GetEnv(timeout(t), &agentv1.GetEnvRequest{SiteId: s.Id})
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`<?php
define( 'DB_NAME', '%[1]s' );
define( 'DB_USER', '%[1]s' );
define( 'DB_PASSWORD', '%[2]s' );
define( 'DB_HOST', '127.0.0.1' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );
$table_prefix = 'wp_';
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
`, name, password)
	if _, err := configClient().PutEnv(timeout(t), &agentv1.PutEnvRequest{SiteId: s.Id, Content: config, ExpectedSha256: env.Sha256, Actor: actor}); err != nil {
		t.Fatalf("PutEnv: %v", err)
	}

	mustDeploy(t, s.Id)

	// A configured, not yet installed WordPress sends visitors to its install page.
	code, _, header, err := get("blog.test")
	if err != nil || code != 302 || !strings.Contains(header.Get("Location"), "/wp-admin/install.php") {
		t.Fatalf("GET blog.test = %d %v %v, want a redirect to the install page", code, header.Get("Location"), err)
	}

	// The second deploy finds WordPress there and leaves it, wp-config.php included.
	mustDeploy(t, s.Id)
	after, err := configClient().GetEnv(timeout(t), &agentv1.GetEnvRequest{SiteId: s.Id})
	if err != nil || after.Content != config {
		t.Errorf("wp-config.php after a second deploy = %q %v", after.GetContent(), err)
	}
	if code, _, _, err := get("blog.test"); err != nil || code != 302 {
		t.Errorf("GET blog.test after a second deploy = %d %v", code, err)
	}
}
