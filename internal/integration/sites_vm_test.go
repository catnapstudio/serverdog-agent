//go:build vmtest

package integration

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Two sites created at once for one domain: one wins, and the other leaves no Nginx config behind that could
// shadow the winner.
func TestTwoSitesRacingForADomainLeaveOneConfig(t *testing.T) {
	for round := range 3 {
		domain := fmt.Sprintf("race-%d.test", round)
		sites := []*agentv1.Site{
			newSite(agentv1.Runtime_RUNTIME_STATIC, "html", domain, ""),
			newSite(agentv1.Runtime_RUNTIME_STATIC, "html", domain, ""),
		}

		errs := make([]error, len(sites))
		var wg sync.WaitGroup
		for i, s := range sites {
			s.Branch = ""
			t.Cleanup(func() {
				sitesClient().DeleteSite(context.Background(), &agentv1.DeleteSiteRequest{Id: s.Id, RemoveFiles: true, Actor: actor})
			})

			wg.Go(func() {
				_, errs[i] = sitesClient().PutSite(timeout(t), &agentv1.PutSiteRequest{Site: s, Actor: actor})
			})
		}
		wg.Wait()

		winners := 0
		for i, s := range sites {
			available := "/etc/nginx/sites-available/serverdog-" + s.Id + ".conf"
			enabled := "/etc/nginx/sites-enabled/serverdog-" + s.Id + ".conf"

			if errs[i] == nil {
				winners++
				if _, err := os.Lstat(enabled); err != nil {
					t.Errorf("round %d: the winning site lost %s (%v)", round, enabled, err)
				}
				continue
			}

			if status.Code(errs[i]) != codes.AlreadyExists {
				t.Errorf("round %d: the losing PutSite = %v, want AlreadyExists", round, errs[i])
			}
			for _, config := range []string{available, enabled} {
				if _, err := os.Lstat(config); !os.IsNotExist(err) {
					t.Errorf("round %d: the losing site left %s (%v)", round, config, err)
				}
			}
		}
		if winners != 1 {
			t.Errorf("round %d: %d PutSite calls succeeded, want 1 (%v)", round, winners, errs)
		}
	}

	sh(t, "/", "nginx", "-t")
}

// A PHP version uninstalled after a site was created must not keep the site from being deleted.
func TestASiteOnAnUninstalledPHPVersionCanBeDeleted(t *testing.T) {
	version := phpVersion(t)
	fpm := "php" + version + "-fpm"
	apt := func(args ...string) {
		sh(t, "/", "env", append([]string{"DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "DPkg::Lock::Timeout=300", "-y", "-q"}, args...)...)
	}

	s := newSite(agentv1.Runtime_RUNTIME_PHP, "php", "uninstalled-php.test", "")
	s.Branch, s.PhpVersion, s.WebDirectory = "", version, "public"
	put, err := sitesClient().PutSite(timeout(t), &agentv1.PutSiteRequest{Site: s, Actor: actor})
	if err != nil {
		t.Fatalf("PutSite: %v", err)
	}
	t.Cleanup(func() {
		sitesClient().DeleteSite(context.Background(), &agentv1.DeleteSiteRequest{Id: s.Id, RemoveFiles: true, Actor: actor})
	})

	pool := "/etc/php/" + version + "/fpm/pool.d/serverdog-" + s.Id + ".conf"
	if _, err := os.Stat(pool); err != nil {
		t.Fatalf("pool: %v", err)
	}

	// The rest of the suite needs this version back.
	t.Cleanup(func() { apt("install", fpm) })
	apt("purge", fpm)
	if _, err := os.Stat("/usr/sbin/php-fpm" + version); !os.IsNotExist(err) {
		t.Fatalf("/usr/sbin/php-fpm%s after the purge: %v", version, err)
	}

	if _, err := sitesClient().DeleteSite(timeout(t), &agentv1.DeleteSiteRequest{Id: s.Id, RemoveFiles: true, Actor: actor}); err != nil {
		t.Fatalf("DeleteSite after uninstalling PHP %s: %v", version, err)
	}

	for _, leftover := range []string{pool, "/etc/nginx/sites-enabled/serverdog-" + s.Id + ".conf", put.Site.Directory} {
		if _, err := os.Lstat(leftover); !os.IsNotExist(err) {
			t.Errorf("%s is still there (%v)", leftover, err)
		}
	}
	if _, err := sitesClient().GetSite(timeout(t), &agentv1.GetSiteRequest{Id: s.Id}); status.Code(err) != codes.NotFound {
		t.Errorf("GetSite after the delete = %v, want NotFound", err)
	}
}
