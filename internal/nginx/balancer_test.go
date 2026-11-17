package nginx

import (
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/site"
)

func TestBalancedSiteProxiesToItsBackends(t *testing.T) {
	s := site.Site{
		ID: "abcdefghijkl", Runtime: site.Balancer, Directory: "/home/serverdog/shop.test", Balancing: site.LeastConnections,
		Domains: []site.Domain{{Name: "shop.test", Redirect: site.NoRedirect}},
		Backends: []site.Backend{
			{Address: "10.0.0.2", Port: 80, Weight: 2},
			{Address: "fd00::3", Port: 8080, Weight: 1, Backup: true},
		},
	}

	// The placeholder never shows: a balanced site has no releases.
	config := string(Render(Input{Site: s, Placeholder: true}))

	for _, want := range []string{
		"upstream serverdog_balancer_abcdefghijkl {\n    least_conn;\n    server 10.0.0.2:80 weight=2 max_fails=3 fail_timeout=30s;\n    server [fd00::3]:8080 weight=1 max_fails=3 fail_timeout=30s backup;\n}",
		"proxy_pass http://serverdog_balancer_abcdefghijkl;",
		"proxy_set_header X-Forwarded-Proto $scheme;",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("config lacks %q:\n%s", want, config)
		}
	}
	if strings.Contains(config, "root ") || strings.Contains(config, "proxy_ssl_server_name") {
		t.Errorf("config serves files or speaks TLS:\n%s", config)
	}

	s.BackendTLS = true
	if config := string(Render(Input{Site: s})); !strings.Contains(config, "proxy_pass https://serverdog_balancer_abcdefghijkl;") || !strings.Contains(config, "proxy_ssl_name $host;") {
		t.Errorf("TLS config:\n%s", config)
	}
}
