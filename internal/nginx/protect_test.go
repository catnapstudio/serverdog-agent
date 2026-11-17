package nginx

import (
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/site"
)

func TestProtectedSiteWithRedirects(t *testing.T) {
	s := site.Site{
		ID: "abcdefghijkl", Runtime: site.PHP, Directory: "/home/serverdog/shop.test",
		Domains:   []site.Domain{{Name: "shop.test", Redirect: site.NoRedirect}},
		BasicAuth: &site.BasicAuth{Username: "client", Hash: "$2a$10$x"},
		Redirects: []site.PathRedirect{{From: "/old", To: "/new", Permanent: true}, {From: "/docs", To: "https://docs.example.com/"}},
	}

	config := string(Render(Input{Site: s}))

	for _, want := range []string{
		`auth_basic "Protected";`,
		"auth_basic_user_file /etc/nginx/serverdog/passwords/abcdefghijkl;",
		"location = /old { return 301 /new; }",
		"location = /docs { return 302 https://docs.example.com/; }",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("config lacks %q:\n%s", want, config)
		}
	}
}
