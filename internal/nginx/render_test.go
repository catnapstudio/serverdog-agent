package nginx

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/site"
)

var update = flag.Bool("update", false, "rewrite golden files")

func base(runtime site.Runtime) site.Site {
	s := site.Site{
		ID:           "abcdefghijkl",
		Runtime:      runtime,
		Domains:      []site.Domain{{Name: "orchard.com", Redirect: site.FromWWW, Primary: true}},
		WebDirectory: "public",
		User:         "serverdog",
		Directory:    "/home/serverdog/orchard.com",
	}
	if runtime == site.PHP {
		s.PHPVersion = "8.4"
	}

	return s
}

var cert = Certificate{Fullchain: "/etc/serverdog/certs/abcdefghijkl/orchard.com/active/fullchain.pem", Key: "/etc/serverdog/certs/abcdefghijkl/orchard.com/active/privkey.pem"}

func cases() map[string]Input {
	secure := base(site.PHP)
	secure.ForceHTTPS = true
	secure.HSTS = true

	node := base(site.Node)
	node.Domains[0].Redirect = site.ToWWW

	static := base(site.Static)
	static.WebDirectory = ""
	static.Domains = []site.Domain{
		{Name: "docs.orchard.com", Redirect: site.NoRedirect, Primary: true},
		{Name: "orchard.dev", Wildcards: true, Redirect: site.FromWWW},
	}

	placeholderPHP := base(site.PHP)
	placeholderPHP.ForceHTTPS, placeholderPHP.HSTS = true, true

	placeholderStatic := base(site.Static)
	placeholderStatic.WebDirectory = ""

	return map[string]Input{
		"php":                          {Site: base(site.PHP)},
		"php-https-forced":             {Site: secure, Certificates: map[string]Certificate{"orchard.com": cert}},
		"node-to-www-https":            {Site: node, HTTP2Directive: true, Certificates: map[string]Certificate{"orchard.com": cert}},
		"static-two-domains":           {Site: static},
		"php-placeholder-https-forced": {Site: placeholderPHP, Placeholder: true, Certificates: map[string]Certificate{"orchard.com": cert}},
		"node-placeholder":             {Site: base(site.Node), Placeholder: true},
		"static-placeholder":           {Site: placeholderStatic, Placeholder: true},
	}
}

func TestGolden(t *testing.T) {
	for name, input := range cases() {
		got := Render(input)
		path := filepath.Join("testdata", name+".conf")

		if *update {
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}

		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run go test ./internal/nginx -update)", name, err)
		}
		if string(got) != string(want) {
			t.Errorf("%s differs from %s:\n%s", name, path, got)
		}
	}
}

func TestPHPPassesTheRealPath(t *testing.T) {
	config := string(Render(Input{Site: base(site.PHP)}))

	for _, line := range []string{
		"root /home/serverdog/orchard.com/current/public;",
		"fastcgi_pass unix:/run/php/serverdog-abcdefghijkl.sock;",
		"fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;",
		"fastcgi_param DOCUMENT_ROOT $realpath_root;",
		"include /etc/nginx/serverdog/acme.conf;",
	} {
		if !strings.Contains(config, line) {
			t.Errorf("missing %q", line)
		}
	}
}

func TestWWWRedirectBlocks(t *testing.T) {
	config := string(Render(Input{Site: base(site.PHP)}))

	if !strings.Contains(config, "server_name www.orchard.com;") || !strings.Contains(config, "return 301 http://orchard.com$request_uri;") {
		t.Errorf("from-www redirect missing:\n%s", config)
	}
}

func TestForcedHTTPSRedirectsButKeepsACME(t *testing.T) {
	config := string(Render(cases()["php-https-forced"]))

	plain := config[:strings.Index(config, "listen 443")]
	if !strings.Contains(plain, "return 301 https://$host$request_uri;") || !strings.Contains(plain, "include /etc/nginx/serverdog/acme.conf;") {
		t.Errorf("port 80 block wrong:\n%s", plain)
	}
	for _, line := range []string{"listen 443 ssl http2;", "ssl_certificate " + cert.Fullchain + ";", `add_header Strict-Transport-Security "max-age=31536000" always;`, "return 301 https://orchard.com$request_uri;"} {
		if !strings.Contains(config, line) {
			t.Errorf("missing %q", line)
		}
	}
}

func TestHTTP2DirectiveForNewNginx(t *testing.T) {
	config := string(Render(cases()["node-to-www-https"]))

	if !strings.Contains(config, "http2 on;") || strings.Contains(config, "ssl http2") {
		t.Errorf("wrong http2 form:\n%s", config)
	}
	if !strings.Contains(config, "include /etc/nginx/serverdog/upstreams/abcdefghijkl.conf;") || !strings.Contains(config, "proxy_pass http://serverdog_abcdefghijkl;") {
		t.Error("node upstream missing")
	}
	if !strings.Contains(config, "server_name www.orchard.com;") || !strings.Contains(config, "return 301 http://www.orchard.com$request_uri;") {
		t.Error("to-www redirect missing")
	}
}

func TestWildcardsAndRootWebDirectory(t *testing.T) {
	config := string(Render(cases()["static-two-domains"]))

	for _, line := range []string{"server_name orchard.dev *.orchard.dev;", "server_name docs.orchard.com;", "root /home/serverdog/orchard.com/current;", "try_files $uri $uri/ =404;"} {
		if !strings.Contains(config, line) {
			t.Errorf("missing %q", line)
		}
	}
	if strings.Contains(config, "www.docs.orchard.com") {
		t.Error("no-redirect domain got a www block")
	}
}

// www-data is in every site user's group, so without this a symlink in one site's web root could serve another
// site's group-readable files.
func TestServedFilesMustBeOwnedLikeTheirLinks(t *testing.T) {
	const directive = "    disable_symlinks if_not_owner;\n"

	for _, runtime := range []site.Runtime{site.PHP, site.Static} {
		config := string(Render(Input{Site: base(runtime)}))
		if strings.Count(config, directive) != 1 {
			t.Errorf("%s config has %d disable_symlinks lines, want one in its serving block:\n%s", runtime, strings.Count(config, directive), config)
		}
	}

	if config := string(Render(Input{Site: base(site.Node)})); strings.Contains(config, "disable_symlinks") {
		t.Errorf("node config serves no files but has disable_symlinks:\n%s", config)
	}
}

func TestThePlaceholderIsServedForEveryRuntime(t *testing.T) {
	for _, runtime := range []site.Runtime{site.PHP, site.Node, site.Static} {
		config := string(Render(Input{Site: base(runtime), Placeholder: true}))

		for _, line := range []string{
			"    root /home/serverdog/orchard.com/placeholder;\n",
			"    try_files $uri /index.html;\n",
			"    disable_symlinks if_not_owner;\n",
			"    include /etc/nginx/serverdog/acme.conf;\n",
		} {
			if !strings.Contains(config, line) {
				t.Errorf("%s placeholder config lacks %q:\n%s", runtime, line, config)
			}
		}

		for _, release := range []string{"/current", "fastcgi_pass", "proxy_pass"} {
			if strings.Contains(config, release) {
				t.Errorf("%s placeholder config serves the release (%q):\n%s", runtime, release, config)
			}
		}
	}
}

func TestThePlaceholderKeepsHTTPSForceHTTPSAndHSTS(t *testing.T) {
	config := string(Render(cases()["php-placeholder-https-forced"]))

	plain := config[:strings.Index(config, "listen 443")]
	if !strings.Contains(plain, "return 301 https://$host$request_uri;") || !strings.Contains(plain, "include /etc/nginx/serverdog/acme.conf;") {
		t.Errorf("port 80 block wrong:\n%s", plain)
	}

	for _, line := range []string{
		"ssl_certificate " + cert.Fullchain + ";",
		`add_header Strict-Transport-Security "max-age=31536000" always;`,
		"root /home/serverdog/orchard.com/placeholder;",
		"return 301 https://orchard.com$request_uri;",
	} {
		if !strings.Contains(config, line) {
			t.Errorf("missing %q:\n%s", line, config)
		}
	}
}

func TestAReverbDomainForwardsToReverb(t *testing.T) {
	s := base(site.PHP)
	s.ForceHTTPS = true
	s.BasicAuth = &site.BasicAuth{Username: "a", Hash: "h"}
	s.ReverbPort = 20004
	s.Domains = append(s.Domains, site.Domain{Name: "ws.orchard.com", Redirect: site.NoRedirect, Reverb: true})

	plain := string(Render(Input{Site: s}))
	reverbBlock := plain[strings.Index(plain, "server_name ws.orchard.com;"):]
	for _, want := range []string{"proxy_pass http://127.0.0.1:20004;", "proxy_set_header Connection $serverdog_connection_upgrade;", "proxy_read_timeout 300s;"} {
		if !strings.Contains(reverbBlock, want) {
			t.Errorf("the Reverb block lacks %q:\n%s", want, reverbBlock)
		}
	}
	if strings.Contains(reverbBlock, "auth_basic") || strings.Contains(reverbBlock, "www.ws.orchard.com") {
		t.Errorf("the Reverb block took the website's password or a www name:\n%s", reverbBlock)
	}

	secure := string(Render(Input{Site: s, Certificates: map[string]Certificate{"ws.orchard.com": cert}}))
	reverbBlocks := secure[strings.Index(secure, "server_name ws.orchard.com;"):]
	if strings.Count(reverbBlocks, "server_name ws.orchard.com;") != 2 || !strings.Contains(reverbBlocks, "return 301 https://$host$request_uri;") || !strings.Contains(reverbBlocks, "listen 443 ssl") {
		t.Errorf("with a certificate, Reverb should redirect to HTTPS and serve it:\n%s", reverbBlocks)
	}
}

func TestOctaneServesFilesAndForwardsTheRest(t *testing.T) {
	s := base(site.PHP)
	s.Octane = true

	config := string(Render(Input{Site: s, OctaneLive: true}))
	for _, want := range []string{
		"include /etc/nginx/serverdog/upstreams/abcdefghijkl.conf;",
		"root /home/serverdog/orchard.com/current/public;",
		"try_files $uri @octane;",
		`location ~ \.php$ {`,
		`location ~ ^/index\.php(/|$) {`,
		`rewrite ^/index\.php/?(.*)$ /$1 last;`,
		"proxy_pass http://serverdog_abcdefghijkl;",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("config lacks %q:\n%s", want, config)
		}
	}
	if strings.Contains(config, "fastcgi_pass") {
		t.Errorf("an Octane site still uses PHP-FPM:\n%s", config)
	}
	// index.php must reach Octane as a path, never as a file: its rule comes before the general .php one.
	if strings.Index(config, `location ~ ^/index\.php`) > strings.Index(config, `location ~ \.php$`) {
		t.Errorf("the index.php rule comes after the .php rule:\n%s", config)
	}
}

// Until a deploy brought an Octane server up, PHP-FPM keeps serving: turning Octane on never takes the site down.
func TestOctaneWaitsForItsFirstDeploy(t *testing.T) {
	s := base(site.PHP)
	s.Octane = true

	config := string(Render(Input{Site: s}))
	if !strings.Contains(config, "fastcgi_pass") || strings.Contains(config, "@octane") || strings.Contains(config, "upstreams") {
		t.Errorf("an Octane site without a live server doesn't use PHP-FPM:\n%s", config)
	}
}

func TestOnlyPresetsWithKnownUploadFoldersBlockPHPInThem(t *testing.T) {
	for preset, want := range map[string]string{
		"laravel":   "location ~* ^/(storage|uploads)/.*\\.(php|phtml|phar)$ {",
		"wordpress": "location ~* ^/wp-content/uploads/.*\\.(php|phtml|phar)$ {",
		"symfony":   "location ~* ^/uploads/.*\\.(php|phtml|phar)$ {",
		"php":       "",
	} {
		if got := uploadFolders(preset); (got == "") != (want == "") {
			t.Errorf("%s: folders %q, want a rule: %v", preset, got, want != "")
		} else if got != "" && "location ~* ^/"+got+"/.*\\.(php|phtml|phar)$ {" != want {
			t.Errorf("%s: got %q", preset, got)
		}
	}
}

func TestASitesOwnRulesReplaceOnlyTheGeneratedRules(t *testing.T) {
	s := site.Site{
		ID: "abcdefghijkl", Runtime: site.PHP, Preset: "laravel", Directory: "/home/serverdog/shop.test", WebDirectory: "public",
		Domains:    []site.Domain{{Name: "shop.test", Primary: true}},
		Redirects:  []site.PathRedirect{{From: "/old", To: "/new", Permanent: true}},
		NginxRules: "root /srv/custom;\nlocation / {\n    return 204;\n}\n",
	}

	got := string(Render(Input{Site: s}))

	for _, want := range []string{
		"# shop.test: the site", "server_name shop.test;", "access_log /var/log/nginx/serverdog-abcdefghijkl-access.log;",
		"location = /old { return 301 /new; }", "    root /srv/custom;\n    location / {\n        return 204;\n    }\n}",
		"# www.shop.test: redirects to shop.test",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "fastcgi_pass") || strings.Contains(got, "/home/serverdog/shop.test/current") {
		t.Errorf("the generated rules are still there:\n%s", got)
	}

	// Until a release is live the placeholder page is served, whatever the rules say.
	if placeholder := string(Render(Input{Site: s, Placeholder: true})); strings.Contains(placeholder, "/srv/custom") {
		t.Errorf("the placeholder page used the site's rules:\n%s", placeholder)
	}

	s.NginxRules = ""
	if rules := DefaultRules(s, false); !strings.HasPrefix(rules, "root /home/serverdog/shop.test/current/public;\n") || !strings.Contains(rules, "fastcgi_pass") || strings.Contains(rules, "serverdog-abcdefghijkl-access.log") {
		t.Errorf("default rules = %s", rules)
	}
}
