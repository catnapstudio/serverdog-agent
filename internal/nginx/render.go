// Package nginx generates a site's Nginx configuration: one server block per domain and port,
// plus a block for the www (or bare) name that redirects.
package nginx

import (
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/nodeservice"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

var Check = system.Command{Name: "nginx", Args: []string{"-t"}}

// Certificate is the active certificate of one domain (stable paths, see plan 2).
type Certificate struct {
	Fullchain string
	Key       string
}

type Input struct {
	Site site.Site
	// HTTP2Directive is true on Nginx 1.25.1+, which takes "http2 on;" instead of "listen ... http2".
	HTTP2Directive bool
	// Certificates maps a domain name to its active certificate. Domains without one get HTTP only.
	Certificates map[string]Certificate
	// Placeholder serves the site's placeholder page instead of its releases, until its first release is live.
	Placeholder bool
	// OctaneLive sends an Octane site's requests to its Octane server. Until a deploy brought one up, PHP-FPM serves.
	OctaneLive bool
}

// Render returns the site's configuration file.
func Render(in Input) []byte {
	s := in.Site
	var b strings.Builder

	fmt.Fprintf(&b, "# Managed by ServerDog for site %s.\n", s.ID)
	b.WriteString("# Saving this file from ServerDog marks it customised, and ServerDog stops regenerating it.\n")

	if s.Runtime == site.Node || in.OctaneLive {
		fmt.Fprintf(&b, "\ninclude %s;\n", paths.NginxUpstream(s.ID))
	}
	if s.Runtime == site.Balancer {
		b.WriteString(upstream(s))
	}

	for _, domain := range s.Domains {
		certificate, secure := in.Certificates[domain.Name]
		if domain.Reverb {
			reverb(&b, s, domain.Name, certificate, secure, in.HTTP2Directive)
			continue
		}

		forced := secure && s.ForceHTTPS
		served, from, to := names(domain)

		// Each block is labelled: a site with a certificate and a www redirect has four, and only one is the site.
		name := strings.Join(served, ", ")
		switch {
		case forced:
			server(&b, name+" over HTTP: redirects to HTTPS", plainListen, served, acme, redirect("https://$host$request_uri"))
		case secure:
			server(&b, name+" over HTTP: the site", plainListen, served, acme, body(s, in.Placeholder, in.OctaneLive))
		default:
			server(&b, name+": the site", plainListen, served, acme, body(s, in.Placeholder, in.OctaneLive))
		}
		if secure {
			server(&b, name+" over HTTPS: the site", secureListen(in.HTTP2Directive), served, tls(certificate, s.HSTS), body(s, in.Placeholder, in.OctaneLive))
		}

		if from == "" {
			continue
		}

		scheme := "http"
		if forced {
			scheme = "https"
		}
		if secure {
			server(&b, from+" over HTTP: redirects to "+to, plainListen, []string{from}, acme, redirect(scheme+"://"+to+"$request_uri"))
			server(&b, from+" over HTTPS: redirects to "+to, secureListen(in.HTTP2Directive), []string{from}, tls(certificate, false), redirect("https://"+to+"$request_uri"))
		} else {
			server(&b, from+": redirects to "+to, plainListen, []string{from}, acme, redirect(scheme+"://"+to+"$request_uri"))
		}
	}

	return []byte(b.String())
}

// names returns the names a domain serves, and the name that redirects (from) to which one (to).
func names(domain site.Domain) (served []string, from, to string) {
	bare, www := domain.Name, "www."+domain.Name

	switch domain.Redirect {
	case site.ToWWW:
		served, from, to = []string{www}, bare, www
	case site.NoRedirect:
		served = []string{bare}
	default:
		served, from, to = []string{bare}, www, bare
	}

	if domain.Wildcards {
		served = append(served, "*."+bare)
	}

	return served, from, to
}

var (
	plainListen = []string{"listen 80;", "listen [::]:80;"}
	acme        = []string{"include " + paths.NginxACME + ";"}
)

func secureListen(directive bool) []string {
	if directive {
		return []string{"listen 443 ssl;", "listen [::]:443 ssl;", "http2 on;"}
	}

	return []string{"listen 443 ssl http2;", "listen [::]:443 ssl http2;"}
}

func tls(certificate Certificate, hsts bool) []string {
	lines := []string{
		"ssl_certificate " + certificate.Fullchain + ";",
		"ssl_certificate_key " + certificate.Key + ";",
		"include " + paths.NginxTLS + ";",
	}
	if hsts {
		lines = append(lines, `add_header Strict-Transport-Security "max-age=31536000" always;`)
	}

	return lines
}

func redirect(target string) []string {
	return []string{"location / {", "    return 301 " + target + ";", "}"}
}

// body is what a site's server block holds after its names and certificate: the managed part, then the site's rules,
// its own when it has them. The placeholder page ignores them: nothing they point at exists yet.
func body(s site.Site, placeholder, octaneLive bool) []string {
	if s.NginxRules != "" && (s.Runtime == site.Balancer || !placeholder) {
		return append(managed(s), strings.Split(strings.Trim(s.NginxRules, "\n"), "\n")...)
	}

	return append(managed(s), rules(s, placeholder, octaneLive)...)
}

// DefaultRules are the rules ServerDog generates for a site once it has a release: what its own rules start from.
func DefaultRules(s site.Site, octaneLive bool) string {
	return strings.Join(rules(s, false, octaneLive), "\n") + "\n"
}

// managed is the part of a site's server block that follows its settings: logs, password protection and redirects.
func managed(s site.Site) []string {
	lines := []string{
		fmt.Sprintf("access_log /var/log/nginx/serverdog-%s-access.log;", s.ID),
		fmt.Sprintf("error_log /var/log/nginx/serverdog-%s-error.log;", s.ID),
		"",
	}

	if s.BasicAuth != nil {
		lines = append(lines, `auth_basic "Protected";`, "auth_basic_user_file "+paths.NginxPasswords(s.ID)+";", "")
	}
	for _, r := range s.Redirects {
		status := "302"
		if r.Permanent {
			status = "301"
		}
		lines = append(lines, "location = "+r.From+" { return "+status+" "+r.To+"; }")
	}
	if len(s.Redirects) > 0 {
		lines = append(lines, "")
	}

	return lines
}

// rules are the site's own part of its server block: where its files are and how requests reach its code.
func rules(s site.Site, placeholder, octaneLive bool) []string {
	var lines []string

	// www-data is in every site user's group: a symlink to another site's files must not be followed.
	// Every link on the path, the web root's own included (current, a committed public link), must be owned like its
	// target. The site user creates them all, pointing at its own files; /home and /home/<user> are real directories.
	symlinks := "disable_symlinks if_not_owner;"

	// A load-balanced site has no releases, so never a placeholder page.
	if s.Runtime == site.Balancer {
		scheme := "http"
		if s.BackendTLS {
			scheme = "https"
		}
		lines = append(lines,
			"location / {",
			"    proxy_pass "+scheme+"://"+upstreamName(s.ID)+";",
			"    proxy_http_version 1.1;",
			"    proxy_set_header Host $host;",
			"    proxy_set_header X-Real-IP $remote_addr;",
			"    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
			"    proxy_set_header X-Forwarded-Proto $scheme;",
			"    proxy_set_header X-Forwarded-Port $server_port;",
			"    proxy_set_header Upgrade $http_upgrade;",
			"    proxy_set_header Connection $serverdog_connection_upgrade;",
		)
		if s.BackendTLS {
			lines = append(lines, "    proxy_ssl_server_name on;", "    proxy_ssl_name $host;")
		}
		return append(lines, "    proxy_next_upstream error timeout http_502 http_503 http_504;", "}")
	}

	// Every runtime serves the placeholder page the same way until a release is live: nothing runs yet.
	if placeholder {
		return append(lines,
			"root "+paths.Placeholder(s.Directory)+";",
			symlinks,
			"index index.html;",
			"charset utf-8;",
			"",
			"location / {",
			"    try_files $uri /index.html;",
			"}",
		)
	}

	root := path.Join(s.Directory, "current", s.WebDirectory)
	hidden := []string{"", `location ~ /\.(?!well-known).* {`, "    deny all;", "}"}

	switch {
	case s.Runtime == site.PHP && octaneLive:
		lines = append(lines,
			"root "+root+";",
			symlinks,
			"charset utf-8;",
			"",
			// A file the release has is served as it is; everything else goes to Octane.
			"location / {",
			"    try_files $uri @octane;",
			"}",
			"",
			// Asked for index.php as a file, FrankenPHP runs it outside its workers, and that sometimes kills the whole
			// server (seen with FrankenPHP 1.13.5). Octane gets the path after it instead: / for /index.php, /up for
			// /index.php/up. First of the regex locations, so it wins over the one below.
			`location ~ ^/index\.php(/|$) {`,
			"    rewrite ^/index\\.php/?(.*)$ /$1 last;",
			"}",
			"",
			// Any other .php path goes to Octane too, never out as a file.
			`location ~ \.php$ {`,
			"    try_files /serverdog-octane-never-a-file @octane;",
			"}",
			"",
			"location = /favicon.ico { access_log off; log_not_found off; try_files $uri @octane; }",
			"location = /robots.txt { access_log off; log_not_found off; try_files $uri @octane; }",
			"",
			"location @octane {",
			"    proxy_pass http://"+nodeservice.UpstreamName(s.ID)+";",
			"    proxy_http_version 1.1;",
			"    proxy_set_header Host $host;",
			"    proxy_set_header X-Real-IP $remote_addr;",
			"    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
			"    proxy_set_header X-Forwarded-Proto $scheme;",
			"    proxy_set_header X-Forwarded-Port $server_port;",
			"    proxy_set_header Upgrade $http_upgrade;",
			"    proxy_set_header Connection $serverdog_connection_upgrade;",
			"}",
		)
		return append(lines, hidden...)

	case s.Runtime == site.PHP:
		lines = append(lines,
			"root "+root+";",
			symlinks,
			"index index.php index.html;",
			"charset utf-8;",
			`add_header X-Frame-Options "SAMEORIGIN" always;`,
			`add_header X-Content-Type-Options "nosniff" always;`,
			"",
			"location / {",
			"    try_files $uri $uri/ /index.php?$query_string;",
			"}",
			"",
			"location = /favicon.ico { access_log off; log_not_found off; }",
			"location = /robots.txt { access_log off; log_not_found off; }",
			"",
		)
		if writable := uploadFolders(s.Preset); writable != "" {
			// A file someone managed to upload must never run as code.
			lines = append(lines, `location ~* ^/`+writable+`/.*\.(php|phtml|phar)$ {`, "    deny all;", "}", "")
		}
		lines = append(lines,
			// Dumps and editor leftovers that end up in a web folder by accident.
			`location ~* \.(sql|sqlite|bak|old|swp)$ {`,
			"    deny all;",
			"}",
			"",
			`location ~ \.php$ {`,
			"    try_files $uri =404;",
			"    fastcgi_pass unix:"+paths.FPMSocket(s.ID)+";",
			"    fastcgi_index index.php;",
			"    include fastcgi_params;",
			"    fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;",
			"    fastcgi_param DOCUMENT_ROOT $realpath_root;",
			"    fastcgi_hide_header X-Powered-By;",
			// Room for large headers and cookies, which otherwise end in a 502.
			"    fastcgi_buffers 16 16k;",
			"    fastcgi_buffer_size 32k;",
			"}",
		)
		return append(lines, hidden...)

	case s.Runtime == site.Node:
		return append(lines,
			"location / {",
			"    proxy_pass http://"+nodeservice.UpstreamName(s.ID)+";",
			"    proxy_http_version 1.1;",
			"    proxy_set_header Host $host;",
			"    proxy_set_header X-Real-IP $remote_addr;",
			"    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
			"    proxy_set_header X-Forwarded-Proto $scheme;",
			"    proxy_set_header Upgrade $http_upgrade;",
			"    proxy_set_header Connection $serverdog_connection_upgrade;",
			"}",
		)

	default:
		lines = append(lines,
			"root "+root+";",
			symlinks,
			"index index.html;",
			"charset utf-8;",
			"",
			"location / {",
			"    try_files $uri $uri/ =404;",
			"}",
		)
		return append(lines, hidden...)
	}
}

// reverb forwards a domain to the site's Reverb server, always over HTTPS once it has a certificate: browsers refuse a
// plain WebSocket from an HTTPS page. Password protection and redirects are the website's, not Reverb's.
func reverb(b *strings.Builder, s site.Site, name string, certificate Certificate, secure, http2Directive bool) {
	proxy := []string{
		fmt.Sprintf("access_log /var/log/nginx/serverdog-%s-reverb-access.log;", s.ID),
		fmt.Sprintf("error_log /var/log/nginx/serverdog-%s-error.log;", s.ID),
		"",
		"location / {",
		fmt.Sprintf("    proxy_pass http://127.0.0.1:%d;", s.ReverbPort),
		"    proxy_http_version 1.1;",
		"    proxy_set_header Host $host;",
		"    proxy_set_header X-Real-IP $remote_addr;",
		"    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
		"    proxy_set_header X-Forwarded-Proto $scheme;",
		"    proxy_set_header Upgrade $http_upgrade;",
		"    proxy_set_header Connection $serverdog_connection_upgrade;",
		// Clients ping at least every two minutes; a quiet socket must outlive that.
		"    proxy_read_timeout 300s;",
		"    proxy_send_timeout 300s;",
		"}",
	}

	if !secure {
		server(b, name+": the Reverb server", plainListen, []string{name}, acme, proxy)
		return
	}

	server(b, name+" over HTTP: redirects to HTTPS", plainListen, []string{name}, acme, redirect("https://$host$request_uri"))
	server(b, name+" over HTTPS: the Reverb server", secureListen(http2Directive), []string{name}, tls(certificate, s.HSTS), proxy)
}

func server(b *strings.Builder, label string, listen, names []string, sections ...[]string) {
	fmt.Fprintf(b, "\n# %s\nserver {\n", label)
	for _, line := range listen {
		fmt.Fprintf(b, "    %s\n", line)
	}
	fmt.Fprintf(b, "    server_name %s;\n", strings.Join(names, " "))

	for _, section := range sections {
		b.WriteString("\n")
		for _, line := range section {
			if line == "" {
				b.WriteString("\n")
				continue
			}
			fmt.Fprintf(b, "    %s\n", line)
		}
	}

	b.WriteString("}\n")
}

func upstreamName(siteID string) string { return "serverdog_balancer_" + siteID }

// upstream is a load-balanced site's backends. Nginx stops sending to one for 30 s after 3 failed tries.
// shortcut: no upstream keepalive, since the shared Connection map closes plain requests; add one if backends tire.
func upstream(s site.Site) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nupstream %s {\n", upstreamName(s.ID))

	switch s.Balancing {
	case site.LeastConnections:
		b.WriteString("    least_conn;\n")
	case site.IPHash:
		b.WriteString("    ip_hash;\n")
	}

	for _, backend := range s.Backends {
		fmt.Fprintf(&b, "    server %s weight=%d max_fails=3 fail_timeout=30s", net.JoinHostPort(backend.Address, strconv.Itoa(backend.Port)), backend.Weight)
		if backend.Backup {
			b.WriteString(" backup")
		}
		b.WriteString(";\n")
	}
	b.WriteString("}\n")

	return b.String()
}

// uploadFolders is the pattern for the web folders a preset's app writes uploads into, or "" when it isn't known:
// a plain PHP site may keep real pages anywhere.
func uploadFolders(preset string) string {
	switch preset {
	case "laravel", "statamic":
		return "(storage|uploads)"
	case "symfony":
		return "uploads"
	case "wordpress":
		return "wp-content/uploads"
	default:
		return ""
	}
}
