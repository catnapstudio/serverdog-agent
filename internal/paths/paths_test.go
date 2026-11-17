package paths

import "testing"

func TestFileJoinsUnderRoot(t *testing.T) {
	p := Paths{Root: "/tmp/root"}

	if got := p.File(SiteDirectory("serverdog", "example.com")); got != "/tmp/root/home/serverdog/example.com" {
		t.Errorf("File = %q", got)
	}

	if got := (Paths{Root: "/"}).File(StateDir); got != "/var/lib/serverdog" {
		t.Errorf("production File = %q", got)
	}
}

func TestLogicalPaths(t *testing.T) {
	cases := map[string]string{
		DeployLog("s1", "d1"):                      "/var/lib/serverdog/deploys/s1/d1.log",
		PendingKeyDir("s1"):                        "/var/lib/serverdog/keys/s1",
		DeployKey("serverdog", "s1"):               "/home/serverdog/.ssh/serverdog-s1",
		SiteKnownHosts("serverdog", "s1"):          "/home/serverdog/.ssh/serverdog-s1.known_hosts",
		SiteEtcDir("s1"):                           "/etc/serverdog/sites/s1",
		NginxSiteAvailable("s1"):                   "/etc/nginx/sites-available/serverdog-s1.conf",
		NginxSiteEnabled("s1"):                     "/etc/nginx/sites-enabled/serverdog-s1.conf",
		NginxUpstream("s1"):                        "/etc/nginx/serverdog/upstreams/s1.conf",
		FPMPool("8.4", "s1"):                       "/etc/php/8.4/fpm/pool.d/serverdog-s1.conf",
		FPMSocket("s1"):                            "/run/php/serverdog-s1.sock",
		PHPHelperBin("8.4"):                        "/usr/local/lib/serverdog/php/8.4/bin",
		SystemdUnit("serverdog-site-s1@.service"):  "/etc/systemd/system/serverdog-site-s1@.service",
		Placeholder("/home/serverdog/example.com"): "/home/serverdog/example.com/placeholder",
	}

	for got, want := range cases {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestCertificatePaths(t *testing.T) {
	cases := map[string]string{
		SiteCertificates("s1"):                    "/etc/serverdog/certs/s1",
		CertificateDir("s1", "c1"):                "/etc/serverdog/certs/s1/c1",
		ActiveCertificateDir("s1", "orchard.com"): "/etc/serverdog/certs/s1/orchard.com/active",
	}

	for got, want := range cases {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
