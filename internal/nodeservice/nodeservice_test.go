package nodeservice

import (
	"strings"
	"testing"
)

func TestRenderUnit(t *testing.T) {
	unit := string(RenderUnit("abcdefghijkl", "serverdog"))

	for _, line := range []string{
		"User=serverdog",
		"EnvironmentFile=/etc/serverdog/sites/abcdefghijkl/%i.env",
		"ExecStart=/etc/serverdog/sites/abcdefghijkl/start.sh",
		"Restart=always",
	} {
		if !strings.Contains(unit, line+"\n") {
			t.Errorf("unit lacks %q:\n%s", line, unit)
		}
	}

	// systemd reads EnvironmentFile= as root and follows symlinks, so no site-owned file may be listed.
	if strings.Count(unit, "EnvironmentFile=") != 1 {
		t.Errorf("unit lists environment files other than the root-owned port file:\n%s", unit)
	}
}

func TestNames(t *testing.T) {
	if Template("abc") != "serverdog-site-abc@.service" || Instance("abc", 20001) != "serverdog-site-abc@20001.service" {
		t.Error(Template("abc"), Instance("abc", 20001))
	}
	if PortEnv("abc", 20001) != "/etc/serverdog/sites/abc/20001.env" || StartScript("abc") != "/etc/serverdog/sites/abc/start.sh" {
		t.Error(PortEnv("abc", 20001), StartScript("abc"))
	}
}

func TestRenderPortEnvAndUpstream(t *testing.T) {
	env := string(RenderPortEnv(20001, "/home/serverdog/app.com/releases/20261016-181245"))
	for _, line := range []string{"PORT=20001", "HOST=127.0.0.1", "HOSTNAME=127.0.0.1", "NODE_ENV=production", "PYTHONUNBUFFERED=1", "SERVERDOG_RELEASE_DIRECTORY=/home/serverdog/app.com/releases/20261016-181245"} {
		if !strings.Contains(env, line+"\n") {
			t.Errorf("env lacks %q", line)
		}
	}

	upstream := string(RenderUpstream("abc", 20001))
	if !strings.Contains(upstream, "upstream serverdog_abc {") || !strings.Contains(upstream, "server 127.0.0.1:20001;") {
		t.Error(upstream)
	}
}

func TestUpstreamPortReadsWhatRenderUpstreamWrote(t *testing.T) {
	if port, ok := UpstreamPort(RenderUpstream("abcdefghijkl", 20001)); !ok || port != 20001 {
		t.Errorf("UpstreamPort = %d %v, want 20001", port, ok)
	}

	for _, content := range []string{"", "upstream serverdog_x {\n}\n", "    server 127.0.0.1:abc;\n", "    server 127.0.0.1:20000;\n    server 127.0.0.1:20001;\n"} {
		if port, ok := UpstreamPort([]byte(content)); ok {
			t.Errorf("UpstreamPort(%q) = %d, want none", content, port)
		}
	}
}

func TestStartScriptExecsTheCommandInTheRelease(t *testing.T) {
	script := string(RenderStartScript("npm run start -- -H 127.0.0.1", ""))

	if !strings.HasPrefix(script, "#!/bin/sh\n") || !strings.Contains(script, `cd "${SERVERDOG_RELEASE_DIRECTORY:?}" || exit 1`) || !strings.HasSuffix(script, "exec npm run start -- -H 127.0.0.1\n") {
		t.Error(script)
	}

	if strings.Contains(script, "eval") {
		t.Errorf("a site without an environment file still loads one:\n%s", script)
	}
}

func TestStartScriptLoadsTheEnvironmentAsTheSiteUser(t *testing.T) {
	script := string(RenderStartScript("npm run start", "/home/serverdog/app.com/shared/.env"))

	want := "exports=\"$(/usr/local/bin/serverdog-agent env-exports '/home/serverdog/app.com/shared/.env')\" || exit 1\neval \"$exports\"\n"
	if !strings.Contains(script, want) {
		t.Fatalf("script lacks %q:\n%s", want, script)
	}

	cd := strings.Index(script, "cd ")
	load := strings.Index(script, "exports=")
	eval := strings.Index(script, "eval ")
	exec := strings.Index(script, "exec ")
	if !(cd < load && load < eval && eval < exec) {
		t.Errorf("want cd, then load, then eval, then exec:\n%s", script)
	}
}

func TestStartScriptQuotesTheEnvironmentPath(t *testing.T) {
	script := string(RenderStartScript("npm run start", "/home/serverdog/it's/.env"))

	if !strings.Contains(script, `'/home/serverdog/it'\''s/.env'`) {
		t.Errorf("environment path is not single-quote escaped:\n%s", script)
	}
}
