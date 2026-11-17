package phpfpm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
)

func TestRenderPool(t *testing.T) {
	pool := string(RenderPool("abcdefghijkl", "serverdog", 25))

	for _, line := range []string{
		"[serverdog-abcdefghijkl]",
		"user = serverdog",
		"group = serverdog",
		"listen = /run/php/serverdog-abcdefghijkl.sock",
		"listen.owner = www-data",
		"listen.group = www-data",
		"listen.mode = 0600",
		"pm = ondemand",
		"pm.max_children = 25",
	} {
		if !strings.Contains(pool, line+"\n") {
			t.Errorf("pool lacks %q:\n%s", line, pool)
		}
	}
}

func TestCommandsUseTheVersion(t *testing.T) {
	if c := Check("8.4"); c.Name != "/usr/sbin/php-fpm8.4" || c.Args[0] != "-t" {
		t.Errorf("Check = %+v", c)
	}
	if c := Reload("8.4"); strings.Join(c.Args, " ") != "reload php8.4-fpm" {
		t.Errorf("Reload = %+v", c)
	}
	if Binary("8.3") != "/usr/bin/php8.3" {
		t.Error(Binary("8.3"))
	}
	if !strings.Contains(string(RenderComposer("8.3")), `exec /usr/bin/php8.3 /usr/local/bin/composer "$@"`) {
		t.Error(string(RenderComposer("8.3")))
	}
}

func TestInstalledNeedsTheBinaryAndTheUnit(t *testing.T) {
	root := t.TempDir()
	p := paths.Paths{Root: root}
	put := func(logical string) {
		if err := os.MkdirAll(filepath.Dir(p.File(logical)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p.File(logical), nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if Installed(p, "8.4") {
		t.Error("installed with neither the binary nor the unit")
	}

	put("/usr/sbin/php-fpm8.4")
	if Installed(p, "8.4") {
		t.Error("installed without the unit")
	}

	put("/usr/lib/systemd/system/php8.4-fpm.service")
	if !Installed(p, "8.4") {
		t.Error("not installed with the binary and the unit")
	}
	if Installed(p, "8.3") {
		t.Error("8.3 installed because 8.4 is")
	}

	put("/lib/systemd/system/php8.3-fpm.service")
	if Installed(p, "8.3") {
		t.Error("installed without the binary")
	}
	put("/usr/sbin/php-fpm8.3")
	if !Installed(p, "8.3") {
		t.Error("a unit under /lib doesn't count")
	}
}
