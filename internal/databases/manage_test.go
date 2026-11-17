package databases

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

// scripted answers each SQL script sent on stdin with the first answer whose key it contains, and records the scripts.
func scripted(answers map[string]string) (*systemtest.Fake, *[]string) {
	fake := &systemtest.Fake{}
	var scripts []string

	answer := func(c system.Command) (system.Result, error) {
		sql, _ := io.ReadAll(c.Stdin)
		scripts = append(scripts, string(sql))
		for key, output := range answers {
			if strings.Contains(string(sql), key) {
				return system.Result{Output: []byte(output)}, nil
			}
		}
		return system.Result{}, nil
	}
	fake.Handle("mariadb", answer)
	fake.Handle("runuser", answer)

	return fake, &scripts
}

func TestTheListLeavesOutTheEnginesOwn(t *testing.T) {
	fake, _ := scripted(map[string]string{
		"SCHEMATA":   "information_schema\nmysql\nshop\nperformance_schema\nsys\n",
		"mysql.user": "mariadb.sys\nmysql\nroot\nshop\n",
	})

	listing, err := Creator{Runner: fake, Engine: func(context.Context) string { return "mariadb" }}.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(listing.Databases, ",") != "shop" || strings.Join(listing.Users, ",") != "shop" {
		t.Errorf("listing = %+v", listing)
	}
}

func TestAMySQLUserIsChangedOnEveryHost(t *testing.T) {
	fake, scripts := scripted(map[string]string{"SELECT Host": "localhost\n127.0.0.1\n"})
	c := Creator{Runner: fake, Engine: func(context.Context) string { return "mariadb" }}

	if err := c.SetPassword(ctx, "shop", password); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteUser(ctx, "shop"); err != nil {
		t.Fatal(err)
	}

	all := strings.Join(*scripts, "")
	if !strings.Contains(all, "ALTER USER 'shop'@'localhost' IDENTIFIED BY '"+password+"';\nALTER USER 'shop'@'127.0.0.1'") {
		t.Errorf("scripts:\n%s", all)
	}
	if !strings.Contains(all, "DROP USER 'shop'@'localhost', 'shop'@'127.0.0.1';") {
		t.Errorf("scripts:\n%s", all)
	}
	for _, c := range fake.Calls() {
		if strings.Contains(strings.Join(c.Args, " "), password) {
			t.Errorf("the password was an argument: %v", c.Args)
		}
	}
}

func TestPostgresGetsAVerifierAndAForcedDrop(t *testing.T) {
	fake, scripts := scripted(nil)
	c := Creator{Runner: fake, Engine: func(context.Context) string { return "postgres" }}

	if err := c.SetPassword(ctx, "shop", password); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteDatabase(ctx, "shop"); err != nil {
		t.Fatal(err)
	}

	all := strings.Join(*scripts, "")
	if strings.Contains(all, password) || !strings.Contains(all, "PASSWORD 'SCRAM-SHA-256$") || !strings.Contains(all, `DROP DATABASE IF EXISTS "shop" WITH (FORCE);`) {
		t.Errorf("scripts:\n%s", all)
	}
}

func TestTheEnginesOwnAndOddNamesAreRefused(t *testing.T) {
	fake, scripts := scripted(map[string]string{"SELECT Host": "localhost\nevil'host\n"})
	c := Creator{Runner: fake, Engine: func(context.Context) string { return "mariadb" }}

	for _, err := range []error{
		c.DeleteDatabase(ctx, "mysql"),
		c.DeleteDatabase(ctx, "shop`; DROP DATABASE x; --"),
		c.DeleteUser(ctx, "root"),
		c.SetPassword(ctx, "shop", "short"),
		c.DeleteUser(ctx, "shop"),
	} {
		if err == nil {
			t.Error("accepted")
		}
	}
	for _, script := range *scripts {
		if strings.Contains(script, "DROP") {
			t.Errorf("ran %q", script)
		}
	}
}
