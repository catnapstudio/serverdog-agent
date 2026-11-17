package databases

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

func readOnlyCreator(engine string, counts string) (Creator, *systemtest.Fake, *[]string) {
	fake := &systemtest.Fake{}
	var scripts []string
	answer := func(cmd system.Command) (system.Result, error) {
		var b strings.Builder
		if cmd.Stdin != nil {
			buf := new(strings.Builder)
			_, _ = io.Copy(buf, cmd.Stdin)
			b.WriteString(buf.String())
		}
		scripts = append(scripts, strings.Join(cmd.Args, " ")+"\n"+b.String())
		switch {
		case strings.Contains(b.String(), "SELECT COUNT(*)"), strings.Contains(b.String(), "SELECT count(*)"):
			return system.Result{Output: []byte(counts)}, nil
		case strings.Contains(b.String(), "pg_get_userbyid"):
			return system.Result{Output: []byte("shop\n")}, nil
		}
		return system.Result{}, nil
	}
	fake.Handle("mariadb", answer)
	fake.Handle("runuser", answer)

	return Creator{Runner: fake, Engine: func(context.Context) string { return engine }}, fake, &scripts
}

func TestReadOnlyUserGetsSelectOnly(t *testing.T) {
	c, _, scripts := readOnlyCreator("mariadb", "1\n0\n")

	if err := c.CreateReadOnlyUser(context.Background(), "shop", "reports", "abcdefghijklmnop1234"); err != nil {
		t.Fatal(err)
	}

	all := strings.Join(*scripts, "\n")
	if !strings.Contains(all, "GRANT SELECT, SHOW VIEW ON `shop`.* TO 'reports'@'localhost';") || strings.Contains(all, "ALL PRIVILEGES") {
		t.Errorf("scripts:\n%s", all)
	}
}

func TestReadOnlyPostgresUserReadsLaterTablesToo(t *testing.T) {
	c, _, scripts := readOnlyCreator("postgres", "1\n0\n")

	if err := c.CreateReadOnlyUser(context.Background(), "shop", "reports", "abcdefghijklmnop1234"); err != nil {
		t.Fatal(err)
	}

	all := strings.Join(*scripts, "\n")
	for _, want := range []string{"-d shop", `GRANT SELECT ON ALL TABLES IN SCHEMA public TO "reports";`, `ALTER DEFAULT PRIVILEGES FOR ROLE "shop" IN SCHEMA public GRANT SELECT ON TABLES TO "reports";`} {
		if !strings.Contains(all, want) {
			t.Errorf("scripts lack %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, "abcdefghijklmnop1234") {
		t.Error("the password reached PostgreSQL instead of its verifier")
	}
}

func TestReadOnlyUserNeedsTheDatabaseAndANewName(t *testing.T) {
	var invalid *site.InvalidError
	var exists *ExistsError

	c, _, _ := readOnlyCreator("mariadb", "0\n0\n")
	if err := c.CreateReadOnlyUser(context.Background(), "shop", "reports", "abcdefghijklmnop1234"); !errors.As(err, &invalid) {
		t.Errorf("missing database: err = %v", err)
	}

	c, _, _ = readOnlyCreator("mariadb", "1\n1\n")
	if err := c.CreateReadOnlyUser(context.Background(), "shop", "reports", "abcdefghijklmnop1234"); !errors.As(err, &exists) {
		t.Errorf("existing user: err = %v", err)
	}

	if err := c.CreateReadOnlyUser(context.Background(), "mysql", "reports", "abcdefghijklmnop1234"); !errors.As(err, &invalid) {
		t.Errorf("system database: err = %v", err)
	}
}
