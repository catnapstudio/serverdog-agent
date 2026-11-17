package databases

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

var ctx = context.Background()

const password = "Zr8kQ2mVx7LpT4nWb9Ys"

// recorder answers the existence query with counts and records every script sent over stdin. Login tests (psql, or
// the engine's client without stdin) are recorded too, and log in unless login says otherwise.
type recorder struct {
	fake    *systemtest.Fake
	mu      sync.Mutex
	scripts []string
	logins  []system.Command
	login   func(system.Command) (system.Result, error)
}

func newRecorder(name, counts string, failCreate string) *recorder {
	r := &recorder{fake: &systemtest.Fake{}}

	answerLogin := func(c system.Command) (system.Result, error) {
		r.mu.Lock()
		r.logins = append(r.logins, c)
		login := r.login
		r.mu.Unlock()

		if login == nil {
			return system.Result{Output: []byte("1\n")}, nil
		}

		return login(c)
	}
	r.fake.Handle("psql", answerLogin)

	r.fake.Handle(name, func(c system.Command) (system.Result, error) {
		if c.Stdin == nil {
			return answerLogin(c)
		}

		script, _ := io.ReadAll(c.Stdin)

		r.mu.Lock()
		r.scripts = append(r.scripts, string(script))
		r.mu.Unlock()

		switch {
		case strings.Contains(string(script), "SELECT"):
			return system.Result{Output: []byte(counts)}, nil
		case failCreate != "" && strings.Contains(string(script), "CREATE"):
			return system.Result{Output: []byte(failCreate), ExitCode: 1}, &system.ExitError{Command: name, ExitCode: 1, Output: []byte(failCreate)}
		default:
			return system.Result{}, nil
		}
	})

	return r
}

func creator(r *recorder, engine string) Creator {
	return Creator{Runner: r.fake, Engine: func(context.Context) string { return engine }}
}

func loginCreator(t *testing.T, r *recorder, engine string) Creator {
	c := creator(r, engine)
	c.LoginDir = filepath.Join(t.TempDir(), "db-login")

	return c
}

func refuse(output string) func(system.Command) (system.Result, error) {
	return func(c system.Command) (system.Result, error) {
		return system.Result{Output: []byte(output), ExitCode: 1}, &system.ExitError{Command: c.Name, ExitCode: 1, Output: []byte(output)}
	}
}

// adminCommand is the command each engine's SQL runs through; bothExist is its answer when the database and user exist.
var (
	adminCommand = map[string]string{"mysql": "mysql", "mariadb": "mariadb", "postgres": "runuser"}
	bothExist    = map[string]string{"mysql": "1\n2\n", "mariadb": "1\n2\n", "postgres": "1\n1\n"}
)

func TestCreateRejectsUnsafeInput(t *testing.T) {
	cases := []Request{
		{Name: "app'; DROP DATABASE mysql; --", User: "app", Password: password},
		{Name: "my app", User: "app", Password: password},
		{Name: "App", User: "app", Password: password},
		{Name: "1app", User: "app", Password: password},
		{Name: "a`b", User: "app", Password: password},
		{Name: strings.Repeat("a", 33), User: "app", Password: password},
		{Name: "", User: "app", Password: password},
		{Name: "app", User: "app'@'%", Password: password},
		{Name: "app", User: "app user", Password: password},
		{Name: "app", User: "app", Password: "short"},
		{Name: "app", User: "app", Password: "has spaces in it 12345"},
		{Name: "app", User: "app", Password: "quote'0123456789abcdef"},
		{Name: "app", User: "app", Password: "semi;0123456789abcdef"},
		{Name: "app", User: "app", Password: strings.Repeat("a", 129)},
	}

	for _, request := range cases {
		r := newRecorder("mariadb", "0\n0\n", "")

		_, err := creator(r, "mariadb").Create(ctx, request)

		var invalid *site.InvalidError
		if !errors.As(err, &invalid) {
			t.Errorf("%+v: err = %v", request, err)
		}
		if calls := r.fake.Calls(); len(calls) != 0 {
			t.Errorf("%+v ran %d commands", request, len(calls))
		}
	}
}

func TestPasswordOnlyTravelsOverStdin(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb", "postgres"} {
		name := map[string]string{"mysql": "mysql", "mariadb": "mariadb", "postgres": "runuser"}[engine]
		r := newRecorder(name, "0\n0\n", "")

		if _, err := creator(r, engine).Create(ctx, Request{Name: "orchard", User: "orchard", Password: password}); err != nil {
			t.Fatalf("%s: %v", engine, err)
		}

		for _, call := range r.fake.Calls() {
			if strings.Contains(strings.Join(call.Args, " "), password) || len(call.Env) > 0 {
				t.Errorf("%s: the password is in a command's arguments or environment: %v", engine, call.Args)
			}
		}
		// PostgreSQL gets a SCRAM verifier instead of the password (TestPostgresRunsAsThePostgresUser).
		if len(r.scripts) != 2 || strings.Contains(r.scripts[1], password) != (engine != "postgres") {
			t.Errorf("%s scripts = %q", engine, r.scripts)
		}
	}
}

func TestMariaDBCreatesUsersForTheSocketAndTCP(t *testing.T) {
	r := newRecorder("mariadb", "0\n0\n", "")

	result, err := creator(r, "mariadb").Create(ctx, Request{Name: "orchard", User: "orchard_web", Password: password})
	if err != nil {
		t.Fatal(err)
	}

	if result != (Result{Engine: "mariadb", Connection: "mariadb", Name: "orchard", User: "orchard_web", Host: "127.0.0.1", Port: 3306}) {
		t.Errorf("result = %+v", result)
	}
	if calls := r.fake.Calls(); !slices.Equal(calls[0].Args, []string{"--batch", "--skip-column-names"}) {
		t.Errorf("args = %v", calls[0].Args)
	}

	script := r.scripts[1]
	for _, want := range []string{
		"CREATE DATABASE `orchard` CHARACTER SET utf8mb4;",
		"CREATE USER 'orchard_web'@'localhost' IDENTIFIED BY '" + password + "';",
		"CREATE USER 'orchard_web'@'127.0.0.1' IDENTIFIED BY '" + password + "';",
		"GRANT ALL PRIVILEGES ON `orchard`.* TO 'orchard_web'@'localhost';",
		"GRANT ALL PRIVILEGES ON `orchard`.* TO 'orchard_web'@'127.0.0.1';",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
}

func TestGrantEscapesUnderscoresSoOnlyTheNamedDatabaseMatches(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb"} {
		r := newRecorder(engine, "0\n0\n", "")

		if _, err := creator(r, engine).Create(ctx, Request{Name: "my_shop", User: "my_shop", Password: password}); err != nil {
			t.Fatal(err)
		}

		script := r.scripts[1]
		for _, want := range []string{
			"CREATE DATABASE `my_shop` CHARACTER SET utf8mb4;",
			"GRANT ALL PRIVILEGES ON `my\\_shop`.* TO 'my_shop'@'localhost';",
			"GRANT ALL PRIVILEGES ON `my\\_shop`.* TO 'my_shop'@'127.0.0.1';",
		} {
			if !strings.Contains(script, want) {
				t.Errorf("%s script lacks %q:\n%s", engine, want, script)
			}
		}
	}
}

func TestMySQLUsesRootsOptionFile(t *testing.T) {
	r := newRecorder("mysql", "0\n0\n", "")

	result, err := creator(r, "mysql").Create(ctx, Request{Name: "orchard", User: "orchard", Password: password})
	if err != nil || result.Connection != "mysql" || result.Port != 3306 {
		t.Fatalf("Create = %+v %v", result, err)
	}
	if args := r.fake.Calls()[0].Args; args[0] != "--defaults-extra-file=/root/.my.cnf" {
		t.Errorf("args = %v", args)
	}
}

func TestPostgresRunsAsThePostgresUser(t *testing.T) {
	r := newRecorder("runuser", "0\n0\n", "")

	result, err := creator(r, "postgres").Create(ctx, Request{Name: "orchard", User: "orchard", Password: password})
	if err != nil {
		t.Fatal(err)
	}

	if result.Connection != "pgsql" || result.Port != 5432 || result.Engine != "postgres" {
		t.Errorf("result = %+v", result)
	}
	if args := r.fake.Calls()[0].Args; !slices.Equal(args, []string{"-u", "postgres", "--", "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-At"}) {
		t.Errorf("args = %v", args)
	}
	role := regexp.MustCompile(`CREATE ROLE "orchard" LOGIN PASSWORD 'SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]{24}\$[A-Za-z0-9+/=]{44}:[A-Za-z0-9+/=]{44}';`)
	if !role.MatchString(r.scripts[1]) || strings.Contains(r.scripts[1], password) {
		t.Errorf("the role doesn't get a SCRAM verifier:\n%s", r.scripts[1])
	}
	for _, want := range []string{
		`CREATE DATABASE "orchard" OWNER "orchard" ENCODING 'UTF8' TEMPLATE template0;`,
		`REVOKE CONNECT, TEMPORARY ON DATABASE "orchard" FROM PUBLIC;`,
	} {
		if !strings.Contains(r.scripts[1], want) {
			t.Errorf("script lacks %q:\n%s", want, r.scripts[1])
		}
	}
}

func TestAnExistingDatabaseOrUserIsLeftAlone(t *testing.T) {
	for counts, kind := range map[string]string{"1\n0\n": "database", "0\n1\n": "user"} {
		r := newRecorder("mariadb", counts, "")

		_, err := creator(r, "mariadb").Create(ctx, Request{Name: "orchard", User: "orchard", Password: password})

		var exists *ExistsError
		if !errors.As(err, &exists) || exists.Kind != kind {
			t.Errorf("%q: err = %v", counts, err)
		}
		if len(r.scripts) != 1 || len(r.logins) != 0 {
			t.Errorf("%q: ran %d scripts and %d login tests", counts, len(r.scripts), len(r.logins))
		}
	}
}

func TestAFailedCreateIsUndoneAndHidesThePassword(t *testing.T) {
	r := newRecorder("mariadb", "0\n0\n", "ERROR 1396 (HY000) at line 2: Operation CREATE USER failed for 'orchard'@'localhost' identified by '"+password+"'")

	_, err := creator(r, "mariadb").Create(ctx, Request{Name: "orchard", User: "orchard", Password: password})

	var failure *Error
	if !errors.As(err, &failure) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), password) || !strings.Contains(err.Error(), "ERROR 1396") || !strings.HasPrefix(err.Error(), "MariaDB couldn't create the database.") {
		t.Errorf("err = %v", err)
	}
	if len(r.scripts) != 3 || !strings.Contains(r.scripts[2], "DROP USER IF EXISTS 'orchard'@'localhost', 'orchard'@'127.0.0.1';") || !strings.Contains(r.scripts[2], "DROP DATABASE IF EXISTS `orchard`;") {
		t.Errorf("scripts = %q", r.scripts)
	}
}

func TestAnExistingDatabaseIsConfirmedWhenThePasswordLogsIn(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb", "postgres"} {
		r := newRecorder(adminCommand[engine], bothExist[engine], "")

		result, err := loginCreator(t, r, engine).Create(ctx, Request{Name: "orchard", User: "orchard_web", Password: password})
		if err != nil {
			t.Fatalf("%s: %v", engine, err)
		}

		want := engines[engine].result(Request{Name: "orchard", User: "orchard_web"})
		want.Existing = true
		if result != want {
			t.Errorf("%s: result = %+v", engine, result)
		}
		if len(r.scripts) != 1 || len(r.logins) != 1 {
			t.Fatalf("%s: ran scripts %q and %d login tests", engine, r.scripts, len(r.logins))
		}
		if login := r.logins[0]; login.Stdin != nil || strings.Contains(strings.Join(login.Args, " "), password) {
			t.Errorf("%s: the password is in the login's arguments or stdin: %v", engine, login.Args)
		}
	}
}

func TestPostgresLogsInOverTCPWithPGPASSWORD(t *testing.T) {
	r := newRecorder("runuser", "1\n1\n", "")

	if _, err := creator(r, "postgres").Create(ctx, Request{Name: "orchard", User: "orchard_web", Password: password}); err != nil {
		t.Fatal(err)
	}

	login := r.logins[0]
	if login.Name != "psql" || login.User != nil || !slices.Equal(login.Args, []string{"-X", "-q", "-w", "-At", "-h", "127.0.0.1", "-p", "5432", "-U", "orchard_web", "-d", "orchard", "-c", postgresOwnerQuery}) {
		t.Errorf("login = %s %v", login.Name, login.Args)
	}
	if !slices.Equal(login.Env, []string{"PATH=" + loginPath, "PGPASSWORD=" + password, "PGCONNECT_TIMEOUT=10"}) {
		t.Errorf("env = %v", login.Env)
	}
}

func TestMySQLAndMariaDBLogInWithAPrivateOptionFileThatIsRemoved(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb"} {
		r := newRecorder(engine, "1\n2\n", "")
		c := loginCreator(t, r, engine)

		var file string
		r.login = func(command system.Command) (system.Result, error) {
			file = strings.TrimPrefix(command.Args[0], "--defaults-file=")

			content, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("%s: %v", engine, err)
			}
			if string(content) != "[client]\nuser=orchard_web\npassword="+password+"\n" {
				t.Errorf("%s option file = %q", engine, content)
			}
			for path, want := range map[string]os.FileMode{file: 0o600, filepath.Dir(file): 0o700, c.LoginDir: 0o700} {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatalf("%s: %v", engine, err)
				}
				if info.Mode().Perm() != want {
					t.Errorf("%s: %s has mode %v, want %v", engine, path, info.Mode().Perm(), want)
				}
			}

			return system.Result{Output: []byte("1\n")}, nil
		}

		if _, err := c.Create(ctx, Request{Name: "orchard", User: "orchard_web", Password: password}); err != nil {
			t.Fatalf("%s: %v", engine, err)
		}

		login := r.logins[0]
		want := []string{"--protocol=tcp", "--host=127.0.0.1", "--port=3306", "--connect-timeout=10", "--batch", "--skip-column-names", "--database=orchard", "--execute=SELECT 1"}
		if login.Name != engine || !strings.HasPrefix(login.Args[0], "--defaults-file=") || !slices.Equal(login.Args[1:], want) || login.Env != nil {
			t.Errorf("%s login = %s %v %v", engine, login.Name, login.Args, login.Env)
		}
		if filepath.Dir(filepath.Dir(file)) != c.LoginDir {
			t.Errorf("%s option file %s isn't in its own folder under %s", engine, file, c.LoginDir)
		}
		if _, err := os.Stat(filepath.Dir(file)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s left %s behind", engine, filepath.Dir(file))
		}
	}
}

func TestAWrongPasswordForAnExistingDatabaseIsTaken(t *testing.T) {
	refusals := map[string]string{
		"mysql":    "ERROR 1045 (28000): Access denied for user 'orchard_web'@'localhost' (using password: YES)",
		"mariadb":  "ERROR 1044 (42000): Access denied for user 'orchard_web'@'localhost' to database 'orchard'",
		"postgres": `psql: error: connection to server at "127.0.0.1", port 5432 failed: FATAL:  password authentication failed for user "orchard_web"`,
	}

	for engine, output := range refusals {
		r := newRecorder(adminCommand[engine], bothExist[engine], "")
		r.login = refuse(output)

		_, err := loginCreator(t, r, engine).Create(ctx, Request{Name: "orchard", User: "orchard_web", Password: password})

		var exists *ExistsError
		if !errors.As(err, &exists) || exists.Kind != "database" || exists.Name != "orchard" {
			t.Errorf("%s: err = %v", engine, err)
		}
		if len(r.scripts) != 1 {
			t.Errorf("%s ran %q", engine, r.scripts)
		}
	}
}

func TestAPostgresDatabaseTheUserDoesntOwnIsTaken(t *testing.T) {
	for _, output := range []string{"", "0\n", "SELECT 1\n"} {
		r := newRecorder("runuser", "1\n1\n", "")
		r.login = func(system.Command) (system.Result, error) { return system.Result{Output: []byte(output)}, nil }

		result, err := creator(r, "postgres").Create(ctx, Request{Name: "orchard", User: "orchard_web", Password: password})

		var exists *ExistsError
		if !errors.As(err, &exists) || exists.Kind != "database" || result.Existing {
			t.Errorf("output %q: result = %+v, err = %v", output, result, err)
		}
	}
}

func TestALoginThatCantBeCheckedIsAnInternalError(t *testing.T) {
	r := newRecorder("runuser", "1\n1\n", "")
	r.login = refuse(`psql: error: connection to server at "127.0.0.1", port 5432 failed: Connection refused ` + password)

	_, err := creator(r, "postgres").Create(ctx, Request{Name: "orchard", User: "orchard_web", Password: password})

	var failure *Error
	if !errors.As(err, &failure) || failure.Summary != "Couldn't check the existing database login." || !strings.Contains(failure.Output, "Connection refused") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), password) {
		t.Errorf("err = %v", err)
	}
}

// slowLogins hangs every login test until its context ends, and passes other commands on.
type slowLogins struct{ system.Runner }

func (s slowLogins) Run(ctx context.Context, c system.Command) (system.Result, error) {
	if c.Name != "psql" {
		return s.Runner.Run(ctx, c)
	}

	<-ctx.Done()

	return system.Result{ExitCode: -1}, &system.ExitError{Command: c.Name, ExitCode: -1}
}

func TestASlowLoginIsAnInternalError(t *testing.T) {
	defer func(original time.Duration) { loginTimeout = original }(loginTimeout)
	loginTimeout = 20 * time.Millisecond

	r := newRecorder("runuser", "1\n1\n", "")
	c := creator(r, "postgres")
	c.Runner = slowLogins{r.fake}

	_, err := c.Create(ctx, Request{Name: "orchard", User: "orchard_web", Password: password})

	var failure *Error
	if !errors.As(err, &failure) || failure.Output != "PostgreSQL didn't answer within 20ms." {
		t.Errorf("err = %v", err)
	}
}

func TestACancelledLoginIsReportedAsACancel(t *testing.T) {
	cancelled, cancel := context.WithCancel(ctx)
	defer cancel()

	r := newRecorder("runuser", "1\n1\n", "")
	r.login = func(c system.Command) (system.Result, error) {
		cancel()
		return refuse("psql: error: killed")(c)
	}

	if _, err := creator(r, "postgres").Create(cancelled, Request{Name: "orchard", User: "orchard_web", Password: password}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestSweepLoginFilesRemovesLeftovers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db-login")
	if err := os.MkdirAll(filepath.Join(dir, "login-123"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "login-123", "client.cnf"), []byte("[client]\npassword="+password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := SweepLoginFiles(dir); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s is still there: %v", dir, err)
	}
	if err := SweepLoginFiles(dir); err != nil {
		t.Errorf("a second sweep: %v", err)
	}
}

func TestAnUnexpectedAnswerHidesThePassword(t *testing.T) {
	r := newRecorder("mariadb", "ERROR near '"+password+"'\n", "")

	_, err := creator(r, "mariadb").Create(ctx, Request{Name: "orchard", User: "orchard", Password: password})

	var failure *Error
	if !errors.As(err, &failure) || !strings.HasPrefix(err.Error(), "MariaDB gave an unexpected answer.") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), password) || !strings.Contains(err.Error(), "********") {
		t.Errorf("err = %v", err)
	}
}

func TestACancelledCreateIsUndoneAndReportedAsACancel(t *testing.T) {
	cancelled, cancel := context.WithCancel(ctx)
	defer cancel()

	var scripts []string
	fake := &systemtest.Fake{}
	fake.Handle("mariadb", func(c system.Command) (system.Result, error) {
		script, _ := io.ReadAll(c.Stdin)
		scripts = append(scripts, string(script))

		switch {
		case strings.Contains(string(script), "SELECT"):
			return system.Result{Output: []byte("0\n0\n")}, nil
		case strings.Contains(string(script), "CREATE"):
			cancel()
			return system.Result{ExitCode: -1}, &system.ExitError{Command: "mariadb", ExitCode: -1}
		default:
			return system.Result{}, nil
		}
	})

	_, err := Creator{Runner: fake, Engine: func(context.Context) string { return "mariadb" }}.Create(cancelled, Request{Name: "orchard", User: "orchard", Password: password})

	var failure *Error
	if !errors.Is(err, context.Canceled) || errors.As(err, &failure) {
		t.Errorf("err = %v", err)
	}
	if len(scripts) != 3 || !strings.Contains(scripts[2], "DROP DATABASE IF EXISTS `orchard`;") {
		t.Errorf("scripts = %q", scripts)
	}
}

func TestNoEngine(t *testing.T) {
	r := newRecorder("mariadb", "0\n0\n", "")

	var invalid *site.InvalidError
	if _, err := creator(r, "").Create(ctx, Request{Name: "orchard", User: "orchard", Password: password}); !errors.As(err, &invalid) {
		t.Errorf("err = %v", err)
	}
}

func TestEnvValues(t *testing.T) {
	got := EnvValues(Result{Connection: "pgsql", Name: "orchard", User: "web", Host: "127.0.0.1", Port: 5432}, password)

	want := [][2]string{
		{"DB_CONNECTION", "pgsql"}, {"DB_HOST", "127.0.0.1"}, {"DB_PORT", "5432"},
		{"DB_DATABASE", "orchard"}, {"DB_USERNAME", "web"}, {"DB_PASSWORD", password},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v", got)
	}
}

func TestConcurrentCreationsDoNotInterleave(t *testing.T) {
	fake := &systemtest.Fake{}

	var mu sync.Mutex
	open, overlapped := 0, false

	fake.Handle("mariadb", func(c system.Command) (system.Result, error) {
		script, _ := io.ReadAll(c.Stdin)

		mu.Lock()
		defer mu.Unlock()

		if strings.Contains(string(script), "SELECT") {
			open++
			overlapped = overlapped || open > 1
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			mu.Lock()

			return system.Result{Output: []byte("0\n0\n")}, nil
		}

		open--

		return system.Result{}, nil
	})

	var wg sync.WaitGroup
	for _, name := range []string{"one", "two", "three", "four"} {
		wg.Add(1)
		go func() {
			defer wg.Done()

			Creator{Runner: fake, Engine: func(context.Context) string { return "mariadb" }}.Create(ctx, Request{Name: name, User: name, Password: password})
		}()
	}
	wg.Wait()

	if overlapped {
		t.Error("a creation began its existence check before another finished creating")
	}
}

func networked(c Creator) Creator {
	c.Network = func() (string, []string, error) { return "10.0.0.5", []string{"10.0.0.7", "10.0.0.8"}, nil }

	return c
}

func TestPeersGetTheirOwnAccountsAndTheResultPointsAtThePrivateAddress(t *testing.T) {
	r := newRecorder("mysql", "0\n0\n", "")

	result, err := networked(creator(r, "mysql")).Create(ctx, Request{Name: "shop", User: "shop", Password: password, From: []string{"10.0.0.7"}})
	if err != nil {
		t.Fatal(err)
	}

	if result.Host != "10.0.0.5" {
		t.Errorf("host = %q, want the private address", result.Host)
	}
	for _, want := range []string{
		"CREATE USER 'shop'@'10.0.0.7' IDENTIFIED BY '" + password + "';",
		"GRANT ALL PRIVILEGES ON `shop`.* TO 'shop'@'10.0.0.7';",
	} {
		if !strings.Contains(r.scripts[1], want) {
			t.Errorf("script lacks %q:\n%s", want, r.scripts[1])
		}
	}
}

func TestAnExistingDatabaseLetsANewPeerIn(t *testing.T) {
	r := newRecorder("mysql", bothExist["mysql"], "")

	result, err := networked(loginCreator(t, r, "mysql")).Create(ctx, Request{Name: "shop", User: "shop", Password: password, From: []string{"10.0.0.8"}})
	if err != nil {
		t.Fatal(err)
	}

	if !result.Existing || result.Host != "10.0.0.5" {
		t.Errorf("result = %+v", result)
	}
	if len(r.scripts) != 2 || !strings.Contains(r.scripts[1], "CREATE USER IF NOT EXISTS 'shop'@'10.0.0.8' IDENTIFIED BY '"+password+"';") {
		t.Errorf("scripts = %q", r.scripts)
	}
}

func TestOnlyPeersCanBeLetIn(t *testing.T) {
	for name, c := range map[string]Creator{
		"not a peer":    networked(creator(newRecorder("mysql", "0\n0\n", ""), "mysql")),
		"no networking": creator(newRecorder("mysql", "0\n0\n", ""), "mysql"),
	} {
		_, err := c.Create(ctx, Request{Name: "shop", User: "shop", Password: password, From: []string{"10.0.0.9"}})

		var invalid *site.InvalidError
		if !errors.As(err, &invalid) {
			t.Errorf("%s: err = %v, want an invalid argument", name, err)
		}
	}
}

func TestPostgresLetsPeersInThroughPgHBAOnce(t *testing.T) {
	hba := filepath.Join(t.TempDir(), "pg_hba.conf")
	if err := os.WriteFile(hba, []byte("local all postgres peer\nhost all all 127.0.0.1/32 scram-sha-256"), 0o640); err != nil {
		t.Fatal(err)
	}

	fake := &systemtest.Fake{}
	var reloads int
	fake.Handle("runuser", func(c system.Command) (system.Result, error) {
		script, _ := io.ReadAll(c.Stdin)
		switch {
		case strings.Contains(string(script), "SHOW hba_file"):
			return system.Result{Output: []byte(hba + "\n")}, nil
		case strings.Contains(string(script), "pg_reload_conf"):
			reloads++
		case strings.Contains(string(script), "SELECT count(*)"):
			return system.Result{Output: []byte("0\n0\n")}, nil
		}
		return system.Result{}, nil
	})
	c := networked(Creator{Runner: fake, Engine: func(context.Context) string { return "postgres" }})

	request := Request{Name: "shop", User: "shop", Password: password, From: []string{"10.0.0.7", "10.0.0.8"}}
	result, err := c.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.allowInHBA(ctx, engines["postgres"], request); err != nil {
		t.Fatal(err)
	}

	content, _ := os.ReadFile(hba)
	want := "local all postgres peer\nhost all all 127.0.0.1/32 scram-sha-256\nhost shop shop 10.0.0.7/32 scram-sha-256 # serverdog\nhost shop shop 10.0.0.8/32 scram-sha-256 # serverdog\n"
	if string(content) != want {
		t.Errorf("pg_hba.conf =\n%s\nwant\n%s", content, want)
	}
	if info, _ := os.Stat(hba); info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want it kept", info.Mode().Perm())
	}
	if reloads != 1 || result.Host != "10.0.0.5" {
		t.Errorf("reloads = %d, host = %q; want one reload and the private address", reloads, result.Host)
	}
}
