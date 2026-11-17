//go:build vmtest

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// serverEngine is the database engine on the VM. prepare.sh installs MariaDB on 24.04 and PostgreSQL on 26.04; a
// server ServerDog provisioned with MySQL runs this suite's database tests too.
func serverEngine(t *testing.T) string {
	// MariaDB comes first: it installs a mysqld link too.
	if _, err := exec.LookPath("mariadbd"); err == nil {
		return "mariadb"
	}
	if _, err := exec.LookPath("mysqld"); err == nil {
		return "mysql"
	}

	return "postgres"
}

// rootSQL is the command line that runs sql as the engine's root. MySQL's root password is in /root/.my.cnf, where the
// agent reads it too.
func rootSQL(engine, sql string) []string {
	if engine == "mysql" {
		return []string{"mysql", "--defaults-extra-file=/root/.my.cnf", "-e", sql}
	}

	return []string{"mariadb", "-e", sql}
}

// createByHand makes a database and its user without the agent, as an earlier attempt or a person would have.
func createByHand(t *testing.T, engine, name, user, password string) {
	t.Helper()

	if engine == "postgres" {
		sh(t, "/", "runuser", "-u", "postgres", "--", "psql", "-X", "-v", "ON_ERROR_STOP=1",
			"-c", fmt.Sprintf(`CREATE ROLE "%s" LOGIN PASSWORD '%s'`, user, password),
			"-c", fmt.Sprintf(`CREATE DATABASE "%s" OWNER "%s"`, name, user))
		return
	}

	command := rootSQL(engine, fmt.Sprintf("CREATE DATABASE `%[1]s`; "+
		"CREATE USER '%[2]s'@'localhost' IDENTIFIED BY '%[3]s'; CREATE USER '%[2]s'@'127.0.0.1' IDENTIFIED BY '%[3]s'; "+
		"GRANT ALL PRIVILEGES ON `%[1]s`.* TO '%[2]s'@'localhost', '%[2]s'@'127.0.0.1';", name, user, password))
	sh(t, "/", command[0], command[1:]...)
}

func TestADatabaseMadeByHandIsConfirmedByItsPassword(t *testing.T) {
	ctx := timeout(t)
	engine := serverEngine(t)
	name, user, password := "db_"+ids.New(), "u_"+ids.New(), ids.New()+ids.New()

	createByHand(t, engine, name, user, password)
	t.Cleanup(func() { dropDatabase(engine, name, user) })

	if _, err := databasesClient().CreateDatabase(ctx, &agentv1.CreateDatabaseRequest{Name: name, User: user, Password: ids.New() + ids.New(), Actor: actor}); status.Code(err) != codes.AlreadyExists {
		t.Errorf("another password: %v", err)
	}

	confirmed, err := databasesClient().CreateDatabase(ctx, &agentv1.CreateDatabaseRequest{Name: name, User: user, Password: password, Actor: actor})
	if err != nil || confirmed.Engine != engine || confirmed.Name != name || confirmed.Host != "127.0.0.1" {
		t.Fatalf("its own password: %v %v", confirmed, err)
	}

	if leftovers, _ := os.ReadDir("/run/serverdog/db-login"); len(leftovers) != 0 {
		t.Errorf("login files were left behind: %v", leftovers)
	}

	journal := sh(t, "/", "journalctl", "-u", "serverdog-agent", "--no-pager")
	if strings.Contains(journal, password) {
		t.Error("the agent's journal holds the password")
	}
}

func TestAPostgresDatabaseOwnedBySomeoneElseIsTakenEvenWithTheUsersPassword(t *testing.T) {
	if serverEngine(t) != "postgres" {
		t.Skip("this release's server runs MariaDB")
	}

	ctx := timeout(t)
	name, user, password := "db_"+ids.New(), "u_"+ids.New(), ids.New()+ids.New()

	// PUBLIC may connect to a database nobody revoked it from, so the user's password logs in to this one.
	sh(t, "/", "runuser", "-u", "postgres", "--", "psql", "-X", "-v", "ON_ERROR_STOP=1",
		"-c", fmt.Sprintf(`CREATE ROLE "%s" LOGIN PASSWORD '%s'`, user, password),
		"-c", fmt.Sprintf(`CREATE DATABASE "%s"`, name))
	t.Cleanup(func() { dropDatabase("postgres", name, user) })

	if _, err := databasesClient().CreateDatabase(ctx, &agentv1.CreateDatabaseRequest{Name: name, User: user, Password: password, Actor: actor}); status.Code(err) != codes.AlreadyExists {
		t.Errorf("a database owned by postgres: %v", err)
	}
}

func postgresLog(t *testing.T) string {
	t.Helper()

	files, err := filepath.Glob("/var/log/postgresql/*.log")
	if err != nil || len(files) == 0 {
		t.Fatalf("no PostgreSQL log: %v", err)
	}

	var b strings.Builder
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(content)
	}

	return b.String()
}

func TestAFailedCreateRoleLeavesNoPasswordInThePostgresLog(t *testing.T) {
	if serverEngine(t) != "postgres" {
		t.Skip("this release's server runs MariaDB")
	}

	ctx := timeout(t)
	// Role names starting with pg_ are reserved: the existence check passes and CREATE ROLE fails.
	name, user, password := "db_"+ids.New(), "pg_"+ids.New(), ids.New()+ids.New()

	_, err := databasesClient().CreateDatabase(ctx, &agentv1.CreateDatabaseRequest{Name: name, User: user, Password: password, Actor: actor})
	if status.Code(err) != codes.Internal || !strings.Contains(status.Convert(err).Message(), "is reserved") {
		t.Fatalf("err = %v", err)
	}

	statement := `CREATE ROLE "` + user + `" LOGIN PASSWORD 'SCRAM-SHA-256$4096:`
	logged := postgresLog(t)
	for range 50 {
		if strings.Contains(logged, statement) {
			break
		}
		time.Sleep(100 * time.Millisecond)
		logged = postgresLog(t)
	}

	if !strings.Contains(logged, statement) {
		t.Fatal("the failed CREATE ROLE isn't in the log, so this check proves nothing")
	}
	if strings.Contains(logged, password) {
		t.Error("the PostgreSQL log holds the password")
	}
}

func TestMariaDBLogsHoldNoPasswordByDefault(t *testing.T) {
	if serverEngine(t) != "mariadb" {
		t.Skip("this release's server runs PostgreSQL")
	}

	ctx := timeout(t)

	// CREATE USER keeps IDENTIFIED BY, so the plaintext stays out of MariaDB's logs only while these are off.
	if settings := sh(t, "/", "mariadb", "--batch", "--skip-column-names", "-e", "SELECT @@global.general_log, @@global.log_bin"); settings != "0\t0" {
		t.Errorf("general_log and log_bin = %q, want both off", settings)
	}

	generalLog := "/var/lib/mysql/serverdog-vmtest-general.log"
	sh(t, "/", "mariadb", "-e", fmt.Sprintf("SET GLOBAL general_log_file = '%s'; SET GLOBAL general_log = ON;", generalLog))
	t.Cleanup(func() {
		exec.Command("mariadb", "-e", "SET GLOBAL general_log = OFF;").Run()
		os.Remove(generalLog)
	})

	name, user, password := "db_"+ids.New(), "u_"+ids.New(), ids.New()+ids.New()
	if _, err := databasesClient().CreateDatabase(ctx, &agentv1.CreateDatabaseRequest{Name: name, User: user, Password: password, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dropDatabase("mariadb", name, user) })

	sh(t, "/", "mariadb", "-e", "SET GLOBAL general_log = OFF;")

	general, err := os.ReadFile(generalLog)
	if err != nil || !strings.Contains(string(general), "CREATE USER '"+user+"'") {
		t.Fatalf("the general log didn't record the CREATE USER, so this check proves nothing: %v", err)
	}
	// MariaDB doesn't rewrite passwords in the general log (MDEV-35902). Record what this version does.
	t.Logf("with the general log on, MariaDB %s records the password: %v",
		sh(t, "/", "mariadb", "--batch", "--skip-column-names", "-e", "SELECT VERSION()"), strings.Contains(string(general), password))

	errorLog := sh(t, "/", "journalctl", "-u", "mariadb", "--no-pager")
	if content, err := os.ReadFile("/var/log/mysql/error.log"); err == nil {
		errorLog += string(content)
	}
	if strings.Contains(errorLog, password) {
		t.Error("MariaDB's error log holds the password")
	}
}
