// Package databases creates a database and a user that can reach only it, on the server's MySQL, MariaDB or
// PostgreSQL. SQL, which holds the password, goes to the client over stdin.
package databases

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

var (
	identifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,31}$`)
	secret     = regexp.MustCompile(`^[A-Za-z0-9]{16,128}$`)
)

type Request struct {
	Name     string
	User     string
	Password string
	// From are peers' private addresses that may log in too (network package).
	From []string
}

type Result struct {
	Engine     string
	Connection string
	Name       string
	User       string
	Host       string
	Port       int
	// Existing is true when the database and user were already there and the password logged in. Nothing changed.
	Existing bool
}

// ExistsError is a database or user that already exists. Nothing was changed.
type ExistsError struct {
	Kind string
	Name string
}

func (e *ExistsError) Error() string {
	return fmt.Sprintf("A %s named %s already exists on this server.", e.Kind, e.Name)
}

// Error is a failed client command: a summary, then its output with the password removed.
type Error struct {
	Summary string
	Output  string
}

func (e *Error) Error() string {
	if e.Output == "" {
		return e.Summary
	}

	return e.Summary + "\n\n" + e.Output
}

// creating serialises Create, so that a failed creation's undo can't drop an object another request made between the
// existence check and its own creation.
var creating sync.Mutex

type Creator struct {
	Runner system.Runner
	// Engine is the server's database engine: "mysql", "mariadb", "postgres", or "" for none.
	Engine func(context.Context) string
	// LoginDir holds the short-lived option files of MySQL and MariaDB login tests (/run/serverdog/db-login).
	LoginDir string
	// Network is the server's private address and its peers' addresses (network.Manager.Network); nil means none.
	Network func() (string, []string, error)
}

type engine struct {
	name       string
	label      string
	connection string
	port       int
	command    system.Command
	exists     func(Request) string
	create     func(Request) (string, error)
	drop       func(Request) string
	login      func(dir string, r Request) (system.Command, func(), error)
	refused    func(output string) bool
	// owned, when set, tells from a successful login's output whether the user owns the database.
	owned func(output string) bool
	// allow lets r.From log in to a database and user that exist: MySQL and MariaDB accounts. PostgreSQL's go in
	// pg_hba.conf instead.
	allow func(Request) string
}

func (e engine) result(r Request) Result {
	return Result{Engine: e.name, Connection: e.connection, Name: r.Name, User: r.User, Host: "127.0.0.1", Port: e.port}
}

var mysqlLike = struct {
	exists, drop, allow func(Request) string
	create              func(Request) (string, error)
}{
	exists: func(r Request) string {
		return fmt.Sprintf("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '%s';\nSELECT COUNT(*) FROM mysql.user WHERE User = '%s';\n", r.Name, r.User)
	},
	create: func(r Request) (string, error) {
		var b strings.Builder
		grantable := strings.ReplaceAll(r.Name, "_", `\_`)
		fmt.Fprintf(&b, "CREATE DATABASE `%s` CHARACTER SET utf8mb4;\n", r.Name)
		for _, host := range append([]string{"localhost", "127.0.0.1"}, r.From...) {
			fmt.Fprintf(&b, "CREATE USER '%s'@'%s' IDENTIFIED BY '%s';\n", r.User, host, r.Password)
			fmt.Fprintf(&b, "GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%s';\n", grantable, r.User, host)
		}
		return b.String(), nil
	},
	drop: func(r Request) string {
		accounts := []string{fmt.Sprintf("'%s'@'localhost'", r.User), fmt.Sprintf("'%s'@'127.0.0.1'", r.User)}
		for _, host := range r.From {
			accounts = append(accounts, fmt.Sprintf("'%s'@'%s'", r.User, host))
		}
		return fmt.Sprintf("DROP USER IF EXISTS %s;\nDROP DATABASE IF EXISTS `%s`;\n", strings.Join(accounts, ", "), r.Name)
	},
	allow: func(r Request) string {
		var b strings.Builder
		grantable := strings.ReplaceAll(r.Name, "_", `\_`)
		for _, host := range r.From {
			fmt.Fprintf(&b, "CREATE USER IF NOT EXISTS '%s'@'%s' IDENTIFIED BY '%s';\n", r.User, host, r.Password)
			fmt.Fprintf(&b, "GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%s';\n", grantable, r.User, host)
		}
		return b.String()
	},
}

var engines = map[string]engine{
	"mysql": {
		name: "mysql", label: "MySQL", connection: "mysql", port: 3306,
		command: system.Command{Name: "mysql", Args: []string{"--defaults-extra-file=/root/.my.cnf", "--batch", "--skip-column-names"}},
		exists:  mysqlLike.exists, create: mysqlLike.create, drop: mysqlLike.drop, allow: mysqlLike.allow,
		login: mysqlLogin("mysql"), refused: mysqlRefused,
	},
	"mariadb": {
		name: "mariadb", label: "MariaDB", connection: "mariadb", port: 3306,
		command: system.Command{Name: "mariadb", Args: []string{"--batch", "--skip-column-names"}},
		exists:  mysqlLike.exists, create: mysqlLike.create, drop: mysqlLike.drop, allow: mysqlLike.allow,
		login: mysqlLogin("mariadb"), refused: mysqlRefused,
	},
	"postgres": {
		name: "postgres", label: "PostgreSQL", connection: "pgsql", port: 5432,
		command: system.Command{Name: "runuser", Args: []string{"-u", "postgres", "--", "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-At"}},
		exists: func(r Request) string {
			return fmt.Sprintf("SELECT count(*) FROM pg_database WHERE datname = '%s';\nSELECT count(*) FROM pg_roles WHERE rolname = '%s';\n", r.Name, r.User)
		},
		// The role gets a SCRAM-SHA-256 verifier, not the password: a failed CREATE ROLE is logged with its text.
		create: func(r Request) (string, error) {
			verifier, err := scramVerifier(r.Password)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("CREATE ROLE \"%[2]s\" LOGIN PASSWORD '%[3]s';\nCREATE DATABASE \"%[1]s\" OWNER \"%[2]s\" ENCODING 'UTF8' TEMPLATE template0;\nREVOKE CONNECT, TEMPORARY ON DATABASE \"%[1]s\" FROM PUBLIC;\n", r.Name, r.User, verifier), nil
		},
		drop: func(r Request) string {
			return fmt.Sprintf("DROP DATABASE IF EXISTS \"%s\";\nDROP ROLE IF EXISTS \"%s\";\n", r.Name, r.User)
		},
		login:   postgresLogin,
		refused: postgresRefused,
		owned:   postgresOwned,
	},
}

// Validate checks names and password before anything runs; only these characters ever reach SQL.
func Validate(r Request) error {
	if !identifier.MatchString(r.Name) {
		return &site.InvalidError{Field: "name", Reason: "Database names use lowercase letters, digits and _, start with a letter or _, and have at most 32 characters."}
	}
	if !identifier.MatchString(r.User) {
		return &site.InvalidError{Field: "user", Reason: "User names use lowercase letters, digits and _, start with a letter or _, and have at most 32 characters."}
	}
	if !secret.MatchString(r.Password) {
		return &site.InvalidError{Field: "password", Reason: "The password must be 16 to 128 letters and digits."}
	}

	return nil
}

// Create makes the database and its user, and undoes a failed creation. When both exist and the password logs in, it
// succeeds with Result.Existing and changes nothing. Otherwise an existing database or user is an *ExistsError.
func (c Creator) Create(ctx context.Context, r Request) (Result, error) {
	if err := Validate(r); err != nil {
		return Result{}, err
	}

	creating.Lock()
	defer creating.Unlock()

	e, ok := engines[c.Engine(ctx)]
	if !ok {
		return Result{}, &site.InvalidError{Field: "engine", Reason: "This server has no MySQL, MariaDB or PostgreSQL server to create the database on."}
	}

	address, err := c.privateAddress(r)
	if err != nil {
		return Result{}, err
	}

	counts, err := c.run(ctx, e, e.exists(r), r.Password)
	if err != nil {
		return Result{}, err
	}

	fields := strings.Fields(counts)
	if len(fields) != 2 {
		return Result{}, &Error{Summary: e.label + " gave an unexpected answer.", Output: redact(counts, r.Password)}
	}
	databaseExists, userExists := fields[0] != "0", fields[1] != "0"
	if databaseExists && userExists {
		result, err := c.confirm(ctx, e, r)
		if err != nil {
			return Result{}, err
		}
		return c.letPeersIn(ctx, e, r, result, address)
	}
	if databaseExists {
		return Result{}, &ExistsError{Kind: "database", Name: r.Name}
	}
	if userExists {
		return Result{}, &ExistsError{Kind: "user", Name: r.User}
	}

	script, err := e.create(r)
	if err != nil {
		return Result{}, err
	}

	if _, err := c.run(ctx, e, script, r.Password); err != nil {
		if _, undoErr := c.run(context.WithoutCancel(ctx), e, e.drop(r), r.Password); undoErr != nil {
			slog.Warn("could not undo a failed database creation", "database", r.Name, "user", r.User, "error", undoErr)
		}

		return Result{}, err
	}

	return c.letPeersIn(ctx, e, r, e.result(r), address)
}

// privateAddress is the server's private address when r lets peers in, after checking that each one is a peer.
func (c Creator) privateAddress(r Request) (string, error) {
	if len(r.From) == 0 {
		return "", nil
	}

	var address string
	var peers []string
	if c.Network != nil {
		var err error
		if address, peers, err = c.Network(); err != nil {
			return "", err
		}
	}
	if address == "" {
		return "", &site.InvalidError{Field: "allowed_from", Reason: "Turn on private networking on this server first."}
	}

	for _, from := range r.From {
		if !slices.Contains(peers, from) {
			return "", &site.InvalidError{Field: "allowed_from", Reason: fmt.Sprintf("%q isn't one of the servers that can connect to this one.", from)}
		}
	}

	return address, nil
}

// letPeersIn lets r.From log in, on a database just created or confirmed, and points the result at the private
// address. Both steps are idempotent, so a retry finishes what a failure left.
func (c Creator) letPeersIn(ctx context.Context, e engine, r Request, result Result, address string) (Result, error) {
	if len(r.From) == 0 {
		return result, nil
	}

	var err error
	if e.allow != nil {
		_, err = c.run(ctx, e, e.allow(r), r.Password)
	} else {
		err = c.allowInHBA(ctx, e, r)
	}
	if err != nil {
		return Result{}, &Error{Summary: "The database was created, but the other servers couldn't be let in.", Output: err.Error()}
	}

	result.Host = address

	return result, nil
}

// confirm answers a request whose database and user both exist. Knowing the user's password proves the caller made
// them, such as in an attempt whose answer was lost, so a login that works is a success. A refused login means they
// belong to someone else.
func (c Creator) confirm(ctx context.Context, e engine, r Request) (Result, error) {
	works, err := c.login(ctx, e, r)
	if err != nil {
		return Result{}, err
	}
	if !works {
		return Result{}, &ExistsError{Kind: "database", Name: r.Name}
	}

	result := e.result(r)
	result.Existing = true

	return result, nil
}

// run sends sql to the engine's client on stdin. Errors never contain password. A cancelled or expired ctx is returned
// as it is, so the caller reports a cancel and not a failed command.
func (c Creator) run(ctx context.Context, e engine, sql, password string) (string, error) {
	return c.runFor(ctx, e, sql, password, e.label+" couldn't create the database.")
}

func (c Creator) runFor(ctx context.Context, e engine, sql, password, summary string) (string, error) {
	command := e.command
	command.Args = slices.Clone(command.Args)
	command.Stdin = strings.NewReader(sql)

	result, err := c.Runner.Run(ctx, command)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}

		output := strings.TrimSpace(string(result.Output))
		if output == "" {
			output = err.Error()
		}

		return "", &Error{Summary: summary, Output: redact(output, password)}
	}

	return string(result.Output), nil
}

// redact hides password in a client's output.
func redact(output, password string) string {
	return strings.ReplaceAll(output, password, "********")
}

// EnvValues are the DB_* settings for the site's environment file.
func EnvValues(r Result, password string) [][2]string {
	return [][2]string{
		{"DB_CONNECTION", r.Connection},
		{"DB_HOST", r.Host},
		{"DB_PORT", strconv.Itoa(r.Port)},
		{"DB_DATABASE", r.Name},
		{"DB_USERNAME", r.User},
		{"DB_PASSWORD", password},
	}
}
