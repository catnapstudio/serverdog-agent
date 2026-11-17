package databases

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/site"
)

// Listing is the server's databases and users, without the engine's own.
type Listing struct {
	Engine    string
	Databases []string
	Users     []string
}

var (
	systemDatabases = []string{"information_schema", "mysql", "performance_schema", "sys", "postgres", "template0", "template1"}
	systemUsers     = []string{"root", "mysql", "debian-sys-maint", "mariadb.sys", "mysql.sys", "mysql.session", "mysql.infoschema", "postgres", "PUBLIC"}
	// host is a MySQL account's host as the server stores it; anything else is left alone rather than quoted.
	host = regexp.MustCompile(`^[A-Za-z0-9._%:-]{1,255}$`)
)

func (c Creator) List(ctx context.Context) (Listing, error) {
	e, err := c.engine(ctx)
	if err != nil {
		return Listing{}, err
	}

	databases := "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA ORDER BY 1;\n"
	users := "SELECT DISTINCT User FROM mysql.user ORDER BY 1;\n"
	if e.name == "postgres" {
		databases = "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY 1;\n"
		users = "SELECT rolname FROM pg_roles WHERE rolname NOT LIKE 'pg\\_%' ORDER BY 1;\n"
	}

	listing := Listing{Engine: e.name}

	output, err := c.runFor(ctx, e, databases, "", e.label+" couldn't list the databases.")
	if err != nil {
		return Listing{}, err
	}
	listing.Databases = without(lines(output), systemDatabases)

	output, err = c.runFor(ctx, e, users, "", e.label+" couldn't list the users.")
	if err != nil {
		return Listing{}, err
	}
	listing.Users = without(lines(output), systemUsers)

	return listing, nil
}

// DeleteDatabase drops a database. PostgreSQL closes its connections first.
func (c Creator) DeleteDatabase(ctx context.Context, name string) error {
	if err := deletable("database", name, systemDatabases); err != nil {
		return err
	}

	e, err := c.engine(ctx)
	if err != nil {
		return err
	}

	sql := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`;\n", name)
	if e.name == "postgres" {
		sql = fmt.Sprintf("DROP DATABASE IF EXISTS \"%s\" WITH (FORCE);\n", name)
	}

	_, err = c.runFor(ctx, e, sql, "", fmt.Sprintf("%s couldn't delete the database %s.", e.label, name))

	return err
}

// DeleteUser drops a user from every host it has. PostgreSQL refuses while the user owns a database.
func (c Creator) DeleteUser(ctx context.Context, name string) error {
	if err := deletable("user", name, systemUsers); err != nil {
		return err
	}

	e, err := c.engine(ctx)
	if err != nil {
		return err
	}

	summary := fmt.Sprintf("%s couldn't delete the user %s.", e.label, name)

	if e.name == "postgres" {
		_, err := c.runFor(ctx, e, fmt.Sprintf("DROP ROLE IF EXISTS \"%s\";\n", name), "", summary)
		return err
	}

	accounts, err := c.accounts(ctx, e, name, summary)
	if err != nil || len(accounts) == 0 {
		return err
	}

	_, err = c.runFor(ctx, e, fmt.Sprintf("DROP USER %s;\n", strings.Join(accounts, ", ")), "", summary)

	return err
}

// SetPassword changes a user's password on every host it has.
func (c Creator) SetPassword(ctx context.Context, name, password string) error {
	if err := deletable("user", name, systemUsers); err != nil {
		return err
	}
	if !secret.MatchString(password) {
		return &site.InvalidError{Field: "password", Reason: "The password must be 16 to 128 letters and digits."}
	}

	e, err := c.engine(ctx)
	if err != nil {
		return err
	}

	summary := fmt.Sprintf("%s couldn't change %s's password.", e.label, name)

	if e.name == "postgres" {
		verifier, err := scramVerifier(password)
		if err != nil {
			return err
		}
		_, err = c.runFor(ctx, e, fmt.Sprintf("ALTER ROLE \"%s\" PASSWORD '%s';\n", name, verifier), password, summary)
		return err
	}

	accounts, err := c.accounts(ctx, e, name, summary)
	if err != nil {
		return err
	}
	if len(accounts) == 0 {
		return &site.InvalidError{Field: "user", Reason: fmt.Sprintf("This server has no database user %s.", name)}
	}

	var sql strings.Builder
	for _, account := range accounts {
		fmt.Fprintf(&sql, "ALTER USER %s IDENTIFIED BY '%s';\n", account, password)
	}
	_, err = c.runFor(ctx, e, sql.String(), password, summary)

	return err
}

// accounts are a MySQL or MariaDB user's 'name'@'host' accounts.
func (c Creator) accounts(ctx context.Context, e engine, name, summary string) ([]string, error) {
	output, err := c.runFor(ctx, e, fmt.Sprintf("SELECT Host FROM mysql.user WHERE User = '%s';\n", name), "", summary)
	if err != nil {
		return nil, err
	}

	var accounts []string
	for _, h := range lines(output) {
		if !host.MatchString(h) {
			return nil, &Error{Summary: fmt.Sprintf("%s has a host ServerDog doesn't handle (%q). Change it with %s's own client.", name, h, e.label)}
		}
		accounts = append(accounts, fmt.Sprintf("'%s'@'%s'", name, h))
	}

	return accounts, nil
}

func (c Creator) engine(ctx context.Context) (engine, error) {
	e, ok := engines[c.Engine(ctx)]
	if !ok {
		return engine{}, &site.InvalidError{Field: "engine", Reason: "This server has no MySQL, MariaDB or PostgreSQL server."}
	}

	return e, nil
}

func deletable(kind, name string, reserved []string) error {
	if !identifier.MatchString(name) {
		return &site.InvalidError{Field: kind, Reason: fmt.Sprintf("ServerDog only changes %ss named with lowercase letters, digits and _.", kind)}
	}
	if slices.Contains(reserved, name) {
		return &site.InvalidError{Field: kind, Reason: fmt.Sprintf("%s belongs to the database server itself.", name)}
	}

	return nil
}

func lines(output string) []string {
	var result []string
	for _, line := range strings.Split(output, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			result = append(result, line)
		}
	}

	return result
}

func without(names, reserved []string) []string {
	return slices.DeleteFunc(names, func(name string) bool { return slices.Contains(reserved, name) })
}
