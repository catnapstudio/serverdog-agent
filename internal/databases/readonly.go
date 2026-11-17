package databases

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/site"
)

// CreateReadOnlyUser adds a user who can read one existing database and change nothing: for reporting tools and
// support staff. A failed creation is undone.
func (c Creator) CreateReadOnlyUser(ctx context.Context, database, user, password string) error {
	if !identifier.MatchString(database) || slices.Contains(systemDatabases, database) {
		return &site.InvalidError{Field: "database", Reason: "Pick one of the server's databases."}
	}
	if !identifier.MatchString(user) || slices.Contains(systemUsers, user) {
		return &site.InvalidError{Field: "user", Reason: "User names use lowercase letters, digits and _, start with a letter or _, and have at most 32 characters."}
	}
	if !secret.MatchString(password) {
		return &site.InvalidError{Field: "password", Reason: "The password must be 16 to 128 letters and digits."}
	}

	creating.Lock()
	defer creating.Unlock()

	e, err := c.engine(ctx)
	if err != nil {
		return err
	}

	summary := fmt.Sprintf("%s couldn't create the read-only user %s.", e.label, user)
	counts, err := c.runFor(ctx, e, e.exists(Request{Name: database, User: user}), "", summary)
	if err != nil {
		return err
	}
	fields := strings.Fields(counts)
	if len(fields) != 2 {
		return &Error{Summary: e.label + " gave an unexpected answer.", Output: counts}
	}
	if fields[0] == "0" {
		return &site.InvalidError{Field: "database", Reason: fmt.Sprintf("This server has no database %s.", database)}
	}
	if fields[1] != "0" {
		return &ExistsError{Kind: "user", Name: user}
	}

	if e.name == "postgres" {
		err = c.postgresReadOnly(ctx, e, database, user, password, summary)
	} else {
		var sql strings.Builder
		grantable := strings.ReplaceAll(database, "_", `\_`)
		for _, host := range []string{"localhost", "127.0.0.1"} {
			fmt.Fprintf(&sql, "CREATE USER '%s'@'%s' IDENTIFIED BY '%s';\n", user, host, password)
			fmt.Fprintf(&sql, "GRANT SELECT, SHOW VIEW ON `%s`.* TO '%s'@'%s';\n", grantable, user, host)
		}
		_, err = c.runFor(ctx, e, sql.String(), password, summary)
	}
	if err == nil {
		return nil
	}

	undo := context.WithoutCancel(ctx)
	drop := fmt.Sprintf("DROP USER IF EXISTS '%[1]s'@'localhost', '%[1]s'@'127.0.0.1';\n", user)
	if e.name == "postgres" {
		_, _ = c.runIn(undo, e, database, fmt.Sprintf("DROP OWNED BY \"%s\";\n", user), "", summary)
		drop = fmt.Sprintf("DROP ROLE IF EXISTS \"%s\";\n", user)
	}
	if _, undoErr := c.runFor(undo, e, drop, "", summary); undoErr != nil {
		slog.Warn("could not undo a failed read-only user", "user", user, "error", undoErr)
	}

	return err
}

// postgresReadOnly grants reading the tables there are and, through the owner's default privileges, the ones its
// migrations add later.
func (c Creator) postgresReadOnly(ctx context.Context, e engine, database, user, password, summary string) error {
	owner, err := c.runFor(ctx, e, fmt.Sprintf("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '%s';\n", database), "", summary)
	if err != nil {
		return err
	}
	owner = strings.TrimSpace(owner)
	if !identifier.MatchString(owner) && owner != "postgres" {
		return &Error{Summary: fmt.Sprintf("%s is owned by %q, which ServerDog doesn't handle. Grant access with psql.", database, owner)}
	}

	verifier, err := scramVerifier(password)
	if err != nil {
		return err
	}

	if _, err := c.runFor(ctx, e, fmt.Sprintf("CREATE ROLE \"%[1]s\" LOGIN PASSWORD '%[2]s';\nGRANT CONNECT ON DATABASE \"%[3]s\" TO \"%[1]s\";\n", user, verifier, database), password, summary); err != nil {
		return err
	}

	grants := fmt.Sprintf(`GRANT USAGE ON SCHEMA public TO "%[1]s";
GRANT SELECT ON ALL TABLES IN SCHEMA public TO "%[1]s";
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO "%[1]s";
ALTER DEFAULT PRIVILEGES FOR ROLE "%[2]s" IN SCHEMA public GRANT SELECT ON TABLES TO "%[1]s";
ALTER DEFAULT PRIVILEGES FOR ROLE "%[2]s" IN SCHEMA public GRANT SELECT ON SEQUENCES TO "%[1]s";
`, user, owner)
	_, err = c.runIn(ctx, e, database, grants, "", summary)

	return err
}

// runIn runs sql connected to database: PostgreSQL grants on tables only apply inside it.
func (c Creator) runIn(ctx context.Context, e engine, database, sql, password, summary string) (string, error) {
	e.command.Args = append(slices.Clone(e.command.Args), "-d", database)
	return c.runFor(ctx, e, sql, password, summary)
}
