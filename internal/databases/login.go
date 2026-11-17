package databases

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// loginTimeout bounds a login test. Tests shorten it.
var loginTimeout = 15 * time.Second

// loginPath is the PATH of psql's replaced environment.
const loginPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

const loginFailed = "Couldn't check the existing database login."

var mysqlAccessDenied = regexp.MustCompile(`ERROR 104[45] \(`)

// SweepLoginFiles removes the option files of login tests that never finished, such as when the agent was killed
// during one. The agent calls it at startup.
func SweepLoginFiles(dir string) error {
	return os.RemoveAll(dir)
}

// login reports whether r.User can log in to r.Name with r.Password over TCP on 127.0.0.1, as the site's .env does.
// A refused login is false with no error; anything else that stops the check is an *Error, or ctx's error.
// The password never goes on a command line or into SQL.
func (c Creator) login(ctx context.Context, e engine, r Request) (bool, error) {
	command, cleanup, err := e.login(c.LoginDir, r)
	if err != nil {
		return false, &Error{Summary: loginFailed, Output: redact(err.Error(), r.Password)}
	}
	defer cleanup()

	attempt, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()

	result, err := c.Runner.Run(attempt, command)
	if err == nil {
		return e.owned == nil || e.owned(strings.TrimSpace(string(result.Output))), nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	output := redact(strings.TrimSpace(string(result.Output)), r.Password)
	if e.refused(output) {
		return false, nil
	}
	if attempt.Err() != nil {
		output = fmt.Sprintf("%s didn't answer within %s.", e.label, loginTimeout)
	}
	if output == "" {
		output = redact(err.Error(), r.Password)
	}

	return false, &Error{Summary: loginFailed, Output: output}
}

// postgresOwnerQuery answers 1 only when the user owns the database. PUBLIC may connect to a database by default, so
// a login alone doesn't show that the database is the user's.
const postgresOwnerQuery = "SELECT 1 FROM pg_database WHERE datname = current_database() AND pg_get_userbyid(datdba) = current_user"

// postgresLogin runs psql as root over TCP, so pg_hba's host line asks for the password. runuser postgres would
// connect over the socket, where peer authentication skips it.
func postgresLogin(_ string, r Request) (system.Command, func(), error) {
	return system.Command{
		Name: "psql",
		Args: []string{"-X", "-q", "-w", "-At", "-h", "127.0.0.1", "-p", "5432", "-U", r.User, "-d", r.Name, "-c", postgresOwnerQuery},
		Env:  []string{"PATH=" + loginPath, "PGPASSWORD=" + r.Password, "PGCONNECT_TIMEOUT=10"},
	}, func() {}, nil
}

func postgresOwned(output string) bool {
	return output == "1"
}

func postgresRefused(output string) bool {
	return strings.Contains(output, "password authentication failed") || strings.Contains(output, "permission denied for database")
}

// mysqlLogin writes the credentials to an option file in a fresh 0700 folder under dir, and returns a command that
// reads only that file (--defaults-file must come first) and a cleanup that removes the folder.
func mysqlLogin(client string) func(dir string, r Request) (system.Command, func(), error) {
	return func(dir string, r Request) (system.Command, func(), error) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return system.Command{}, nil, err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return system.Command{}, nil, err
		}

		private, err := os.MkdirTemp(dir, "login-")
		if err != nil {
			return system.Command{}, nil, err
		}
		cleanup := func() {
			if err := os.RemoveAll(private); err != nil {
				slog.Warn("could not remove a database login file", "path", private, "error", err)
			}
		}

		file := filepath.Join(private, "client.cnf")
		if err := os.WriteFile(file, fmt.Appendf(nil, "[client]\nuser=%s\npassword=%s\n", r.User, r.Password), 0o600); err != nil {
			cleanup()
			return system.Command{}, nil, err
		}

		return system.Command{Name: client, Args: []string{
			"--defaults-file=" + file, "--protocol=tcp", "--host=127.0.0.1", "--port=3306", "--connect-timeout=10",
			"--batch", "--skip-column-names", "--database=" + r.Name, "--execute=SELECT 1",
		}}, cleanup, nil
	}
}

func mysqlRefused(output string) bool {
	return mysqlAccessDenied.MatchString(output)
}
