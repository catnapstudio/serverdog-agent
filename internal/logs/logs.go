// Package logs reads the server's logs for the app: a fixed set of sources the agent finds on the server, never a path
// the app sends.
package logs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// Source is one log the app can read.
type Source struct {
	ID    string
	Title string
	// Group is "Server" or the site's name.
	Group string
}

// MaxLines bounds a read.
const MaxLines = 2000

// maxBytes bounds a read too: a log of very long lines still fits a gRPC message.
const maxBytes = 1 << 20

// ErrUnknownSource is a source ID that isn't in List.
var ErrUnknownSource = errors.New("unknown log")

// colour is a terminal colour code, which Meilisearch writes into its log even when it isn't a terminal.
var colour = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Reader lists and reads the logs.
type Reader struct {
	Paths      paths.Paths
	System     system.Runner
	Sites      func() ([]site.Site, error)
	LookupUser func(string) (system.User, error)
}

// entry is a source with how to read it: a file with tail, or the journal with journalctl and these arguments.
type entry struct {
	Source
	file    string
	journal []string
	// user reads the file, for logs in a site's directory, which its user controls.
	user string
}

// List returns the sources that exist on this server, server-wide ones first.
func (r *Reader) List() ([]Source, error) {
	entries, err := r.entries()
	if err != nil {
		return nil, err
	}

	sources := make([]Source, 0, len(entries))
	for _, e := range entries {
		sources = append(sources, e.Source)
	}

	return sources, nil
}

// Read returns the last lines of the source, oldest first.
func (r *Reader) Read(ctx context.Context, id string, lines int) (string, error) {
	if lines <= 0 || lines > MaxLines {
		lines = MaxLines
	}

	entries, err := r.entries()
	if err != nil {
		return "", err
	}

	for _, e := range entries {
		if e.ID == id {
			return r.read(ctx, e, lines)
		}
	}

	return "", ErrUnknownSource
}

func (r *Reader) read(ctx context.Context, e entry, lines int) (string, error) {
	command := system.Command{Name: "tail", Args: []string{"-n", fmt.Sprint(lines), "--", e.file}}
	if e.journal != nil {
		command = system.Command{Name: "journalctl", Args: append([]string{"--no-pager", "--quiet", "--output=short-iso", fmt.Sprintf("--lines=%d", lines)}, e.journal...)}
	}

	if e.user != "" {
		user, err := r.LookupUser(e.user)
		if err != nil {
			return "", err
		}
		command.User = &user
	}

	result, err := r.System.Run(ctx, command)
	if err != nil {
		return "", fmt.Errorf("Couldn't read %s: %s", e.Title, strings.TrimSpace(string(result.Output)))
	}

	output := colour.ReplaceAll(result.Output, nil)
	if len(output) > maxBytes {
		output = output[len(output)-maxBytes:]
	}

	return string(output), nil
}

func (r *Reader) entries() ([]entry, error) {
	var entries []entry

	server := func(id, title, file string) {
		if _, err := os.Stat(r.Paths.File(file)); err == nil {
			entries = append(entries, entry{Source: Source{ID: id, Title: title, Group: "Server"}, file: r.Paths.File(file)})
		}
	}

	entries = append(entries,
		entry{Source: Source{ID: "journal", Title: "System journal", Group: "Server"}, journal: []string{}},
		entry{Source: Source{ID: "agent", Title: "ServerDog agent", Group: "Server"}, journal: []string{"--unit=serverdog-agent"}},
	)
	server("auth", "SSH and sudo (auth.log)", "/var/log/auth.log")
	server("nginx-error", "Nginx errors", "/var/log/nginx/error.log")
	server("nginx-access", "Nginx access", "/var/log/nginx/access.log")

	fpm, _ := filepath.Glob(r.Paths.File("/var/log/php*-fpm.log"))
	sort.Sort(sort.Reverse(sort.StringSlice(fpm)))
	for _, file := range fpm {
		name := strings.TrimSuffix(filepath.Base(file), ".log")
		entries = append(entries, entry{Source: Source{ID: name, Title: "PHP-FPM " + strings.TrimSuffix(strings.TrimPrefix(name, "php"), "-fpm"), Group: "Server"}, file: file})
	}

	server("mysql", "MySQL errors", "/var/log/mysql/error.log")
	if postgres, _ := filepath.Glob(r.Paths.File("/var/log/postgresql/postgresql-*-main.log")); len(postgres) > 0 {
		sort.Strings(postgres)
		entries = append(entries, entry{Source: Source{ID: "postgres", Title: "PostgreSQL", Group: "Server"}, file: postgres[len(postgres)-1]})
	}
	if _, err := os.Stat(r.Paths.File("/etc/mysql/mariadb.conf.d")); err == nil {
		entries = append(entries, entry{Source: Source{ID: "mariadb", Title: "MariaDB", Group: "Server"}, journal: []string{"--unit=mariadb"}})
	}
	if _, err := os.Stat(r.Paths.File("/etc/systemd/system/meilisearch.service")); err == nil {
		entries = append(entries, entry{Source: Source{ID: "meilisearch", Title: "Meilisearch", Group: "Server"}, journal: []string{"--unit=meilisearch"}})
	}

	sites, err := r.Sites()
	if err != nil {
		return nil, err
	}

	for _, s := range sites {
		entries = append(entries, r.siteEntries(s)...)
	}

	return entries, nil
}

func (r *Reader) siteEntries(s site.Site) []entry {
	var entries []entry
	group := s.DirectoryName()

	if s.HasWebsite() {
		for _, kind := range []string{"error", "access"} {
			file := r.Paths.File(fmt.Sprintf("/var/log/nginx/serverdog-%s-%s.log", s.ID, kind))
			if _, err := os.Stat(file); err == nil {
				title := map[string]string{"error": "Nginx errors", "access": "Nginx access"}[kind]
				entries = append(entries, entry{Source: Source{ID: fmt.Sprintf("site:%s:%s", s.ID, kind), Title: title, Group: group}, file: file})
			}
		}
	}

	// laravel.log, or laravel-2026-11-12.log with daily logs: the one written last is the one in use.
	found, _ := filepath.Glob(r.Paths.File(path.Join(s.Directory, "current", s.AppDirectory, "storage", "logs", "laravel*.log")))
	newest, newestTime := "", time.Time{}
	for _, file := range found {
		if info, err := os.Stat(file); err == nil && info.ModTime().After(newestTime) {
			newest, newestTime = file, info.ModTime()
		}
	}

	if newest != "" {
		entries = append(entries, entry{Source: Source{ID: fmt.Sprintf("site:%s:laravel", s.ID), Title: "Laravel (" + filepath.Base(newest) + ")", Group: group}, file: newest, user: s.User})
	}

	return entries
}
