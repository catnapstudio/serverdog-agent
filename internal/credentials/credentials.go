// Package credentials edits a user's package-manager logins in place: the http-basic part of Composer's auth.json
// and the auth tokens in .npmrc. Everything else in those files stays. The files are read and written as the user,
// and nothing is kept elsewhere.
package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/userfs"
)

type Composer struct {
	Host     string
	Username string
	Password string
}

type NPM struct {
	// A registry without its scheme, e.g. registry.npmjs.org or npm.pkg.github.com/acme.
	Registry string
	Token    string
}

const maxCredentials = 50

var (
	hostPattern     = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)
	registryPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[A-Za-z0-9._~@-]+)*$`)
	tokenLine       = regexp.MustCompile(`^//(.+)/:_authToken=(.*)$`)
)

type Manager struct {
	Paths      paths.Paths
	Runner     system.Runner
	LookupUser func(string) (system.User, error)
	// AsUser runs file commands with the user's ids; tests leave it false and run as themselves.
	AsUser bool
}

// ComposerFile is where Composer looks without XDG variables, as in deploys: ~/.composer/auth.json.
func ComposerFile(home string) string { return path.Join(home, ".composer", "auth.json") }

func NPMFile(home string) string { return path.Join(home, ".npmrc") }

// Composer returns the user's http-basic logins, sorted by host.
func (m *Manager) Composer(ctx context.Context, user string) ([]Composer, error) {
	fs, home, err := m.files(user)
	if err != nil {
		return nil, err
	}

	document, err := readAuth(ctx, fs, ComposerFile(home))
	if err != nil {
		return nil, err
	}

	var basic map[string]struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if raw, ok := document["http-basic"]; ok {
		if err := json.Unmarshal(raw, &basic); err != nil {
			return nil, fmt.Errorf("%s's http-basic section isn't valid: %w", ComposerFile(home), err)
		}
	}

	var list []Composer
	for host, login := range basic {
		list = append(list, Composer{Host: host, Username: login.Username, Password: login.Password})
	}
	slices.SortFunc(list, func(a, b Composer) int { return strings.Compare(a.Host, b.Host) })

	return list, nil
}

// PutComposer replaces the user's http-basic logins and keeps the rest of auth.json.
func (m *Manager) PutComposer(ctx context.Context, user string, list []Composer) error {
	if err := validateComposer(list); err != nil {
		return err
	}

	fs, home, err := m.files(user)
	if err != nil {
		return err
	}

	file := ComposerFile(home)
	document, err := readAuth(ctx, fs, file)
	if err != nil {
		return err
	}

	if len(list) == 0 {
		delete(document, "http-basic")
	} else {
		basic := map[string]map[string]string{}
		for _, c := range list {
			basic[c.Host] = map[string]string{"username": c.Username, "password": c.Password}
		}
		encoded, _ := json.Marshal(basic)
		document["http-basic"] = encoded
	}

	content, err := json.MarshalIndent(document, "", "    ")
	if err != nil {
		return err
	}

	if err := fs.MkdirAll(ctx, "0700", path.Dir(file)); err != nil {
		return err
	}

	return fs.WriteFile(ctx, file, append(content, '\n'), "0600")
}

// NPM returns the user's registry tokens, in the file's order.
func (m *Manager) NPM(ctx context.Context, user string) ([]NPM, error) {
	fs, home, err := m.files(user)
	if err != nil {
		return nil, err
	}

	content, _, err := fs.ReadFile(ctx, NPMFile(home))
	if err != nil {
		return nil, err
	}

	var list []NPM
	for _, line := range strings.Split(string(content), "\n") {
		if match := tokenLine.FindStringSubmatch(strings.TrimSpace(line)); match != nil {
			list = append(list, NPM{Registry: match[1], Token: match[2]})
		}
	}

	return list, nil
}

// PutNPM replaces the user's registry tokens and keeps the file's other lines.
func (m *Manager) PutNPM(ctx context.Context, user string, list []NPM) error {
	if err := validateNPM(list); err != nil {
		return err
	}

	fs, home, err := m.files(user)
	if err != nil {
		return err
	}

	file := NPMFile(home)
	content, _, err := fs.ReadFile(ctx, file)
	if err != nil {
		return err
	}

	var lines []string
	for _, line := range strings.Split(strings.TrimRight(string(content), "\n"), "\n") {
		if line != "" && !tokenLine.MatchString(strings.TrimSpace(line)) {
			lines = append(lines, line)
		}
	}
	for _, n := range list {
		lines = append(lines, "//"+n.Registry+"/:_authToken="+n.Token)
	}

	var out bytes.Buffer
	for _, line := range lines {
		out.WriteString(line + "\n")
	}

	return fs.WriteFile(ctx, file, out.Bytes(), "0600")
}

// files works in the home of a user under /home, never root's or a system account's.
func (m *Manager) files(name string) (userfs.FS, string, error) {
	user, err := m.LookupUser(name)
	if err != nil {
		return userfs.FS{}, "", invalid("This server has no user %q.", name)
	}
	if path.Dir(user.Home) != paths.HomeDir {
		return userfs.FS{}, "", invalid("%s's home isn't in /home, so ServerDog doesn't keep its credentials.", name)
	}

	fs := userfs.FS{Runner: m.Runner}
	if m.AsUser {
		fs.User = &user
	}

	return fs, m.Paths.File(user.Home), nil
}

func readAuth(ctx context.Context, fs userfs.FS, file string) (map[string]json.RawMessage, error) {
	content, found, err := fs.ReadFile(ctx, file)
	if err != nil {
		return nil, err
	}

	document := map[string]json.RawMessage{}
	if !found || len(bytes.TrimSpace(content)) == 0 {
		return document, nil
	}
	if err := json.Unmarshal(content, &document); err != nil {
		return nil, invalid("%s isn't valid JSON, so ServerDog leaves it alone. Fix it over SSH first.", file)
	}
	// A file that holds only "null" decodes without an error, to no map at all.
	if document == nil {
		document = map[string]json.RawMessage{}
	}

	return document, nil
}

func validateComposer(list []Composer) error {
	if len(list) > maxCredentials {
		return invalid("A user can have at most %d Composer credentials.", maxCredentials)
	}

	seen := map[string]bool{}
	for _, c := range list {
		if !hostPattern.MatchString(c.Host) || len(c.Host) > 253 || seen[c.Host] {
			return invalid("%q isn't a repository host like nova.laravel.com, or is listed twice.", c.Host)
		}
		seen[c.Host] = true

		if c.Username == "" || c.Password == "" || len(c.Username) > 500 || len(c.Password) > 2000 {
			return invalid("%s needs a username and a password.", c.Host)
		}
	}

	return nil
}

func validateNPM(list []NPM) error {
	if len(list) > maxCredentials {
		return invalid("A user can have at most %d npm credentials.", maxCredentials)
	}

	seen := map[string]bool{}
	for _, n := range list {
		if !registryPattern.MatchString(n.Registry) || len(n.Registry) > 253 || seen[n.Registry] {
			return invalid("%q isn't a registry like registry.npmjs.org, or is listed twice.", n.Registry)
		}
		seen[n.Registry] = true

		if n.Token == "" || len(n.Token) > 2000 || strings.ContainsAny(n.Token, " \t\r\n") {
			return invalid("%s needs a token without spaces.", n.Registry)
		}
	}

	return nil
}

func invalid(format string, args ...any) error {
	return &site.InvalidError{Field: "credentials", Reason: fmt.Sprintf(format, args...)}
}
