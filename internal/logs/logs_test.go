package logs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

type recorder struct{ commands []system.Command }

func (r *recorder) Run(_ context.Context, c system.Command) (system.Result, error) {
	r.commands = append(r.commands, c)
	return system.Result{Output: []byte("a line\n")}, nil
}

func write(t *testing.T, file string, at time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, at, at); err != nil {
		t.Fatal(err)
	}
}

func TestSourcesAreWhatTheServerHasAndSiteLogsAreReadAsTheSiteUser(t *testing.T) {
	root := t.TempDir()
	now := time.Now()

	write(t, root+"/var/log/nginx/error.log", now)
	write(t, root+"/var/log/php8.4-fpm.log", now)
	write(t, root+"/var/log/php8.3-fpm.log", now)
	write(t, root+"/var/log/nginx/serverdog-aaaaaaaaaaaa-error.log", now)
	write(t, root+"/home/serverdog/app.test/current/storage/logs/laravel.log", now.Add(-48*time.Hour))
	write(t, root+"/home/serverdog/app.test/current/storage/logs/laravel-2026-11-12.log", now)

	app := site.Site{ID: "aaaaaaaaaaaa", Domains: []site.Domain{{Name: "app.test", Primary: true}}, User: "serverdog", Directory: "/home/serverdog/app.test"}
	runner := &recorder{}
	r := &Reader{
		Paths:      paths.Paths{Root: root},
		System:     runner,
		Sites:      func() ([]site.Site, error) { return []site.Site{app}, nil },
		LookupUser: func(name string) (system.User, error) { return system.User{Name: name, UID: 1000}, nil },
	}

	sources, err := r.List()
	if err != nil {
		t.Fatal(err)
	}

	var titles []string
	for _, s := range sources {
		titles = append(titles, s.Group+"/"+s.Title)
	}
	want := "Server/System journal,Server/ServerDog agent,Server/Nginx errors,Server/PHP-FPM 8.4,Server/PHP-FPM 8.3,app.test/Nginx errors,app.test/Laravel (laravel-2026-11-12.log)"
	if strings.Join(titles, ",") != want {
		t.Errorf("sources = %s\nwant      %s", strings.Join(titles, ","), want)
	}

	if _, err := r.Read(context.Background(), "site:aaaaaaaaaaaa:laravel", 50); err != nil {
		t.Fatal(err)
	}
	last := runner.commands[len(runner.commands)-1]
	if last.Name != "tail" || last.User == nil || last.User.Name != "serverdog" || last.Args[1] != "50" || !strings.HasSuffix(last.Args[3], "laravel-2026-11-12.log") {
		t.Errorf("laravel read = %+v, want tail as serverdog", last)
	}

	if _, err := r.Read(context.Background(), "nginx-error", 99999); err != nil {
		t.Fatal(err)
	}
	if last := runner.commands[len(runner.commands)-1]; last.User != nil || last.Args[1] != "2000" {
		t.Errorf("server log read = %+v, want tail as root capped at 2000", last)
	}

	if _, err := r.Read(context.Background(), "/etc/shadow", 10); !errors.Is(err, ErrUnknownSource) {
		t.Errorf("a path was read: %v", err)
	}
}

type colourful struct{}

func (colourful) Run(context.Context, system.Command) (system.Result, error) {
	return system.Result{Output: []byte("\x1b[2m2026-11-17\x1b[0m \x1b[32m INFO\x1b[0m HTTP request\n")}, nil
}

func TestMeilisearchIsReadFromTheJournalWithoutColours(t *testing.T) {
	root := t.TempDir()
	write(t, root+"/etc/systemd/system/meilisearch.service", time.Now())
	r := &Reader{Paths: paths.Paths{Root: root}, System: colourful{}, Sites: func() ([]site.Site, error) { return nil, nil }}

	sources, err := r.List()
	if err != nil {
		t.Fatal(err)
	}
	if last := sources[len(sources)-1]; last.ID != "meilisearch" || last.Title != "Meilisearch" {
		t.Fatalf("sources = %+v", sources)
	}

	text, err := r.Read(context.Background(), "meilisearch", 10)
	if err != nil {
		t.Fatal(err)
	}
	if text != "2026-11-17  INFO HTTP request\n" {
		t.Errorf("text = %q", text)
	}
}
