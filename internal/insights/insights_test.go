package insights

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

var now = time.Date(2026, 11, 14, 12, 0, 0, 0, time.Local)

type server struct {
	t       *testing.T
	root    string
	scanner *Scanner
	// commands are the command lines run. outputs is what each prints, by "program" or "program first-argument";
	// failing names the programs that fail.
	commands []string
	outputs  map[string]string
	failing  map[string]bool
	saved    []site.Site
}

func (s *server) Run(_ context.Context, c system.Command) (system.Result, error) {
	s.commands = append(s.commands, c.Name+" "+strings.Join(c.Args, " "))
	if s.failing[c.Name] {
		return system.Result{}, errors.New(c.Name + " failed")
	}

	if output, ok := s.outputs[c.Name+" "+c.Args[0]]; ok {
		return system.Result{Output: []byte(output)}, nil
	}

	return system.Result{Output: []byte(s.outputs[c.Name])}, nil
}

func (s *server) write(logical, content string) {
	file := filepath.Join(s.root, logical)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		s.t.Fatal(err)
	}
}

func (s *server) scan() []Insight {
	found, _, partial := s.scanner.Insights(context.Background(), true)
	if partial {
		s.t.Fatal("the scan was partial")
	}

	return found
}

// healthy is a server with nothing to report: swap, a synchronised clock, the firewall on.
func healthy(t *testing.T, sites ...site.Site) *server {
	s := &server{t: t, root: t.TempDir(), outputs: map[string]string{"timedatectl": "NTP=yes\nNTPSynchronized=yes\n"}, failing: map[string]bool{}}
	s.write("/proc/meminfo", "MemTotal:        4000000 kB\nSwapTotal:       2000000 kB\n")
	s.write("/proc/vmstat", "oom_kill 0\n")
	s.write("/etc/ufw/ufw.conf", "# comment\nENABLED=yes\nLOGLEVEL=low\n")
	s.write("/etc/fstab", "LABEL=root / ext4 defaults 0 1")

	s.scanner = &Scanner{
		Paths: paths.Paths{Root: s.root}, Runner: s, Now: func() time.Time { return now },
		Sites: func() ([]site.Site, error) { return sites, nil },
		Env: func(_ context.Context, id string) ([]byte, error) {
			return os.ReadFile(filepath.Join(s.root, "env-"+id))
		},
		SaveSite: func(_ context.Context, changed site.Site, _ string) error {
			s.saved = append(s.saved, changed)
			return nil
		},
		BackgroundProcesses: func() map[string][2]string {
			return map[string][2]string{"daemonaaaaaa": {"Sync", "/usr/bin/sync-things"}}
		},
		RestartService: func(context.Context, string) error { return nil },
		RebootRequired: func() (time.Time, bool) { return time.Time{}, false },
		Disk:           func() (uint64, uint64) { return 100 * gib, 60 * gib },
	}

	return s
}

func kinds(found []Insight) []string {
	var list []string
	for _, insight := range found {
		list = append(list, insight.Kind+":"+insight.Subject)
	}

	return list
}

func find(t *testing.T, found []Insight, kind string) Insight {
	for _, insight := range found {
		if insight.Kind == kind {
			return insight
		}
	}
	t.Fatalf("no %s in %v", kind, kinds(found))

	return Insight{}
}

func TestHealthyServerHasNothing(t *testing.T) {
	s := healthy(t, site.Site{ID: "siteaaaaaaaa", Runtime: site.PHP, PHPVersion: "8.5", Preset: "laravel"})

	if found := s.scan(); len(found) != 0 {
		t.Fatalf("found %v", kinds(found))
	}
	// A healthy server costs two commands: no second systemctl, no journal read.
	if len(s.commands) != 2 {
		t.Fatalf("ran %v", s.commands)
	}
}

func TestScanIsKeptForAMinute(t *testing.T) {
	s := healthy(t)
	s.scanner.Insights(context.Background(), false)
	s.scanner.Insights(context.Background(), false)
	if len(s.commands) != 2 {
		t.Fatalf("a kept scan ran commands again: %v", s.commands)
	}

	s.scanner.Insights(context.Background(), true)
	if len(s.commands) != 4 {
		t.Fatalf("refresh didn't scan: %v", s.commands)
	}

	now = now.Add(2 * time.Minute)
	defer func() { now = now.Add(-2 * time.Minute) }()
	s.scanner.Insights(context.Background(), false)
	if len(s.commands) != 6 {
		t.Fatalf("an old scan was reused: %v", s.commands)
	}
}

func TestAScanWithACheckThatCouldntLookIsPartialAndNotKept(t *testing.T) {
	s := healthy(t)
	s.write("/etc/ufw/ufw.conf", "ENABLED=no\n")
	s.failing["systemctl"] = true

	found, _, partial := s.scanner.Insights(context.Background(), false)
	if !partial || len(found) != 1 {
		t.Fatalf("partial %v, found %v", partial, kinds(found))
	}

	// Not kept: the next request looks again, and is whole once systemctl answers.
	s.failing["systemctl"] = false
	before := len(s.commands)
	if _, _, partial := s.scanner.Insights(context.Background(), false); partial || len(s.commands) == before {
		t.Fatalf("partial %v, commands %v", partial, s.commands[before:])
	}
}

func TestPHPWorkers(t *testing.T) {
	busy := site.Site{ID: "siteaaaaaaaa", Runtime: site.PHP, PHPVersion: "8.5"}
	raised := site.Site{ID: "sitebbbbbbbb", Runtime: site.PHP, PHPVersion: "8.5", PHPWorkers: 20}
	s := healthy(t, busy, raised)

	recent := now.Add(-time.Hour).Format("02-Jan-2006 15:04:05")
	old := now.Add(-48 * time.Hour).Format("02-Jan-2006 15:04:05")
	s.write("/var/log/php8.5-fpm.log", strings.Join([]string{
		"[" + old + "] WARNING: [pool serverdog-siteaaaaaaaa] server reached pm.max_children setting (10), consider raising it",
		"[" + recent + "] NOTICE: ready to handle connections",
		"[" + recent + "] WARNING: [pool serverdog-siteaaaaaaaa] server reached max_children setting (10), consider raising it",
		"[" + recent + "] WARNING: [pool serverdog-siteaaaaaaaa] server reached pm.max_children setting (10), consider raising it",
		// Logged under the limit this site had before it was raised.
		"[" + recent + "] WARNING: [pool serverdog-sitebbbbbbbb] server reached pm.max_children setting (10), consider raising it",
	}, "\n"))

	found := s.scan()
	if got := kinds(found); len(got) != 1 || got[0] != PHPWorkersExhausted+":siteaaaaaaaa" {
		t.Fatalf("found %v", got)
	}
	// 4 GB allows 30 workers at 64 MB each in half the memory, and the other site already holds 20 of them.
	if values := found[0].Values; values["limit"] != "10" || values["hits"] != "2" || found[0].Fixable {
		t.Fatalf("values %v fixable %v", values, found[0].Fixable)
	}

	// With the other site back at the default, there is room to double.
	raised.PHPWorkers = 0
	s.scanner.Sites = func() ([]site.Site, error) { return []site.Site{busy, raised}, nil }
	found = s.scan()
	if values := found[0].Values; values["suggested"] != "20" || !found[0].Fixable {
		t.Fatalf("values %v fixable %v", values, found[0].Fixable)
	}

	if err := s.scanner.Fix(context.Background(), PHPWorkersExhausted, "siteaaaaaaaa", "Mac"); err != nil {
		t.Fatal(err)
	}
	if len(s.saved) != 1 || s.saved[0].PHPWorkers != 20 {
		t.Fatalf("saved %+v", s.saved)
	}
}

func TestPHPWorkersStopAtWhatMemoryAllows(t *testing.T) {
	s := healthy(t, site.Site{ID: "siteaaaaaaaa", Runtime: site.PHP, PHPVersion: "8.5", PHPWorkers: 31})
	// 4 GB: half of it at 64 MB a worker is 30.
	s.write("/var/log/php8.5-fpm.log", "["+now.Format("02-Jan-2006 15:04:05")+"] WARNING: [pool serverdog-siteaaaaaaaa] server reached pm.max_children setting (31), consider raising it\n")

	if insight := find(t, s.scan(), PHPWorkersExhausted); insight.Fixable || insight.Values["suggested"] != "" {
		t.Fatalf("offered a fix past the ceiling: %+v", insight)
	}
	if err := s.scanner.Fix(context.Background(), PHPWorkersExhausted, "siteaaaaaaaa", "Mac"); !errors.Is(err, ErrGone) {
		t.Fatalf("fix returned %v", err)
	}
}

func TestUnits(t *testing.T) {
	s := healthy(t, site.Site{ID: "siteaaaaaaaa", Processes: []site.Process{{ID: "procaaaaaaaa", Name: "Queue"}, {ID: "procbbbbbbbb", Name: "Horizon"}}})
	s.outputs["systemctl list-units"] = strings.Join([]string{
		"redis-server.service loaded failed failed Advanced key-value store",
		"php8.5-fpm.service loaded activating auto-restart The PHP 8.5 FastCGI Process Manager",
		"serverdog-process-siteaaaaaaaa-procaaaaaaaa@1.service loaded activating auto-restart ServerDog process",
		"serverdog-process-siteaaaaaaaa-procaaaaaaaa@2.service loaded activating auto-restart ServerDog process",
		"serverdog-process-siteaaaaaaaa-procbbbbbbbb@1.service loaded activating auto-restart ServerDog process",
		"serverdog-daemon-daemonaaaaaa@1.service loaded failed failed ServerDog background process",
		"serverdog-site-siteaaaaaaaa@20001.service loaded activating auto-restart ServerDog site",
		"snapd.service loaded failed failed Snap Daemon",
	}, "\n")
	// Horizon ended on purpose (horizon:terminate after a deploy) and waits to start again: not a failure.
	s.outputs["systemctl show"] = strings.Join([]string{
		"Id=serverdog-process-siteaaaaaaaa-procaaaaaaaa@1.service", "Result=exit-code", "",
		"Id=serverdog-process-siteaaaaaaaa-procaaaaaaaa@2.service", "Result=exit-code", "",
		"Id=serverdog-process-siteaaaaaaaa-procbbbbbbbb@1.service", "Result=success", "",
		"Id=serverdog-site-siteaaaaaaaa@20001.service", "Result=signal", "",
	}, "\n")

	found := s.scan()
	want := []string{ServiceFailed + ":redis-server", ServiceFailed + ":php8.5-fpm", ProcessFailing + ":siteaaaaaaaa/procaaaaaaaa", ProcessFailing + ":daemonaaaaaa", ProcessFailing + ":siteaaaaaaaa/server"}
	if got := kinds(found); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("found %v", got)
	}
	if !found[0].Fixable || found[1].Fixable {
		t.Fatalf("only a service that gave up restarts: %+v %+v", found[0], found[1])
	}
	if found[2].Values["name"] != "Queue" || found[3].Values["name"] != "Sync" || found[4].Values["server"] != "true" {
		t.Fatalf("values %v %v %v", found[2].Values, found[3].Values, found[4].Values)
	}

	var restarted string
	s.scanner.RestartService = func(_ context.Context, unit string) error { restarted = unit; return nil }
	if err := s.scanner.Fix(context.Background(), ServiceFailed, "redis-server", "Mac"); err != nil || restarted != "redis-server" {
		t.Fatalf("restarted %q, %v", restarted, err)
	}
	if err := s.scanner.Fix(context.Background(), ServiceFailed, "php8.5-fpm", "Mac"); !errors.Is(err, ErrGone) {
		t.Fatalf("fix returned %v", err)
	}
}

func TestSystem(t *testing.T) {
	s := healthy(t, site.Site{ID: "siteaaaaaaaa", Runtime: site.PHP, PHPVersion: "8.1"}, site.Site{ID: "sitebbbbbbbb", Runtime: site.PHP, PHPVersion: "8.1"})
	s.outputs["timedatectl"] = "NTP=no\nNTPSynchronized=no\n"
	s.write("/proc/vmstat", "nr_free_pages 1\noom_kill 3\n")
	// The counter also has a container's own limit in it; the kernel's log tells them apart.
	s.outputs["journalctl"] = "Out of memory: Killed process 812 (mariadbd) total-vm:1kB\nOut of memory: Killed process 990 (php-fpm8.5) total-vm:1kB\n"
	s.write("/etc/ufw/ufw.conf", "ENABLED=no\n")
	s.scanner.RebootRequired = func() (time.Time, bool) { return now.Add(-5 * 24 * time.Hour), true }
	s.scanner.Disk = func() (uint64, uint64) { return 100 * gib, 9 * gib }

	found := s.scan()
	if insight := find(t, found, PHPEndOfLife); insight.Subject != "8.1" || insight.Values["sites"] != "2" {
		t.Fatalf("%+v", insight)
	}
	if insight := find(t, found, OutOfMemory); insight.Values["kills"] != "2" || insight.Values["days"] != "7" {
		t.Fatalf("%+v", insight)
	}
	if insight := find(t, found, RestartPending); insight.Values["days"] != "5" {
		t.Fatalf("%+v", insight)
	}
	if insight := find(t, found, DiskAlmostFull); insight.Values["percent"] != "91" {
		t.Fatalf("%+v", insight)
	}
	find(t, found, FirewallInactive)
	if !find(t, found, ClockUnsynced).Fixable {
		t.Fatal("the clock has a fix")
	}

	if err := s.scanner.Fix(context.Background(), ClockUnsynced, "", "Mac"); err != nil {
		t.Fatal(err)
	}
	if last := s.commands[len(s.commands)-1]; last != "timedatectl set-ntp true" {
		t.Fatalf("ran %q", last)
	}
}

func TestOldOrContainerKillsAreNotReported(t *testing.T) {
	s := healthy(t)
	s.write("/proc/vmstat", "oom_kill 4\n")
	s.outputs["journalctl"] = ""

	if found := s.scan(); len(found) != 0 {
		t.Fatalf("found %v", kinds(found))
	}
}

func TestAClockStillCatchingUpIsNotReported(t *testing.T) {
	s := healthy(t)
	s.outputs["timedatectl"] = "NTP=yes\nNTPSynchronized=no\n"

	if found := s.scan(); len(found) != 0 {
		t.Fatalf("found %v", kinds(found))
	}
}

func TestSwap(t *testing.T) {
	s := healthy(t)
	s.write("/proc/meminfo", "MemTotal:        1000000 kB\nSwapTotal:             0 kB\n")

	insight := find(t, s.scan(), NoSwap)
	if insight.Values["megabytes"] != "976" || !insight.Fixable {
		t.Fatalf("%+v", insight)
	}

	s.scanner.Disk = func() (uint64, uint64) { return 100 * gib, 2 * gib }
	if find(t, s.scan(), NoSwap).Fixable {
		t.Fatal("offered a swap file that would leave under 2 GB free")
	}
	s.scanner.Disk = func() (uint64, uint64) { return 100 * gib, 60 * gib }

	if err := s.scanner.Fix(context.Background(), NoSwap, "", "Mac"); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(s.root, "swapfile")
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("swap file: %v %v", info, err)
	}
	if got := strings.Join(s.commands[len(s.commands)-3:], "; "); got != "fallocate --length 976M "+file+"; mkswap "+file+"; swapon "+file {
		t.Fatalf("ran %s", got)
	}
	if table, _ := os.ReadFile(filepath.Join(s.root, "etc/fstab")); string(table) != "LABEL=root / ext4 defaults 0 1\n/swapfile none swap sw 0 0\n" {
		t.Fatalf("fstab:\n%s", table)
	}
}

// After a restart without its fstab line, the file is there and swap is off: the fix turns it on and keeps it, and
// a commented line doesn't count as keeping it.
func TestSwapFileThatIsOffIsTurnedOn(t *testing.T) {
	s := healthy(t)
	s.write("/proc/meminfo", "MemTotal:        1000000 kB\nSwapTotal:             0 kB\n")
	s.write("/swapfile", strings.Repeat("x", 3<<20))
	s.write("/etc/fstab", "LABEL=root / ext4 defaults 0 1\n#/swapfile none swap sw 0 0\n")
	s.scanner.Disk = func() (uint64, uint64) { return 100 * gib, 1 * gib }

	insight := find(t, s.scan(), NoSwap)
	if !insight.Fixable || insight.Values["existing"] != "true" || insight.Values["megabytes"] != "3" {
		t.Fatalf("%+v", insight)
	}

	before := len(s.commands)
	if err := s.scanner.Fix(context.Background(), NoSwap, "", "Mac"); err != nil {
		t.Fatal(err)
	}
	ran := strings.Join(s.commands[before:], "; ")
	if strings.Contains(ran, "fallocate") || strings.Contains(ran, "mkswap") || !strings.HasSuffix(ran, "swapon "+filepath.Join(s.root, "swapfile")) {
		t.Fatalf("ran %s", ran)
	}
	if table, _ := os.ReadFile(filepath.Join(s.root, "etc/fstab")); !strings.HasSuffix(string(table), "#/swapfile none swap sw 0 0\n/swapfile none swap sw 0 0\n") {
		t.Fatalf("fstab:\n%s", table)
	}
}

func TestLaravel(t *testing.T) {
	laravel := func(id string, processes ...site.Process) site.Site {
		return site.Site{ID: id, Preset: "laravel", EnvironmentFile: ".env", Directory: "/home/serverdog/" + id, Processes: processes}
	}
	other := site.Site{ID: "sitedddddddd", Preset: "wordpress", EnvironmentFile: ".env"}
	s := healthy(t,
		laravel("siteaaaaaaaa"), laravel("sitebbbbbbbb"),
		laravel("sitecccccccc", site.Process{ID: "procaaaaaaaa", Command: "php8.5 artisan horizon"}),
		other, laravel("siteeeeeeeee"), laravel("siteffffffff"), laravel("sitegggggggg"),
	)
	s.write("env-siteaaaaaaaa", "APP_ENV=production\nAPP_DEBUG=true\nQUEUE_CONNECTION=sync\n")
	s.write("env-sitebbbbbbbb", "APP_ENV=production\nAPP_DEBUG=false\nQUEUE_CONNECTION=redis\n")
	s.write("env-sitecccccccc", "APP_ENV=local\nAPP_DEBUG=true\nQUEUE_CONNECTION=redis\n")
	s.write("env-sitedddddddd", "APP_ENV=production\nAPP_DEBUG=true\n")
	// No APP_ENV is production to Laravel, and "on" turns debug on. A new app's database queue says nothing.
	s.write("env-siteeeeeeeee", "APP_DEBUG=on\nQUEUE_CONNECTION=database\n")
	// Its worker runs as one of the server's background processes.
	s.write("env-siteffffffff", "APP_DEBUG=(false)\nQUEUE_CONNECTION=redis\n")
	// Longer than a scan reads: left out.
	s.write("env-sitegggggggg", "APP_DEBUG=true\n"+strings.Repeat("#", EnvLimit))
	s.scanner.BackgroundProcesses = func() map[string][2]string {
		return map[string][2]string{"daemonaaaaaa": {"Worker", "php8.5 /home/serverdog/siteffffffff/current/artisan queue:work"}}
	}

	found := s.scan()
	want := []string{LaravelDebug + ":siteaaaaaaaa", LaravelQueueNoWork + ":sitebbbbbbbb", LaravelDebug + ":siteeeeeeeee"}
	if got := kinds(found); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("found %v", got)
	}
	if found[1].Values["connection"] != "redis" {
		t.Fatalf("%+v", found[1])
	}
}

func TestTailReadsOnlyTheEnd(t *testing.T) {
	file := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(file, []byte(strings.Repeat("a", 100)+"end"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := string(tail(file, 5)); got != "aaend" {
		t.Fatalf("tail %q", got)
	}
	if got := tail(filepath.Join(t.TempDir(), "missing"), 5); got != nil {
		t.Fatalf("tail of a missing file %q", got)
	}
}
