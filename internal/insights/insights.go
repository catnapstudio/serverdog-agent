// Package insights finds what is wrong on the server right now and fixes what has one safe fix. It works only
// when asked: no timer, no stored state, bounded reads, and at most two commands a scan plus one environment file
// read per Laravel site. A scan that couldn't finish every check says so and isn't kept.
package insights

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/catnapstudio/serverdog-agent/internal/dotenv"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/servicectl"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

const (
	PHPWorkersExhausted = "php_workers_exhausted"
	PHPEndOfLife        = "php_end_of_life"
	ServiceFailed       = "service_failed"
	ProcessFailing      = "process_failing"
	ClockUnsynced       = "clock_unsynced"
	NoSwap              = "no_swap"
	OutOfMemory         = "out_of_memory"
	DiskAlmostFull      = "disk_almost_full"
	RestartPending      = "restart_pending"
	FirewallInactive    = "firewall_inactive"
	LaravelDebug        = "laravel_debug"
	LaravelQueueNoWork  = "laravel_queue_without_worker"
)

const (
	// Keep is how long a scan answers later requests.
	Keep = time.Minute
	// Limit bounds one scan.
	Limit = 10 * time.Second

	logTail = 64 << 10
	// EnvLimit is how much of a site's environment file a scan reads; a longer one is left out.
	EnvLimit    = 64 << 10
	workerBytes = 64 << 20
	gib         = 1 << 30

	swapFile = "/swapfile"
	fstab    = "/etc/fstab"
)

// ErrGone is a fix asked for an insight that is no longer found, or that has no fix.
var ErrGone = errors.New("That is no longer a problem on this server, or it has no automatic fix. Refresh the list.")

// Error is a fix that failed; Detail is the tool's output.
type Error struct {
	Summary string
	Detail  string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Summary
	}

	return e.Summary + "\n\n" + e.Detail
}

type Insight struct {
	Kind string
	// Subject is a site id, a systemd unit or a PHP version; empty for the server itself.
	Subject string
	Values  map[string]string
	Fixable bool
}

// phpEndOfLife is the day each PHP version stopped getting security fixes, from php.net/supported-versions.
var phpEndOfLife = map[string]time.Time{
	"7.4": time.Date(2022, 11, 28, 0, 0, 0, 0, time.UTC),
	"8.0": time.Date(2023, 11, 26, 0, 0, 0, 0, time.UTC),
	"8.1": time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC),
	"8.2": time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
	"8.3": time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC),
	"8.4": time.Date(2028, 12, 31, 0, 0, 0, 0, time.UTC),
	"8.5": time.Date(2029, 12, 31, 0, 0, 0, 0, time.UTC),
}

type Scanner struct {
	Paths  paths.Paths
	Runner system.Runner
	Sites  func() ([]site.Site, error)
	// Env returns at most EnvLimit bytes of a site's environment file; nothing when it has none.
	Env func(ctx context.Context, siteID string) ([]byte, error)
	// SaveSite stores a changed site and applies it.
	SaveSite func(ctx context.Context, s site.Site, actor string) error
	// BackgroundProcesses returns the server's background processes: their names and commands by id.
	BackgroundProcesses func() map[string][2]string
	RestartService      func(ctx context.Context, unit string) error
	// RebootRequired reports since when an installed update has waited for a restart.
	RebootRequired func() (time.Time, bool)
	// Disk returns the root filesystem's size and what is free on it, in bytes; zeros when it can't be read.
	Disk func() (total, free uint64)
	Now  func() time.Time

	mu      sync.Mutex
	kept    []Insight
	scanned time.Time
	// skipped is set by a check that couldn't look, during the scan in progress.
	skipped bool
}

// Insights returns what the last complete scan found when it is at most Keep old and refresh is false; otherwise it
// scans. partial means a check couldn't look (a command failed, or time ran out), so something may be missing.
func (s *Scanner) Insights(ctx context.Context, refresh bool) (found []Insight, scanned time.Time, partial bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !refresh && !s.scanned.IsZero() && s.Now().Sub(s.scanned) <= Keep {
		return s.kept, s.scanned, false
	}

	found, complete := s.scan(ctx)
	if !complete {
		// Not kept: the next request looks again rather than repeating an answer with holes.
		s.scanned = time.Time{}

		return found, s.Now(), true
	}
	s.kept, s.scanned = found, s.Now()

	return s.kept, s.scanned, false
}

// Fix applies the fix of a fixable insight that a fresh scan still finds.
func (s *Scanner) Fix(ctx context.Context, kind, subject, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found, _ := s.scan(ctx)
	// Whatever happens next, the kept answer is stale.
	s.scanned = time.Time{}

	index := slices.IndexFunc(found, func(i Insight) bool { return i.Kind == kind && i.Subject == subject && i.Fixable })
	if index < 0 {
		return ErrGone
	}
	insight := found[index]

	switch kind {
	case PHPWorkersExhausted:
		return s.raiseWorkers(ctx, insight, actor)
	case ServiceFailed:
		return s.RestartService(ctx, subject)
	case ClockUnsynced:
		return s.run(ctx, "Couldn't turn time synchronisation on.", "timedatectl", "set-ntp", "true")
	case NoSwap:
		megabytes, _ := strconv.Atoi(insight.Values["megabytes"])

		return s.addSwap(ctx, megabytes)
	default:
		return ErrGone
	}
}

// scan runs every check and reports whether all of them could look.
func (s *Scanner) scan(ctx context.Context) ([]Insight, bool) {
	ctx, cancel := context.WithTimeout(ctx, Limit)
	defer cancel()

	s.skipped = false

	sites, err := s.Sites()
	if err != nil {
		s.skipped = true
	}
	memory := counters(s.Paths.File("/proc/meminfo"))

	var found []Insight
	found = append(found, s.units(ctx, sites)...)
	found = append(found, s.phpWorkers(sites, memory["MemTotal"]*1024)...)
	found = append(found, s.endOfLife(sites)...)
	found = append(found, s.memory(ctx, memory)...)
	found = append(found, s.system(ctx)...)
	found = append(found, s.laravel(ctx, sites)...)

	return found, !s.skipped && ctx.Err() == nil
}

// On-demand pools, which ServerDog writes, log "max_children"; dynamic and static ones "pm.max_children".
var maxChildren = regexp.MustCompile(`^\[([^\]]+)\] WARNING: \[pool serverdog-([a-z2-7]+)\] server reached (?:pm\.)?max_children setting \((\d+)\)`)

// phpWorkers reports the sites whose pool ran out of workers in the last 24 hours at its current limit; a hit
// logged under an earlier limit says nothing about this one.
func (s *Scanner) phpWorkers(sites []site.Site, memory uint64) []Insight {
	var versions []string
	for _, candidate := range sites {
		if candidate.Runtime == site.PHP && !slices.Contains(versions, candidate.PHPVersion) {
			versions = append(versions, candidate.PHPVersion)
		}
	}

	hits := map[string]int{}
	since := s.Now().Add(-24 * time.Hour)
	for _, version := range versions {
		for _, line := range strings.Split(string(tail(s.Paths.File("/var/log/php"+version+"-fpm.log"), logTail)), "\n") {
			match := maxChildren.FindStringSubmatch(line)
			if match == nil {
				continue
			}

			at, err := time.ParseInLocation("02-Jan-2006 15:04:05", match[1], time.Local)
			if err != nil || at.Before(since) {
				continue
			}
			hits[match[2]+"/"+match[3]]++
		}
	}

	// Half the memory, at 64 MB a worker, is what every site's raised limit shares; pools at the default start
	// workers only on demand and aren't counted.
	budget := min(int(memory/2/workerBytes), site.MaxPHPWorkers)

	var found []Insight
	for _, candidate := range sites {
		limit := candidate.PHPWorkerLimit()
		count := hits[candidate.ID+"/"+strconv.Itoa(limit)]
		if candidate.Runtime != site.PHP || count == 0 {
			continue
		}

		ceiling := budget
		for _, other := range sites {
			if other.ID != candidate.ID && other.Runtime == site.PHP && other.PHPWorkers > site.DefaultPHPWorkers {
				ceiling -= other.PHPWorkers
			}
		}

		insight := Insight{Kind: PHPWorkersExhausted, Subject: candidate.ID, Values: map[string]string{"limit": strconv.Itoa(limit), "hits": strconv.Itoa(count)}}
		if suggested := min(limit*2, ceiling); suggested > limit {
			insight.Values["suggested"] = strconv.Itoa(suggested)
			insight.Fixable = true
		}
		found = append(found, insight)
	}

	return found
}

func (s *Scanner) raiseWorkers(ctx context.Context, insight Insight, actor string) error {
	sites, err := s.Sites()
	if err != nil {
		return err
	}

	index := slices.IndexFunc(sites, func(candidate site.Site) bool { return candidate.ID == insight.Subject })
	if index < 0 {
		return ErrGone
	}

	changed := sites[index]
	changed.PHPWorkers, _ = strconv.Atoi(insight.Values["suggested"])

	return s.SaveSite(ctx, changed, actor)
}

func (s *Scanner) endOfLife(sites []site.Site) []Insight {
	using := map[string]int{}
	for _, candidate := range sites {
		if candidate.Runtime == site.PHP {
			using[candidate.PHPVersion]++
		}
	}

	var found []Insight
	for version, count := range using {
		if end, ok := phpEndOfLife[version]; ok && s.Now().After(end) {
			found = append(found, Insight{Kind: PHPEndOfLife, Subject: version, Values: map[string]string{"sites": strconv.Itoa(count), "since": end.Format(time.DateOnly)}})
		}
	}
	slices.SortFunc(found, func(a, b Insight) int { return strings.Compare(a.Subject, b.Subject) })

	return found
}

var (
	processUnit = regexp.MustCompile(`^serverdog-process-([a-z2-7]+)-([a-z2-7]+)@\d+\.service$`)
	daemonUnit  = regexp.MustCompile(`^serverdog-daemon-([a-z2-7]+)@\d+\.service$`)
	// A Node site's server, or a PHP site's Octane.
	siteUnit = regexp.MustCompile(`^serverdog-site-([a-z2-7]+)@\d+\.service$`)
)

// units reports failed services, and processes that failed or exited with an error and are waiting to start again.
// A worker that ended on purpose (queue:restart, --max-time) waits the same few seconds, so how it ended is asked.
func (s *Scanner) units(ctx context.Context, sites []site.Site) []Insight {
	result, err := s.Runner.Run(ctx, system.Command{Name: "systemctl", Args: []string{"list-units", "--type=service", "--state=failed,auto-restart", "--no-legend", "--plain", "--no-pager"}})
	if err != nil {
		s.skipped = true

		return nil
	}

	var units, waiting []string
	failed := map[string]bool{}
	for _, line := range strings.Split(string(result.Output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		units = append(units, fields[0])
		failed[fields[0]] = fields[2] == "failed"
		if !failed[fields[0]] && (processUnit.MatchString(fields[0]) || daemonUnit.MatchString(fields[0]) || siteUnit.MatchString(fields[0])) {
			waiting = append(waiting, fields[0])
		}
	}

	ended := s.results(ctx, waiting)

	var found []Insight
	add := func(insight Insight) {
		if !slices.ContainsFunc(found, func(i Insight) bool { return i.Kind == insight.Kind && i.Subject == insight.Subject }) {
			found = append(found, insight)
		}
	}

	for _, unit := range units {
		if !failed[unit] && ended[unit] == "success" {
			continue
		}

		if match := processUnit.FindStringSubmatch(unit); match != nil {
			add(Insight{Kind: ProcessFailing, Subject: match[1] + "/" + match[2], Values: map[string]string{"site": match[1], "name": processName(sites, match[1], match[2])}})
		} else if match := daemonUnit.FindStringSubmatch(unit); match != nil {
			add(Insight{Kind: ProcessFailing, Subject: match[1], Values: map[string]string{"name": s.BackgroundProcesses()[match[1]][0]}})
		} else if match := siteUnit.FindStringSubmatch(unit); match != nil {
			add(Insight{Kind: ProcessFailing, Subject: match[1] + "/server", Values: map[string]string{"site": match[1], "server": "true"}})
		} else if name := strings.TrimSuffix(unit, ".service"); servicectl.Known(name) {
			// A restart helps a service that gave up, not one that keeps exiting.
			add(Insight{Kind: ServiceFailed, Subject: name, Fixable: failed[unit]})
		}
	}

	return found
}

// results returns how each unit's last run ended, as systemd's Result has it ("success", "exit-code", "signal"…).
func (s *Scanner) results(ctx context.Context, units []string) map[string]string {
	ended := map[string]string{}
	if len(units) == 0 {
		return ended
	}

	result, err := s.Runner.Run(ctx, system.Command{Name: "systemctl", Args: append([]string{"show", "--property=Id,Result"}, units...)})
	if err != nil {
		s.skipped = true

		return ended
	}

	id := ""
	for _, line := range strings.Split(string(result.Output), "\n") {
		if value, ok := strings.CutPrefix(line, "Id="); ok {
			id = value
		} else if value, ok := strings.CutPrefix(line, "Result="); ok {
			ended[id] = value
		}
	}

	return ended
}

func processName(sites []site.Site, siteID, processID string) string {
	for _, candidate := range sites {
		if candidate.ID != siteID {
			continue
		}
		for _, process := range candidate.Processes {
			if process.ID == processID {
				return process.Name
			}
		}
	}

	return ""
}

// oomWindow is how far back the kernel's log is read for processes it killed.
const oomWindow = 7 * 24 * time.Hour

// memory reports a server without swap, and processes the kernel killed because the whole server ran out of memory
// in the last week. The kernel's counter gates the log read, so a server that never ran out runs nothing.
func (s *Scanner) memory(ctx context.Context, memory map[string]uint64) []Insight {
	var found []Insight

	total := memory["MemTotal"] * 1024
	if _, ok := memory["SwapTotal"]; ok && memory["SwapTotal"] == 0 && total > 0 && total <= 8*gib {
		megabytes := min(total, 2*gib) >> 20
		values := map[string]string{"megabytes": strconv.FormatUint(megabytes, 10)}
		_, free := s.Disk()

		// A swap file that is there but off (after a restart without its fstab line) only needs turning on.
		info, err := os.Stat(s.Paths.File(swapFile))
		exists := err == nil && info.Mode().IsRegular()
		if exists {
			values["megabytes"], values["existing"] = strconv.FormatInt(info.Size()>>20, 10), "true"
		}

		found = append(found, Insight{Kind: NoSwap, Values: values, Fixable: exists || free >= megabytes<<20+2*gib})
	}

	if counters(s.Paths.File("/proc/vmstat"))["oom_kill"] > 0 {
		// Exits 1 when nothing matches. A container's own limit logs "Memory cgroup out of memory", which isn't this.
		result, _ := s.Runner.Run(ctx, system.Command{Name: "journalctl", Args: []string{"--dmesg", "--since=-" + strconv.Itoa(int(oomWindow.Hours())) + "h", "--no-pager", "--output=cat", "--grep=^Out of memory: Killed process"}})
		if kills := strings.Count(string(result.Output), "Out of memory: Killed process"); kills > 0 {
			found = append(found, Insight{Kind: OutOfMemory, Values: map[string]string{"kills": strconv.Itoa(kills), "days": strconv.Itoa(int(oomWindow.Hours() / 24))}})
		}
	}

	return found
}

// system reports an unsynchronised clock, a nearly full disk, a restart that has waited and a firewall that is off.
func (s *Scanner) system(ctx context.Context) []Insight {
	var found []Insight

	// With synchronisation on, an unsynchronised clock is one still catching up, and there is nothing to turn on.
	result, err := s.Runner.Run(ctx, system.Command{Name: "timedatectl", Args: []string{"show", "--property=NTP", "--property=NTPSynchronized"}})
	if err != nil {
		s.skipped = true
	} else if lines := strings.Fields(string(result.Output)); slices.Contains(lines, "NTP=no") && slices.Contains(lines, "NTPSynchronized=no") {
		found = append(found, Insight{Kind: ClockUnsynced, Fixable: true})
	}

	if total, free := s.Disk(); total > 0 {
		if percent := 100 - free*100/total; percent >= 85 {
			found = append(found, Insight{Kind: DiskAlmostFull, Values: map[string]string{"percent": strconv.FormatUint(percent, 10)}})
		}
	}

	if since, ok := s.RebootRequired(); ok {
		if days := int(s.Now().Sub(since).Hours() / 24); days >= 3 {
			found = append(found, Insight{Kind: RestartPending, Values: map[string]string{"days": strconv.Itoa(days)}})
		}
	}

	if conf, err := os.ReadFile(s.Paths.File("/etc/ufw/ufw.conf")); err == nil && !slices.Contains(strings.Fields(string(conf)), "ENABLED=yes") {
		found = append(found, Insight{Kind: FirewallInactive})
	}

	return found
}

var (
	// database is left out: a new Laravel app's .env has it whether or not anything is ever queued.
	workerQueues  = []string{"redis", "sqs", "beanstalkd"}
	workerCommand = regexp.MustCompile(`queue:work|queue:listen|horizon`)
	// What Laravel reads as false for APP_DEBUG; anything else, "on" and "yes" included, turns debug on.
	debugOff = []string{"", "0", "false", "(false)", "null", "(null)", "empty", "(empty)"}
)

// laravel reports debug mode in production, and a queue nothing works through.
func (s *Scanner) laravel(ctx context.Context, sites []site.Site) []Insight {
	var found []Insight

	for _, candidate := range sites {
		if candidate.Preset != "laravel" || candidate.EnvironmentFile == "" {
			continue
		}

		content, err := s.Env(ctx, candidate.ID)
		if err != nil {
			s.skipped = true

			continue
		}
		if len(content) >= EnvLimit {
			continue
		}

		env := map[string]string{}
		for _, assignment := range dotenv.Parse(content) {
			key, value, _ := strings.Cut(assignment, "=")
			env[key] = strings.ToLower(value)
		}

		// Without APP_ENV, Laravel runs as production.
		environment, set := env["APP_ENV"]
		if (!set || environment == "production") && !slices.Contains(debugOff, env["APP_DEBUG"]) {
			found = append(found, Insight{Kind: LaravelDebug, Subject: candidate.ID})
		}

		// A worker run as one of the server's background processes, from the site's folder, counts too.
		works := slices.ContainsFunc(candidate.Processes, func(p site.Process) bool { return workerCommand.MatchString(p.Command) })
		for _, process := range s.BackgroundProcesses() {
			works = works || (workerCommand.MatchString(process[1]) && strings.Contains(process[1], candidate.Directory))
		}
		if slices.Contains(workerQueues, env["QUEUE_CONNECTION"]) && !works {
			found = append(found, Insight{Kind: LaravelQueueNoWork, Subject: candidate.ID, Values: map[string]string{"connection": env["QUEUE_CONNECTION"]}})
		}
	}

	return found
}

// addSwap creates the swap file unless one is there, turns it on and keeps it across restarts. A failure removes
// the file it created.
func (s *Scanner) addSwap(ctx context.Context, megabytes int) error {
	file := s.Paths.File(swapFile)
	summary := "Couldn't add the swap file."

	created, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	switch {
	case err == nil:
		created.Close()
		for _, command := range [][]string{{"fallocate", "--length", strconv.Itoa(megabytes) + "M", file}, {"mkswap", file}} {
			if err := s.run(ctx, summary, command[0], command[1:]...); err != nil {
				os.Remove(file)

				return err
			}
		}
	case !errors.Is(err, os.ErrExist):
		return &Error{Summary: summary, Detail: err.Error()}
	}

	if err := s.run(ctx, summary, "swapon", file); err != nil {
		if created != nil {
			os.Remove(file)
		}

		return err
	}

	if err := s.keepSwap(); err != nil {
		return &Error{Summary: "Swap is on, but it couldn't be added to /etc/fstab, so it will be off again after a restart.", Detail: err.Error()}
	}

	return nil
}

// keepSwap adds the swap file to /etc/fstab unless a line that isn't a comment already mounts it. The file is
// replaced in one rename, so a failure never leaves half a table.
func (s *Scanner) keepSwap() error {
	table, err := os.ReadFile(s.Paths.File(fstab))
	if err != nil {
		return err
	}

	for _, line := range strings.Split(string(table), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == swapFile {
			return nil
		}
	}

	if len(table) > 0 && !strings.HasSuffix(string(table), "\n") {
		table = append(table, '\n')
	}

	staged := s.Paths.File(fstab + ".serverdog")
	if err := os.WriteFile(staged, append(table, []byte(swapFile+" none swap sw 0 0\n")...), 0o644); err != nil {
		return err
	}

	return os.Rename(staged, s.Paths.File(fstab))
}

func (s *Scanner) run(ctx context.Context, summary, name string, args ...string) error {
	result, err := s.Runner.Run(ctx, system.Command{Name: name, Args: args})
	if err != nil {
		return &Error{Summary: summary, Detail: strings.TrimSpace(fmt.Sprintf("%s\n%s", err, result.Output))}
	}

	return nil
}

// RootDisk is Disk for the filesystem at root, counted as the server's overview counts it.
func RootDisk(root string) func() (total, free uint64) {
	return func() (uint64, uint64) {
		var disk unix.Statfs_t
		if err := unix.Statfs(root, &disk); err != nil {
			return 0, 0
		}

		return disk.Blocks * uint64(disk.Bsize), disk.Bfree * uint64(disk.Bsize)
	}
}

// counters reads "name value" lines, as /proc/vmstat and /proc/meminfo ("Name: value kB") have them.
func counters(file string) map[string]uint64 {
	values := map[string]uint64{}

	content, err := os.ReadFile(file)
	if err != nil {
		return values
	}

	for _, line := range strings.Split(string(content), "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 {
			if value, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				values[strings.TrimSuffix(fields[0], ":")] = value
			}
		}
	}

	return values
}

// tail returns at most limit bytes from the end of a file; nothing when it can't be read.
func tail(file string, limit int64) []byte {
	opened, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer opened.Close()

	if info, err := opened.Stat(); err == nil && info.Size() > limit {
		if _, err := opened.Seek(-limit, io.SeekEnd); err != nil {
			return nil
		}
	}

	content, _ := io.ReadAll(io.LimitReader(opened, limit))

	return content
}
