// Package processes renders the systemd units that keep a site's processes, such as queue workers, running, and the
// cron entry of its Laravel scheduler.
//
// Each process is a template unit with one instance per copy (name@1 … name@N), run as the site's user in
// <site directory>/current. Units carry ConditionPathExists on current, so a site without a live release starts
// nothing and the first deploy's restart brings them up.
package processes

import (
	"fmt"
	"path"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
)

// Template is the unit file name of one of a site's processes.
func Template(siteID, processID string) string {
	return "serverdog-process-" + siteID + "-" + processID + "@.service"
}

// Instances names the units of every copy of p.
func Instances(siteID string, p site.Process) []string {
	return instances(siteID, p.ID, 1, p.Count)
}

// Extra names the copies a process had beyond count, which stop when it shrinks.
func Extra(siteID string, p site.Process, count int) []string {
	return instances(siteID, p.ID, count+1, p.Count)
}

// Running names every copy of the processes of s that aren't stopped: the ones a deploy restarts.
func Running(s site.Site) []string {
	var names []string
	for _, p := range s.Processes {
		if !p.Stopped {
			names = append(names, Instances(s.ID, p)...)
		}
	}

	return names
}

// AllInstances names every copy of every process of s.
func AllInstances(s site.Site) []string {
	var names []string
	for _, p := range s.Processes {
		names = append(names, Instances(s.ID, p)...)
	}

	return names
}

func instances(siteID, processID string, from, to int) []string {
	var names []string
	for n := from; n <= to; n++ {
		names = append(names, fmt.Sprintf("serverdog-process-%s-%s@%d.service", siteID, processID, n))
	}

	return names
}

func StartScript(siteID, processID string) string {
	return path.Join(paths.SiteEtcDir(siteID), "process-"+processID+".sh")
}

// RenderUnit returns the template unit of process p. Stopping waits up to its stop timeout, a minute by default, so a
// queue worker sent SIGTERM can finish the job it is running.
func RenderUnit(s site.Site, p site.Process) []byte {
	current := path.Join(s.Directory, "current")

	return []byte(fmt.Sprintf(`# Managed by ServerDog for site %[1]s.
[Unit]
Description=ServerDog process %[2]s of site %[1]s (copy %%i)
After=network.target
ConditionPathExists=%[3]s
StartLimitIntervalSec=0

[Service]
Type=simple
User=%[4]s
Group=%[4]s
WorkingDirectory=%[6]s
ExecStart=%[5]s
Restart=always
RestartSec=5
TimeoutStopSec=%[7]d
# Each WebSocket client of a Reverb or Soketi server is an open file.
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, s.ID, oneLine(p.Name), current, s.User, StartScript(s.ID, p.ID), path.Join(current, p.Directory), site.StopTimeout(p.StopSeconds)))
}

// RenderStartScript runs the process's command. The site's .env isn't exported: Laravel and most frameworks read it
// themselves, and exported values would take precedence over the file.
func RenderStartScript(command string) []byte {
	return []byte("#!/bin/sh\n# Managed by ServerDog.\nexec " + command + "\n")
}

// RenderSchedulerCron runs Laravel's scheduler every minute in the live release, as cron's own entry would on Forge.
// Each minute starts its own schedule:run, so a long task never delays the next minute's.
func RenderSchedulerCron(s site.Site, phpBinary string) []byte {
	current := path.Join(s.Directory, "current")

	return []byte(fmt.Sprintf("# Managed by ServerDog for site %s.\n* * * * * %s cd %s && %s artisan schedule:run >> /dev/null 2>&1\n",
		s.ID, s.User, shellQuote(path.Join(current, s.AppDirectory)), phpBinary))
}

// oneLine makes a name safe in a unit's Description: no line breaks or continuations, and % escaped.
func oneLine(value string) string {
	return strings.NewReplacer("\n", " ", "\r", " ", "\\", " ", "%", "%%").Replace(value)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// Retired names the copies that stop when previous becomes s: every copy of a removed process, and the copies
// beyond the new count of one that shrank.
func Retired(s site.Site, previous *site.Site) []string {
	if previous == nil {
		return nil
	}

	var names []string
	for _, old := range previous.Processes {
		current, kept := find(s.Processes, old.ID)
		if !kept {
			names = append(names, Instances(previous.ID, old)...)
			continue
		}
		names = append(names, Extra(previous.ID, old, current.Count)...)
	}

	return names
}

// Removed lists the processes of previous that s no longer has.
func Removed(s site.Site, previous *site.Site) []site.Process {
	if previous == nil {
		return nil
	}

	var removed []site.Process
	for _, old := range previous.Processes {
		if _, kept := find(s.Processes, old.ID); !kept {
			removed = append(removed, old)
		}
	}

	return removed
}

// Changed lists the processes of s that are new or differ from previous: they (re)start once their units are saved.
func Changed(s site.Site, previous *site.Site) []site.Process {
	var changed []site.Process
	for _, p := range s.Processes {
		if previous != nil {
			if old, found := find(previous.Processes, p.ID); found && old == p {
				continue
			}
		}
		changed = append(changed, p)
	}

	return changed
}

func find(list []site.Process, id string) (site.Process, bool) {
	for _, p := range list {
		if p.ID == id {
			return p, true
		}
	}

	return site.Process{}, false
}
