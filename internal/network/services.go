package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// service is something that listens on the private address while networking is on.
type service struct {
	name  string
	label string
	port  int
	// unit's journal explains a failed restart.
	unit string
	// files are the files that make it listen on address, or on 127.0.0.1 only when address is "".
	files func(m *Manager, address string) (map[string]fileState, error)
	// stop runs before the files change, its errors ignored; start runs after, in order.
	stop  func(address string) [][]string
	start func(address string) [][]string
}

const (
	redisInclude      = "/etc/redis/serverdog-network.conf"
	meilisearchSocket = "serverdog-meilisearch-local.socket"
	meilisearchProxy  = "serverdog-meilisearch-local.service"
)

func newFile(content string, mode os.FileMode) fileState {
	return fileState{exists: true, content: []byte(content), mode: mode, uid: -1, gid: -1}
}

func restart(unit string) func(string) [][]string {
	return func(string) [][]string { return [][]string{{"systemctl", "restart", unit}} }
}

func nothing(string) [][]string { return nil }

func binds(address, separator string) string {
	if address == "" {
		return "127.0.0.1"
	}

	return "127.0.0.1" + separator + address
}

var mysql = service{
	name: "mysql", label: "MySQL", port: 3306, unit: "mysql",
	files: func(_ *Manager, address string) (map[string]fileState, error) {
		return map[string]fileState{
			"/etc/mysql/mysql.conf.d/zz-serverdog.cnf": newFile(fmt.Sprintf("[mysqld]\nbind-address = %s\nmysqlx-bind-address = 127.0.0.1\n", binds(address, ",")), 0o644),
		}, nil
	},
	stop: nothing, start: restart("mysql"),
}

var mariadb = service{
	name: "mariadb", label: "MariaDB", port: 3306, unit: "mariadb",
	files: func(_ *Manager, address string) (map[string]fileState, error) {
		return map[string]fileState{
			"/etc/mysql/mariadb.conf.d/99-serverdog.cnf": newFile(fmt.Sprintf("[mysqld]\nbind-address = %s\n", binds(address, ",")), 0o644),
		}, nil
	},
	stop: nothing, start: restart("mariadb"),
}

func postgres(confDir string) service {
	return service{
		name: "postgres", label: "PostgreSQL", port: 5432, unit: "postgresql@" + filepath.Base(filepath.Dir(filepath.Dir(confDir))) + "-main",
		files: func(_ *Manager, address string) (map[string]fileState, error) {
			file := fileState{}
			if address != "" {
				file = newFile(fmt.Sprintf("# Managed by ServerDog's private networking.\nlisten_addresses = 'localhost,%s'\n", address), 0o644)
			}
			return map[string]fileState{confDir + "/serverdog-network.conf": file}, nil
		},
		stop: nothing, start: restart("postgresql"),
	}
}

// Redis turns away other servers without a password unless protected mode is off, even on an explicit bind; the
// firewall limits who connects, as Forge's cache servers do.
var redis = service{
	name: "redis", label: "Redis", port: 6379, unit: "redis-server",
	files: func(m *Manager, address string) (map[string]fileState, error) {
		config, err := readFile(m.Paths.File("/etc/redis/redis.conf"))
		if err != nil {
			return nil, err
		}

		include := "include " + redisInclude
		lines := slices.DeleteFunc(strings.Split(strings.TrimRight(string(config.content), "\n"), "\n"), func(line string) bool {
			return strings.TrimSpace(line) == include
		})

		extra := fileState{}
		if address != "" {
			lines = append(lines, include)
			extra = newFile(fmt.Sprintf("# Managed by ServerDog's private networking.\nbind 127.0.0.1 -::1 %s\nprotected-mode no\n", address), 0o644)
		}
		config.content = []byte(strings.Join(lines, "\n") + "\n")

		return map[string]fileState{"/etc/redis/redis.conf": config, redisInclude: extra}, nil
	},
	stop: nothing, start: restart("redis-server"),
}

var memcached = service{
	name: "memcached", label: "Memcached", port: 11211, unit: "memcached",
	files: func(m *Manager, address string) (map[string]fileState, error) {
		config, err := readFile(m.Paths.File("/etc/memcached.conf"))
		if err != nil {
			return nil, err
		}

		// Only the 127.0.0.1 line changes; Ubuntu's "-l ::1" stays as it is.
		listen := "-l " + binds(address, ",")
		lines := strings.Split(strings.TrimRight(string(config.content), "\n"), "\n")
		found := false
		for i, line := range lines {
			fields := strings.Fields(line)
			if !found && len(fields) == 2 && fields[0] == "-l" && strings.Split(fields[1], ",")[0] == "127.0.0.1" {
				lines[i], found = listen, true
			}
		}
		if !found {
			lines = append(lines, listen)
		}
		config.content = []byte(strings.Join(lines, "\n") + "\n")

		return map[string]fileState{"/etc/memcached.conf": config}, nil
	},
	stop: nothing, start: restart("memcached"),
}

// Meilisearch listens on one address only, so it moves to the private one and systemd-socket-proxyd keeps
// 127.0.0.1:7700 working for the server's own sites.
var meilisearch = service{
	name: "meilisearch", label: "Meilisearch", port: 7700, unit: "meilisearch",
	files: func(m *Manager, address string) (map[string]fileState, error) {
		env, err := readFile(m.Paths.File("/etc/meilisearch.env"))
		if err != nil {
			return nil, err
		}

		listen := "127.0.0.1:7700"
		if address != "" {
			listen = address + ":7700"
		}
		lines := strings.Split(strings.TrimRight(string(env.content), "\n"), "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "MEILI_HTTP_ADDR=") {
				lines[i] = "MEILI_HTTP_ADDR=" + listen
			}
		}
		env.content = []byte(strings.Join(lines, "\n") + "\n")

		socket, proxy := fileState{}, fileState{}
		if address != "" {
			socket = newFile("# Managed by ServerDog: the server's own sites reach Meilisearch, which listens on the private address.\n[Socket]\nListenStream=127.0.0.1:7700\n\n[Install]\nWantedBy=sockets.target\n", 0o644)
			proxy = newFile(fmt.Sprintf("# Managed by ServerDog.\n[Unit]\nRequires=%[1]s\nAfter=%[1]s meilisearch.service\n\n[Service]\nExecStart=/usr/lib/systemd/systemd-socket-proxyd %[2]s:7700\n", meilisearchSocket, address), 0o644)
		}

		return map[string]fileState{
			"/etc/meilisearch.env":                     env,
			"/etc/systemd/system/" + meilisearchSocket: socket,
			"/etc/systemd/system/" + meilisearchProxy:  proxy,
		}, nil
	},
	// The proxy lets go of 127.0.0.1:7700 before Meilisearch may take it back, and before its units go.
	stop: func(string) [][]string {
		return [][]string{{"systemctl", "disable", "--now", meilisearchSocket, meilisearchProxy}}
	},
	start: func(address string) [][]string {
		commands := [][]string{{"systemctl", "daemon-reload"}, {"systemctl", "restart", "meilisearch"}}
		if address != "" {
			commands = append(commands, []string{"systemctl", "enable", "--now", meilisearchSocket})
		}
		return commands
	},
}

// services are the ones installed, in a fixed order.
func (m *Manager) services(ctx context.Context) []service {
	var list []service

	switch m.Engine(ctx) {
	case "mysql":
		list = append(list, mysql)
	case "mariadb":
		list = append(list, mariadb)
	case "postgres":
		if dirs, _ := filepath.Glob(m.Paths.File("/etc/postgresql/*/main/conf.d")); len(dirs) > 0 {
			slices.Sort(dirs)
			relative, _ := filepath.Rel(m.Paths.File("/"), dirs[len(dirs)-1])
			list = append(list, postgres("/"+filepath.ToSlash(relative)))
		}
	}

	for _, candidate := range []struct {
		file    string
		service service
	}{
		{"/etc/redis/redis.conf", redis},
		{"/etc/memcached.conf", memcached},
		{"/etc/meilisearch.env", meilisearch},
	} {
		if _, err := os.Stat(m.Paths.File(candidate.file)); err == nil {
			list = append(list, candidate.service)
		}
	}

	return list
}

// configure moves a service from one address to another. It does nothing when its files already say so. When the
// service doesn't come back answering, its previous files go back and it restarts on them.
func (m *Manager) configure(ctx context.Context, s service, from, to string) error {
	wanted, err := s.files(m, to)
	if err != nil {
		return err
	}

	previous := map[string]fileState{}
	changed := false
	for name, file := range wanted {
		current, err := readFile(m.Paths.File(name))
		if err != nil {
			return err
		}
		previous[name] = current
		changed = changed || !current.same(file)
		if current.exists && file.exists {
			// The file keeps its mode and owner.
			file.mode, file.uid, file.gid = current.mode, current.uid, current.gid
			wanted[name] = file
		}
	}
	if !changed {
		return nil
	}

	m.run(ctx, s.stop(to), true)

	err = m.write(wanted)
	if err == nil {
		err = m.run(ctx, s.start(to), false)
	}
	if err == nil {
		err = m.answers(ctx, s.port, to)
	}
	if err == nil {
		return nil
	}

	output := m.journal(ctx, s.unit)
	if output == "" {
		output = err.Error()
	}

	restore := context.WithoutCancel(ctx)
	m.run(restore, s.stop(from), true)
	_ = m.write(previous)
	m.run(restore, s.start(from), true)

	return &Error{Summary: fmt.Sprintf("%s didn't come back up on the new address, so its previous settings were put back.", s.label), Output: output}
}

func (m *Manager) write(files map[string]fileState) error {
	for name, file := range files {
		if err := writeFile(m.Paths.File(name), file); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) run(ctx context.Context, commands [][]string, ignoreErrors bool) error {
	for _, command := range commands {
		result, err := m.System.Run(ctx, system.Command{Name: command[0], Args: command[1:]})
		if err != nil && !ignoreErrors {
			return &Error{Summary: strings.Join(command, " ") + " failed.", Output: system.Tail(result.Output, 10)}
		}
	}

	return nil
}

// answers waits for the service to accept connections on 127.0.0.1 and on address.
func (m *Manager) answers(ctx context.Context, port int, address string) error {
	wait := m.Wait
	if wait == 0 {
		wait = 30 * time.Second
	}
	deadline := time.Now().Add(wait)

	hosts := []string{"127.0.0.1"}
	if address != "" {
		hosts = append(hosts, address)
	}

	for _, host := range hosts {
		target := net.JoinHostPort(host, strconv.Itoa(port))
		for {
			conn, err := m.Dial(ctx, "tcp", target)
			if err == nil {
				conn.Close()
				break
			}
			if time.Now().After(deadline) || ctx.Err() != nil {
				return fmt.Errorf("nothing answers on %s: %w", target, err)
			}
			time.Sleep(250 * time.Millisecond)
		}
	}

	return nil
}

func (m *Manager) journal(ctx context.Context, unit string) string {
	result, _ := m.System.Run(context.WithoutCancel(ctx), system.Command{Name: "journalctl", Args: []string{"-u", unit, "-n", "15", "--no-pager", "-o", "cat"}})

	return system.Tail(result.Output, 15)
}
