package network

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

const (
	mysqlConf     = "[mysqld]\nbind-address = 127.0.0.1\nmysqlx-bind-address = 127.0.0.1\n"
	redisConf     = "bind 127.0.0.1 -::1\nprotected-mode yes\nport 6379\n"
	memcachedConf = "-m 64\n-p 11211\n-l 127.0.0.1\n-l ::1\n"
)

type fixture struct {
	m    *Manager
	fake *systemtest.Fake
	root string
	// refuse makes the fake dial fail for this address.
	refuse string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	root := t.TempDir()
	write(t, root, "/etc/mysql/mysql.conf.d/zz-serverdog.cnf", mysqlConf)
	write(t, root, "/etc/redis/redis.conf", redisConf)
	write(t, root, "/etc/memcached.conf", memcachedConf)
	write(t, root, "/etc/sysctl.d/.keep", "")

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	fake := &systemtest.Fake{}
	fake.Handle("ufw", func(c system.Command) (system.Result, error) {
		switch strings.Join(c.Args, " ") {
		case "status":
			return system.Result{Output: []byte("Status: active\n")}, nil
		case "show added":
			return system.Result{Output: []byte("Added user rules:\nufw allow 22/tcp\nufw allow in on eth1\nufw allow in on eth1 to any port 80\n")}, nil
		}
		return system.Result{Output: []byte("Rule added\n")}, nil
	})

	f := &fixture{fake: fake, root: root}
	f.m = &Manager{
		Store: store, Paths: paths.Paths{Root: root}, System: fake, Wait: 10 * time.Millisecond,
		Links: func() ([]Link, error) {
			return []Link{{Name: "eth1", Up: true, Addresses: []net.IP{net.ParseIP("10.0.0.5")}}}, nil
		},
		Engine: func(context.Context) string { return "mysql" },
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			if f.refuse != "" && address == f.refuse {
				return nil, errors.New("connection refused")
			}
			client, server := net.Pipe()
			server.Close()
			return client, nil
		},
	}

	return f
}

func write(t *testing.T, root, name, content string) {
	t.Helper()

	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) read(t *testing.T, name string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(f.root, name))
	if errors.Is(err, os.ErrNotExist) {
		return "<missing>"
	}
	if err != nil {
		t.Fatal(err)
	}

	return string(content)
}

func (f *fixture) commands(prefix string) []string {
	var matching []string
	for _, c := range f.fake.Commands() {
		if strings.HasPrefix(c, prefix) {
			matching = append(matching, c)
		}
	}

	return matching
}

var web = Peer{ID: "aaaaaaaaaaaa", Name: "web-1", Address: "10.0.0.7"}

func TestCandidatesSkipTheLoopbackDockerBridgesAndPublicAddresses(t *testing.T) {
	links := []Link{
		{Name: "lo", Up: true, Addresses: []net.IP{net.ParseIP("127.0.0.1")}},
		{Name: "eth0", Up: true, Addresses: []net.IP{net.ParseIP("203.0.113.4"), net.ParseIP("2001:db8::1")}},
		{Name: "eth1", Up: true, Addresses: []net.IP{net.ParseIP("10.0.0.5")}},
		{Name: "tailscale0", Up: true, Addresses: []net.IP{net.ParseIP("100.101.102.103"), net.ParseIP("fd7a:115c:a1e0::1")}},
		{Name: "wg0", Up: true, Addresses: []net.IP{net.ParseIP("192.168.50.2")}},
		{Name: "docker0", Up: true, Addresses: []net.IP{net.ParseIP("172.17.0.1")}},
		{Name: "br-1a2b", Up: true, Addresses: []net.IP{net.ParseIP("172.18.0.1")}},
		{Name: "lxdbr0", Up: true, Bridge: true, Addresses: []net.IP{net.ParseIP("10.10.0.1")}},
		{Name: "eth2", Up: false, Addresses: []net.IP{net.ParseIP("10.1.0.5")}},
	}

	got := Candidates(links)
	want := []Candidate{{"10.0.0.5", "eth1"}, {"100.101.102.103", "tailscale0"}, {"192.168.50.2", "wg0"}}
	if !slices.Equal(got, want) {
		t.Errorf("Candidates = %v, want %v", got, want)
	}
}

func TestTurningNetworkingOnAndOffMovesTheServicesAndTheRules(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	revision, err := f.m.Put(ctx, "10.0.0.5", []Peer{web}, 0)
	if err != nil {
		t.Fatal(err)
	}

	if got := f.read(t, "/etc/mysql/mysql.conf.d/zz-serverdog.cnf"); !strings.Contains(got, "bind-address = 127.0.0.1,10.0.0.5\nmysqlx-bind-address = 127.0.0.1\n") {
		t.Errorf("MySQL config = %q", got)
	}
	if got := f.read(t, "/etc/redis/redis.conf"); got != redisConf+"include /etc/redis/serverdog-network.conf\n" {
		t.Errorf("redis.conf = %q", got)
	}
	if got := f.read(t, redisInclude); !strings.Contains(got, "bind 127.0.0.1 -::1 10.0.0.5\nprotected-mode no\n") {
		t.Errorf("Redis include = %q", got)
	}
	if got := f.read(t, "/etc/memcached.conf"); got != "-m 64\n-p 11211\n-l 127.0.0.1,10.0.0.5\n-l ::1\n" {
		t.Errorf("memcached.conf = %q", got)
	}
	if got := f.read(t, sysctlFile); got != "net.ipv4.ip_nonlocal_bind = 1\n" {
		t.Errorf("sysctl file = %q", got)
	}
	if info, err := os.Stat(filepath.Join(f.root, "/etc/redis/redis.conf")); err != nil || info.Mode().Perm() != 0o640 {
		t.Errorf("redis.conf mode = %v %v, want it kept at 0640", info.Mode().Perm(), err)
	}

	wantRules := []string{
		"ufw allow proto tcp from 10.0.0.7 to 10.0.0.5 port 3306 comment serverdog-network:aaaaaaaaaaaa",
		"ufw allow proto tcp from 10.0.0.7 to 10.0.0.5 port 6379 comment serverdog-network:aaaaaaaaaaaa",
		"ufw allow proto tcp from 10.0.0.7 to 10.0.0.5 port 11211 comment serverdog-network:aaaaaaaaaaaa",
	}
	if got := f.commands("ufw allow"); !slices.Equal(got, wantRules) {
		t.Errorf("rules added = %v, want %v", got, wantRules)
	}
	if got := f.commands("systemctl restart"); !slices.Equal(got, []string{"systemctl restart mysql", "systemctl restart redis-server", "systemctl restart memcached"}) {
		t.Errorf("restarts = %v", got)
	}

	// Saving the same settings again changes nothing.
	before := len(f.fake.Commands())
	revision, err = f.m.Put(ctx, "10.0.0.5", []Peer{web}, revision)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.fake.Commands()[before:] {
		if strings.HasPrefix(c, "systemctl") || strings.HasPrefix(c, "ufw allow") || strings.HasPrefix(c, "ufw delete") {
			t.Errorf("an unchanged save ran %q", c)
		}
	}

	if _, err := f.m.Put(ctx, "", nil, revision); err != nil {
		t.Fatal(err)
	}

	if got := f.read(t, "/etc/mysql/mysql.conf.d/zz-serverdog.cnf"); got != mysqlConf {
		t.Errorf("MySQL config after turning off = %q", got)
	}
	if got := f.read(t, "/etc/redis/redis.conf"); got != redisConf {
		t.Errorf("redis.conf after turning off = %q", got)
	}
	if got := f.read(t, redisInclude); got != "<missing>" {
		t.Errorf("Redis include after turning off = %q", got)
	}
	if got := f.read(t, "/etc/memcached.conf"); got != memcachedConf {
		t.Errorf("memcached.conf after turning off = %q", got)
	}
	if got := f.read(t, sysctlFile); got != "<missing>" {
		t.Errorf("sysctl file after turning off = %q", got)
	}
	if got := len(f.commands("ufw delete allow proto tcp from 10.0.0.7 to 10.0.0.5")); got != 3 {
		t.Errorf("%d rules deleted, want 3", got)
	}
}

func TestAServiceThatDoesNotComeBackIsPutBackWithTheOnesBeforeIt(t *testing.T) {
	f := newFixture(t)
	f.refuse = "10.0.0.5:6379"
	f.fake.Handle("journalctl", func(system.Command) (system.Result, error) {
		return system.Result{Output: []byte("Could not create server TCP listening socket 10.0.0.5:6379\n")}, nil
	})

	_, err := f.m.Put(context.Background(), "10.0.0.5", []Peer{web}, 0)

	var networkErr *Error
	if !errors.As(err, &networkErr) || !strings.Contains(networkErr.Summary, "Redis") || !strings.Contains(networkErr.Output, "listening socket") {
		t.Fatalf("Put = %v, want Redis's failure with its journal", err)
	}
	if got := f.read(t, "/etc/redis/redis.conf"); got != redisConf {
		t.Errorf("redis.conf = %q, want it put back", got)
	}
	if got := f.read(t, redisInclude); got != "<missing>" {
		t.Errorf("Redis include = %q, want it removed", got)
	}
	if got := f.read(t, "/etc/mysql/mysql.conf.d/zz-serverdog.cnf"); got != mysqlConf {
		t.Errorf("MySQL config = %q, want it put back", got)
	}
	if got := f.commands("ufw allow"); len(got) != 0 {
		t.Errorf("rules added = %v, want none", got)
	}
	if status, _ := f.m.Status(context.Background()); status.Address != "" || status.Revision != 0 {
		t.Errorf("saved %+v, want nothing", status)
	}
}

func TestPutRefusesWhatItCannotSafelyApply(t *testing.T) {
	for _, test := range []struct {
		name    string
		address string
		peers   []Peer
	}{
		{"an address the server doesn't have", "10.9.9.9", nil},
		{"peers without an address", "", []Peer{web}},
		{"a public peer", "10.0.0.5", []Peer{{ID: "aaaaaaaaaaaa", Name: "web-1", Address: "203.0.113.9"}}},
		{"the server itself", "10.0.0.5", []Peer{{ID: "aaaaaaaaaaaa", Name: "me", Address: "10.0.0.5"}}},
		{"a peer listed twice", "10.0.0.5", []Peer{web, {ID: "bbbbbbbbbbbb", Name: "web-2", Address: "10.0.0.7"}}},
		{"a two-line name", "10.0.0.5", []Peer{{ID: "aaaaaaaaaaaa", Name: "web\n1", Address: "10.0.0.7"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)

			_, err := f.m.Put(context.Background(), test.address, test.peers, 0)

			var invalidErr *site.InvalidError
			if !errors.As(err, &invalidErr) {
				t.Fatalf("Put = %v, want an invalid argument", err)
			}
			if len(f.fake.Commands()) > 1 {
				t.Errorf("ran %v before refusing", f.fake.Commands())
			}
		})
	}
}

func TestStatusWarnsAboutRulesThatLetTheWholeInterfaceIn(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	if _, err := f.m.Put(ctx, "10.0.0.5", []Peer{web}, 0); err != nil {
		t.Fatal(err)
	}

	status, err := f.m.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(status.BroadRules, []string{"allow in on eth1"}) {
		t.Errorf("BroadRules = %v", status.BroadRules)
	}
	if !status.FirewallActive || status.Address != "10.0.0.5" || !slices.Equal(status.Peers, []Peer{web}) {
		t.Errorf("Status = %+v", status)
	}
	wantServices := []Service{{"mysql", 3306}, {"redis", 6379}, {"memcached", 11211}}
	if !slices.Equal(status.Services, wantServices) {
		t.Errorf("Services = %v, want %v", status.Services, wantServices)
	}
}

func TestCheckTellsAnAnsweringPortFromAClosedOne(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	if result, _, err := Check(context.Background(), "127.0.0.1", port); err != nil || result != "connected" {
		t.Errorf("Check on a listening port = %q %v", result, err)
	}

	listener.Close()
	if result, _, err := Check(context.Background(), "127.0.0.1", port); err != nil || result != "refused" {
		t.Errorf("Check on a closed port = %q %v", result, err)
	}

	if _, _, err := Check(context.Background(), "web-1", 3306); err == nil {
		t.Error("Check accepted a name")
	}
}
