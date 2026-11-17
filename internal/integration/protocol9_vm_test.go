//go:build vmtest

package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
)

// A dummy interface stands in for the provider's private network or Tailscale. The server is 10.99.0.1; the peer is
// 10.99.0.2 on the same interface, so its connections come from that address.
const (
	privateAddress = "10.99.0.1"
	peerAddress    = "10.99.0.2"
)

func addDummyInterface(t *testing.T) {
	t.Helper()

	if exec.Command("ip", "link", "show", "sdnet0").Run() != nil {
		sh(t, "/", "ip", "link", "add", "sdnet0", "type", "dummy")
	}
	for _, address := range []string{privateAddress, peerAddress} {
		if !strings.Contains(sh(t, "/", "ip", "-4", "addr", "show", "sdnet0"), address+"/") {
			sh(t, "/", "ip", "addr", "add", address+"/24", "dev", "sdnet0")
		}
	}
	sh(t, "/", "ip", "link", "set", "sdnet0", "up")
}

func networkPorts(engine string) []int {
	database := 3306
	if engine == "postgres" {
		database = 5432
	}

	return []int{database, 6379, 11211}
}

// dialFrom connects to address:port from the source address, within 5 seconds.
func dialFrom(source, address string, port int) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}

	return dialer.Dial("tcp", net.JoinHostPort(address, strconv.Itoa(port)))
}

func putNetwork(t *testing.T, address string, peers []*agentv1.NetworkPeer) *agentv1.GetNetworkResponse {
	t.Helper()

	server := agentv1.NewServerServiceClient(conn)
	current, err := server.GetNetwork(timeout(t), &agentv1.GetNetworkRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.PutNetwork(timeout(t), &agentv1.PutNetworkRequest{Address: address, Peers: peers, ExpectedRevision: current.Revision}); err != nil {
		t.Fatalf("PutNetwork(%q): %v", address, err)
	}

	after, err := server.GetNetwork(timeout(t), &agentv1.GetNetworkRequest{})
	if err != nil {
		t.Fatal(err)
	}

	return after
}

func TestPrivateNetworkingLetsOnlyPeersReachTheServices(t *testing.T) {
	engine := serverEngine(t)
	addDummyInterface(t)
	server := agentv1.NewServerServiceClient(conn)
	t.Cleanup(func() {
		current, err := server.GetNetwork(context.Background(), &agentv1.GetNetworkRequest{})
		if err == nil {
			server.PutNetwork(context.Background(), &agentv1.PutNetworkRequest{ExpectedRevision: current.Revision})
		}
	})

	// TestNetworkingIsLeftOnForTheReboot leaves it on when a run stops before the reboot.
	before := putNetwork(t, "", nil)
	if !slices.ContainsFunc(before.Candidates, func(c *agentv1.NetworkAddress) bool {
		return c.Address == privateAddress && c.Interface == "sdnet0"
	}) {
		t.Fatalf("candidates = %v, want %s on sdnet0", before.Candidates, privateAddress)
	}

	// Before: nothing listens on the private address.
	for _, port := range networkPorts(engine) {
		if c, err := dialFrom(peerAddress, privateAddress, port); err == nil {
			c.Close()
			t.Fatalf("port %d answers on the private address before networking is on", port)
		}
	}

	peer := &agentv1.NetworkPeer{Id: ids.New(), Name: "web-1", Address: peerAddress}
	status := putNetwork(t, privateAddress, []*agentv1.NetworkPeer{peer})
	if status.Address != privateAddress || len(status.Peers) != 1 || len(status.Services) != 3 {
		t.Fatalf("network after turning on = %v", status)
	}

	for _, port := range networkPorts(engine) {
		c, err := dialFrom(peerAddress, privateAddress, port)
		if err != nil {
			t.Errorf("port %d from the peer: %v", port, err)
			continue
		}
		c.Close()

		if c, err := dialFrom("127.0.0.1", "127.0.0.1", port); err != nil {
			t.Errorf("port %d on 127.0.0.1 after turning on: %v", port, err)
		} else {
			c.Close()
		}
	}

	// Redis answers the peer without a password.
	if c, err := dialFrom(peerAddress, privateAddress, 6379); err == nil {
		c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(c, "PING\r\n")
		reply := make([]byte, 7)
		n, _ := c.Read(reply)
		if string(reply[:n]) != "+PONG\r\n" {
			t.Errorf("Redis answered the peer %q", reply[:n])
		}
		c.Close()
	}

	added := sh(t, "/", "ufw", "show", "added")
	if got := strings.Count(added, "comment 'serverdog-network:"+peer.Id+"'"); got != 3 {
		t.Errorf("%d network rules, want 3:\n%s", got, added)
	}

	check, err := server.CheckConnection(timeout(t), &agentv1.CheckConnectionRequest{Address: privateAddress, Port: uint32(networkPorts(engine)[0])})
	if err != nil || check.Result != "connected" {
		t.Errorf("CheckConnection = %v %v", check, err)
	}
	check, err = server.CheckConnection(timeout(t), &agentv1.CheckConnectionRequest{Address: privateAddress, Port: 1})
	if err != nil || check.Result != "refused" {
		t.Errorf("CheckConnection on a closed port = %v %v", check, err)
	}

	// A database the peer logs in to.
	name, password := "net"+strings.ToLower(ids.New()[:6]), "Pw1"+strings.ToLower(ids.New())+"x"
	created, err := databasesClient().CreateDatabase(timeout(t), &agentv1.CreateDatabaseRequest{Name: name, User: name, Password: password, AllowedFrom: []string{peerAddress}, Actor: actor})
	if err != nil {
		t.Fatalf("CreateDatabase: %v", err)
	}
	t.Cleanup(func() {
		databasesClient().DeleteDatabase(context.Background(), &agentv1.DeleteDatabaseRequest{Name: name})
		databasesClient().DeleteDatabaseUser(context.Background(), &agentv1.DeleteDatabaseUserRequest{User: name})
	})
	if created.Host != privateAddress {
		t.Errorf("host = %q, want the private address", created.Host)
	}

	if _, err := databasesClient().CreateDatabase(timeout(t), &agentv1.CreateDatabaseRequest{Name: name + "x", User: name + "x", Password: password, AllowedFrom: []string{"10.99.0.3"}, Actor: actor}); err == nil {
		t.Error("CreateDatabase let in an address that isn't a peer")
	}

	if engine == "postgres" {
		// psql can't pick its source address, so the peer's line is checked in pg_hba.conf, and the server's own login.
		hba := sh(t, "/", "runuser", "-u", "postgres", "--", "psql", "-XAtc", "SHOW hba_file")
		content, _ := os.ReadFile(hba)
		if !strings.Contains(string(content), fmt.Sprintf("host %[1]s %[1]s %[2]s/32 scram-sha-256 # serverdog", name, peerAddress)) {
			t.Errorf("pg_hba.conf lacks the peer's line:\n%s", content)
		}
		login := exec.Command("psql", "-XAtc", "SELECT 1", fmt.Sprintf("host=127.0.0.1 dbname=%[1]s user=%[1]s", name))
		login.Env = append(os.Environ(), "PGPASSWORD="+password)
		if output, err := login.CombinedOutput(); err != nil {
			t.Errorf("login on 127.0.0.1: %v\n%s", err, output)
		}
	} else {
		// Neither client can pick its source address, so the peer's account is checked; the app's two-server test logs in.
		command := rootSQL(engine, fmt.Sprintf("SELECT Host FROM mysql.user WHERE User = '%s' ORDER BY Host", name))
		hosts := strings.Fields(sh(t, "/", command[0], append(command[1:], "-N")...))
		if !slices.Equal(hosts, []string{peerAddress, "127.0.0.1", "localhost"}) {
			t.Errorf("%s's hosts = %v, want the peer's too", name, hosts)
		}
	}

	// Turning it off takes the services back to 127.0.0.1 and the rules away.
	putNetwork(t, "", nil)

	for _, port := range networkPorts(engine) {
		if c, err := dialFrom(peerAddress, privateAddress, port); err == nil {
			c.Close()
			t.Errorf("port %d still answers on the private address after turning off", port)
		}
		if c, err := dialFrom("127.0.0.1", "127.0.0.1", port); err != nil {
			t.Errorf("port %d on 127.0.0.1 after turning off: %v", port, err)
		} else {
			c.Close()
		}
	}
	if added := sh(t, "/", "ufw", "show", "added"); strings.Contains(added, "serverdog-network:") {
		t.Errorf("network rules left after turning off:\n%s", added)
	}
	if _, err := os.Stat("/etc/sysctl.d/60-serverdog-network.conf"); !os.IsNotExist(err) {
		t.Errorf("the nonlocal bind setting is left: %v", err)
	}
}

// TestNetworkingIsLeftOnForTheReboot runs before scripts/vm-test.sh restarts the VM. The dummy interface doesn't
// survive the restart, so the services boot without their private address, as with Tailscale coming up late.
func TestNetworkingIsLeftOnForTheReboot(t *testing.T) {
	if os.Getenv("SERVERDOG_AFTER_REBOOT") != "" {
		t.Skip("runs before the restart")
	}

	addDummyInterface(t)
	putNetwork(t, privateAddress, []*agentv1.NetworkPeer{{Id: ids.New(), Name: "web-1", Address: peerAddress}})
}

func TestServicesStartBeforeTheirPrivateAddressExists(t *testing.T) {
	if os.Getenv("SERVERDOG_AFTER_REBOOT") == "" {
		t.Skip("scripts/vm-test.sh runs this after restarting the VM")
	}

	engine := serverEngine(t)
	server := agentv1.NewServerServiceClient(conn)
	status, err := server.GetNetwork(timeout(t), &agentv1.GetNetworkRequest{})
	if err != nil || status.Address != privateAddress {
		t.Fatalf("network after the reboot = %v %v, want it left on", status, err)
	}

	if exec.Command("ip", "link", "show", "sdnet0").Run() == nil {
		t.Fatal("sdnet0 survived the reboot, so this proves nothing")
	}

	addDummyInterface(t)
	for _, port := range networkPorts(engine) {
		c, err := dialFrom(peerAddress, privateAddress, port)
		if err != nil {
			t.Errorf("port %d on an address that came up after boot: %v", port, err)
			continue
		}
		c.Close()
	}

	putNetwork(t, "", nil)
}
