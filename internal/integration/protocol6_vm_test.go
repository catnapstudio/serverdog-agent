//go:build vmtest

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
)

func TestFirewallRulesAreAddedChangedAndRemovedInUfw(t *testing.T) {
	if _, err := exec.LookPath("ufw"); err != nil {
		sh(t, "/", "apt-get", "install", "-y", "-q", "ufw")
	}
	server := agentv1.NewServerServiceClient(conn)
	get := func() *agentv1.GetFirewallResponse {
		response, err := server.GetFirewall(timeout(t), &agentv1.GetFirewallRequest{})
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	put := func(revision uint64, rules ...*agentv1.FirewallRule) (uint64, error) {
		response, err := server.PutFirewall(timeout(t), &agentv1.PutFirewallRequest{Rules: rules, ExpectedRevision: revision})
		return response.GetRevision(), err
	}

	// Rules an earlier run left go first; SSH is added after, as setup adds it.
	if _, err := put(get().Revision); err != nil {
		t.Fatal(err)
	}
	sh(t, "/", "ufw", "allow", "22/tcp")
	sh(t, "/", "ufw", "--force", "enable")
	t.Cleanup(func() { _ = exec.Command("ufw", "--force", "disable").Run() })

	before := get()
	if !before.Installed || !before.Active || !strings.Contains(strings.Join(before.OtherRules, "\n"), "allow 22/tcp") {
		t.Fatalf("firewall = %v", before)
	}

	rule := &agentv1.FirewallRule{Id: ids.New(), Name: "Metrics from the office", Action: "allow", Port: "8081", Protocol: "tcp", From: "10.1.2.3"}
	revision, err := put(before.Revision, rule)
	if err != nil {
		t.Fatal(err)
	}
	if status := sh(t, "/", "ufw", "status"); !strings.Contains(status, "8081/tcp") || !strings.Contains(status, "10.1.2.3") || !strings.Contains(status, "serverdog:"+rule.Id) {
		t.Fatalf("ufw status after adding:\n%s", status)
	}

	// Changed to anywhere and both protocols: the old rule goes, for IPv4 and IPv6.
	rule.From, rule.Protocol = "", ""
	if revision, err = put(revision, rule); err != nil {
		t.Fatal(err)
	}
	status := sh(t, "/", "ufw", "status")
	if strings.Contains(status, "10.1.2.3") || !strings.Contains(status, "8081 (v6)") {
		t.Fatalf("ufw status after changing:\n%s", status)
	}

	// A rule setup already added stays setup's: owning it would let the app delete SSH.
	ssh := &agentv1.FirewallRule{Id: ids.New(), Name: "SSH", Action: "allow", Port: "22", Protocol: "tcp"}
	if _, err := put(revision, rule, ssh); err == nil || !strings.Contains(err.Error(), "already has") {
		t.Fatalf("taking over the SSH rule: %v", err)
	}
	if added := sh(t, "/", "ufw", "show", "added"); !strings.Contains(added, "ufw allow 22/tcp\n") && !strings.HasSuffix(added, "ufw allow 22/tcp") {
		t.Fatalf("the SSH rule changed:\n%s", added)
	}

	if _, err := put(revision); err != nil {
		t.Fatal(err)
	}
	if status := sh(t, "/", "ufw", "status"); strings.Contains(status, "8081") || !strings.Contains(status, "22/tcp") {
		t.Fatalf("ufw status after removing:\n%s", status)
	}
}

func TestSSHKeysLetPeopleLogInAndRemovingThemLocksThemOut(t *testing.T) {
	r := newRepo(t, map[string]string{"index.html": "keys\n"})
	createSite(t, newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "keys.test", r.URL))

	dir := t.TempDir()
	sh(t, "/", "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "laptop", "-f", dir+"/key")
	public, err := os.ReadFile(dir + "/key.pub")
	if err != nil {
		t.Fatal(err)
	}

	server := agentv1.NewServerServiceClient(conn)
	keys, err := server.GetSSHKeys(timeout(t), &agentv1.GetSSHKeysRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(keys.Users, ","), "serverdog") {
		t.Fatalf("users = %v", keys.Users)
	}

	login := func(user string) error {
		return exec.Command("ssh", "-i", dir+"/key", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", user+"@127.0.0.1", "true").Run()
	}

	key := strings.TrimSpace(string(public))
	put, err := server.PutSSHKeys(timeout(t), &agentv1.PutSSHKeysRequest{ExpectedRevision: keys.Revision, Keys: []*agentv1.SSHKey{
		{Id: ids.New(), Name: "Laptop", User: "root", PublicKey: key},
		{Id: ids.New(), Name: "Laptop", User: "serverdog", PublicKey: key},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"root", "serverdog"} {
		if err := login(user); err != nil {
			t.Errorf("%s can't log in with the key: %v", user, err)
		}
	}

	if _, err := server.PutSSHKeys(timeout(t), &agentv1.PutSSHKeysRequest{ExpectedRevision: put.Revision}); err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"root", "serverdog"} {
		if err := login(user); err == nil {
			t.Errorf("%s still logs in after the key was removed", user)
		}
	}
}

func TestDatabasesAreListedTheirPasswordsChangedAndDeleted(t *testing.T) {
	engine := serverEngine(t)
	databases := databasesClient()
	name, user := "p6_"+strings.ToLower(ids.New()[:6]), "p6u_"+strings.ToLower(ids.New()[:6])

	if _, err := databases.CreateDatabase(timeout(t), &agentv1.CreateDatabaseRequest{Name: name, User: user, Password: ids.New() + ids.New(), Actor: actor}); err != nil {
		t.Fatal(err)
	}

	listing, err := databases.ListDatabases(timeout(t), &agentv1.ListDatabasesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(" "+strings.Join(listing.Databases, " ")+" ", " "+name+" ") || !strings.Contains(" "+strings.Join(listing.Users, " ")+" ", " "+user+" ") {
		t.Fatalf("listing = %v", listing)
	}
	for _, own := range []string{"mysql", "information_schema", "postgres", "template1"} {
		if strings.Contains(" "+strings.Join(listing.Databases, " ")+" ", " "+own+" ") {
			t.Errorf("the engine's own %s is listed", own)
		}
	}

	password := ids.New() + ids.New()
	if _, err := databases.SetDatabaseUserPassword(timeout(t), &agentv1.SetDatabaseUserPasswordRequest{User: user, Password: password}); err != nil {
		t.Fatal(err)
	}

	connect := exec.Command("mariadb", "-h", "127.0.0.1", "-u", user, "-p"+password, name, "-e", "SELECT 1")
	if engine == "postgres" {
		connect = exec.Command("psql", "-h", "127.0.0.1", "-U", user, "-d", name, "-c", "SELECT 1")
		connect.Env = append(os.Environ(), "PGPASSWORD="+password)
	}
	if output, err := connect.CombinedOutput(); err != nil {
		t.Fatalf("the new password doesn't log in: %v\n%s", err, output)
	}

	if _, err := databases.DeleteDatabase(timeout(t), &agentv1.DeleteDatabaseRequest{Name: name}); err != nil {
		t.Fatal(err)
	}
	if _, err := databases.DeleteDatabaseUser(timeout(t), &agentv1.DeleteDatabaseUserRequest{User: user}); err != nil {
		t.Fatal(err)
	}

	listing, err = databases.ListDatabases(timeout(t), &agentv1.ListDatabasesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if all := fmt.Sprint(listing.Databases, listing.Users); strings.Contains(all, name) || strings.Contains(all, user) {
		t.Errorf("still listed: %s", all)
	}

	if _, err := databases.DeleteDatabaseUser(timeout(t), &agentv1.DeleteDatabaseUserRequest{User: "root"}); err == nil {
		t.Error("root was deleted")
	}
}

func TestTheOnlyPHPVersionIsReportedAndKept(t *testing.T) {
	server := agentv1.NewServerServiceClient(conn)
	versions, err := server.GetPHPVersions(timeout(t), &agentv1.GetPHPVersionsRequest{})
	if err != nil {
		t.Fatal(err)
	}

	installed := sh(t, "/", "sh", "-c", "ls /etc/php")
	if len(versions.Installed) == 0 || !strings.Contains(installed, versions.Installed[0]) || versions.Cli != versions.Installed[0] {
		t.Fatalf("versions = %v, /etc/php has %s", versions, installed)
	}

	if _, err := server.InstallPHPVersion(timeout(t), &agentv1.InstallPHPVersionRequest{Version: versions.Installed[0]}); err != nil {
		t.Errorf("installing the installed version: %v", err)
	}
	if _, err := server.RemovePHPVersion(timeout(t), &agentv1.RemovePHPVersionRequest{Version: versions.Installed[0]}); err == nil {
		t.Error("the php command's version was removed")
	}
	if _, err := server.SetCLIPHPVersion(timeout(t), &agentv1.SetCLIPHPVersionRequest{Version: versions.Installed[0]}); err != nil {
		t.Errorf("setting the php command: %v", err)
	}
}
