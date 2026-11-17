//go:build vmtest

package integration

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/nodeservice"
	"github.com/catnapstudio/serverdog-agent/internal/portguard"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// bindLoopScript tries to bind and listen on a port as fast as it can for a number of seconds, and prints "won" with
// the address if it ever succeeds, or "lost". Arguments: port, seconds.
const bindLoopScript = `import socket, sys, time
port, until = int(sys.argv[1]), time.time() + float(sys.argv[2])
while time.time() < until:
    for host in ("127.0.0.1", "0.0.0.0"):
        s = socket.socket()
        try:
            s.bind((host, port))
            s.listen()
            print("won", host)
            sys.exit(0)
        except OSError:
            pass
        finally:
            s.close()
print("lost")
`

// stranger is a user that no site runs as, created on first use.
func stranger(t *testing.T) *system.User {
	t.Helper()

	if _, err := system.LookupUser("intruder"); err != nil {
		sh(t, "/", "useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "intruder")
	}

	return lookup(t, "intruder")
}

func asUser(user *system.User) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: user.UID, Gid: user.GID}}
}

var upstreamPort = regexp.MustCompile(`127\.0\.0\.1:(\d+);`)

// nodePorts returns the port Nginx sends the site's traffic to and the other port of its pair. Both have a port file
// once the site has been deployed twice.
func nodePorts(t *testing.T, siteID string) (live, idle int) {
	t.Helper()

	upstream, err := os.ReadFile("/etc/nginx/serverdog/upstreams/" + siteID + ".conf")
	if err != nil {
		t.Fatal(err)
	}
	match := upstreamPort.FindSubmatch(upstream)
	if match == nil {
		t.Fatalf("upstream = %s", upstream)
	}
	live, _ = strconv.Atoi(string(match[1]))

	files, _ := filepath.Glob("/etc/serverdog/sites/" + siteID + "/*.env")
	for _, file := range files {
		if port, err := strconv.Atoi(strings.TrimSuffix(filepath.Base(file), ".env")); err == nil && port != live {
			idle = port
		}
	}
	if idle == 0 {
		t.Fatalf("no idle port among %v (live %d)", files, live)
	}

	return live, idle
}

// squat serves "pwned" on 127.0.0.1:port as user until the returned func is called.
func squat(t *testing.T, user *system.User, port int) func() {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "squat")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o755)
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("pwned\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("python3", "-m", "http.server", "--bind", "127.0.0.1", "--directory", dir, strconv.Itoa(port))
	cmd.Dir, cmd.SysProcAttr = "/", asUser(user)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	stop := func() {
		cmd.Process.Kill()
		cmd.Wait()
		os.RemoveAll(dir)
	}
	t.Cleanup(stop)

	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	for range 50 {
		if response, err := http.Get(url); err == nil {
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if strings.TrimSpace(string(body)) == "pwned" {
				return stop
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s couldn't squat port %d", user.Name, port)

	return nil
}

// failedWith deploys and fails the test unless the deploy fails with message.
func failedWith(t *testing.T, siteID, message string) {
	t.Helper()

	d, log := deploy(t, siteID)
	if d == nil || d.State != agentv1.DeploymentState_DEPLOYMENT_STATE_FAILED || d.WentLive || d.Error != message {
		t.Fatalf("deployment = %v, want failed with %q\n%s", d, message, log)
	}
}

// eventually waits up to 30 s for host to answer body.
func eventually(t *testing.T, host, body string) {
	t.Helper()

	for range 150 {
		if code, got, _, err := get(host); err == nil && code == 200 && got == body {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	expect(t, host, 200, body)
}

func TestNodePortsCannotBeHijacked(t *testing.T) {
	intruder := stranger(t)
	r := newRepo(t, map[string]string{
		"VERSION":   "v1",
		"server.js": "require('http').createServer((q, s) => s.end(require('fs').readFileSync('VERSION'))).listen(Number(process.env.PORT), process.env.HOST);\n",
	})
	s := newSite(agentv1.Runtime_RUNTIME_NODE, "other", "guard.test", r.URL)
	s.NodeStartCommand = "node server.js"
	s = createSite(t, s)

	mustDeploy(t, s.Id)
	r.push(map[string]string{"VERSION": "v2"}, "Second")
	mustDeploy(t, s.Id)
	expect(t, "guard.test", 200, "v2")
	live, idle := nodePorts(t, s.Id)

	t.Run("another user can't bind the site's ports or a free one", func(t *testing.T) {
		for _, port := range []int{idle, live, state.LastNodePort} {
			for _, address := range []string{"127.0.0.1", "0.0.0.0", "::"} {
				if got := bindIn(t, "", intruder, "tcp", address, port); got != "EPERM" {
					t.Errorf("intruder bind %s:%d = %s, want EPERM", address, port, got)
				}
			}
		}
	})

	t.Run("another user can bind the site's ports and a free one inside another network namespace", func(t *testing.T) {
		for _, port := range []int{idle, live, state.LastNodePort} {
			for _, address := range []string{"0.0.0.0", "::"} {
				if got := bindInNewNetns(t, "", intruder, "tcp", address, port); got != "ok" {
					t.Errorf("intruder bind %s:%d in another network namespace = %s, want ok", address, port, got)
				}
			}
		}
	})

	t.Run("another user never wins the live port while the site restarts after a crash", func(t *testing.T) {
		var output bytes.Buffer
		loop := exec.Command("python3", "-c", bindLoopScript, strconv.Itoa(live), "12")
		loop.Dir, loop.SysProcAttr, loop.Stdout, loop.Stderr = "/", asUser(intruder), &output, &output
		if err := loop.Start(); err != nil {
			t.Fatal(err)
		}

		pid, err := strconv.Atoi(sh(t, "/", "systemctl", "show", "--property=MainPID", "--value", nodeservice.Instance(s.Id, live)))
		if err != nil || pid == 0 {
			t.Fatalf("main pid = %d (%v)", pid, err)
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		if err := loop.Wait(); err != nil || strings.TrimSpace(output.String()) != "lost" {
			t.Errorf("bind loop = %q (%v), want lost", output.String(), err)
		}
		eventually(t, "guard.test", "v2")
	})

	t.Run("the site user squatting the idle port fails the deploy", func(t *testing.T) {
		stop := squat(t, lookup(t, s.User), idle)
		r.push(map[string]string{"VERSION": "v3"}, "Third")

		failedWith(t, s.Id, fmt.Sprintf("Port %d is held by a process outside the release.", idle))
		expect(t, "guard.test", 200, "v2")

		stop()
		mustDeploy(t, s.Id)
		expect(t, "guard.test", 200, "v3")
	})

	t.Run("without the guard deploys stop, and the listener check catches a squat made meanwhile", func(t *testing.T) {
		live, idle := nodePorts(t, s.Id)
		t.Cleanup(func() { exec.Command("systemctl", "restart", "serverdog-port-guard.service").Run() })

		sh(t, "/", "/usr/local/bin/serverdog-agent", "port-guard", "--remove")
		failedWith(t, s.Id, "The port guard isn't active, so the release wasn't started.")

		stop := squat(t, intruder, idle)
		sh(t, "/", "systemctl", "restart", "serverdog-port-guard.service")
		failedWith(t, s.Id, fmt.Sprintf("Port %d is held by a process outside the release.", idle))
		expect(t, "guard.test", 200, "v3")

		stop()
		mustDeploy(t, s.Id)
		expect(t, "guard.test", 200, "v3")
		if now, _ := nodePorts(t, s.Id); now != idle {
			t.Errorf("live port = %d, want %d (it was %d)", now, idle, live)
		}
	})
}

// TestPortGuardIsAttachedAtBoot runs after scripts/vm-test.sh restarts the VM: the guard must be attached before
// sysinit.target, so before any login, cron job or site starts.
func TestPortGuardIsAttachedAtBoot(t *testing.T) {
	if os.Getenv("SERVERDOG_AFTER_REBOOT") == "" {
		t.Skip("scripts/vm-test.sh runs this after restarting the VM")
	}

	if !portguard.Default().Attached() {
		t.Fatal("the port guard isn't attached after a reboot")
	}

	entered := func(unit string) int64 {
		value, err := strconv.ParseInt(sh(t, "/", "systemctl", "show", "--property=ActiveEnterTimestampMonotonic", "--value", unit), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	if guard, sysinit := entered("serverdog-port-guard.service"), entered("sysinit.target"); guard == 0 || guard > sysinit {
		t.Errorf("the guard was attached at %d µs, sysinit.target reached at %d µs", guard, sysinit)
	}

	intruder := stranger(t)
	for _, port := range []int{state.FirstNodePort, state.LastNodePort} {
		if got := bindIn(t, "", intruder, "tcp", "127.0.0.1", port); got != "EPERM" {
			t.Errorf("intruder bind 127.0.0.1:%d after a reboot = %s, want EPERM", port, got)
		}
	}
}
