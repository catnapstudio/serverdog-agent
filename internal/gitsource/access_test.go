package gitsource

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
	"golang.org/x/crypto/ssh"
)

func randomKeyLine(t *testing.T, host string) string {
	t.Helper()

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ssh.NewPublicKey(public)

	return host + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func githubLines() string {
	var lines []string
	for _, key := range ParseKnownHosts(ProviderKnownHosts) {
		if key.Names("github.com") {
			lines = append(lines, key.Line)
		}
	}

	return "# github.com:22 SSH-2.0-babeld\n" + strings.Join(lines, "\n") + "\n"
}

func tester(keyscan string, git func(system.Command) (system.Result, error)) (Tester, *systemtest.Fake) {
	fake := &systemtest.Fake{}
	fake.Handle("ssh-keyscan", func(system.Command) (system.Result, error) {
		return system.Result{Output: []byte(keyscan)}, nil
	})
	if git != nil {
		fake.Handle("git", git)
	}

	return Tester{Runner: fake}, fake
}

func gitOutput(text string, code int) func(system.Command) (system.Result, error) {
	return func(system.Command) (system.Result, error) {
		if code != 0 {
			return system.Result{Output: []byte(text)}, &system.ExitError{Command: "git", ExitCode: code, Output: []byte(text)}
		}
		return system.Result{Output: []byte(text)}, nil
	}
}

var trusted = ParseKnownHosts(ProviderKnownHosts)

func TestAccessOK(t *testing.T) {
	tester, fake := tester(githubLines(), gitOutput("b4c5d6e7f8a9\trefs/heads/main\n", 0))

	result := tester.Test(context.Background(), "git@github.com:morgan/orchard.git", "main", trusted, Credentials{KeyPath: "/k", KnownHostsPath: "/kh", GlobalKnownHostsPath: "/g", Home: "/home/serverdog", Path: "/usr/bin"})
	if result.Access != AccessOK || result.Commit != "b4c5d6e7f8a9" || result.Host != "github.com" {
		t.Fatalf("result = %+v", result)
	}

	var git system.Command
	for _, call := range fake.Calls() {
		if call.Name == "git" {
			git = call
		}
	}
	if strings.Join(git.Args, " ") != "ls-remote git@github.com:morgan/orchard.git refs/heads/main" {
		t.Errorf("git args = %v", git.Args)
	}
	if !strings.Contains(strings.Join(git.Env, "\n"), "GIT_SSH_COMMAND=ssh -i '/k' -o IdentitiesOnly=yes") {
		t.Errorf("env = %v", git.Env)
	}
}

func TestBranchNotFound(t *testing.T) {
	tester, _ := tester(githubLines(), gitOutput("", 0))

	if result := tester.Test(context.Background(), "git@github.com:a/b.git", "nope", trusted, Credentials{}); result.Access != AccessBranchNotFound {
		t.Errorf("access = %s", result.Access)
	}
}

func TestUnknownHostReportsItsKey(t *testing.T) {
	line := randomKeyLine(t, "[git.example.com]:2222")
	tester, fake := tester(line+"\n", nil)

	result := tester.Test(context.Background(), "ssh://git@git.example.com:2222/app.git", "main", trusted, Credentials{})
	if result.Access != AccessHostKeyUnknown || result.Host != "[git.example.com]:2222" || result.HostKeyType != "ssh-ed25519" || !strings.HasPrefix(result.HostKeyFingerprint, "SHA256:") {
		t.Fatalf("result = %+v", result)
	}
	for _, command := range fake.Commands() {
		if strings.HasPrefix(command, "git ") {
			t.Error("git ran against an unconfirmed host")
		}
	}
}

// A host ServerDog already trusts is never scanned: OpenSSH 9.8+ penalises connections that don't authenticate.
func TestTrustedHostIsNotScanned(t *testing.T) {
	tester, fake := tester(githubLines(), gitOutput("b4c5d6e7f8a9\trefs/heads/main\n", 0))

	result := tester.Test(context.Background(), "git@github.com:a/b.git", "main", trusted, Credentials{})
	if result.Access != AccessOK || result.Commit != "b4c5d6e7f8a9" {
		t.Fatalf("result = %+v", result)
	}
	for _, command := range fake.Commands() {
		if strings.HasPrefix(command, "ssh-keyscan ") {
			t.Errorf("scanned a trusted host: %s", command)
		}
	}
}

// ssh enforces the trusted key; when it refuses the host, one ed25519 scan shows which key the host offers now.
func TestChangedHostKeyIsNeverAccepted(t *testing.T) {
	line := randomKeyLine(t, "github.com")
	tester, fake := tester(line+"\n", gitOutput("@@@@@@@@@@@\nHost key verification failed.\nfatal: Could not read from remote repository.\n", 128))

	result := tester.Test(context.Background(), "git@github.com:a/b.git", "main", trusted, Credentials{})
	want := ParseKnownHosts(line)[0]
	if result.Access != AccessHostKeyChanged || result.Commit != "" || result.HostKeyType != "ssh-ed25519" || result.HostKeyFingerprint != want.Fingerprint {
		t.Fatalf("result = %+v, want fingerprint %s", result, want.Fingerprint)
	}

	var scans []string
	for _, command := range fake.Commands() {
		if strings.HasPrefix(command, "ssh-keyscan ") {
			scans = append(scans, command)
		}
	}
	if strings.Join(scans, "\n") != "ssh-keyscan -T 10 -p 22 -t ed25519 github.com" {
		t.Errorf("scans = %q", scans)
	}
}

func TestChangedHostKeyWithoutAScanHasNoFingerprint(t *testing.T) {
	tester, _ := tester("", gitOutput("Host key verification failed.\n", 128))

	result := tester.Test(context.Background(), "git@github.com:a/b.git", "main", trusted, Credentials{})
	if result.Access != AccessHostKeyChanged || result.HostKeyType != "" || result.HostKeyFingerprint != "" {
		t.Errorf("result = %+v", result)
	}
}

func TestUnreachableHost(t *testing.T) {
	tester, _ := tester("", nil)

	if result := tester.Test(context.Background(), "git@nowhere.example:a/b.git", "main", trusted, Credentials{}); result.Access != AccessHostUnreachable {
		t.Errorf("access = %s", result.Access)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]Access{
		"git@github.com: Permission denied (publickey).\r\nfatal: Could not read from remote repository.":                                         AccessKeyNotAdded,
		"ERROR: Repository not found.\nfatal: Could not read from remote repository.":                                                             AccessRepositoryNotFound,
		"remote: \nremote: ERROR: The project you were looking for could not be found or you don't have permission to view it.\nfatal: Could not": AccessRepositoryNotFound,
		"fatal: '/srv/git/missing.git' does not appear to be a git repository":                                                                    AccessRepositoryNotFound,
		"ssh: Could not resolve hostname nowhere.example: Name or service not known":                                                              AccessHostUnreachable,
		"ssh: connect to host 10.0.0.9 port 22: Connection timed out":                                                                             AccessHostUnreachable,
		"Host key verification failed.": AccessHostKeyChanged,
		"fatal: something unexpected":   AccessFailed,
	}

	for output, want := range cases {
		if got := Classify(output); got != want {
			t.Errorf("Classify(%q) = %s, want %s", output, got, want)
		}
	}
}

func TestGitRunnerFailureIsReported(t *testing.T) {
	gitMissing, _ := tester(githubLines(), func(system.Command) (system.Result, error) {
		return system.Result{}, errors.New("run git: executable file not found in $PATH")
	})

	result := gitMissing.Test(context.Background(), "git@github.com:a/b.git", "main", trusted, Credentials{})
	if result.Access != AccessFailed || !strings.Contains(result.Detail, "executable file not found") {
		t.Errorf("result = %+v", result)
	}
}

func TestKeyscanRunnerFailureIsReported(t *testing.T) {
	fake := &systemtest.Fake{}
	fake.Handle("ssh-keyscan", func(system.Command) (system.Result, error) {
		return system.Result{}, errors.New("run ssh-keyscan: context canceled")
	})

	result := Tester{Runner: fake}.Test(context.Background(), "git@git.example.com:a/b.git", "main", trusted, Credentials{})
	if result.Access != AccessHostUnreachable || !strings.Contains(result.Detail, "context canceled") {
		t.Errorf("result = %+v", result)
	}
}

func TestKeyscanExitOutputIsReported(t *testing.T) {
	text := "getaddrinfo nowhere.example: Name or service not known\n"
	fake := &systemtest.Fake{}
	fake.Handle("ssh-keyscan", func(system.Command) (system.Result, error) {
		return system.Result{Output: []byte(text)}, &system.ExitError{Command: "ssh-keyscan", ExitCode: 1, Output: []byte(text)}
	})

	result := Tester{Runner: fake}.Test(context.Background(), "git@nowhere.example:a/b.git", "main", trusted, Credentials{})
	if result.Access != AccessHostUnreachable || !strings.Contains(result.Detail, "Name or service not known") {
		t.Errorf("result = %+v", result)
	}
}

func TestGitEnvLocksDownSSH(t *testing.T) {
	env := strings.Join(GitEnv(Credentials{KeyPath: "/k", KnownHostsPath: "/kh", GlobalKnownHostsPath: "/g"}), "\n")

	for _, option := range []string{
		"-F /dev/null",
		"-o IdentitiesOnly=yes",
		"-o IdentityAgent=none",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=yes",
		"-o UpdateHostKeys=no",
		"-o UserKnownHostsFile='/kh'",
		"-o GlobalKnownHostsFile='/g'",
		"-i '/k'",
	} {
		if !strings.Contains(env, option) {
			t.Errorf("GIT_SSH_COMMAND lacks %s: %s", option, env)
		}
	}
}
