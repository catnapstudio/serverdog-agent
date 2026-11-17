package gitsource

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/system"
)

type Access string

const (
	AccessOK                 Access = "ok"
	AccessKeyNotAdded        Access = "keyNotAdded"
	AccessRepositoryNotFound Access = "repositoryNotFound"
	AccessBranchNotFound     Access = "branchNotFound"
	AccessHostKeyChanged     Access = "hostKeyChanged"
	AccessHostKeyUnknown     Access = "hostKeyUnknown"
	AccessHostUnreachable    Access = "hostUnreachable"
	AccessFailed             Access = "failed"
)

type Result struct {
	Access             Access
	Commit             string
	Host               string
	HostKeyType        string
	HostKeyFingerprint string
	Detail             string
}

// Credentials say how git reaches the repository: which key, which known_hosts files, as whom.
type Credentials struct {
	KeyPath              string
	KnownHostsPath       string
	GlobalKnownHostsPath string
	Home                 string
	Path                 string
	// User is the site user; nil (a site not created yet) runs as root with the pending key.
	User *system.User
}

// GitEnv is the environment for git commands that reach the repository. Paths are ServerDog's own and contain no quotes.
func GitEnv(c Credentials) []string {
	ssh := fmt.Sprintf("ssh -i '%s' -o IdentitiesOnly=yes -F /dev/null -o IdentityAgent=none -o BatchMode=yes -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o UserKnownHostsFile='%s' -o GlobalKnownHostsFile='%s' -o ConnectTimeout=15",
		c.KeyPath, c.KnownHostsPath, c.GlobalKnownHostsPath)

	return []string{"HOME=" + c.Home, "PATH=" + c.Path, "LANG=C.UTF-8", "GIT_TERMINAL_PROMPT=0", "GIT_SSH_COMMAND=" + ssh}
}

// Tester checks that the server can read a repository.
type Tester struct {
	Runner system.Runner
}

// Scan returns the keys the host offers now. ssh-keyscan connects once per key type.
func (t Tester) Scan(ctx context.Context, remote Remote) ([]HostKey, error) {
	return t.scan(ctx, remote, "ed25519,ecdsa,rsa")
}

func (t Tester) scan(ctx context.Context, remote Remote, types string) ([]HostKey, error) {
	port := strconv.Itoa(remote.SSHPort())
	result, err := t.Runner.Run(ctx, system.Command{Name: "ssh-keyscan", Args: []string{"-T", "10", "-p", port, "-t", types, remote.Host}})

	keys := ParseKnownHosts(string(result.Output))
	if len(keys) == 0 {
		reason := system.Tail(result.Output, 3)
		if reason == "" && err != nil {
			reason = err.Error()
		}
		if reason == "" {
			return nil, fmt.Errorf("%s didn't answer on port %s", remote.Host, port)
		}

		return nil, fmt.Errorf("%s didn't answer on port %s: %s", remote.Host, port, reason)
	}

	return keys, nil
}

// Test asks git for the branch's latest commit. A host without a trusted key is only scanned, so its key can be
// shown and trusted first. A trusted host is never scanned up front: ssh enforces its key, and OpenSSH 9.8+ penalises
// the connections ssh-keyscan makes without authenticating.
func (t Tester) Test(ctx context.Context, rawURL, branch string, trusted []HostKey, c Credentials) Result {
	remote, err := ParseURL(rawURL)
	if err != nil {
		return Result{Access: AccessFailed, Detail: err.Error()}
	}

	result := Result{Host: remote.KnownHostsName()}

	if !anyNames(trusted, result.Host) {
		scanned, err := t.Scan(ctx, remote)
		if err != nil {
			result.Access, result.Detail = AccessHostUnreachable, err.Error()
			return result
		}

		offered := Preferred(scanned)
		result.HostKeyType, result.HostKeyFingerprint = offered.Type, offered.Fingerprint
		result.Access = AccessHostKeyUnknown

		return result
	}

	output, err := t.Runner.Run(ctx, lsRemote(rawURL, branch, c))
	if err != nil {
		if _, exited := system.ExitCode(err); !exited {
			result.Access, result.Detail = AccessFailed, err.Error()
			return result
		}

		result.Access, result.Detail = Classify(string(output.Output)), system.Tail(output.Output, 5)
		if result.Access == AccessHostKeyChanged {
			// One connection, to show which key the host offers now.
			if scanned, err := t.scan(ctx, remote, "ed25519"); err == nil {
				offered := Preferred(scanned)
				result.HostKeyType, result.HostKeyFingerprint = offered.Type, offered.Fingerprint
			}
		}

		return result
	}

	fields := strings.Fields(string(output.Output))
	if len(fields) == 0 {
		result.Access = AccessBranchNotFound
		return result
	}

	result.Access, result.Commit = AccessOK, fields[0]

	return result
}

// Head returns the branch's latest commit. ssh checks the host against the credentials' known_hosts files.
func Head(ctx context.Context, runner system.Runner, rawURL, branch string, c Credentials) (string, error) {
	output, err := runner.Run(ctx, lsRemote(rawURL, branch, c))
	if err != nil {
		if _, exited := system.ExitCode(err); !exited {
			return "", err
		}

		return "", fmt.Errorf("%s: %s", Classify(string(output.Output)), system.Tail(output.Output, 3))
	}

	fields := strings.Fields(string(output.Output))
	if len(fields) == 0 {
		return "", fmt.Errorf("the branch %s isn't in the repository", branch)
	}

	return fields[0], nil
}

func lsRemote(rawURL, branch string, c Credentials) system.Command {
	return system.Command{
		Name: "git",
		Args: []string{"ls-remote", rawURL, "refs/heads/" + branch},
		Env:  GitEnv(c),
		User: c.User,
	}
}

// Classify reads git's and ssh's messages from a failed ls-remote.
func Classify(output string) Access {
	lower := strings.ToLower(output)

	switch {
	case strings.Contains(output, "Permission denied (publickey"):
		return AccessKeyNotAdded
	case strings.Contains(output, "Host key verification failed"), strings.Contains(output, "REMOTE HOST IDENTIFICATION HAS CHANGED"):
		return AccessHostKeyChanged
	case containsAny(output, "Could not resolve hostname", "Connection timed out", "Connection refused", "No route to host", "Network is unreachable", "Operation timed out"):
		return AccessHostUnreachable
	case containsAny(lower, "repository not found", "could not be found", "does not appear to be a git repository", "does not exist"):
		return AccessRepositoryNotFound
	default:
		return AccessFailed
	}
}

func anyNames(keys []HostKey, host string) bool {
	for _, key := range keys {
		if key.Names(host) {
			return true
		}
	}

	return false
}

func containsAny(text string, parts ...string) bool {
	for _, part := range parts {
		if strings.Contains(text, part) {
			return true
		}
	}

	return false
}
