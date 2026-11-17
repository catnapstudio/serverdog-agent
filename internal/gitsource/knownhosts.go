package gitsource

import (
	"bytes"
	_ "embed"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ProviderKnownHosts holds the host keys GitHub, GitLab.com and Bitbucket publish. Server setup writes it to /etc/serverdog/known_hosts.
//
//go:embed providers_known_hosts
var ProviderKnownHosts string

// HostKey is one key line from a known_hosts file or ssh-keyscan output.
type HostKey struct {
	Line        string
	Hosts       []string
	Type        string
	Fingerprint string
	key         ssh.PublicKey
}

// Names reports whether the line applies to host, written as in known_hosts ("github.com", "[host]:2222").
func (k HostKey) Names(host string) bool { return slices.Contains(k.Hosts, host) }

// SameKey reports whether both lines carry the same public key.
func (k HostKey) SameKey(other HostKey) bool {
	return bytes.Equal(k.key.Marshal(), other.key.Marshal())
}

// ParseKnownHosts reads known_hosts lines, skipping comments and lines it can't parse.
func ParseKnownHosts(content string) []HostKey {
	var keys []HostKey

	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		_, hosts, key, _, _, err := ssh.ParseKnownHosts([]byte(line))
		if err != nil {
			continue
		}

		keys = append(keys, HostKey{Line: line, Hosts: hosts, Type: key.Type(), Fingerprint: ssh.FingerprintSHA256(key), key: key})
	}

	return keys
}

// Preferred picks the key to show a person: ed25519, then ECDSA, then whatever came first.
func Preferred(keys []HostKey) HostKey {
	for _, wanted := range []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256} {
		for _, key := range keys {
			if key.Type == wanted {
				return key
			}
		}
	}

	if len(keys) == 0 {
		return HostKey{}
	}

	return keys[0]
}

// RenderKnownHosts writes lines as a known_hosts file.
func RenderKnownHosts(lines []string) []byte {
	if len(lines) == 0 {
		return []byte("# Managed by ServerDog.\n")
	}

	return []byte("# Managed by ServerDog.\n" + strings.Join(lines, "\n") + "\n")
}
