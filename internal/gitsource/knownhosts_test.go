package gitsource

import "testing"

func TestProviderKeysParse(t *testing.T) {
	keys := ParseKnownHosts(ProviderKnownHosts)
	if len(keys) != 9 {
		t.Fatalf("parsed %d keys, want 9", len(keys))
	}

	want := map[string]string{
		"github.com":    "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
		"gitlab.com":    "SHA256:eUXGGm1YGsMAS7vkcx6JOJdOGHPem5gQp4taiCfCLB8",
		"bitbucket.org": "SHA256:ybgmFkzwOSotHTHLJgHO0QN8L0xErw6vd0VhFA9m3SM",
	}

	for host, fingerprint := range want {
		var found bool
		for _, key := range keys {
			if key.Names(host) && key.Type == "ssh-ed25519" {
				found = key.Fingerprint == fingerprint
			}
		}
		if !found {
			t.Errorf("%s ed25519 fingerprint doesn't match the published %s", host, fingerprint)
		}
	}
}

func TestPreferredPicksEd25519(t *testing.T) {
	var github []HostKey
	for _, key := range ParseKnownHosts(ProviderKnownHosts) {
		if key.Names("github.com") {
			github = append(github, key)
		}
	}

	if Preferred(github).Type != "ssh-ed25519" {
		t.Errorf("Preferred = %s", Preferred(github).Type)
	}
}
