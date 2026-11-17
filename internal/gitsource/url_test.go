package gitsource

import "testing"

func TestParseURL(t *testing.T) {
	cases := []struct {
		raw       string
		want      Remote
		knownHost string
	}{
		{"git@github.com:morgan/orchard.git", Remote{User: "git", Host: "github.com", Path: "morgan/orchard.git"}, "github.com"},
		{"git@GitHub.com:morgan/orchard.git", Remote{User: "git", Host: "github.com", Path: "morgan/orchard.git"}, "github.com"},
		{"ssh://git@gitlab.com/group/sub/app.git", Remote{User: "git", Host: "gitlab.com", Path: "group/sub/app.git"}, "gitlab.com"},
		{"ssh://git@git.example.com:2222/app.git", Remote{User: "git", Host: "git.example.com", Port: 2222, Path: "app.git"}, "[git.example.com]:2222"},
		{"git@127.0.0.1:/srv/git/app.git", Remote{User: "git", Host: "127.0.0.1", Path: "/srv/git/app.git"}, "127.0.0.1"},
	}

	for _, c := range cases {
		got, err := ParseURL(c.raw)
		if err != nil {
			t.Errorf("ParseURL(%q): %v", c.raw, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseURL(%q) = %+v, want %+v", c.raw, got, c.want)
		}
		if name := got.KnownHostsName(); name != c.knownHost {
			t.Errorf("KnownHostsName(%q) = %q, want %q", c.raw, name, c.knownHost)
		}
	}
}

func TestParseURLRejects(t *testing.T) {
	for _, raw := range []string{
		"",
		"https://github.com/morgan/orchard.git",
		"github.com:morgan/orchard.git",
		"git@github.com:",
		"git@-oProxyCommand=evil:repo",
		"git@github.com:repo name.git",
		"ssh://git@github.com:99999/app.git",
		"git@github.com:repo\nnext",
		"-u@host:repo",
	} {
		if _, err := ParseURL(raw); err == nil {
			t.Errorf("ParseURL(%q) accepted", raw)
		}
	}
}
