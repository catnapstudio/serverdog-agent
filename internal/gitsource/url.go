// Package gitsource gives the server read access to a site's Git repository.
package gitsource

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Remote is an SSH Git URL.
type Remote struct {
	User string
	Host string
	Port int // 0 means 22
	Path string
}

var (
	scpLike  = regexp.MustCompile(`^([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+):(.+)$`)
	userName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	hostName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)
	repoPath = regexp.MustCompile(`^[A-Za-z0-9._~/+-]+$`)
)

// ParseURL accepts "user@host:path" and "ssh://user@host[:port]/path".
func ParseURL(raw string) (Remote, error) {
	var remote Remote

	if strings.HasPrefix(raw, "ssh://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return Remote{}, fmt.Errorf("parse repository URL: %w", err)
		}
		if parsed.User == nil {
			return Remote{}, errors.New("the repository URL needs a user, e.g. ssh://git@host/path")
		}

		remote = Remote{User: parsed.User.Username(), Host: strings.ToLower(parsed.Hostname()), Path: strings.TrimPrefix(parsed.Path, "/")}
		if port := parsed.Port(); port != "" {
			value, err := strconv.Atoi(port)
			if err != nil || value < 1 || value > 65535 {
				return Remote{}, fmt.Errorf("invalid port %q", port)
			}
			if value != 22 {
				remote.Port = value
			}
		}
	} else {
		match := scpLike.FindStringSubmatch(raw)
		if match == nil {
			return Remote{}, errors.New("use an SSH repository URL, e.g. git@github.com:you/app.git")
		}
		remote = Remote{User: match[1], Host: strings.ToLower(match[2]), Path: match[3]}
	}

	if !userName.MatchString(remote.User) || strings.HasPrefix(remote.User, "-") {
		return Remote{}, fmt.Errorf("invalid user %q in the repository URL", remote.User)
	}
	if !hostName.MatchString(remote.Host) {
		return Remote{}, fmt.Errorf("invalid host %q in the repository URL", remote.Host)
	}
	if remote.Path == "" || !repoPath.MatchString(remote.Path) || strings.HasPrefix(remote.Path, "-") {
		return Remote{}, fmt.Errorf("invalid repository path %q", remote.Path)
	}

	return remote, nil
}

// KnownHostsName is how the host appears in a known_hosts file.
func (r Remote) KnownHostsName() string {
	if r.Port == 0 || r.Port == 22 {
		return r.Host
	}

	return fmt.Sprintf("[%s]:%d", r.Host, r.Port)
}

// SSHPort returns the port to connect to.
func (r Remote) SSHPort() int {
	if r.Port == 0 {
		return 22
	}

	return r.Port
}
