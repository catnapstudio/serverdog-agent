// Package domains tells which DNS records a site's domains need and whether each name reaches this server.
package domains

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/certs"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
)

type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type Record struct {
	Type  string
	Name  string
	Value string
}

type Name struct {
	Name       string
	Answers    []string
	PointsHere bool
	// ReachesHere is whether HTTP through the name reaches this server, directly or through a proxy. It is what
	// Let's Encrypt checks, and is always false for a wildcard.
	ReachesHere bool
}

type Status struct {
	Domain    string
	Records   []Record
	Names     []Name
	Reachable bool
}

type Checker struct {
	Paths    paths.Paths
	Resolver Resolver
	// HTTP fetches the self-check token; it must not follow redirects (see NoRedirects).
	HTTP      *http.Client
	Addresses func(context.Context) []string
	NewToken  func() string
	// AllowLoopback lets a name that resolves only to loopback addresses pass the self-check. It is off in production,
	// where such a name is the server's own hostname in /etc/hosts and says nothing about DNS; the VM suite turns it
	// on because it points its test domains at 127.0.0.1.
	AllowLoopback bool
}

// NoRedirects makes client report redirects instead of following them.
func NoRedirects(client *http.Client) *http.Client {
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 5 * time.Second
	}

	return client
}

// Check returns the records a domain needs, what its names resolve to now, and whether its certificate's names reach this server.
func (c Checker) Check(ctx context.Context, domain site.Domain) Status {
	status := Status{Domain: domain.Name}
	addresses := c.Addresses(ctx)

	shown := certs.Names(domain)
	if domain.Wildcards {
		shown = append(shown, "*."+domain.Name)
	}

	for _, name := range shown {
		for _, address := range addresses {
			kind := "A"
			if strings.Contains(address, ":") {
				kind = "AAAA"
			}
			status.Records = append(status.Records, Record{Type: kind, Name: name, Value: address})
		}

		lookup := name
		if strings.HasPrefix(name, "*.") {
			lookup = "serverdog-check." + strings.TrimPrefix(name, "*.")
		}

		answers := c.answers(ctx, lookup)
		here := pointsHere(answers, addresses)
		reaches := lookup == name && (here || c.reaches(ctx, name, answers))
		status.Names = append(status.Names, Name{Name: name, Answers: answers, PointsHere: here, ReachesHere: reaches})
	}

	status.Reachable = true
	for _, name := range status.Names {
		if !strings.HasPrefix(name.Name, "*.") && !name.ReachesHere {
			status.Reachable = false
		}
	}

	return status
}

// Reachable reports whether every name reaches this server, and if not, why (for the certificate's waiting note).
func (c Checker) Reachable(ctx context.Context, names []string) (bool, string) {
	addresses := c.Addresses(ctx)

	for _, name := range names {
		answers := c.answers(ctx, name)

		if pointsHere(answers, addresses) || c.reaches(ctx, name, answers) {
			continue
		}

		if len(answers) == 0 {
			return false, fmt.Sprintf("%s doesn't resolve yet.", name)
		}

		return false, fmt.Sprintf("%s points at %s, not at this server.", name, strings.Join(answers, ", "))
	}

	return true, ""
}

// reaches is whether the self-check gets through name. A name that resolves only to loopback addresses is the
// server's own hostname in /etc/hosts, which says nothing about DNS.
func (c Checker) reaches(ctx context.Context, name string, answers []string) bool {
	return (c.AllowLoopback || !onlyLoopback(answers)) && c.selfCheck(ctx, name)
}

func (c Checker) answers(ctx context.Context, name string) []string {
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	addrs, err := c.Resolver.LookupIPAddr(lookupCtx, name)
	if err != nil {
		return nil
	}

	var answers []string
	for _, addr := range addrs {
		answers = append(answers, addr.IP.String())
	}
	slices.Sort(answers)

	return answers
}

// onlyLoopback is whether the name resolves, and only to loopback addresses.
func onlyLoopback(answers []string) bool {
	if len(answers) == 0 {
		return false
	}

	for _, answer := range answers {
		if ip := net.ParseIP(answer); ip == nil || !ip.IsLoopback() {
			return false
		}
	}

	return true
}

func pointsHere(answers, addresses []string) bool {
	if len(answers) == 0 {
		return false
	}

	for _, answer := range answers {
		if !slices.Contains(addresses, answer) {
			return false
		}
	}

	return true
}

// selfCheck serves a random token from the ACME webroot and fetches it through name, the way Let's Encrypt will.
func (c Checker) selfCheck(ctx context.Context, name string) bool {
	token := c.token()
	file := filepath.Join(c.Paths.File(paths.ACMERoot), ".well-known", "acme-challenge", token)

	if err := os.WriteFile(file, []byte(token), 0o644); err != nil {
		return false
	}
	defer os.Remove(file)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+name+"/.well-known/acme-challenge/"+token, nil)
	if err != nil {
		return false
	}

	response, err := c.HTTP.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 256))

	return err == nil && response.StatusCode == http.StatusOK && string(body) == token
}

func (c Checker) token() string {
	if c.NewToken != nil {
		return c.NewToken()
	}

	buffer := make([]byte, 16)
	rand.Read(buffer)

	return "serverdog-" + hex.EncodeToString(buffer)
}
