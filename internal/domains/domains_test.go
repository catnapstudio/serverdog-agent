package domains

import (
	"context"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
)

type resolver map[string][]string

func (r resolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	answers, ok := r[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	var addrs []net.IPAddr
	for _, answer := range answers {
		addrs = append(addrs, net.IPAddr{IP: net.ParseIP(answer)})
	}
	return addrs, nil
}

// checker serves the ACME webroot of a temp root from a test server and sends every HTTP request there,
// as if each domain pointed at this server. reachable lists the names that "reach" it.
func checker(t *testing.T, dns resolver, reachable ...string) Checker {
	t.Helper()

	root := t.TempDir()
	webroot := filepath.Join(root, "var/lib/serverdog-acme")
	os.MkdirAll(filepath.Join(webroot, ".well-known/acme-challenge"), 0o755)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := strings.Cut(r.Host, ":")
		if !slices.Contains(reachable, host) {
			http.NotFound(w, r)
			return
		}
		http.FileServer(http.Dir(webroot)).ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}

	return Checker{
		Paths:     paths.Paths{Root: root},
		Resolver:  dns,
		HTTP:      NoRedirects(&http.Client{Transport: transport}),
		Addresses: func(context.Context) []string { return []string{"204.168.251.65", "2a01:4f9::1"} },
		NewToken:  func() string { return "token123" },
	}
}

func TestCheckListsRecordsAndAnswers(t *testing.T) {
	c := checker(t, resolver{"orchard.com": {"204.168.251.65"}, "www.orchard.com": {"192.0.2.10"}, "serverdog-check.orchard.com": {"204.168.251.65"}})

	status := c.Check(context.Background(), site.Domain{Name: "orchard.com", Redirect: site.FromWWW, Wildcards: true})

	var records []string
	for _, record := range status.Records {
		records = append(records, record.Type+" "+record.Name+" "+record.Value)
	}
	want := []string{
		"A orchard.com 204.168.251.65", "AAAA orchard.com 2a01:4f9::1",
		"A www.orchard.com 204.168.251.65", "AAAA www.orchard.com 2a01:4f9::1",
		"A *.orchard.com 204.168.251.65", "AAAA *.orchard.com 2a01:4f9::1",
	}
	if !slices.Equal(records, want) {
		t.Errorf("records =\n%v\nwant\n%v", records, want)
	}

	points := map[string]bool{}
	for _, name := range status.Names {
		points[name.Name] = name.PointsHere
	}
	if !points["orchard.com"] || points["www.orchard.com"] || !points["*.orchard.com"] {
		t.Errorf("points here = %v", points)
	}
	if status.Reachable {
		t.Error("www points elsewhere and isn't reachable, yet the domain is reachable")
	}
}

func TestReachableThroughTheSelfCheckEvenBehindNAT(t *testing.T) {
	// DNS answers with a NAT address the server doesn't know, but HTTP reaches it.
	c := checker(t, resolver{"orchard.com": {"10.1.2.3"}}, "orchard.com")

	ok, reason := c.Reachable(context.Background(), []string{"orchard.com"})
	if !ok {
		t.Fatalf("not reachable: %s", reason)
	}

	if _, err := os.Stat(filepath.Join(c.Paths.File(paths.ACMERoot), ".well-known/acme-challenge/token123")); !os.IsNotExist(err) {
		t.Error("the self-check token was left behind")
	}
}

func TestUnreachableNameIsReported(t *testing.T) {
	c := checker(t, resolver{"orchard.com": {"192.0.2.10"}})

	ok, reason := c.Reachable(context.Background(), []string{"orchard.com", "www.orchard.com"})
	if ok || !strings.Contains(reason, "orchard.com") {
		t.Errorf("ok = %v, reason = %q", ok, reason)
	}
}

func TestAnswersMatchingTheServerCountAsReachable(t *testing.T) {
	c := checker(t, resolver{"orchard.com": {"204.168.251.65"}})

	if ok, reason := c.Reachable(context.Background(), []string{"orchard.com"}); !ok {
		t.Errorf("not reachable: %s", reason)
	}
}

func TestNameResolvingOnlyToLoopbackFailsTheSelfCheck(t *testing.T) {
	// The server's hostname in /etc/hosts: HTTP reaches this very server, but DNS says nothing.
	c := checker(t, resolver{"orchard.com": {"127.0.1.1"}, "mixed.orchard.com": {"127.0.0.1", "::1"}}, "orchard.com", "mixed.orchard.com")

	ok, reason := c.Reachable(context.Background(), []string{"orchard.com"})
	if ok || !strings.Contains(reason, "127.0.1.1") {
		t.Errorf("ok = %v, reason = %q", ok, reason)
	}

	if ok, _ := c.Reachable(context.Background(), []string{"mixed.orchard.com"}); ok {
		t.Error("a name resolving to loopback addresses only was reachable")
	}
}

func TestLoopbackIsAllowedWhenTheSettingSaysSo(t *testing.T) {
	c := checker(t, resolver{"orchard.com": {"127.0.0.1"}}, "orchard.com")
	c.AllowLoopback = true

	if ok, reason := c.Reachable(context.Background(), []string{"orchard.com"}); !ok {
		t.Errorf("not reachable: %s", reason)
	}
}

func TestLoopbackAmongOtherAnswersStillUsesTheSelfCheck(t *testing.T) {
	c := checker(t, resolver{"orchard.com": {"127.0.0.1", "10.1.2.3"}}, "orchard.com")

	if ok, reason := c.Reachable(context.Background(), []string{"orchard.com"}); !ok {
		t.Errorf("not reachable: %s", reason)
	}
}

func TestAProxiedNameReachesHereWithoutPointingHere(t *testing.T) {
	// www goes through Cloudflare's proxy, which forwards to this server; the apex points straight here.
	c := checker(t, resolver{"orchard.com": {"204.168.251.65"}, "www.orchard.com": {"104.21.57.222"}, "serverdog-check.orchard.com": {"104.21.57.222"}}, "www.orchard.com", "serverdog-check.orchard.com")

	status := c.Check(context.Background(), site.Domain{Name: "orchard.com", Redirect: site.FromWWW, Wildcards: true})

	got := map[string][2]bool{}
	for _, name := range status.Names {
		got[name.Name] = [2]bool{name.PointsHere, name.ReachesHere}
	}
	want := map[string][2]bool{"orchard.com": {true, true}, "www.orchard.com": {false, true}, "*.orchard.com": {false, false}}
	if !maps.Equal(got, want) {
		t.Errorf("points here, reaches here = %v, want %v", got, want)
	}
	if !status.Reachable {
		t.Error("every certificate name reaches this server, yet the domain isn't reachable")
	}
}
