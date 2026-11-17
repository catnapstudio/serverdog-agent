package domains

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// zones is a nameserver for the zones it lists. Asked with recursion it answers NS queries like a recursive resolver
// would; asked without, it answers like each zone's own nameserver.
type zones map[string][]string

// nameserver serves zones on a local UDP port and returns a resolver that uses it for both roles. Its nameservers'
// names resolve through fallback, which also answers names in no zone.
func nameserver(t *testing.T, records zones, fallback resolver) Authoritative {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(query)
		question := query.Question[0]

		if question.Qtype == dns.TypeNS {
			if _, ok := records[question.Name]; ok {
				reply.Answer = append(reply.Answer, &dns.NS{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.nameserver.test."})
			}
			w.WriteMsg(reply)
			return
		}

		zone := ""
		for name := range records {
			if dns.IsSubDomain(name, question.Name) && len(name) > len(zone) {
				zone = name
			}
		}
		if zone == "" {
			reply.Rcode = dns.RcodeRefused
			w.WriteMsg(reply)
			return
		}

		reply.Authoritative = true
		found := false
		for _, line := range records[zone] {
			record, err := dns.NewRR(line)
			if err != nil {
				t.Errorf("bad record %q: %v", line, err)
				continue
			}
			if !strings.EqualFold(record.Header().Name, question.Name) {
				continue
			}
			found = true
			if record.Header().Rrtype == question.Qtype || record.Header().Rrtype == dns.TypeCNAME {
				reply.Answer = append(reply.Answer, record)
			}
		}
		if !found {
			reply.Rcode = dns.RcodeNameError
		}
		w.WriteMsg(reply)
	})}

	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })

	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	fallback["ns1.nameserver.test."] = []string{"127.0.0.1"}

	return Authoritative{Fallback: fallback, Recursive: conn.LocalAddr().String(), Port: port}
}

func lookup(t *testing.T, r Resolver, host string) []string {
	t.Helper()

	addrs, err := r.LookupIPAddr(context.Background(), host)
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

func TestTheZoneAnswersBeforeTheServersCache(t *testing.T) {
	r := nameserver(t, zones{"harbourview.com.": {
		"harbourview.com. 300 IN A 204.168.232.50",
		"harbourview.com. 300 IN AAAA 2a01:4f9::1",
	}}, resolver{"harbourview.com": {"104.21.57.222"}})

	if got := lookup(t, r, "harbourview.com"); !slices.Equal(got, []string{"204.168.232.50", "2a01:4f9::1"}) {
		t.Errorf("answers = %v", got)
	}
}

func TestCNAMEsAreFollowedInsideAndOutsideTheZone(t *testing.T) {
	r := nameserver(t, zones{
		"harbourview.com.": {
			"harbourview.com. 300 IN A 204.168.232.50",
			"www.harbourview.com. 300 IN CNAME harbourview.com.",
			"shop.harbourview.com. 300 IN CNAME stores.shops.test.",
		},
		"shops.test.": {"stores.shops.test. 300 IN A 192.0.2.7"},
	}, resolver{})

	if got := lookup(t, r, "www.harbourview.com"); !slices.Equal(got, []string{"204.168.232.50"}) {
		t.Errorf("www = %v", got)
	}
	if got := lookup(t, r, "shop.harbourview.com"); !slices.Equal(got, []string{"192.0.2.7"}) {
		t.Errorf("shop = %v", got)
	}
}

func TestAMissingRecordIsMissingEvenIfTheCacheStillHasIt(t *testing.T) {
	r := nameserver(t, zones{"harbourview.com.": {"harbourview.com. 300 IN A 204.168.232.50"}}, resolver{"old.harbourview.com": {"192.0.2.1"}})

	if _, err := r.LookupIPAddr(context.Background(), "old.harbourview.com"); err == nil {
		t.Error("a name the zone doesn't have resolved")
	}
}

func TestNamesWithoutAZoneUseTheFallback(t *testing.T) {
	// The VM suites point .test names at the VM in /etc/hosts; no nameserver knows them.
	r := nameserver(t, zones{}, resolver{"secure.test": {"127.0.0.1"}})

	if got := lookup(t, r, "secure.test"); !slices.Equal(got, []string{"127.0.0.1"}) {
		t.Errorf("answers = %v", got)
	}
}

func TestAnUnreachableNameserverUsesTheFallback(t *testing.T) {
	r := nameserver(t, zones{"harbourview.com.": {"harbourview.com. 300 IN A 204.168.232.50"}}, resolver{"harbourview.com": {"192.0.2.1"}})
	r.Port = "1"

	if got := lookup(t, r, "harbourview.com"); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("answers = %v", got)
	}
}

func TestDialViaConnectsToTheResolversAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("here"))
	}))
	t.Cleanup(server.Close)

	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	client := &http.Client{Transport: &http.Transport{DialContext: DialVia(resolver{"harbourview.com": {"127.0.0.1"}})}}

	response, err := client.Get("http://harbourview.com:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	if _, err := client.Get("http://unknown.harbourview.com:" + port + "/"); err == nil {
		t.Error("a name the resolver doesn't know was dialled")
	}
}
