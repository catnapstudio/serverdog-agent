package domains

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Authoritative looks names up at their zone's own nameservers, as Let's Encrypt does, so a record changed a moment
// ago counts at once instead of when the server's cached answer expires. A name it can't look up that way, such as
// one that exists only in /etc/hosts, goes to Fallback.
type Authoritative struct {
	Fallback Resolver
	// Recursive is the "host:port" of the resolver that finds a zone's nameservers. Empty reads /etc/resolv.conf.
	Recursive string
	// Port is the nameservers' port. Empty means 53.
	Port string
}

const (
	authoritativeBudget = 3 * time.Second
	queryTimeout        = 2 * time.Second
	maxCNAMEs           = 8
)

func (a Authoritative) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	authoritativeCtx, cancel := context.WithTimeout(ctx, authoritativeBudget)
	defer cancel()

	addrs, ok := a.lookup(authoritativeCtx, dns.Fqdn(host), 0)
	if !ok {
		return a.Fallback.LookupIPAddr(ctx, host)
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	return addrs, nil
}

// lookup returns the name's addresses, following CNAMEs into other zones. ok is false when no nameserver of the
// name's zone gave an authoritative answer.
func (a Authoritative) lookup(ctx context.Context, name string, cnames int) (addrs []net.IPAddr, ok bool) {
	servers := a.nameservers(ctx, name)
	if len(servers) == 0 {
		return nil, false
	}

	target := ""

	for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
		reply := a.ask(ctx, servers, name, kind)
		if reply == nil {
			return nil, false
		}
		if reply.Rcode == dns.RcodeNameError {
			return nil, true
		}

		found, end := addresses(reply, name)
		addrs = append(addrs, found...)
		if end != name {
			target = end
		}
	}

	if len(addrs) == 0 && target != "" && cnames < maxCNAMEs {
		return a.lookup(ctx, target, cnames+1)
	}

	return addrs, true
}

// nameservers walks up from name to the closest zone with NS records and returns its nameservers' addresses.
// It stops above the second level: a top-level domain's servers only refer elsewhere.
func (a Authoritative) nameservers(ctx context.Context, name string) []string {
	recursive := a.recursive()
	if recursive == "" {
		return nil
	}

	for zone := name; dns.CountLabel(zone) >= 2; zone = parent(zone) {
		query := new(dns.Msg)
		query.SetQuestion(zone, dns.TypeNS)

		reply, err := exchange(ctx, query, recursive)
		if err != nil {
			return nil
		}

		var hosts []string
		for _, record := range reply.Answer {
			// An answer for another owner came through a CNAME: the name isn't a zone of its own.
			if ns, isNS := record.(*dns.NS); isNS && strings.EqualFold(ns.Hdr.Name, zone) {
				hosts = append(hosts, ns.Ns)
			}
		}
		if len(hosts) == 0 {
			continue
		}

		// IPv4 first: a server whose IPv6 is broken would spend the whole budget timing out.
		var v4, v6 []string
		for _, host := range hosts {
			addrs, err := a.Fallback.LookupIPAddr(ctx, host)
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				server := net.JoinHostPort(addr.IP.String(), a.port())
				if addr.IP.To4() != nil {
					v4 = append(v4, server)
				} else {
					v6 = append(v6, server)
				}
			}
		}

		return append(v4, v6...)
	}

	return nil
}

// ask returns the first authoritative answer from servers, or nil when none gave one.
func (a Authoritative) ask(ctx context.Context, servers []string, name string, kind uint16) *dns.Msg {
	query := new(dns.Msg)
	query.SetQuestion(name, kind)
	query.RecursionDesired = false

	for _, server := range servers {
		reply, err := exchange(ctx, query, server)
		if err != nil || !reply.Authoritative {
			continue
		}
		if reply.Rcode != dns.RcodeSuccess && reply.Rcode != dns.RcodeNameError {
			continue
		}

		return reply
	}

	return nil
}

// addresses follows the CNAMEs in reply from name and returns the addresses of where they end, and that name.
func addresses(reply *dns.Msg, name string) ([]net.IPAddr, string) {
	end := name

	for range maxCNAMEs {
		next := ""
		for _, record := range reply.Answer {
			if cname, isCNAME := record.(*dns.CNAME); isCNAME && strings.EqualFold(cname.Hdr.Name, end) {
				next = cname.Target
			}
		}
		if next == "" {
			break
		}
		end = next
	}

	var addrs []net.IPAddr
	for _, record := range reply.Answer {
		switch r := record.(type) {
		case *dns.A:
			if strings.EqualFold(r.Hdr.Name, end) {
				addrs = append(addrs, net.IPAddr{IP: r.A})
			}
		case *dns.AAAA:
			if strings.EqualFold(r.Hdr.Name, end) {
				addrs = append(addrs, net.IPAddr{IP: r.AAAA})
			}
		}
	}

	return addrs, end
}

// exchange sends query over UDP, and again over TCP when the answer was cut short.
func exchange(ctx context.Context, query *dns.Msg, server string) (*dns.Msg, error) {
	client := &dns.Client{Timeout: queryTimeout}

	reply, _, err := client.ExchangeContext(ctx, query, server)
	if err == nil && reply.Truncated {
		client.Net = "tcp"
		reply, _, err = client.ExchangeContext(ctx, query, server)
	}

	return reply, err
}

func (a Authoritative) recursive() string {
	if a.Recursive != "" {
		return a.Recursive
	}

	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(config.Servers) == 0 {
		return ""
	}

	return net.JoinHostPort(config.Servers[0], config.Port)
}

func (a Authoritative) port() string {
	if a.Port != "" {
		return a.Port
	}

	return "53"
}

func parent(name string) string {
	_, rest, _ := strings.Cut(name, ".")

	return rest
}

// DialVia makes an HTTP transport connect through resolver's answers rather than the system's cached ones, so the
// self-check reaches the address Let's Encrypt will.
func DialVia(resolver Resolver) func(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || net.ParseIP(host) != nil {
			return dialer.DialContext(ctx, network, address)
		}

		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}

		err = &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		for _, addr := range addrs {
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			err = dialErr
		}

		return nil, err
	}
}
