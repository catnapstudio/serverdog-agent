// Package network lets other servers reach this server's database, Redis, Memcached and Meilisearch over a private
// network: a provider's VPC, or Tailscale or another WireGuard network. The services also listen on the server's
// private address, never on every address, and ufw lets in only the listed servers, on those services' ports. Its
// rules carry a "serverdog-network:<peer id>" comment, apart from the Firewall section's.
package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

type Peer struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

// Candidate is a private address the server has, with its interface ("eth1", "tailscale0").
type Candidate struct {
	Address   string
	Interface string
}

// Service listens on the private address while networking is on.
type Service struct {
	Name string
	Port int
}

type Status struct {
	// Address is "" while networking is off.
	Address    string
	Peers      []Peer
	Revision   uint64
	Candidates []Candidate
	Services   []Service
	// FirewallActive is false when ufw is off, so every machine on the private network reaches the services.
	FirewallActive bool
	// BroadRules are rules added outside ServerDog that let everything in on the address's interface, as ufw prints
	// them ("allow in on tailscale0"). They make the per-server limit pointless.
	BroadRules []string
}

// Link is a network interface as Candidates reads it.
type Link struct {
	Name      string
	Up        bool
	Bridge    bool
	Addresses []net.IP
}

// Error is a service that didn't come back: a summary, then its last log lines.
type Error struct {
	Summary string
	Output  string
}

func (e *Error) Error() string {
	if e.Output == "" {
		return e.Summary
	}

	return e.Summary + "\n\n" + e.Output
}

// MaxPeers bounds the list.
const MaxPeers = 50

const (
	documentName  = "network"
	commentPrefix = "serverdog-network:"
	sysctlFile    = "/etc/sysctl.d/60-serverdog-network.conf"
)

var privateRanges = func() []*net.IPNet {
	var ranges []*net.IPNet
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"} {
		_, network, _ := net.ParseCIDR(cidr)
		ranges = append(ranges, network)
	}
	return ranges
}()

// rule is a ufw rule this package added.
type rule struct {
	PeerID string `json:"peer_id"`
	From   string `json:"from"`
	To     string `json:"to"`
	Port   int    `json:"port"`
}

type document struct {
	Address string `json:"address"`
	Peers   []Peer `json:"peers"`
	// Rules are the ufw rules in place, so the next Put deletes exactly those.
	Rules []rule `json:"rules"`
}

type Manager struct {
	Store  *state.Store
	Paths  paths.Paths
	System system.Runner
	// Links lists the network interfaces: SystemLinks in production.
	Links func() ([]Link, error)
	// Engine is the database engine: "mysql", "mariadb", "postgres" or "".
	Engine func(context.Context) string
	// Dial checks that a service answers after its restart: a net.Dialer's DialContext in production.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// Wait is how long a restarted service gets to answer; 30 seconds when zero.
	Wait time.Duration

	mu sync.Mutex
}

// Candidates are the private IPv4 addresses on interfaces that are up, apart from the loopback, Docker's, bridges and
// veth pairs. WireGuard interfaces count: Tailscale's, NetBird's and wg*.
func Candidates(links []Link) []Candidate {
	var candidates []Candidate

	for _, link := range links {
		if !link.Up || link.Bridge || link.Name == "lo" || strings.HasPrefix(link.Name, "docker") || strings.HasPrefix(link.Name, "br-") || strings.HasPrefix(link.Name, "veth") {
			continue
		}

		for _, ip := range link.Addresses {
			if v4 := ip.To4(); v4 != nil && private(v4) {
				candidates = append(candidates, Candidate{Address: v4.String(), Interface: link.Name})
			}
		}
	}

	return candidates
}

// SystemLinks reads the server's interfaces. A bridge has /sys/class/net/<name>/bridge.
func SystemLinks() ([]Link, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var links []Link
	for _, i := range interfaces {
		addresses, err := i.Addrs()
		if err != nil {
			continue
		}

		_, bridgeErr := os.Stat(filepath.Join("/sys/class/net", i.Name, "bridge"))
		link := Link{Name: i.Name, Up: i.Flags&net.FlagUp != 0, Bridge: bridgeErr == nil}
		for _, address := range addresses {
			if network, ok := address.(*net.IPNet); ok {
				link.Addresses = append(link.Addresses, network.IP)
			}
		}
		links = append(links, link)
	}

	return links, nil
}

func private(ip net.IP) bool {
	return slices.ContainsFunc(privateRanges, func(network *net.IPNet) bool { return network.Contains(ip) })
}

func (m *Manager) Status(ctx context.Context) (Status, error) {
	doc, revision, err := m.load()
	if err != nil {
		return Status{}, err
	}

	status := Status{Address: doc.Address, Peers: doc.Peers, Revision: revision, Candidates: m.candidates()}
	for _, s := range m.services(ctx) {
		status.Services = append(status.Services, Service{Name: s.name, Port: s.port})
	}

	result, _ := m.ufw(ctx, "status")
	status.FirewallActive = strings.Contains(string(result.Output), "Status: active")

	var link string
	for _, candidate := range status.Candidates {
		if candidate.Address == doc.Address {
			link = candidate.Interface
		}
	}
	if link == "" {
		return status, nil
	}

	added, _ := m.ufw(ctx, "show", "added")
	for _, line := range strings.Split(string(added.Output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ufw allow in on "+link) && !strings.Contains(line, " port ") {
			status.BroadRules = append(status.BroadRules, strings.TrimPrefix(line, "ufw "))
		}
	}

	return status, nil
}

// Put makes the services listen on address (none when it is "") and lets peers reach them. A service that doesn't come
// back gets its previous settings again, and the ones changed before it are put back too. Nothing is saved unless every
// step worked.
func (m *Manager) Put(ctx context.Context, address string, peers []Peer, expectedRevision uint64) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	doc, revision, err := m.load()
	if err != nil {
		return 0, err
	}
	if revision != expectedRevision {
		return 0, state.ErrStaleDocument
	}

	if err := m.validate(address, doc.Address, peers); err != nil {
		return 0, err
	}

	if address != "" || len(doc.Rules) > 0 {
		if _, err := m.ufw(ctx, "status"); err != nil {
			var exit *system.ExitError
			if !errors.As(err, &exit) {
				return 0, invalid("ufw isn't installed on this server.")
			}
		}
	}

	services := m.services(ctx)

	if address != "" {
		if err := m.nonlocalBind(ctx, true); err != nil {
			return 0, err
		}
	}

	for i, s := range services {
		if err := m.configure(ctx, s, doc.Address, address); err != nil {
			for _, done := range services[:i] {
				_ = m.configure(context.WithoutCancel(ctx), done, address, doc.Address)
			}
			return 0, err
		}
	}

	wanted := rules(address, peers, services)

	// shortcut: a failure here leaves the services on the new address behind a firewall that doesn't let the peers in
	// yet, which is safe; saving again finishes the job.
	var added []rule
	for _, r := range wanted {
		if slices.Contains(doc.Rules, r) {
			continue
		}
		if _, err := m.ufw(ctx, append(r.args(), "comment", commentPrefix+r.PeerID)...); err != nil {
			m.deleteRules(context.WithoutCancel(ctx), added)
			return 0, err
		}
		added = append(added, r)
	}

	for _, r := range doc.Rules {
		if slices.Contains(wanted, r) {
			continue
		}
		if _, err := m.ufw(ctx, append([]string{"delete"}, r.args()...)...); err != nil {
			return 0, err
		}
	}

	if address == "" && doc.Address != "" {
		if err := m.nonlocalBind(ctx, false); err != nil {
			return 0, err
		}
	}

	encoded, err := json.Marshal(document{Address: address, Peers: peers, Rules: wanted})
	if err != nil {
		return 0, err
	}

	return m.Store.PutDocument(documentName, encoded, expectedRevision)
}

// Network is this server's private address and its peers' addresses, for databases that let peers log in.
func (m *Manager) Network() (string, []string, error) {
	doc, _, err := m.load()
	if err != nil {
		return "", nil, err
	}

	var peers []string
	for _, peer := range doc.Peers {
		peers = append(peers, peer.Address)
	}

	return doc.Address, peers, nil
}

func (m *Manager) validate(address, current string, peers []Peer) error {
	if address != "" && address != current && !slices.ContainsFunc(m.candidates(), func(c Candidate) bool { return c.Address == address }) {
		return invalid("%s isn't a private address of this server.", address)
	}
	if address == "" && len(peers) > 0 {
		return invalid("Choose this server's private address before adding servers that can connect.")
	}
	if len(peers) > MaxPeers {
		return invalid("At most %d servers can connect to this one.", MaxPeers)
	}

	seenIDs, seenAddresses := map[string]bool{}, map[string]bool{}
	for _, peer := range peers {
		if !ids.Valid(peer.ID) || seenIDs[peer.ID] {
			return invalid("The server id %q isn't valid or is listed twice.", peer.ID)
		}
		seenIDs[peer.ID] = true

		if strings.TrimSpace(peer.Name) == "" || strings.ContainsAny(peer.Name, "\r\n") || len(peer.Name) > 60 {
			return invalid("A server needs a single-line name of at most 60 characters.")
		}

		ip := net.ParseIP(peer.Address).To4()
		if ip == nil || ip.String() != peer.Address || !private(ip) {
			return invalid("%s: %q isn't a private IPv4 address, like 10.0.0.5 or 100.101.102.103.", peer.Name, peer.Address)
		}
		if peer.Address == address {
			return invalid("%s has this server's own address.", peer.Name)
		}
		if seenAddresses[peer.Address] {
			return invalid("%s is listed twice.", peer.Address)
		}
		seenAddresses[peer.Address] = true
	}

	return nil
}

func (m *Manager) candidates() []Candidate {
	if m.Links == nil {
		return nil
	}

	links, err := m.Links()
	if err != nil {
		return nil
	}

	return Candidates(links)
}

func rules(address string, peers []Peer, services []service) []rule {
	if address == "" {
		return nil
	}

	var wanted []rule
	for _, peer := range peers {
		for _, s := range services {
			wanted = append(wanted, rule{PeerID: peer.ID, From: peer.Address, To: address, Port: s.port})
		}
	}

	return wanted
}

func (r rule) args() []string {
	return []string{"allow", "proto", "tcp", "from", r.From, "to", r.To, "port", strconv.Itoa(r.Port)}
}

func (m *Manager) deleteRules(ctx context.Context, rules []rule) {
	for _, r := range rules {
		_, _ = m.ufw(ctx, append([]string{"delete"}, r.args()...)...)
	}
}

// nonlocalBind lets services bind to the private address before it exists: at boot, a WireGuard address comes up
// after the database has started.
func (m *Manager) nonlocalBind(ctx context.Context, on bool) error {
	value := "0"
	if on {
		value = "1"
		if err := writeFile(m.Paths.File(sysctlFile), newFile("net.ipv4.ip_nonlocal_bind = 1\n", 0o644)); err != nil {
			return err
		}
	} else if err := os.Remove(m.Paths.File(sysctlFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	result, err := m.System.Run(ctx, system.Command{Name: "sysctl", Args: []string{"-q", "-w", "net.ipv4.ip_nonlocal_bind=" + value}})
	if err != nil {
		return &Error{Summary: "Couldn't let services bind to the private address.", Output: system.Tail(result.Output, 10)}
	}

	return nil
}

func (m *Manager) load() (document, uint64, error) {
	encoded, revision, err := m.Store.Document(documentName)
	if err != nil || encoded == nil {
		return document{}, revision, err
	}

	var doc document

	return doc, revision, json.Unmarshal(encoded, &doc)
}

func (m *Manager) ufw(ctx context.Context, args ...string) (system.Result, error) {
	return m.System.Run(ctx, system.Command{Name: "ufw", Args: args})
}

// Check dials address:port and says how it went: "connected", "refused", "timeout" or "unreachable", with the error
// for the last two.
func Check(ctx context.Context, address string, port int) (string, string, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return "", "", invalid("%q isn't an IP address.", address)
	}
	if port < 1 || port > 65535 {
		return "", "", invalid("Ports go from 1 to 65535.")
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err == nil {
		conn.Close()
		return "connected", "", nil
	}

	var netErr net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused", "", nil
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout", "", nil
	default:
		return "unreachable", err.Error(), nil
	}
}

func invalid(format string, args ...any) error {
	return &site.InvalidError{Field: "network", Reason: fmt.Sprintf(format, args...)}
}

// fileState is a file's content, or its absence, with its mode and owner.
type fileState struct {
	exists   bool
	content  []byte
	mode     os.FileMode
	uid, gid int
}

func readFile(name string) (fileState, error) {
	info, err := os.Stat(name)
	if errors.Is(err, os.ErrNotExist) {
		return fileState{}, nil
	}
	if err != nil {
		return fileState{}, err
	}

	content, err := os.ReadFile(name)
	if err != nil {
		return fileState{}, err
	}

	f := fileState{exists: true, content: content, mode: info.Mode().Perm(), uid: -1, gid: -1}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		f.uid, f.gid = int(stat.Uid), int(stat.Gid)
	}

	return f, nil
}

func (f fileState) same(other fileState) bool {
	return f.exists == other.exists && bytes.Equal(f.content, other.content)
}

// writeFile replaces name in one step, keeping the owner f carries; a file that shouldn't exist is removed.
func writeFile(name string, f fileState) error {
	if !f.exists {
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}

	temporary, err := os.CreateTemp(filepath.Dir(name), "."+filepath.Base(name)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())

	// Synced before the rename: a power cut must leave the old file or the new one, never an empty one.
	if _, err := temporary.Write(f.content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporary.Name(), f.mode); err != nil {
		return err
	}
	if f.uid >= 0 && (f.uid != os.Getuid() || f.gid != os.Getgid()) {
		if err := os.Chown(temporary.Name(), f.uid, f.gid); err != nil {
			return err
		}
	}

	return os.Rename(temporary.Name(), name)
}

// ReplaceFile writes content over an existing file in one step, keeping its mode and owner.
func ReplaceFile(name string, content []byte) error {
	current, err := readFile(name)
	if err != nil {
		return err
	}
	if !current.exists {
		return fmt.Errorf("%s doesn't exist", name)
	}
	current.content = content

	return writeFile(name, current)
}
