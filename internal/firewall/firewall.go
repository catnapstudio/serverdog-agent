// Package firewall keeps the ufw rules the app added. Each one carries a "serverdog:<id>" comment; rules added at setup
// or by hand (SSH among them) are listed but never touched, so the app can't lock anyone out.
package firewall

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

type Rule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// "allow" or "deny".
	Action string `json:"action"`
	// "8080", or a range "8000:8010".
	Port string `json:"port"`
	// "tcp", "udp", or "" for both.
	Protocol string `json:"protocol"`
	// An address or a CIDR network; "" is anywhere.
	From string `json:"from"`
}

// Status is what the app shows.
type Status struct {
	Installed bool
	Active    bool
	Rules     []Rule
	Revision  uint64
	// Other are the rules ServerDog didn't add, as ufw prints them ("allow 22/tcp").
	Other []string
}

// MaxRules bounds the list.
const MaxRules = 100

const document = "firewall_rules"

const commentPrefix = "serverdog:"

var portPattern = regexp.MustCompile(`^[0-9]{1,5}(:[0-9]{1,5})?$`)

type Manager struct {
	Store  *state.Store
	Paths  paths.Paths
	System system.Runner

	mu sync.Mutex
}

func (m *Manager) Status(ctx context.Context) (Status, error) {
	rules, revision, err := m.list()
	if err != nil {
		return Status{}, err
	}

	status := Status{Rules: rules, Revision: revision}

	result, err := m.ufw(ctx, "status")
	var exit *system.ExitError
	if err != nil && !errors.As(err, &exit) {
		// No ufw binary: nothing else to read.
		return status, nil
	}
	status.Installed = true
	status.Active = strings.Contains(string(result.Output), "Status: active")

	added, err := m.ufw(ctx, "show", "added")
	if err != nil {
		return Status{}, err
	}

	for _, line := range strings.Split(string(added.Output), "\n") {
		line = strings.TrimSpace(line)
		// Private networking's "serverdog-network:" rules belong to the Network section.
		if !strings.HasPrefix(line, "ufw ") || strings.Contains(line, "comment 'serverdog") {
			continue
		}
		status.Other = append(status.Other, strings.TrimPrefix(line, "ufw "))
	}

	return status, nil
}

// Put replaces the app's rules: new ones are added before removed ones are deleted, so a changed rule never leaves a
// gap. Nothing is saved unless ufw took every change.
func (m *Manager) Put(ctx context.Context, rules []Rule, expectedRevision uint64) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := validate(rules); err != nil {
		return 0, err
	}

	old, current, err := m.list()
	if err != nil {
		return 0, err
	}
	if current != expectedRevision {
		return 0, state.ErrStaleDocument
	}

	if _, err := m.ufw(ctx, "status"); err != nil {
		var exit *system.ExitError
		if !errors.As(err, &exit) {
			return 0, invalid("ufw isn't installed on this server.")
		}
	}

	oldKeys, newKeys := keys(old), keys(rules)
	theirs := m.othersTuples()
	var added []Rule

	for _, rule := range rules {
		if oldKeys[key(rule)] {
			continue
		}

		// ufw would take such a rule over, rewriting its comment: then removing ours would remove theirs, SSH included.
		if theirs[tuple(rule)] {
			m.remove(ctx, added)
			return 0, invalid("%s: ufw already has this rule, added outside ServerDog. It stays as it is.", rule.Name)
		}

		result, err := m.ufw(ctx, append(spec(rule), "comment", commentPrefix+rule.ID)...)
		if err == nil && (strings.Contains(string(result.Output), "Skipping") || strings.Contains(string(result.Output), "updated")) {
			err = invalid("%s: ufw already has this rule, added outside ServerDog.", rule.Name)
		}
		if err != nil {
			m.remove(ctx, added)
			return 0, err
		}
		added = append(added, rule)
	}

	for _, rule := range old {
		if newKeys[key(rule)] {
			continue
		}
		if _, err := m.ufw(ctx, append([]string{"delete"}, spec(rule)...)...); err != nil {
			return 0, err
		}
	}

	encoded, err := json.Marshal(rules)
	if err != nil {
		return 0, err
	}

	return m.Store.PutDocument(document, encoded, expectedRevision)
}

// remove takes back rules a failed Put added; it's best effort, and a retry adds them again anyway.
func (m *Manager) remove(ctx context.Context, rules []Rule) {
	for _, rule := range rules {
		_, _ = m.ufw(context.WithoutCancel(ctx), append([]string{"delete"}, spec(rule)...)...)
	}
}

func (m *Manager) list() ([]Rule, uint64, error) {
	encoded, revision, err := m.Store.Document(document)
	if err != nil || encoded == nil {
		return nil, revision, err
	}

	var rules []Rule

	return rules, revision, json.Unmarshal(encoded, &rules)
}

func (m *Manager) ufw(ctx context.Context, args ...string) (system.Result, error) {
	return m.System.Run(ctx, system.Command{Name: "ufw", Args: args})
}

// othersTuples are the rules ServerDog didn't add, from ufw's own files ("allow tcp 22 any"): action, protocol, port
// and source, the source "any" for anywhere.
func (m *Manager) othersTuples() map[string]bool {
	tuples := map[string]bool{}

	for _, file := range []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules"} {
		content, err := os.ReadFile(m.Paths.File(file))
		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(content), "\n") {
			fields := strings.Fields(strings.TrimPrefix(line, "### tuple ###"))
			if !strings.HasPrefix(line, "### tuple ###") || len(fields) < 7 || strings.Contains(line, "comment="+hex.EncodeToString([]byte(commentPrefix))) {
				continue
			}

			source := fields[5]
			if source == "0.0.0.0/0" || source == "::/0" {
				source = "any"
			}
			tuples[strings.Join([]string{fields[0], fields[1], fields[2], source}, " ")] = true
		}
	}

	return tuples
}

// tuple is the rule as othersTuples reads ufw's.
func tuple(rule Rule) string {
	protocol, from := rule.Protocol, rule.From
	if protocol == "" {
		protocol = "any"
	}
	if from == "" {
		from = "any"
	}

	return strings.Join([]string{rule.Action, protocol, rule.Port, from}, " ")
}

// spec is the rule in ufw's full syntax, the same for adding and deleting it.
func spec(rule Rule) []string {
	args := []string{rule.Action}
	if rule.Protocol != "" {
		args = append(args, "proto", rule.Protocol)
	}

	from := rule.From
	if from == "" {
		from = "any"
	}

	return append(args, "from", from, "to", "any", "port", rule.Port)
}

func key(rule Rule) string {
	return strings.Join(append(spec(rule), rule.ID), " ")
}

func keys(rules []Rule) map[string]bool {
	set := map[string]bool{}
	for _, rule := range rules {
		set[key(rule)] = true
	}

	return set
}

func validate(rules []Rule) error {
	if len(rules) > MaxRules {
		return invalid("A server can have at most %d firewall rules.", MaxRules)
	}

	seenIDs, seenSpecs := map[string]bool{}, map[string]bool{}

	for _, rule := range rules {
		if !ids.Valid(rule.ID) || seenIDs[rule.ID] {
			return invalid("The rule id %q isn't valid or is listed twice.", rule.ID)
		}
		seenIDs[rule.ID] = true

		if strings.TrimSpace(rule.Name) == "" || strings.ContainsAny(rule.Name, "\r\n") || len(rule.Name) > 60 {
			return invalid("A firewall rule needs a single-line name of at most 60 characters.")
		}
		if rule.Action != "allow" && rule.Action != "deny" {
			return invalid("%s: a rule allows or denies.", rule.Name)
		}
		if rule.Protocol != "" && rule.Protocol != "tcp" && rule.Protocol != "udp" {
			return invalid("%s: the protocol is TCP, UDP or both.", rule.Name)
		}
		if err := validPort(rule); err != nil {
			return err
		}
		if rule.From != "" && net.ParseIP(rule.From) == nil {
			if _, _, err := net.ParseCIDR(rule.From); err != nil {
				return invalid("%s: %q isn't an IP address or a network like 203.0.113.0/24.", rule.Name, rule.From)
			}
		}

		s := strings.Join(spec(rule), " ")
		if seenSpecs[s] {
			return invalid("%s is the same rule as another one in the list.", rule.Name)
		}
		seenSpecs[s] = true
	}

	return nil
}

func validPort(rule Rule) error {
	if !portPattern.MatchString(rule.Port) {
		return invalid("%s: the port is a number like 8080 or a range like 8000:8010.", rule.Name)
	}

	bounds := strings.Split(rule.Port, ":")
	low, _ := strconv.Atoi(bounds[0])
	high := low
	if len(bounds) == 2 {
		high, _ = strconv.Atoi(bounds[1])
		if rule.Protocol == "" {
			return invalid("%s: a port range needs a protocol, TCP or UDP.", rule.Name)
		}
	}

	if low < 1 || high > 65535 || low > high {
		return invalid("%s: ports go from 1 to 65535, the lower one first.", rule.Name)
	}

	return nil
}

func invalid(format string, args ...any) error {
	return &site.InvalidError{Field: "firewall", Reason: fmt.Sprintf(format, args...)}
}
