package firewall

import (
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

func newManager(t *testing.T) (*Manager, *systemtest.Fake) {
	t.Helper()

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	fake := &systemtest.Fake{}
	fake.Handle("ufw", func(c system.Command) (system.Result, error) {
		switch strings.Join(c.Args, " ") {
		case "status":
			return system.Result{Output: []byte("Status: active\n")}, nil
		case "show added":
			return system.Result{Output: []byte("Added user rules (see 'ufw status' for running firewall):\nufw allow 22/tcp\nufw allow from 203.0.113.4 to any port 8080 proto tcp comment 'serverdog:aaaaaaaaaaaa'\nufw allow from 10.0.0.5 to 10.0.0.4 port 3306 proto tcp comment 'serverdog-network:bbbbbbbbbbbb'\n")}, nil
		}
		return system.Result{Output: []byte("Rule added\n")}, nil
	})

	return &Manager{Store: store, System: fake}, fake
}

func TestRulesAreAddedBeforeTheOnesTheyReplaceAreDeleted(t *testing.T) {
	m, fake := newManager(t)
	ctx := context.Background()

	redis := Rule{ID: "aaaaaaaaaaaa", Name: "Redis from the worker", Action: "allow", Port: "6379", Protocol: "tcp", From: "10.0.0.5"}
	revision, err := m.Put(ctx, []Rule{redis}, 0)
	if err != nil {
		t.Fatal(err)
	}

	moved := redis
	moved.From = "10.0.0.0/24"
	moved.Name = "Redis from the network"
	if _, err := m.Put(ctx, []Rule{moved}, revision); err != nil {
		t.Fatal(err)
	}

	var ufw []string
	for _, c := range fake.Commands() {
		if c != "ufw status" {
			ufw = append(ufw, c)
		}
	}
	want := []string{
		"ufw allow proto tcp from 10.0.0.5 to any port 6379 comment serverdog:aaaaaaaaaaaa",
		"ufw allow proto tcp from 10.0.0.0/24 to any port 6379 comment serverdog:aaaaaaaaaaaa",
		"ufw delete allow proto tcp from 10.0.0.5 to any port 6379",
	}
	if strings.Join(ufw, "\n") != strings.Join(want, "\n") {
		t.Errorf("ufw ran\n%s\nwant\n%s", strings.Join(ufw, "\n"), strings.Join(want, "\n"))
	}

	if _, err := m.Put(ctx, nil, revision); err != state.ErrStaleDocument {
		t.Errorf("a stale revision: %v", err)
	}

	status, err := m.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Active || len(status.Rules) != 1 || status.Rules[0].Name != "Redis from the network" || strings.Join(status.Other, ",") != "allow 22/tcp" {
		t.Errorf("status = %+v", status)
	}
}

func TestARuleUfwAlreadyHasIsRefusedBeforeUfwTakesItOver(t *testing.T) {
	m, fake := newManager(t)
	m.Paths = paths.Paths{Root: t.TempDir()}
	if err := os.MkdirAll(m.Paths.File("/etc/ufw"), 0o755); err != nil {
		t.Fatal(err)
	}
	rules := "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n### tuple ### allow any 8080 0.0.0.0/0 any 0.0.0.0/0 in comment=" + hex.EncodeToString([]byte("serverdog:aaaaaaaaaaaa")) + "\n"
	if err := os.WriteFile(m.Paths.File("/etc/ufw/user.rules"), []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}

	list := []Rule{
		{ID: "bbbbbbbbbbbb", Name: "Alt", Action: "allow", Port: "8081"},
		{ID: "cccccccccccc", Name: "SSH", Action: "allow", Port: "22", Protocol: "tcp"},
	}
	if _, err := m.Put(context.Background(), list, 0); err == nil || !strings.Contains(err.Error(), "already has") {
		t.Fatalf("err = %v", err)
	}

	for _, c := range fake.Commands() {
		if strings.Contains(c, "port 22") {
			t.Errorf("ufw was asked about SSH: %s", c)
		}
	}
	if last := fake.Commands()[len(fake.Commands())-1]; last != "ufw delete allow from any to any port 8081" {
		t.Errorf("the first rule wasn't taken back: %s", last)
	}
	if status, _ := m.Status(context.Background()); len(status.Rules) != 0 {
		t.Errorf("saved %v", status.Rules)
	}

	// Our own 8080 rule in ufw's file is ours: re-adding it isn't refused.
	if _, err := m.Put(context.Background(), []Rule{{ID: "aaaaaaaaaaaa", Name: "Alt", Action: "allow", Port: "8080"}}, 0); err != nil {
		t.Errorf("our own rule was refused: %v", err)
	}
}

func TestValidate(t *testing.T) {
	ok := Rule{ID: "aaaaaaaaaaaa", Name: "x", Action: "allow", Port: "8000:8010", Protocol: "udp", From: "2001:db8::/32"}
	if err := validate([]Rule{ok}); err != nil {
		t.Errorf("valid rule refused: %v", err)
	}

	for name, change := range map[string]func(*Rule){
		"range without protocol": func(r *Rule) { r.Protocol = "" },
		"port 0":                 func(r *Rule) { r.Port = "0" },
		"reversed range":         func(r *Rule) { r.Port = "9000:8000" },
		"port too big":           func(r *Rule) { r.Port = "70000" },
		"injected port":          func(r *Rule) { r.Port = "22 comment x" },
		"bad source":             func(r *Rule) { r.From = "any; reboot" },
		"bad action":             func(r *Rule) { r.Action = "reject" },
		"bad protocol":           func(r *Rule) { r.Protocol = "icmp" },
		"multi-line name":        func(r *Rule) { r.Name = "a\nb" },
	} {
		rule := ok
		change(&rule)
		if err := validate([]Rule{rule}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	twin := ok
	twin.ID = "bbbbbbbbbbbb"
	if err := validate([]Rule{ok, twin}); err == nil {
		t.Error("the same rule twice was accepted")
	}
}
