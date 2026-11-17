package sshkeys

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/userfs"
)

const (
	laptop = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEiKwp8GeZ8Xc6CyI70uLeCrPvANiP2B8ChWhzU0gxGY laptop"
	ci     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBpnPNetcgyBxpBQzHdsUw7zhm3d5GAsIbAvIZ/AvFP+ ci"
)

func TestKeysGoInTheBlockAndEverythingElseIsKept(t *testing.T) {
	root := t.TempDir()
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	homes := map[string]string{"root": root + "/root", "serverdog": root + "/home/serverdog"}
	appKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl serverdog-app"
	if err := os.MkdirAll(homes["root"]+"/.ssh", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(homes["root"]+"/.ssh/authorized_keys", []byte(appKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := &Manager{
		Store: store,
		Sites: func() ([]site.Site, error) { return []site.Site{{User: "serverdog"}}, nil },
		LookupUser: func(name string) (system.User, error) {
			return system.User{Name: name, Home: homes[name]}, nil
		},
		FS: func(system.User) userfs.FS { return userfs.FS{Runner: system.Exec{}} },
	}
	ctx := context.Background()

	keys := []Key{
		{ID: "aaaaaaaaaaaa", Name: "Laptop", User: "root", PublicKey: laptop},
		{ID: "bbbbbbbbbbbb", Name: "CI deploys", User: "serverdog", PublicKey: ci},
	}
	revision, err := m.Put(ctx, keys, 0)
	if err != nil {
		t.Fatal(err)
	}

	rootFile, _ := os.ReadFile(homes["root"] + "/.ssh/authorized_keys")
	if !strings.HasPrefix(string(rootFile), appKey+"\n"+begin+"\n") || !strings.Contains(string(rootFile), " Laptop\n"+end+"\n") || strings.Contains(string(rootFile), "CI deploys") {
		t.Errorf("root's file:\n%s", rootFile)
	}

	userFile, _ := os.ReadFile(homes["serverdog"] + "/.ssh/authorized_keys")
	if !strings.Contains(string(userFile), "CI deploys") {
		t.Errorf("serverdog's file:\n%s", userFile)
	}
	if info, _ := os.Stat(filepath.Dir(homes["serverdog"] + "/.ssh/authorized_keys")); info.Mode().Perm() != 0o700 {
		t.Errorf(".ssh mode = %v", info.Mode())
	}

	status, err := m.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Other) != 1 || status.Other[0].Comment != "serverdog-app" || status.Other[0].User != "root" || strings.Join(status.Users, ",") != "root,serverdog" {
		t.Errorf("status = %+v", status)
	}

	if _, err := m.Put(ctx, keys[1:], revision); err != nil {
		t.Fatal(err)
	}
	rootFile, _ = os.ReadFile(homes["root"] + "/.ssh/authorized_keys")
	if string(rootFile) != appKey+"\n" {
		t.Errorf("removing root's last key left:\n%s", rootFile)
	}
}

func TestValidate(t *testing.T) {
	users := []string{"root", "serverdog"}
	ok := Key{ID: "aaaaaaaaaaaa", Name: "Laptop", User: "root", PublicKey: laptop}
	if err := validate([]Key{ok}, users); err != nil {
		t.Fatal(err)
	}

	for name, change := range map[string]func(*Key){
		"options":      func(k *Key) { k.PublicKey = `command="reboot" ` + laptop },
		"two keys":     func(k *Key) { k.PublicKey = laptop + "\n" + ci },
		"not a key":    func(k *Key) { k.PublicKey = "hello" },
		"private key":  func(k *Key) { k.PublicKey = "-----BEGIN OPENSSH PRIVATE KEY-----" },
		"unknown user": func(k *Key) { k.User = "postgres" },
		"no name":      func(k *Key) { k.Name = " " },
	} {
		key := ok
		change(&key)
		if err := validate([]Key{key}, users); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
