package state

import (
	"maps"
	"testing"
)

func TestNodePortUsersFollowTheStoredSites(t *testing.T) {
	store := open(t)

	isolated := sample("bbbbbbbbbbbb", "b.com")
	isolated.Isolated, isolated.User = true, "bob"
	for _, s := range []struct {
		id   string
		save func() error
	}{
		{"aaaaaaaaaaaa", func() error { _, err := store.PutSite(sample("aaaaaaaaaaaa", "a.com"), 0, now); return err }},
		{"bbbbbbbbbbbb", func() error { _, err := store.PutSite(isolated, 0, now); return err }},
		{"cccccccccccc", func() error { _, err := store.PutSite(sample("cccccccccccc", "c.com"), 0, now); return err }},
		// Ports allocated by a create that failed before the site was saved.
		{"dddddddddddd", func() error { return nil }},
	} {
		if err := s.save(); err != nil {
			t.Fatal(err)
		}
		if _, err := store.NodePorts(s.id); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.DeleteSiteData("cccccccccccc"); err != nil {
		t.Fatal(err)
	}

	users, err := store.NodePortUsers()
	if err != nil {
		t.Fatal(err)
	}

	want := map[int]string{20000: "serverdog", 20001: "serverdog", 20002: "bob", 20003: "bob"}
	if !maps.Equal(users, want) {
		t.Errorf("NodePortUsers = %v, want %v", users, want)
	}
}

func TestReverbPortsAreStableAndApartFromNodePorts(t *testing.T) {
	store := open(t)

	reverb, err := store.SitePort("aaaaaaaaaaaa", PortReverb)
	if err != nil || reverb != FirstNodePort {
		t.Fatalf("ReverbPort = %d, %v", reverb, err)
	}
	if again, _ := store.SitePort("aaaaaaaaaaaa", PortReverb); again != reverb {
		t.Errorf("the Reverb port moved from %d to %d", reverb, again)
	}

	node, err := store.NodePorts("aaaaaaaaaaaa")
	if err != nil || node != [2]int{FirstNodePort + 1, FirstNodePort + 2} {
		t.Errorf("NodePorts = %v, %v", node, err)
	}
	if err := store.SetLivePort("aaaaaaaaaaaa", node[1]); err != nil {
		t.Fatal(err)
	}
	if live, _ := store.LivePort("aaaaaaaaaaaa"); live != node[1] {
		t.Errorf("LivePort = %d", live)
	}

	if err := store.DeleteSiteData("aaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if freed, _ := store.SitePort("bbbbbbbbbbbb", PortReverb); freed != FirstNodePort {
		t.Errorf("a deleted site kept its Reverb port: next is %d", freed)
	}
}
