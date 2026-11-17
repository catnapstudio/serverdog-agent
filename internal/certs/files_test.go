package certs

import (
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
)

func TestFileLayout(t *testing.T) {
	p := paths.Paths{Root: "/tmp/r"}

	files := Files(p, "s1", "c1", []byte("chain"), []byte("key"))
	if len(files) != 2 || files[0].Path != "/tmp/r/etc/serverdog/certs/s1/c1/fullchain.pem" || files[1].Path != "/tmp/r/etc/serverdog/certs/s1/c1/privkey.pem" {
		t.Fatalf("files = %+v", files)
	}
	for _, file := range files {
		if file.Mode != 0o600 {
			t.Errorf("%s mode = %v", file.Path, file.Mode)
		}
	}

	link := ActiveLink(p, "s1", "orchard.com", "c1")
	if link.Path != "/tmp/r/etc/serverdog/certs/s1/orchard.com/active" || link.Link != "../c1" {
		t.Errorf("link = %+v", link)
	}
	if remove := RemoveActiveLink(p, "s1", "orchard.com"); !remove.Remove || remove.Path != link.Path {
		t.Errorf("remove = %+v", remove)
	}

	nginx := Nginx("s1", "orchard.com")
	if nginx.Fullchain != "/etc/serverdog/certs/s1/orchard.com/active/fullchain.pem" || nginx.Key != "/etc/serverdog/certs/s1/orchard.com/active/privkey.pem" {
		t.Errorf("nginx = %+v", nginx)
	}
}
