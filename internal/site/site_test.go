package site

import (
	"reflect"
	"testing"
)

func TestLinkedPutsEnvironmentFileFirstWithoutDuplicates(t *testing.T) {
	s := Site{EnvironmentFile: ".env", SharedPaths: []string{"storage", ".env", "var/log"}}

	if got := s.Linked(); !reflect.DeepEqual(got, []string{".env", "storage", "var/log"}) {
		t.Errorf("Linked = %v", got)
	}
}

func TestWithDefaults(t *testing.T) {
	s := Site{}.WithDefaults()

	if s.ReleasesToKeep != 5 || s.DeployTimeoutMinutes != 30 {
		t.Errorf("defaults = %d, %d", s.ReleasesToKeep, s.DeployTimeoutMinutes)
	}
}

func TestPrimary(t *testing.T) {
	s := Site{Domains: []Domain{{Name: "a.com"}, {Name: "b.com", Primary: true}}}

	if s.Primary().Name != "b.com" {
		t.Errorf("Primary = %q", s.Primary().Name)
	}
}

func TestHasRepository(t *testing.T) {
	if (Site{}).HasRepository() {
		t.Error("an empty site has a repository")
	}
	if !(Site{RepositoryURL: "git@github.com:me/app.git", Branch: "main"}).HasRepository() {
		t.Error("a site with a URL has no repository")
	}
}
