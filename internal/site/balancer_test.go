package site

import "testing"

func TestBalancerIsChecked(t *testing.T) {
	base := Site{
		Runtime: Balancer, Domains: []Domain{{Name: "shop.test"}}, Balancing: RoundRobin,
		Backends: []Backend{{Address: "10.0.0.2", Port: 80, Weight: 1}},
	}

	cases := []struct {
		name  string
		edit  func(*Site)
		valid bool
	}{
		{"fine", func(*Site) {}, true},
		{"hostname", func(s *Site) { s.Backends = []Backend{{Address: "web-1.internal", Port: 80, Weight: 1}} }, true},
		{"ipv6", func(s *Site) { s.Backends = []Backend{{Address: "fd00::2", Port: 80, Weight: 1}} }, true},
		{"injection", func(s *Site) { s.Backends = []Backend{{Address: "10.0.0.2; deny all", Port: 80, Weight: 1}} }, false},
		{"no backends", func(s *Site) { s.Backends = nil }, false},
		{"port", func(s *Site) { s.Backends[0].Port = 0 }, false},
		{"weight", func(s *Site) { s.Backends[0].Weight = 0 }, false},
		{"twice", func(s *Site) { s.Backends = append(s.Backends, s.Backends[0]) }, false},
		{"only backup", func(s *Site) { s.Backends = []Backend{{Address: "10.0.0.2", Port: 80, Weight: 1, Backup: true}} }, false},
		{"backup with ip hash", func(s *Site) {
			s.Balancing = IPHash
			s.Backends = append(s.Backends, Backend{Address: "10.0.0.3", Port: 80, Weight: 1, Backup: true})
		}, false},
		{"method", func(s *Site) { s.Balancing = "" }, false},
		{"repository", func(s *Site) { s.RepositoryURL, s.Branch = "git@github.com:a/b.git", "main" }, false},
		{"no domain", func(s *Site) { s.Domains = nil }, false},
	}

	for _, c := range cases {
		s := base
		s.Backends = append([]Backend(nil), base.Backends...)
		c.edit(&s)
		if err := validateBalancer(s); (err == nil) != c.valid {
			t.Errorf("%s: err = %v, want valid %v", c.name, err, c.valid)
		}
	}
}
