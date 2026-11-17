package site

import "testing"

func TestRedirectsAndBasicAuthAreChecked(t *testing.T) {
	base := Site{Domains: []Domain{{Name: "shop.test"}}}

	cases := []struct {
		name  string
		edit  func(*Site)
		valid bool
	}{
		{"path", func(s *Site) { s.Redirects = []PathRedirect{{From: "/old", To: "/new"}} }, true},
		{"url", func(s *Site) { s.Redirects = []PathRedirect{{From: "/old", To: "https://example.com/new?a=1"}} }, true},
		{"injection", func(s *Site) { s.Redirects = []PathRedirect{{From: "/old", To: "/new; deny all"}} }, false},
		{"relative", func(s *Site) { s.Redirects = []PathRedirect{{From: "old", To: "/new"}} }, false},
		{"twice", func(s *Site) { s.Redirects = []PathRedirect{{From: "/a", To: "/b"}, {From: "/a", To: "/c"}} }, false},
		{"itself", func(s *Site) { s.Redirects = []PathRedirect{{From: "/a", To: "/a"}} }, false},
		{"auth", func(s *Site) { s.BasicAuth = &BasicAuth{Username: "client", Password: "secret"} }, true},
		{"bad user", func(s *Site) { s.BasicAuth = &BasicAuth{Username: "a:b", Password: "x"} }, false},
	}

	for _, c := range cases {
		s := base
		c.edit(&s)
		err := checkProtection(s)
		redirectErr := validateRedirects(s)
		if got := err == nil && redirectErr == nil; got != c.valid {
			t.Errorf("%s: valid = %v, want %v (%v, %v)", c.name, got, c.valid, err, redirectErr)
		}
	}
}
