package site

import (
	"errors"
	"strings"
	"testing"
)

var host = Host{PHPVersions: []string{"8.4", "8.3"}, HasNginx: true, HasNode: true}

func laravel() Site {
	return Site{
		ID:              "abcdefghijkl",
		Preset:          "laravel",
		Runtime:         PHP,
		Domains:         []Domain{{Name: "orchard.com", Redirect: FromWWW, Primary: true}},
		RepositoryURL:   "git@github.com:morgan/orchard.git",
		Branch:          "main",
		PHPVersion:      "8.4",
		WebDirectory:    "public",
		EnvironmentFile: ".env",
		SharedPaths:     []string{"storage"},
		DeployScript:    "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\n",
		ZeroDowntime:    true,
		User:            DefaultUser,
	}.WithDefaults()
}

func TestValidAccepted(t *testing.T) {
	if err := Validate(laravel(), host); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Site){
		"bad id":     func(s *Site) { s.ID = "../../etc" },
		"no domains": func(s *Site) { s.Domains = nil },
		"two primaries": func(s *Site) {
			s.Domains = append(s.Domains, Domain{Name: "b.com", Redirect: NoRedirect, Primary: true})
		},
		"no primary":            func(s *Site) { s.Domains[0].Primary = false },
		"uppercase domain":      func(s *Site) { s.Domains[0].Name = "Orchard.com" },
		"www domain":            func(s *Site) { s.Domains[0].Name = "www.orchard.com" },
		"single label":          func(s *Site) { s.Domains[0].Name = "localhost" },
		"wildcard in name":      func(s *Site) { s.Domains[0].Name = "*.orchard.com" },
		"duplicate domain":      func(s *Site) { s.Domains = append(s.Domains, Domain{Name: "orchard.com", Redirect: NoRedirect}) },
		"unknown redirect":      func(s *Site) { s.Domains[0].Redirect = "sideways" },
		"php not installed":     func(s *Site) { s.PHPVersion = "7.4" },
		"web dir escapes":       func(s *Site) { s.WebDirectory = "../public" },
		"web dir absolute":      func(s *Site) { s.WebDirectory = "/var/www" },
		"shared path escapes":   func(s *Site) { s.SharedPaths = []string{"storage/../../x"} },
		"shared path dot":       func(s *Site) { s.SharedPaths = []string{"."} },
		"nested shared paths":   func(s *Site) { s.SharedPaths = []string{"storage", "storage/logs"} },
		"nested shared reverse": func(s *Site) { s.SharedPaths = []string{"storage/logs", "storage"} },
		"shared inside env":     func(s *Site) { s.SharedPaths = []string{".env/x"} },
		"env file with slash":   func(s *Site) { s.EnvironmentFile = "config/.env" },
		"https repository":      func(s *Site) { s.RepositoryURL = "https://github.com/a/b.git" },
		"branch with dots":      func(s *Site) { s.Branch = "a..b" },
		"branch leading dash":   func(s *Site) { s.Branch = "-x" },
		"missing macros":        func(s *Site) { s.DeployScript = "composer install" },
		"keep one release":      func(s *Site) { s.ReleasesToKeep = 1 },
		"timeout too long":      func(s *Site) { s.DeployTimeoutMinutes = 121 },
		"isolated as serverdog": func(s *Site) { s.Isolated = true },
		"shared user renamed":   func(s *Site) { s.User = "bob" },
		"reserved isolated":     func(s *Site) { s.Isolated = true; s.User = "www-data" },
		"bad user name":         func(s *Site) { s.Isolated = true; s.User = "Bob Smith" },
		"node without command":  func(s *Site) { s.Runtime = Node; s.PHPVersion = "" },
		"node without zero": func(s *Site) {
			s.Runtime = Node
			s.PHPVersion = ""
			s.NodeStartCommand = "npm start"
			s.ZeroDowntime = false
		},
		"command with newline": func(s *Site) { s.Runtime = Node; s.PHPVersion = ""; s.NodeStartCommand = "npm start\nrm -rf /" },
		"static with php":      func(s *Site) { s.Runtime = Static },
		"unknown runtime":      func(s *Site) { s.Runtime = "ruby" },
	}

	for name, change := range cases {
		s := laravel()
		change(&s)

		var invalid *InvalidError
		if err := Validate(s, host); !errors.As(err, &invalid) {
			t.Errorf("%s: err = %v, want *InvalidError", name, err)
		}
	}
}

func TestValidateAcceptsSiblingSharedPaths(t *testing.T) {
	s := laravel()
	s.SharedPaths = []string{"storage", "storage2", "config", "var/log", "var/cache"}

	if err := Validate(s, host); err != nil {
		t.Fatal(err)
	}
}

func TestValidateNamesOverlappingSharedPaths(t *testing.T) {
	s := laravel()
	s.SharedPaths = []string{"storage", "storage/logs"}

	err := Validate(s, host)
	if err == nil || err.Error() != "Shared paths storage and storage/logs overlap; keep only storage." {
		t.Errorf("err = %v", err)
	}
}

func TestValidateNeedsNginxAndNode(t *testing.T) {
	if err := Validate(laravel(), Host{PHPVersions: []string{"8.4"}}); err == nil || !strings.Contains(err.Error(), "Nginx") {
		t.Errorf("err = %v", err)
	}

	node := laravel()
	node.Runtime, node.PHPVersion, node.NodeStartCommand = Node, "", "npm run start"
	if err := Validate(node, Host{HasNginx: true}); err == nil || !strings.Contains(err.Error(), "Node.js") {
		t.Errorf("err = %v", err)
	}
}

func TestASiteWithoutAWebsiteNeedsANameAndNoNginx(t *testing.T) {
	s := laravel()
	s.Domains, s.Name = nil, "worker"
	if err := Validate(s, Host{PHPVersions: []string{"8.4"}}); err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(*Site){
		"no name":   func(s *Site) { s.Name = "" },
		"dotted":    func(s *Site) { s.Name = "worker.com" },
		"uppercase": func(s *Site) { s.Name = "Worker" },
		"node":      func(s *Site) { s.Runtime, s.PHPVersion, s.NodeStartCommand = Node, "", "node index.js" },
		"named website": func(s *Site) {
			s.Domains = []Domain{{Name: "orchard.com", Primary: true}}
		},
	}
	for name, change := range cases {
		bad := s
		change(&bad)
		if err := Validate(bad, host); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if err := ValidateChange(s, laravel()); err == nil {
		t.Error("a site without a website got domains")
	}
}

func TestInPlaceScriptNeedsNoMacros(t *testing.T) {
	s := laravel()
	s.ZeroDowntime = false
	s.DeployScript = "composer install"

	if err := Validate(s, host); err != nil {
		t.Fatal(err)
	}
}

func TestValidateChangeKeepsCreationChoices(t *testing.T) {
	old := laravel()
	old.Directory = "/home/serverdog/orchard.com"

	cases := map[string]func(*Site){
		"id":            func(s *Site) { s.ID = "bbbbbbbbbbbb" },
		"runtime":       func(s *Site) { s.Runtime = Static },
		"isolation":     func(s *Site) { s.Isolated = true; s.User = "orchard" },
		"zero downtime": func(s *Site) { s.ZeroDowntime = false },
	}

	for name, change := range cases {
		updated := old
		change(&updated)
		if err := ValidateChange(old, updated); err == nil {
			t.Errorf("%s: change accepted", name)
		}
	}

	allowed := old
	allowed.Branch = "develop"
	allowed.PHPVersion = "8.3"
	if err := ValidateChange(old, allowed); err != nil {
		t.Errorf("allowed change rejected: %v", err)
	}
}

func TestValidateAcceptsASiteWithoutARepository(t *testing.T) {
	s := laravel()
	s.RepositoryURL, s.Branch = "", ""

	if err := Validate(s, host); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsAHalfSetRepository(t *testing.T) {
	cases := map[string]struct {
		url, branch, field string
	}{
		"url without branch": {"git@github.com:morgan/orchard.git", "", "branch"},
		"branch without url": {"", "main", "repositoryUrl"},
	}

	for name, c := range cases {
		s := laravel()
		s.RepositoryURL, s.Branch = c.url, c.branch

		var invalid *InvalidError
		err := Validate(s, host)
		if !errors.As(err, &invalid) || invalid.Field != c.field || invalid.Reason != "A site needs both a repository URL and a branch, or neither." {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestValidateProcessesAndScheduler(t *testing.T) {
	worker := Process{ID: "workerid2345", Name: "Queue worker", Command: "php8.4 artisan queue:work", Count: 1}

	valid := laravel()
	valid.Processes, valid.Scheduler, valid.DeployOnPush, valid.AppDirectory = []Process{worker}, true, true, "app"
	if err := Validate(valid, host); err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(*Site){
		"bad id":           func(s *Site) { s.Processes[0].ID = "../x" },
		"duplicate id":     func(s *Site) { s.Processes = append(s.Processes, worker) },
		"blank name":       func(s *Site) { s.Processes[0].Name = " " },
		"blank command":    func(s *Site) { s.Processes[0].Command = "" },
		"two-line command": func(s *Site) { s.Processes[0].Command = "a\nb" },
		"no copies":        func(s *Site) { s.Processes[0].Count = 0 },
		"too many copies":  func(s *Site) { s.Processes[0].Count = MaxProcessCount + 1 },
		"scheduler on static": func(s *Site) {
			s.Runtime, s.PHPVersion, s.Scheduler = Static, "", true
		},
		"process directory outside the release": func(s *Site) { s.Processes[0].Directory = "../x" },
		"app directory outside the release":     func(s *Site) { s.AppDirectory = "/etc" },
		"deploy on push without a repository": func(s *Site) {
			s.RepositoryURL, s.Branch, s.DeployOnPush = "", "", true
		},
	}

	for name, change := range cases {
		s := laravel()
		s.Processes = []Process{worker}
		change(&s)

		var invalid *InvalidError
		if err := Validate(s, host); !errors.As(err, &invalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestHealthCheckPath(t *testing.T) {
	for path, ok := range map[string]bool{
		"":                             true,
		"/up":                          true,
		"/health?full=1":               true,
		"up":                           false,
		"/up now":                      false,
		"/up;rm":                       false,
		"/" + strings.Repeat("a", 201): false,
	} {
		s := laravel()
		s.HealthCheckPath = path
		if err := Validate(s, host); (err == nil) != ok {
			t.Errorf("%q: err = %v, want ok %v", path, err, ok)
		}
	}

	worker := laravel()
	worker.Domains, worker.Name, worker.HealthCheckPath = nil, "worker", "/up"
	if err := Validate(worker, host); err == nil {
		t.Error("a site without a website got a health check")
	}
}

func TestReverbDomainRules(t *testing.T) {
	withReverb := func(change func(*Site, *Domain)) error {
		s := laravel()
		reverb := Domain{Name: "ws.orchard.com", Redirect: NoRedirect, Reverb: true}
		change(&s, &reverb)
		s.Domains = append(s.Domains, reverb)
		return Validate(s, host)
	}

	if err := withReverb(func(*Site, *Domain) {}); err != nil {
		t.Errorf("a Reverb domain was refused: %v", err)
	}

	for name, change := range map[string]func(*Site, *Domain){
		"primary":   func(s *Site, d *Domain) { s.Domains[0].Primary, d.Primary = false, true },
		"www":       func(_ *Site, d *Domain) { d.Redirect = FromWWW },
		"wildcards": func(_ *Site, d *Domain) { d.Wildcards = true },
		"static":    func(s *Site, _ *Domain) { s.Runtime = Static },
		"twice": func(s *Site, _ *Domain) {
			s.Domains = append(s.Domains, Domain{Name: "ws2.orchard.com", Redirect: NoRedirect, Reverb: true})
		},
	} {
		var invalid *InvalidError
		if err := withReverb(change); !errors.As(err, &invalid) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
}

func TestPHPWorkers(t *testing.T) {
	s := laravel()
	if s.PHPWorkerLimit() != DefaultPHPWorkers {
		t.Fatalf("default limit %d", s.PHPWorkerLimit())
	}

	s.PHPWorkers = 40
	if err := Validate(s, host); err != nil || s.PHPWorkerLimit() != 40 {
		t.Fatalf("40 workers: %v", err)
	}

	for _, workers := range []int{-1, MaxPHPWorkers + 1} {
		s.PHPWorkers = workers
		if err := Validate(s, host); err == nil {
			t.Errorf("%d workers accepted", workers)
		}
	}
}

func TestOctaneRules(t *testing.T) {
	s := laravel()
	s.Octane = true
	if err := Validate(s, host); err != nil {
		t.Fatalf("a Laravel site with zero-downtime deploys can run Octane: %v", err)
	}
	if !s.RunsOwnServer() {
		t.Error("an Octane site runs its own server")
	}

	inPlace := s
	inPlace.ZeroDowntime, inPlace.SharedPaths = false, nil
	inPlace.DeployScript = "cd $SERVERDOG_SITE_DIRECTORY"
	if err := Validate(inPlace, host); err == nil || !strings.Contains(err.Error(), "zero-downtime") {
		t.Errorf("Octane without zero-downtime deploys: %v", err)
	}

	worker := s
	worker.Domains, worker.Name = nil, "worker"
	if err := Validate(worker, host); err == nil || !strings.Contains(err.Error(), "website") {
		t.Errorf("Octane on a site without a website: %v", err)
	}
}
