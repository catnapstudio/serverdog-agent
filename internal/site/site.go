// Package site describes a site: its domains, how it runs, and where its code comes from.
package site

import (
	"fmt"
	"time"
)

type Runtime string

const (
	PHP    Runtime = "php"
	Node   Runtime = "node"
	Static Runtime = "static"
	// Balancer runs nothing: Nginx spreads the site's requests across Backends on other servers.
	Balancer Runtime = "balancer"
)

// Balancing is how a load-balanced site picks a backend for each request.
type Balancing string

const (
	RoundRobin       Balancing = "roundRobin"
	LeastConnections Balancing = "leastConnections"
	// IPHash sends each visitor's address to the same backend while it's up.
	IPHash Balancing = "ipHash"
)

// Backend is a server a load-balanced site sends requests to: usually its private address, where it hosts the site
// under the same domain.
type Backend struct {
	// An IP address or a hostname.
	Address string `json:"address"`
	Port    int    `json:"port"`
	// Weight is its share of requests relative to the others, 1 to 100.
	Weight int `json:"weight"`
	// Backup only gets requests while every other backend is down.
	Backup bool `json:"backup,omitempty"`
}

type Redirect string

const (
	FromWWW    Redirect = "fromWww"
	ToWWW      Redirect = "toWww"
	NoRedirect Redirect = "none"
)

// DefaultUser is the shared user sites run as unless isolated. Provisioning creates it.
const DefaultUser = "serverdog"

type Domain struct {
	Name      string   `json:"name"`
	Wildcards bool     `json:"wildcards"`
	Redirect  Redirect `json:"redirect"`
	Primary   bool     `json:"primary"`
	// Reverb forwards the domain to the site's Reverb server instead of serving the site (protocol 19).
	Reverb bool `json:"reverb,omitempty"`
}

type Site struct {
	ID            string   `json:"id"`
	Preset        string   `json:"preset"`
	Runtime       Runtime  `json:"runtime"`
	Domains       []Domain `json:"domains"`
	RepositoryURL string   `json:"repositoryUrl"`
	Branch        string   `json:"branch"`
	PHPVersion    string   `json:"phpVersion"`
	// PHPWorkers is the PHP-FPM pool's pm.max_children; 0 means DefaultPHPWorkers.
	PHPWorkers           int       `json:"phpWorkers,omitempty"`
	WebDirectory         string    `json:"webDirectory"`
	EnvironmentFile      string    `json:"environmentFile"`
	SharedPaths          []string  `json:"sharedPaths"`
	DeployScript         string    `json:"deployScript"`
	ZeroDowntime         bool      `json:"zeroDowntime"`
	EnvironmentInScript  bool      `json:"environmentInScript"`
	ReleasesToKeep       int       `json:"releasesToKeep"`
	DeployTimeoutMinutes int       `json:"deployTimeoutMinutes"`
	NodeStartCommand     string    `json:"nodeStartCommand"`
	Isolated             bool      `json:"isolated"`
	User                 string    `json:"user"`
	ForceHTTPS           bool      `json:"forceHttps"`
	HSTS                 bool      `json:"hsts"`
	NginxCustomised      bool      `json:"nginxCustomised"`
	Revision             uint64    `json:"revision"`
	Directory            string    `json:"directory"`
	CreatedAt            time.Time `json:"createdAt"`
	Processes            []Process `json:"processes,omitempty"`
	Scheduler            bool      `json:"scheduler,omitempty"`
	// DeployNotifications is where this site's deploys and rollbacks are posted, success or failure. With none set
	// they are left to the server's webhook.
	DeployNotifications DeployNotifications `json:"deployNotifications,omitzero"`
	// NginxRules are the site's own root, index and locations, used in place of the generated ones inside each of its
	// server blocks. Everything around them stays generated.
	NginxRules string `json:"nginxRules,omitempty"`
	// DeployOnPush deploys the branch when it gets a new commit; the agent asks the repository every minute.
	DeployOnPush bool `json:"deployOnPush,omitempty"`
	// AppDirectory is where the app's artisan lives, relative to the repository root ("" is the root itself). The
	// Laravel scheduler runs there.
	AppDirectory string `json:"appDirectory,omitempty"`
	// Name names a site without a website, one with no domains such as a worker's: its directory is named after it.
	Name string `json:"name,omitempty"`
	// HealthCheckPath is requested through Nginx after each deploy, like /up; a status of 400 or more fails the deploy
	// (which stays live). Empty skips the check.
	HealthCheckPath string `json:"healthCheckPath,omitempty"`
	// Redirects answer an exact path with a redirect before the site sees the request.
	Redirects []PathRedirect `json:"redirects,omitempty"`
	// Backends, Balancing and BackendTLS describe a load-balanced site (runtime Balancer).
	Backends  []Backend `json:"backends,omitempty"`
	Balancing Balancing `json:"balancing,omitempty"`
	// BackendTLS talks to the backends over HTTPS, for backends that only serve the site that way.
	BackendTLS bool `json:"backendTls,omitempty"`
	// BasicAuth asks every visitor for a username and password; nil leaves the site open.
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// ReverbPort is where the site's Reverb server listens, set by the agent while a domain serves Reverb.
	ReverbPort int `json:"reverbPort,omitempty"`
	// Octane serves a PHP site with its Laravel Octane server instead of PHP-FPM, from the next deploy on; Nginx still
	// serves the release's static files (protocol 19). Like a Node site, each release's server starts on the site's
	// idle port and takes over once it answers.
	Octane bool `json:"octane,omitempty"`
	// OctanePort is the port Nginx sends requests to, set by the deploy that makes Octane live; 0 until then, while
	// PHP-FPM still serves the site.
	OctanePort int `json:"octanePort,omitempty"`
}

// RunsOwnServer reports whether releases are served by a process of the site's own on one of its two ports (a Node
// site, or a PHP site with Octane) rather than by PHP-FPM or as files.
func (s Site) RunsOwnServer() bool {
	return s.Runtime == Node || (s.Runtime == PHP && s.Octane)
}

// ReverbDomain is the domain that serves the site's Reverb server, if any.
// DefaultPHPWorkers and MaxPHPWorkers bound how many requests a site's PHP-FPM pool runs at once.
const (
	DefaultPHPWorkers = 10
	MaxPHPWorkers     = 500
)

// PHPWorkerLimit is the pool's pm.max_children.
func (s Site) PHPWorkerLimit() int {
	if s.PHPWorkers == 0 {
		return DefaultPHPWorkers
	}

	return s.PHPWorkers
}

func (s Site) ReverbDomain() (Domain, bool) {
	for _, domain := range s.Domains {
		if domain.Reverb {
			return domain, true
		}
	}

	return Domain{}, false
}

// PathRedirect sends requests for one path elsewhere.
type PathRedirect struct {
	// From is an absolute path, like /old-page.
	From string `json:"from"`
	// To is a path on the site or an http(s) URL.
	To        string `json:"to"`
	Permanent bool   `json:"permanent"`
}

// BasicAuth is the one login that opens a protected site.
type BasicAuth struct {
	Username string `json:"username"`
	// Hash is the password's bcrypt hash, as Nginx checks it.
	Hash string `json:"hash"`
	// Password is a new password from the app, hashed before the site is saved; empty keeps the stored hash.
	Password string `json:"-"`
}

// Process is a command kept running as the site's user in its live release, such as a queue worker.
type Process struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Command string `json:"command"`
	Count   int    `json:"count"`
	// Directory is where the process runs, relative to the release root ("" is the root itself).
	Directory string `json:"directory,omitempty"`
	// Stopped keeps every copy down, through deploys and reboots, until it is started again (protocol 19).
	Stopped bool `json:"stopped,omitempty"`
	// StopSeconds is how long a copy may take to finish its work once asked to stop; 0 is DefaultStopSeconds.
	StopSeconds int `json:"stop_seconds,omitempty"`
}

// DefaultStopSeconds and MaxStopSeconds bound how long a process may take to stop.
const (
	DefaultStopSeconds = 60
	MaxStopSeconds     = 3600
)

// StopTimeout is how long systemd waits for a stopping copy before it kills it.
func StopTimeout(seconds int) int {
	if seconds <= 0 {
		return DefaultStopSeconds
	}

	return seconds
}

// StopPatience is the longest stop a save waits for: the app gives a save two minutes. A process allowed longer to
// finish its work is stopped first, without waiting, and removed once it has stopped.
const StopPatience = 90

// TooSlowToRemove is the refusal for removing copies that may take longer than StopPatience to stop.
func TooSlowToRemove(name string, seconds int) error {
	minutes := (seconds + 59) / 60

	return &InvalidError{Field: "processes", Reason: fmt.Sprintf("%s may take up to %d minutes to finish what it's doing. Stop it first, then remove it once it shows Stopped.", name, minutes)}
}

// Primary returns the primary domain, or the first one if none is marked.
func (s Site) Primary() Domain {
	for _, domain := range s.Domains {
		if domain.Primary {
			return domain
		}
	}

	if len(s.Domains) > 0 {
		return s.Domains[0]
	}

	return Domain{}
}

// HasWebsite reports whether the site serves a website. One without (no domains) has no Nginx config, PHP-FPM pool
// or placeholder page: it deploys, runs processes and the scheduler only.
func (s Site) HasWebsite() bool {
	return len(s.Domains) > 0
}

// DirectoryName is what the site's directory is named after: its primary domain, or its name without a website.
func (s Site) DirectoryName() string {
	if s.HasWebsite() {
		return s.Primary().Name
	}

	return s.Name
}

// HasRepository reports whether the site has a repository to deploy from. Since protocol 3 a site can be created
// without one and get it later.
func (s Site) HasRepository() bool {
	return s.RepositoryURL != ""
}

// Linked lists what each release links into shared/: the environment file first, then shared paths.
func (s Site) Linked() []string {
	var linked []string
	seen := map[string]bool{}

	for _, p := range append([]string{s.EnvironmentFile}, s.SharedPaths...) {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		linked = append(linked, p)
	}

	return linked
}

// WithDefaults fills unset numbers: 5 releases kept, a 30-minute deploy timeout.
func (s Site) WithDefaults() Site {
	if s.ReleasesToKeep == 0 {
		s.ReleasesToKeep = 5
	}
	if s.DeployTimeoutMinutes == 0 {
		s.DeployTimeoutMinutes = 30
	}

	return s
}

// DeployNotifications are a site's own deploy webhooks; an empty one is off.
type DeployNotifications struct {
	SlackURL   string `json:"slackUrl,omitempty"`
	DiscordURL string `json:"discordUrl,omitempty"`
	// HookURL gets a JSON document describing the deploy instead of a chat message.
	HookURL string `json:"hookUrl,omitempty"`
}

// Any reports whether at least one is set.
func (n DeployNotifications) Any() bool {
	return n.SlackURL != "" || n.DiscordURL != "" || n.HookURL != ""
}
