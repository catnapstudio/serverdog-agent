package site

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/deployscript"
	"github.com/catnapstudio/serverdog-agent/internal/gitsource"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
)

// Host is what Validate needs to know about the server.
type Host struct {
	PHPVersions []string
	HasNginx    bool
	HasNode     bool
	HasUV       bool
}

// InvalidError is a site description the agent refuses before touching anything.
type InvalidError struct {
	Field  string
	Reason string
}

func (e *InvalidError) Error() string { return e.Reason }

func invalid(field, format string, args ...any) error {
	return &InvalidError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

var (
	label      = `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`
	domainName = regexp.MustCompile(`^(?:` + label + `\.)+` + label + `$`)
	// siteName has no dot, so a site without a website never takes a website's directory name.
	siteName = regexp.MustCompile(`^` + label + `$`)
	// healthCheckPath is an absolute URL path, with an optional query, and nothing Nginx or a shell could misread.
	healthCheckPath = regexp.MustCompile(`^/[A-Za-z0-9._~/?=&%-]{0,200}$`)
	pathSegment     = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	// redirectFrom and redirectTo leave out what Nginx or a shell could misread: spaces, quotes, ; { } and $.
	redirectFrom = regexp.MustCompile(`^/[A-Za-z0-9._~/%@!*+,=:-]{0,300}$`)
	redirectTo   = regexp.MustCompile(`^(?:https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?)?/[A-Za-z0-9._~/?#&%@!*+,=:-]{0,500}$|^https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?$`)
	authUser     = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
	branchName   = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	userPattern  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	reservedUser = []string{"root", "daemon", "bin", "sys", "nobody", "www-data", "mysql", "postgres", "redis", "memcache", "meilisearch", "openclaw", "git", "ubuntu", "syslog"}
)

// Validate checks a site description against itself and the server.
func Validate(s Site, host Host) error {
	if !ids.Valid(s.ID) {
		return invalid("id", "The site id %q isn't valid.", s.ID)
	}
	if err := validateWebsite(s, host); err != nil {
		return err
	}

	switch s.Runtime {
	case PHP:
		if !slices.Contains(host.PHPVersions, s.PHPVersion) {
			return invalid("phpVersion", "PHP %s isn't installed on this server.", s.PHPVersion)
		}
		if s.PHPWorkers < 0 || s.PHPWorkers > MaxPHPWorkers {
			return invalid("phpWorkers", "PHP workers must be between 1 and %d.", MaxPHPWorkers)
		}
	case Node, Python:
		if s.Runtime == Node && !host.HasNode {
			return invalid("runtime", "Node.js isn't installed on this server.")
		}
		if s.Runtime == Python && !host.HasUV {
			return invalid("runtime", "uv isn't installed on this server. Install it for Python sites.")
		}
		name := map[Runtime]string{Node: "Node", Python: "Python"}[s.Runtime]
		if strings.TrimSpace(s.NodeStartCommand) == "" {
			return invalid("nodeStartCommand", "%s sites need a start command.", name)
		}
		if strings.ContainsAny(s.NodeStartCommand, "\r\n") || len(s.NodeStartCommand) > 500 {
			return invalid("nodeStartCommand", "The start command must be a single line of at most 500 characters.")
		}
		if !s.ZeroDowntime {
			return invalid("zeroDowntime", "%s sites always use zero-downtime deploys.", name)
		}
	case Static:
	case Balancer:
		if err := validateBalancer(s); err != nil {
			return err
		}
	default:
		return invalid("runtime", "Unknown runtime %q.", s.Runtime)
	}
	if s.Runtime != Balancer && (len(s.Backends) > 0 || s.Balancing != "" || s.BackendTLS) {
		return invalid("backends", "Only a load-balanced site has backends.")
	}
	if s.Runtime != PHP && s.PHPVersion != "" {
		return invalid("phpVersion", "Only PHP sites have a PHP version.")
	}
	if s.Runtime != PHP && s.PHPWorkers != 0 {
		return invalid("phpWorkers", "Only PHP sites have PHP workers.")
	}
	if s.Octane {
		switch {
		case s.Runtime != PHP:
			return invalid("octane", "Only a PHP site can run Laravel Octane.")
		case !s.HasWebsite():
			return invalid("octane", "Octane serves a website; this site has none.")
		case !s.ZeroDowntime:
			return invalid("octane", "Octane needs zero-downtime deploys: each release's server starts before the previous one stops.")
		}
	}

	if s.WebDirectory != "" && !relativePath(s.WebDirectory) {
		return invalid("webDirectory", "The web directory must be a path inside the repository, like public.")
	}
	if s.HealthCheckPath != "" && (!healthCheckPath.MatchString(s.HealthCheckPath) || !s.HasWebsite()) {
		return invalid("healthCheckPath", "The health check must be a path on the site, like /up.")
	}
	if err := validateRedirects(s); err != nil {
		return err
	}
	if err := checkProtection(s); err != nil {
		return err
	}
	if s.AppDirectory != "" && !relativePath(s.AppDirectory) {
		return invalid("appDirectory", "The app directory must be a path inside the repository, like app.")
	}
	if s.EnvironmentFile != "" && !pathSegment.MatchString(s.EnvironmentFile) || s.EnvironmentFile == "." || s.EnvironmentFile == ".." {
		return invalid("environmentFile", "The environment file must be a file name in the repository root, like .env.")
	}
	for _, p := range s.SharedPaths {
		if !relativePath(p) {
			return invalid("sharedPaths", "Shared path %q must be a path inside the repository.", p)
		}
	}

	if a, b, ok := overlappingPaths(s.Linked()); ok {
		if strings.HasPrefix(b, a+"/") {
			return invalid("sharedPaths", "Shared paths %s and %s overlap; keep only %s.", a, b, a)
		}
		return invalid("sharedPaths", "Shared paths %s and %s overlap.", a, b)
	}

	if err := validateRepository(s); err != nil {
		return err
	}

	if s.ZeroDowntime {
		if _, err := deployscript.Split(s.DeployScript); err != nil {
			return invalid("deployScript", "%s", err)
		}
	}

	if s.ReleasesToKeep < 2 || s.ReleasesToKeep > 50 {
		return invalid("releasesToKeep", "Keep between 2 and 50 releases.")
	}
	if s.DeployTimeoutMinutes < 1 || s.DeployTimeoutMinutes > 120 {
		return invalid("deployTimeoutMinutes", "The deploy timeout must be between 1 and 120 minutes.")
	}

	if err := validateProcesses(s.Processes); err != nil {
		return err
	}
	if s.Scheduler && s.Runtime != PHP {
		return invalid("scheduler", "Only PHP sites can run the Laravel scheduler.")
	}
	if s.DeployOnPush && !s.HasRepository() {
		return invalid("deployOnPush", "Add a repository before turning on deploy on push.")
	}
	if len(s.NginxRules) > MaxNginxRules || strings.ContainsRune(s.NginxRules, 0) {
		return invalid("nginxRules", "The Nginx rules must be text of at most %d KB.", MaxNginxRules/1024)
	}
	if s.NginxRules != "" && s.Octane {
		return invalid("nginxRules", "Octane changes where Nginx sends requests with each deploy, which your own Nginx rules would stop. Reset the rules to the default, or turn Octane off.")
	}
	for field, raw := range map[string]string{"slackUrl": s.DeployNotifications.SlackURL, "discordUrl": s.DeployNotifications.DiscordURL, "hookUrl": s.DeployNotifications.HookURL} {
		if reason := WebhookProblem(raw); reason != "" {
			return invalid("deployNotifications."+field, "%s", reason)
		}
	}

	if s.Isolated {
		if !userPattern.MatchString(s.User) || s.User == DefaultUser || slices.Contains(reservedUser, s.User) {
			return invalid("user", "%q can't be used as an isolated site user.", s.User)
		}
	} else if s.User != DefaultUser {
		return invalid("user", "Sites that aren't isolated run as %s.", DefaultUser)
	}

	return nil
}

// ValidateChange rejects changes to choices made when the site was created.
func ValidateChange(old, updated Site) error {
	switch {
	case old.ID != updated.ID:
		return invalid("id", "A site's id can't change.")
	case old.Runtime != updated.Runtime:
		return invalid("runtime", "A site's runtime can't change. Create a new site instead.")
	case old.Isolated != updated.Isolated || old.User != updated.User:
		return invalid("isolated", "Isolation is chosen when a site is created and can't change.")
	case old.HasWebsite() != updated.HasWebsite() || old.Name != updated.Name:
		return invalid("domains", "Whether a site has a website is chosen when it is created and can't change.")
	case old.ZeroDowntime != updated.ZeroDowntime:
		return invalid("zeroDowntime", "Zero-downtime deploys are chosen when a site is created and can't change.")
	}

	return nil
}

// MaxProcesses and MaxProcessCount bound what one site can keep running.
const (
	MaxProcesses    = 20
	MaxProcessCount = 16
)

func validateProcesses(processes []Process) error {
	if len(processes) > MaxProcesses {
		return invalid("processes", "A site can have at most %d processes.", MaxProcesses)
	}

	seen := map[string]bool{}

	for _, p := range processes {
		if !ids.Valid(p.ID) || seen[p.ID] {
			return invalid("processes", "The process id %q isn't valid or is listed twice.", p.ID)
		}
		seen[p.ID] = true

		if strings.TrimSpace(p.Name) == "" || strings.ContainsAny(p.Name, "\r\n") || len(p.Name) > 60 {
			return invalid("processes", "A process needs a single-line name of at most 60 characters.")
		}
		if strings.TrimSpace(p.Command) == "" || strings.ContainsAny(p.Command, "\r\n") || len(p.Command) > 500 {
			return invalid("processes", "%s needs a command on a single line of at most 500 characters.", p.Name)
		}
		if p.Directory != "" && !relativePath(p.Directory) {
			return invalid("processes", "%s must run in a directory inside the repository, like app.", p.Name)
		}
		if p.Count < 1 || p.Count > MaxProcessCount {
			return invalid("processes", "%s can run between 1 and %d copies.", p.Name, MaxProcessCount)
		}
		if p.StopSeconds < 0 || p.StopSeconds > MaxStopSeconds {
			return invalid("processes", "%s can take between 1 and %d seconds to stop.", p.Name, MaxStopSeconds)
		}
	}

	return nil
}

// MaxBackends bounds a load-balanced site's list.
const MaxBackends = 50

var backendHost = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

func validateBalancer(s Site) error {
	if !s.HasWebsite() {
		return invalid("domains", "A load-balanced site needs a domain.")
	}
	if s.HasRepository() || len(s.Processes) > 0 || s.Scheduler || s.HealthCheckPath != "" {
		return invalid("runtime", "A load-balanced site only forwards requests: it has no repository, processes or scheduler.")
	}
	if !slices.Contains([]Balancing{RoundRobin, LeastConnections, IPHash}, s.Balancing) {
		return invalid("balancing", "Pick round robin, least connections or IP hash.")
	}
	if len(s.Backends) == 0 || len(s.Backends) > MaxBackends {
		return invalid("backends", "Add between 1 and %d backend servers.", MaxBackends)
	}

	seen := map[string]bool{}
	active := 0
	for _, b := range s.Backends {
		if net.ParseIP(b.Address) == nil && !backendHost.MatchString(b.Address) {
			return invalid("backends", "%q isn't an IP address or a hostname.", b.Address)
		}
		if b.Port < 1 || b.Port > 65535 {
			return invalid("backends", "%s needs a port between 1 and 65535.", b.Address)
		}
		if b.Weight < 1 || b.Weight > 100 {
			return invalid("backends", "%s needs a weight between 1 and 100.", b.Address)
		}
		if b.Backup && s.Balancing == IPHash {
			return invalid("backends", "IP hash can't have backup servers; Nginx keeps each visitor on one server.")
		}

		key := net.JoinHostPort(b.Address, strconv.Itoa(b.Port))
		if seen[key] {
			return invalid("backends", "%s is listed twice.", key)
		}
		seen[key] = true

		if !b.Backup {
			active++
		}
	}
	if active == 0 {
		return invalid("backends", "At least one backend must take requests without being a backup.")
	}

	return nil
}

// validateWebsite checks the domains of a site with a website, and the name of one without.
func validateWebsite(s Site, host Host) error {
	if s.HasWebsite() {
		if !host.HasNginx {
			return invalid("runtime", "This server has no Nginx, so it can't host websites.")
		}
		if s.Name != "" {
			return invalid("name", "Only a site without a website has a name; its domains name this one.")
		}

		if err := validateDomains(s.Domains); err != nil {
			return err
		}

		return validateReverb(s)
	}

	if !siteName.MatchString(s.Name) {
		return invalid("name", "A site without a website needs a name of lowercase letters, digits and hyphens, like worker.")
	}
	if s.RunsStartCommand() {
		return invalid("runtime", "A site without a website can't be a Node or Python site. Choose PHP or none, and run the app as a process.")
	}

	return nil
}

func validateDomains(domains []Domain) error {
	if len(domains) == 0 {
		return invalid("domains", "A site needs at least one domain.")
	}

	primaries := 0
	seen := map[string]bool{}

	for _, domain := range domains {
		name := domain.Name
		if len(name) > 253 || !domainName.MatchString(name) {
			return invalid("domains", "%q isn't a valid domain. Use lowercase letters, digits and hyphens, like example.com.", name)
		}
		if strings.HasPrefix(name, "www.") {
			return invalid("domains", "Add %s without www, and choose a www option instead.", strings.TrimPrefix(name, "www."))
		}
		if seen[name] {
			return invalid("domains", "%s is listed twice.", name)
		}
		seen[name] = true

		switch domain.Redirect {
		case FromWWW, ToWWW, NoRedirect:
		default:
			return invalid("domains", "Unknown www option %q for %s.", domain.Redirect, name)
		}

		if domain.Primary {
			primaries++
		}
	}

	if primaries != 1 {
		return invalid("domains", "Exactly one domain must be primary.")
	}

	return nil
}

// validateReverb allows one Reverb domain on a PHP site. It only forwards to Reverb, so it is never the primary
// domain and has no www or wildcard names.
func validateReverb(s Site) error {
	count := 0

	for _, domain := range s.Domains {
		if !domain.Reverb {
			continue
		}
		count++

		if s.Runtime != PHP {
			return invalid("domains", "Only a PHP site can serve Reverb on its own domain.")
		}
		if domain.Primary {
			return invalid("domains", "%s serves Reverb, so it can't be the primary domain.", domain.Name)
		}
		if domain.Wildcards || domain.Redirect != NoRedirect {
			return invalid("domains", "%s serves Reverb, so it can't have www or wildcard names.", domain.Name)
		}
	}

	if count > 1 {
		return invalid("domains", "A site can serve Reverb on one domain only.")
	}

	return nil
}

// validateRepository accepts a site without a repository (URL and branch both empty) or with a complete, valid one.
func validateRepository(s Site) error {
	const halfSet = "A site needs both a repository URL and a branch, or neither."

	switch {
	case s.RepositoryURL == "" && s.Branch == "":
		return nil
	case s.RepositoryURL == "":
		return invalid("repositoryUrl", halfSet)
	case s.Branch == "":
		return invalid("branch", halfSet)
	}

	if _, err := gitsource.ParseURL(s.RepositoryURL); err != nil {
		return invalid("repositoryUrl", "%s", err)
	}
	if !validBranch(s.Branch) {
		return invalid("branch", "%q isn't a valid branch name.", s.Branch)
	}

	return nil
}

func relativePath(p string) bool {
	for segment := range strings.SplitSeq(p, "/") {
		if segment == "." || segment == ".." || !pathSegment.MatchString(segment) {
			return false
		}
	}

	return true
}

// overlappingPaths finds two paths that are equal or where one contains the other, segment-wise.
func overlappingPaths(linked []string) (outer, inner string, found bool) {
	for i, a := range linked {
		for _, b := range linked[i+1:] {
			if a == b || strings.HasPrefix(b, a+"/") {
				return a, b, true
			}
			if strings.HasPrefix(a, b+"/") {
				return b, a, true
			}
		}
	}

	return "", "", false
}

func validBranch(branch string) bool {
	return branchName.MatchString(branch) &&
		!strings.HasPrefix(branch, "-") &&
		!strings.HasPrefix(branch, "/") &&
		!strings.HasSuffix(branch, "/") &&
		!strings.HasSuffix(branch, ".lock") &&
		!strings.Contains(branch, "..") &&
		!strings.Contains(branch, "//")
}

// MaxRedirects keeps a site's Nginx config small enough to read.
const MaxRedirects = 100

func validateRedirects(s Site) error {
	if len(s.Redirects) > 0 && !s.HasWebsite() {
		return invalid("redirects", "Only a site with a domain can redirect.")
	}
	if len(s.Redirects) > MaxRedirects {
		return invalid("redirects", "A site can have at most %d redirects.", MaxRedirects)
	}

	seen := map[string]bool{}
	for _, r := range s.Redirects {
		if !redirectFrom.MatchString(r.From) || strings.Contains(r.From, "//") {
			return invalid("redirects", "Redirect %q must be a path on the site, like /old-page.", r.From)
		}
		if !redirectTo.MatchString(r.To) {
			return invalid("redirects", "The redirect from %s must go to a path, like /new-page, or an http(s) URL.", r.From)
		}
		if r.To == r.From {
			return invalid("redirects", "The redirect from %s goes to itself.", r.From)
		}
		if seen[r.From] {
			return invalid("redirects", "There are two redirects from %s.", r.From)
		}
		seen[r.From] = true
	}

	return nil
}

func checkProtection(s Site) error {
	switch {
	case s.BasicAuth == nil:
		return nil
	case !s.HasWebsite() || !authUser.MatchString(s.BasicAuth.Username):
		return invalid("basicAuth", "The username may use letters, digits and . _ @ -, up to 64 characters.")
	case len(s.BasicAuth.Password) > 72:
		return invalid("basicAuth", "The password can be at most 72 characters.")
	}

	return nil
}

// MaxNginxRules bounds a site's own Nginx rules.
const MaxNginxRules = 64 * 1024

const maxWebhookURL = 2000

// WebhookProblem says why raw can't be a webhook, or "" for an empty URL (off), https, or http on this server.
func WebhookProblem(raw string) string {
	if raw == "" {
		return ""
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || len(raw) > maxWebhookURL || u.User != nil {
		return "Enter the webhook as an address, like https://hooks.slack.com/services/…."
	}

	if u.Scheme == "https" {
		return ""
	}

	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()) {
		return ""
	}

	return "Use https for the webhook."
}
