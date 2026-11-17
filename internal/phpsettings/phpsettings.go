// Package phpsettings keeps the server's PHP limits: upload size, run time, memory, and whether OPcache trusts its
// cache. They apply to every installed version, and Nginx's own upload limit and FastCGI timeout follow them.
package phpsettings

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/nginx"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/phpfpm"
	"github.com/catnapstudio/serverdog-agent/internal/phpversions"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

type Settings struct {
	UploadMB            int `json:"upload_mb"`
	MaxExecutionSeconds int `json:"max_execution_seconds"`
	MemoryMB            int `json:"memory_mb"`
	// OPcacheFrozen stops OPcache checking files for changes; each deploy then reloads PHP-FPM.
	OPcacheFrozen bool `json:"opcache_frozen"`
}

// Defaults match Ubuntu's php.ini and the Nginx limit provisioning writes.
var Defaults = Settings{UploadMB: 64, MaxExecutionSeconds: 30, MemoryMB: 128}

const document = "php_settings"

// NginxConf is provisioning's Nginx file; the agent rewrites it with the upload limit and timeout.
const NginxConf = "/etc/nginx/conf.d/00-serverdog.conf"

type Manager struct {
	Store   *state.Store
	Paths   paths.Paths
	Applier apply.Applier

	mu sync.Mutex
}

// Get returns the settings and their revision, the one Put expects; Defaults with revision 0 before the first save.
func (m *Manager) Get() (Settings, uint64, error) {
	encoded, revision, err := m.Store.Document(document)
	if err != nil || encoded == nil {
		return Defaults, revision, err
	}

	var settings Settings

	return settings, revision, json.Unmarshal(encoded, &settings)
}

// Put saves the settings once every installed version and Nginx took them.
func (m *Manager) Put(ctx context.Context, settings Settings, expectedRevision uint64) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := validate(settings); err != nil {
		return 0, err
	}

	if _, current, err := m.Store.Document(document); err != nil {
		return 0, err
	} else if current != expectedRevision {
		return 0, state.ErrStaleDocument
	}

	plan := m.phpPlan(settings, m.installed())
	if _, err := os.Stat(m.Paths.File(path.Dir(NginxConf))); err == nil {
		plan.Files = append(plan.Files, apply.File{Path: m.Paths.File(NginxConf), Content: RenderNginx(settings)})
		plan.Checks = append(plan.Checks, nginx.Check)
		plan.Reloads = append(plan.Reloads, nginx.Reload)
	}

	if _, err := m.Applier.Apply(ctx, plan); err != nil {
		return 0, err
	}

	encoded, err := json.Marshal(settings)
	if err != nil {
		return 0, err
	}

	return m.Store.PutDocument(document, encoded, expectedRevision)
}

// ApplyVersion writes the saved settings for one version, as installing it does.
func (m *Manager) ApplyVersion(ctx context.Context, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	settings, revision, err := m.Get()
	if err != nil || revision == 0 {
		return err
	}

	_, err = m.Applier.Apply(ctx, m.phpPlan(settings, []string{version}))

	return err
}

// OPcacheFrozen reports whether deploys must reload PHP-FPM for new code to run.
func (m *Manager) OPcacheFrozen() bool {
	settings, _, err := m.Get()

	return err == nil && settings.OPcacheFrozen
}

func (m *Manager) phpPlan(settings Settings, versions []string) apply.Plan {
	var plan apply.Plan

	for _, version := range versions {
		plan.Files = append(plan.Files,
			apply.File{Path: m.Paths.File(FPMIni(version)), Content: RenderFPM(settings)},
			apply.File{Path: m.Paths.File(CLIIni(version)), Content: RenderCLI(settings)})
		plan.Checks = append(plan.Checks, phpfpm.Check(version))
		plan.Reloads = append(plan.Reloads, phpfpm.Reload(version))
	}

	return plan
}

func (m *Manager) installed() []string {
	var versions []string
	for _, version := range phpversions.Candidates {
		if phpfpm.Installed(m.Paths, version) {
			versions = append(versions, version)
		}
	}

	return versions
}

func FPMIni(version string) string { return "/etc/php/" + version + "/fpm/conf.d/99-serverdog.ini" }
func CLIIni(version string) string { return "/etc/php/" + version + "/cli/conf.d/99-serverdog.ini" }

// RenderFPM is the web requests' limits. A form posts the file and its other fields, so post_max_size matches.
func RenderFPM(s Settings) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "; Managed by ServerDog: the server's PHP settings.\nupload_max_filesize = %[1]dM\npost_max_size = %[1]dM\nmax_execution_time = %[2]d\nmemory_limit = %[3]dM\n", s.UploadMB, s.MaxExecutionSeconds, s.MemoryMB)
	if s.OPcacheFrozen {
		b.WriteString("opcache.validate_timestamps = 0\n")
	}

	return []byte(b.String())
}

// RenderCLI raises memory for queue workers and commands. Their run time stays unlimited, as PHP's CLI default.
func RenderCLI(s Settings) []byte {
	return []byte(fmt.Sprintf("; Managed by ServerDog: the server's PHP settings.\nmemory_limit = %dM\n", s.MemoryMB))
}

// RenderNginx lets Nginx accept uploads PHP accepts, and wait for PHP as long as it may run (60 seconds at least,
// Nginx's default).
func RenderNginx(s Settings) []byte {
	return []byte(fmt.Sprintf("# Managed by ServerDog.\nserver_tokens off;\nclient_max_body_size %dm;\nfastcgi_read_timeout %ds;\n", s.UploadMB, max(60, s.MaxExecutionSeconds+5)))
}

func validate(s Settings) error {
	switch {
	case s.UploadMB < 1 || s.UploadMB > 4096:
		return invalid("The upload limit must be 1 to 4096 MB.")
	case s.MaxExecutionSeconds < 1 || s.MaxExecutionSeconds > 3600:
		return invalid("The run time limit must be 1 to 3600 seconds.")
	case s.MemoryMB < 32 || s.MemoryMB > 16384:
		return invalid("The memory limit must be 32 to 16384 MB.")
	}

	return nil
}

func invalid(format string, args ...any) error {
	return &site.InvalidError{Field: "php_settings", Reason: fmt.Sprintf(format, args...)}
}
