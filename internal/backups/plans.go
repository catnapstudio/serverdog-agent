// Package backups dumps the server's databases on a schedule and uploads them to S3-compatible storage.
package backups

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/jobs"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

// Storage is an S3-compatible bucket: AWS S3, Cloudflare R2, Backblaze B2, DigitalOcean Spaces, Wasabi or MinIO.
type Storage struct {
	// Endpoint is the service's address, like https://s3.eu-central-1.amazonaws.com. Plain http only for this server.
	Endpoint string `json:"endpoint"`
	Region   string `json:"region"`
	Bucket   string `json:"bucket"`
	// Prefix is the folder in the bucket the plan's backups go in; empty is the bucket's root.
	Prefix    string `json:"prefix"`
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
}

type Plan struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Databases []string `json:"databases"`
	Schedule  string   `json:"schedule"`
	// Keep is how many backups stay in the bucket; older ones are deleted after a successful run.
	Keep    int     `json:"keep"`
	Storage Storage `json:"storage"`
}

const (
	MaxPlans = 20
	MaxKeep  = 365
	document = "backup_plans"
)

var (
	databaseName = regexp.MustCompile(`^[A-Za-z0-9_$-]{1,64}$`)
	bucketName   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	prefixPath   = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
)

// Manager keeps the plans and the cron file that runs them.
type Manager struct {
	Store   *state.Store
	Paths   paths.Paths
	Applier apply.Applier

	mu sync.Mutex
}

// List returns the plans and their revision. Secret keys are included: callers outside the agent must not see them.
func (m *Manager) List() ([]Plan, uint64, error) {
	encoded, revision, err := m.Store.Document(document)
	if err != nil || encoded == nil {
		return nil, revision, err
	}

	var plans []Plan

	return plans, revision, json.Unmarshal(encoded, &plans)
}

// Get returns one plan, with its secret key.
func (m *Manager) Get(id string) (Plan, error) {
	plans, _, err := m.List()
	if err != nil {
		return Plan{}, err
	}

	for _, plan := range plans {
		if plan.ID == id {
			return plan, nil
		}
	}

	return Plan{}, state.ErrNotFound
}

// Put replaces the plans. A plan saved without a secret key keeps the one it had, so the app never needs it back.
func (m *Manager) Put(ctx context.Context, plans []Plan, expectedRevision uint64) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, current, err := m.List()
	if err != nil {
		return 0, err
	}
	if current != expectedRevision {
		return 0, state.ErrStaleDocument
	}

	for i, plan := range plans {
		if plan.Storage.SecretKey != "" {
			continue
		}
		for _, old := range existing {
			if old.ID == plan.ID {
				plans[i].Storage.SecretKey = old.Storage.SecretKey
			}
		}
	}

	if err := validate(plans); err != nil {
		return 0, err
	}

	file := apply.File{Path: m.Paths.File(paths.BackupsCron), Content: RenderCron(plans)}
	if len(plans) == 0 {
		file = apply.File{Path: m.Paths.File(paths.BackupsCron), Remove: true}
	}
	if _, err := m.Applier.Apply(ctx, apply.Plan{Files: []apply.File{file}}); err != nil {
		return 0, err
	}

	encoded, err := json.Marshal(plans)
	if err != nil {
		return 0, err
	}

	return m.Store.PutDocument(document, encoded, expectedRevision)
}

// RenderCron runs each plan as root on its schedule. The run records its own outcome, so cron's output is dropped.
func RenderCron(plans []Plan) []byte {
	var b strings.Builder
	b.WriteString("# Managed by ServerDog: database backups.\n")

	for _, plan := range plans {
		fmt.Fprintf(&b, "%s root %s run-backup %s >/dev/null 2>&1\n", plan.Schedule, paths.AgentBinary, plan.ID)
	}

	return []byte(b.String())
}

func validate(plans []Plan) error {
	if len(plans) > MaxPlans {
		return invalid("A server can have at most %d backup plans.", MaxPlans)
	}

	seen := map[string]bool{}

	for _, plan := range plans {
		if !ids.Valid(plan.ID) || seen[plan.ID] {
			return invalid("The backup plan id %q isn't valid or is listed twice.", plan.ID)
		}
		seen[plan.ID] = true

		if strings.TrimSpace(plan.Name) == "" || strings.ContainsAny(plan.Name, "\r\n") || len(plan.Name) > 60 {
			return invalid("A backup plan needs a single-line name of at most 60 characters.")
		}
		if len(plan.Databases) == 0 || len(plan.Databases) > 50 {
			return invalid("%s needs between 1 and 50 databases.", plan.Name)
		}
		for _, database := range plan.Databases {
			if !databaseName.MatchString(database) {
				return invalid("%q isn't a database name.", database)
			}
		}
		if !jobs.ValidSchedule(plan.Schedule) || plan.Schedule == "@reboot" {
			return invalid("%s's schedule %q isn't a cron schedule, like 0 3 * * * or @daily.", plan.Name, plan.Schedule)
		}
		if plan.Keep < 1 || plan.Keep > MaxKeep {
			return invalid("Keep between 1 and %d backups.", MaxKeep)
		}
		if err := validateStorage(plan.Storage); err != nil {
			return err
		}
	}

	return nil
}

func validateStorage(s Storage) error {
	if _, _, err := endpoint(s.Endpoint); err != nil {
		return err
	}
	if !bucketName.MatchString(s.Bucket) {
		return invalid("%q isn't a bucket name.", s.Bucket)
	}
	if s.Prefix != "" && (!prefixPath.MatchString(s.Prefix) || slices.ContainsFunc(strings.Split(s.Prefix, "/"), func(segment string) bool { return segment == "." || segment == ".." })) {
		return invalid("The folder must be a path in the bucket, like backups/app, without a leading slash.")
	}
	if s.AccessKey == "" || s.SecretKey == "" || strings.ContainsAny(s.AccessKey+s.SecretKey+s.Region, " \r\n") {
		return invalid("Enter the storage's access key and secret key.")
	}

	return nil
}

// endpoint splits the storage address into the host the S3 client takes and whether it uses TLS. A bare host means
// https. Plain http is allowed only for storage on this server, such as a local MinIO, so dumps never cross a network
// unencrypted.
func endpoint(raw string) (string, bool, error) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return "", false, invalid("Enter the storage endpoint as an address, like https://s3.eu-central-1.amazonaws.com.")
	}

	switch u.Scheme {
	case "https":
		return u.Host, true, nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); u.Hostname() == "localhost" || ip != nil && ip.IsLoopback() {
			return u.Host, false, nil
		}
		return "", false, invalid("Use https for the storage endpoint; plain http is only for storage on this server.")
	default:
		return "", false, invalid("Use https for the storage endpoint.")
	}
}

func invalid(format string, args ...any) error {
	return &site.InvalidError{Field: "backups", Reason: fmt.Sprintf(format, args...)}
}
