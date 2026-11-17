// Package notify posts deploy and backup outcomes to a chat webhook (Slack, Discord, or anything that takes the same
// JSON), so a failure on a deploy nobody watched still reaches someone.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

// Settings is the server's webhook. An empty URL sends nothing.
type Settings struct {
	WebhookURL string `json:"webhook_url"`
	// OnSuccess also posts successful deploys; failures are always posted.
	OnSuccess bool `json:"on_success"`
	// Monitor thresholds in percent; 0 is off. Load is the 5-minute load average per CPU.
	DiskPercent   uint32 `json:"disk_percent,omitempty"`
	MemoryPercent uint32 `json:"memory_percent,omitempty"`
	LoadPercent   uint32 `json:"load_percent,omitempty"`
}

// document is where the store keeps the settings.
const document = "notifications"

// Manager reads, saves and sends.
type Manager struct {
	Store  *state.Store
	Client *http.Client
}

// Get returns the settings and their revision, the one Put expects.
func (m *Manager) Get() (Settings, uint64, error) {
	var settings Settings

	encoded, revision, err := m.Store.Document(document)
	if err != nil || encoded == nil {
		return settings, revision, err
	}

	return settings, revision, json.Unmarshal(encoded, &settings)
}

// Put validates and saves the settings.
func (m *Manager) Put(settings Settings, expectedRevision uint64) (uint64, error) {
	settings.WebhookURL = strings.TrimSpace(settings.WebhookURL)

	if err := Validate(settings.WebhookURL); err != nil {
		return 0, err
	}

	if settings.DiskPercent > 100 || settings.MemoryPercent > 100 || settings.LoadPercent > 1000 {
		return 0, invalid("Alert at most at 100%% disk or memory, and 1000%% load.")
	}

	encoded, err := json.Marshal(settings)
	if err != nil {
		return 0, err
	}

	return m.Store.PutDocument(document, encoded, expectedRevision)
}

// Validate accepts an empty URL (notifications off), https, or http on this server.
func Validate(raw string) error {
	if reason := site.WebhookProblem(raw); reason != "" {
		return invalid("%s", reason)
	}

	return nil
}

// Deploy posts a deploy's outcome: every one to each of the site's own webhooks when it has any, otherwise to the
// server's when its settings ask for it. Errors are returned for the log; they never fail the deploy.
func (m *Manager) Deploy(ctx context.Context, s site.Site, d state.Deployment) error {
	text := DeployText(Hostname(), s.DirectoryName(), d)

	if own := s.DeployNotifications; own.Any() {
		var errs []error

		// Slack's bold is one asterisk, Discord's two.
		if own.SlackURL != "" {
			errs = append(errs, m.send(ctx, own.SlackURL, map[string]string{"text": DeployDetails("*", Hostname(), s, d)}))
		}

		if own.DiscordURL != "" {
			errs = append(errs, m.send(ctx, own.DiscordURL, map[string]string{"content": DeployDetails("**", Hostname(), s, d)}))
		}

		if own.HookURL != "" {
			errs = append(errs, m.send(ctx, own.HookURL, HookPayload(Hostname(), s.DirectoryName(), d, text)))
		}

		return errors.Join(errs...)
	}

	settings, _, err := m.Get()
	if err != nil || settings.WebhookURL == "" {
		return err
	}

	succeeded := d.State == state.Succeeded
	if succeeded && !settings.OnSuccess {
		return nil
	}

	return m.post(ctx, settings.WebhookURL, text)
}

// DeployDetails is the message for a site's own Slack or Discord webhook: a headline, then one labelled line for each
// thing known about the deploy. bold is the chat's marker for bold text.
func DeployDetails(bold, host string, s site.Site, d state.Deployment) string {
	what := "Deploy"
	if d.Kind == state.KindRollback {
		what = "Rollback"
	}

	headline := "❌ " + what + " failed"
	if d.State == state.Succeeded {
		headline = "✅ " + what + " succeeded"
	}

	by := d.Actor
	if by == "push" {
		by = "Deploy on push"
	}

	commit := CommitLink(s.RepositoryURL, d.Commit)
	if commit == "" && len(d.Commit) >= 7 {
		commit = d.Commit[:7]
	}

	lines := []string{headline, ""}
	for _, field := range [][2]string{
		{"Server", host}, {"Site", s.DirectoryName()}, {"By", by}, {"Commit", commit},
		{"Message", plain(firstLine(d.CommitMessage))}, {"Error", plain(d.Error)},
	} {
		if field[1] != "" {
			lines = append(lines, bold+field[0]+":"+bold+" "+field[1])
		}
	}

	return strings.Join(lines, "\n")
}

// CommitLink is the commit's page on GitHub, GitLab or Bitbucket, or "" for another host or no commit.
func CommitLink(repository, commit string) string {
	if commit == "" {
		return ""
	}

	// git@host:owner/repo.git, ssh://git@host/owner/repo.git or https://host/owner/repo.git.
	rest := strings.TrimSuffix(repository, ".git")
	for _, prefix := range []string{"ssh://", "https://"} {
		rest = strings.TrimPrefix(rest, prefix)
	}
	rest = strings.TrimPrefix(rest, "git@")

	host, path, found := strings.Cut(strings.Replace(rest, ":", "/", 1), "/")
	if !found || path == "" || strings.ContainsAny(path, " \n") {
		return ""
	}

	switch host {
	case "github.com", "gitlab.com":
		return "https://" + host + "/" + path + "/commit/" + commit
	case "bitbucket.org":
		return "https://" + host + "/" + path + "/commits/" + commit
	default:
		return ""
	}
}

// HookPayload is what a site's custom hook receives.
func HookPayload(host, siteName string, d state.Deployment, text string) map[string]string {
	kind := "deploy"
	if d.Kind == state.KindRollback {
		kind = "rollback"
	}

	status := "failed"
	if d.State == state.Succeeded {
		status = "succeeded"
	}

	return map[string]string{
		"status": status, "kind": kind, "site": siteName, "server": host,
		"commit": d.Commit, "commit_message": firstLine(d.CommitMessage), "error": d.Error, "message": text,
	}
}

// BackupFailed posts a failed backup.
func (m *Manager) BackupFailed(ctx context.Context, planName, message string) error {
	settings, _, err := m.Get()
	if err != nil || settings.WebhookURL == "" {
		return err
	}

	return m.post(ctx, settings.WebhookURL, fmt.Sprintf("❌ Backup %q failed on %s: %s", planName, Hostname(), message))
}

// Alert posts a monitor's message.
func (m *Manager) Alert(ctx context.Context, text string) error {
	settings, _, err := m.Get()
	if err != nil || settings.WebhookURL == "" {
		return err
	}

	return m.post(ctx, settings.WebhookURL, text)
}

// Test posts a test message to url, which needn't be saved yet.
func (m *Manager) Test(ctx context.Context, url string) error {
	if err := Validate(url); err != nil {
		return err
	}

	if url == "" {
		return invalid("Enter the webhook first.")
	}

	return m.post(ctx, url, fmt.Sprintf("👋 ServerDog on %s will post deploys, backups, alerts and expiring certificates here.", Hostname()))
}

// DeployText is the message for d.
func DeployText(host, siteName string, d state.Deployment) string {
	verb := "Deploy"
	if d.Kind == state.KindRollback {
		verb = "Rollback"
	}

	commit := ""
	if len(d.Commit) >= 7 {
		commit = fmt.Sprintf(" (%s %s)", d.Commit[:7], plain(firstLine(d.CommitMessage)))
	}

	switch d.State {
	case state.Succeeded:
		return fmt.Sprintf("✅ %s of %s on %s succeeded%s.", verb, siteName, host, commit)
	case state.Cancelled:
		return fmt.Sprintf("⏹ %s of %s on %s was cancelled%s.", verb, siteName, host, commit)
	default:
		return fmt.Sprintf("❌ %s of %s on %s failed%s: %s", verb, siteName, host, commit, plain(d.Error))
	}
}

func (m *Manager) post(ctx context.Context, url, text string) error {
	// Slack reads text, Discord reads content; each ignores the other.
	return m.send(ctx, url, map[string]string{"text": text, "content": text})
}

func (m *Manager) send(ctx context.Context, url string, payload map[string]string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")

	client := m.Client
	if client == nil {
		client = http.DefaultClient
	}

	response, err := client.Do(request)
	if err != nil {
		// The client's error names the address, and the address is the webhook's secret; this ends up in the journal.
		var failed *neturl.Error
		if errors.As(err, &failed) {
			err = failed.Err
		}

		return fmt.Errorf("The webhook didn't answer: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode >= 300 {
		return invalid("The webhook answered %s.", response.Status)
	}

	return nil
}

// plain keeps a commit subject or an error from acting as chat markup: no mention of everyone, no link with other
// text on it. Whoever can push a commit shouldn't thereby write to the team's channel in ServerDog's name.
func plain(s string) string {
	return strings.NewReplacer("@", "@\u200b", "<", "‹", ">", "›", "](", "] (").Replace(s)
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	if runes := []rune(line); len(runes) > 72 {
		return string(runes[:72]) + "…"
	}
	return line
}

// Hostname names the server in messages.
func Hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "the server"
	}
	return name
}

func invalid(format string, args ...any) error {
	return &site.InvalidError{Field: "notifications", Reason: fmt.Sprintf(format, args...)}
}
