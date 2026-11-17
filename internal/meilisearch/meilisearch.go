// Package meilisearch edits Meilisearch's settings in /etc/meilisearch.env and reads its API keys.
package meilisearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

const envFile = "/etc/meilisearch.env"

// managed are kept out of the editor: ServerDog generated the master key, and private networking moves the address.
var managed = []string{"MEILI_MASTER_KEY", "MEILI_HTTP_ADDR"}

var setting = regexp.MustCompile(`^MEILI_[A-Z0-9_]+=`)

type Manager struct {
	Paths  paths.Paths
	Runner system.Runner
	// HTTP calls Meilisearch itself; nil uses a client with a short timeout.
	HTTP *http.Client
	// StartWait is how long a restart may take to answer /health; zero means 20 seconds.
	StartWait time.Duration

	mu sync.Mutex
}

// Key is one of Meilisearch's API keys.
type Key struct {
	Name, Description, Key, ExpiresAt string
	Actions, Indexes                  []string
}

// Installed tells whether ServerDog installed Meilisearch on this server.
func (m *Manager) Installed() bool {
	_, err := os.Stat(m.Paths.File(envFile))
	return err == nil
}

// Config is the settings file without the lines ServerDog manages.
func (m *Manager) Config() (string, error) {
	content, err := m.read()
	if err != nil {
		return "", err
	}

	var shown []string
	for _, line := range lines(content) {
		if managedKey(line) == "" {
			shown = append(shown, line)
		}
	}

	return strings.Join(shown, "\n") + "\n", nil
}

// PutConfig saves the settings, keeping the managed lines, and restarts Meilisearch. If it doesn't answer again,
// the previous file is restored and it restarts with that.
func (m *Manager) PutConfig(ctx context.Context, config string) error {
	edited := lines(config)
	for i, line := range edited {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if key := managedKey(trimmed); key != "" {
			return &site.InvalidError{Field: "config", Reason: fmt.Sprintf("Line %d sets %s, which ServerDog manages. Remove it.", i+1, key)}
		}
		if !setting.MatchString(trimmed) || strings.ContainsAny(trimmed, "\x00\r") {
			return &site.InvalidError{Field: "config", Reason: fmt.Sprintf("Line %d isn't a setting like MEILI_MAX_INDEXING_MEMORY=2 GiB.", i+1)}
		}
		edited[i] = trimmed
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	previous, err := m.read()
	if err != nil {
		return err
	}

	kept := edited
	for _, line := range lines(previous) {
		if managedKey(line) != "" {
			kept = append(kept, line)
		}
	}
	content := strings.Join(kept, "\n") + "\n"

	if err := m.write(content); err != nil {
		return err
	}

	if err := m.restart(ctx, content); err != nil {
		restore := context.WithoutCancel(ctx)
		_ = m.write(previous)
		_ = m.restart(restore, previous)

		return fmt.Errorf("Meilisearch didn't start with the new settings, so the previous ones are back: %w", err)
	}

	return nil
}

// Keys are the API keys Meilisearch has, read with the master key.
func (m *Manager) Keys(ctx context.Context) ([]Key, error) {
	content, err := m.read()
	if err != nil {
		return nil, err
	}

	master := value(content, "MEILI_MASTER_KEY")
	if master == "" {
		return nil, &site.InvalidError{Field: "master_key", Reason: "Meilisearch has no master key, so it has no API keys."}
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL(content)+"/keys?limit=100", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+master)

	response, err := m.client().Do(request)
	if err != nil {
		return nil, fmt.Errorf("Couldn't reach Meilisearch: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Meilisearch refused to list its keys (HTTP %d).", response.StatusCode)
	}

	var body struct {
		Results []struct {
			Name        *string  `json:"name"`
			Description *string  `json:"description"`
			Key         string   `json:"key"`
			Actions     []string `json:"actions"`
			Indexes     []string `json:"indexes"`
			ExpiresAt   *string  `json:"expiresAt"`
		} `json:"results"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("Meilisearch's key list didn't parse: %w", err)
	}

	keys := make([]Key, 0, len(body.Results))
	for _, r := range body.Results {
		keys = append(keys, Key{Name: deref(r.Name), Description: deref(r.Description), Key: r.Key, Actions: r.Actions, Indexes: r.Indexes, ExpiresAt: deref(r.ExpiresAt)})
	}

	return keys, nil
}

func (m *Manager) read() (string, error) {
	content, err := os.ReadFile(m.Paths.File(envFile))
	if errors.Is(err, os.ErrNotExist) {
		return "", &site.InvalidError{Field: "meilisearch", Reason: "This server has no Meilisearch."}
	}

	return string(content), err
}

// write keeps the file readable by root only, as provisioning left it: it holds the master key.
func (m *Manager) write(content string) error {
	return os.WriteFile(m.Paths.File(envFile), []byte(content), 0o600)
}

func (m *Manager) restart(ctx context.Context, content string) error {
	if _, err := m.Runner.Run(ctx, system.Command{Name: "systemctl", Args: []string{"restart", "meilisearch"}}); err != nil {
		return err
	}

	wait := m.StartWait
	if wait == 0 {
		wait = 20 * time.Second
	}
	deadline := time.Now().Add(wait)
	url := baseURL(content) + "/health"

	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		if response, err := m.client().Do(request); err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return errors.New("it didn't answer on " + url)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (m *Manager) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}

	return &http.Client{Timeout: 5 * time.Second}
}

func lines(content string) []string {
	return strings.Split(strings.TrimRight(content, "\n"), "\n")
}

func managedKey(line string) string {
	for _, key := range managed {
		if strings.HasPrefix(strings.TrimSpace(line), key+"=") {
			return key
		}
	}

	return ""
}

func value(content, key string) string {
	for _, line := range lines(content) {
		if v, found := strings.CutPrefix(strings.TrimSpace(line), key+"="); found {
			return strings.Trim(v, `"'`)
		}
	}

	return ""
}

func baseURL(content string) string {
	address := value(content, "MEILI_HTTP_ADDR")
	if address == "" {
		address = "127.0.0.1:7700"
	}

	return "http://" + address
}

func deref(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}
