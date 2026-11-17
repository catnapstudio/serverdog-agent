// Package agentconfig reads /etc/serverdog/agent.json: settings the app doesn't show, used by tests and staging.
package agentconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// LetsEncrypt is Let's Encrypt's production ACME directory.
const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

type Config struct {
	// ACMEDirectory is the ACME server certificates come from.
	ACMEDirectory string `json:"acmeDirectory"`
	// ACMECABundle is a PEM file of extra roots to trust for the ACME server (Pebble's test CA).
	ACMECABundle string `json:"acmeCaBundle"`
	// AllowLoopbackDomains lets a domain that resolves to 127.0.0.1 count as reaching the server, for the VM suite.
	AllowLoopbackDomains bool `json:"allowLoopbackDomains"`
}

// Load reads file; a missing file means the defaults.
func Load(file string) (Config, error) {
	config := Config{ACMEDirectory: LetsEncrypt}

	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return config, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", file, err)
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", file, err)
	}
	if config.ACMEDirectory == "" {
		config.ACMEDirectory = LetsEncrypt
	}

	return config, nil
}
