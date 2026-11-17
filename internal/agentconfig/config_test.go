package agentconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMissingFileMeansLetsEncrypt(t *testing.T) {
	config, err := Load(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if config.ACMEDirectory != LetsEncrypt || config.ACMECABundle != "" || config.AllowLoopbackDomains {
		t.Errorf("config = %+v", config)
	}
}

func TestSettingsAreRead(t *testing.T) {
	file := filepath.Join(t.TempDir(), "agent.json")
	os.WriteFile(file, []byte(`{"acmeDirectory": "https://localhost:14000/dir", "acmeCaBundle": "/opt/pebble/test/certs/pebble.minica.pem"}`), 0o644)

	config, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if config.ACMEDirectory != "https://localhost:14000/dir" || config.ACMECABundle != "/opt/pebble/test/certs/pebble.minica.pem" {
		t.Errorf("config = %+v", config)
	}
}

func TestBrokenFileIsAnError(t *testing.T) {
	file := filepath.Join(t.TempDir(), "agent.json")
	os.WriteFile(file, []byte(`{`), 0o644)

	if _, err := Load(file); err == nil {
		t.Error("a broken settings file was accepted")
	}
}

func TestLoopbackDomainsAreOnlyAllowedWhenAsked(t *testing.T) {
	file := filepath.Join(t.TempDir(), "agent.json")
	os.WriteFile(file, []byte(`{"allowLoopbackDomains": true}`), 0o644)

	config, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if !config.AllowLoopbackDomains || config.ACMEDirectory != LetsEncrypt {
		t.Errorf("config = %+v", config)
	}
}
