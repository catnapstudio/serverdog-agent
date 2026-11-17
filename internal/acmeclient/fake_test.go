package acmeclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/certs"
	"github.com/go-acme/lego/v5/acme"
)

func rateLimitingServer(t *testing.T) *httptest.Server {
	t.Helper()

	var nonce atomic.Int64
	var server *httptest.Server

	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonce.Add(1)))
		w.Header().Set("Cache-Control", "no-store")

		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q,"revokeCert":%q,"keyChange":%q}`,
				server.URL+"/nonce", server.URL+"/account", server.URL+"/order", server.URL+"/revoke", server.URL+"/key")
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/account":
			w.Header().Set("Location", server.URL+"/account/1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"status":"valid"}`)
		case "/order":
			w.Header().Set("Content-Type", "application/problem+json")
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many certificates already issued","status":429}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func TestRateLimitFromTheServer(t *testing.T) {
	server := rateLimitingServer(t)

	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o644)

	client := &Lego{Directory: server.URL + "/directory", CABundle: bundle, AccountDir: filepath.Join(dir, "account"), Webroot: filepath.Join(dir, "webroot")}
	os.MkdirAll(client.Webroot, 0o755)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.Obtain(ctx, []string{"orchard.test"}, certs.ECDSAP256)
	if err == nil {
		t.Fatal("expected a rate-limit error")
	}

	failure := Classify(err)
	if !failure.RateLimited || failure.RetryAfter != 2*time.Minute {
		t.Errorf("failure = %+v (err %v)", failure, err)
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "account", "*", "key.pem"))
	if len(matches) != 1 {
		t.Fatalf("account key files = %v", matches)
	}
	if info, _ := os.Stat(matches[0]); info.Mode().Perm() != 0o600 {
		t.Errorf("account key mode = %v", info.Mode())
	}
}

// accountServer answers account lookups (onlyReturnExisting) with status and problem, accepts registrations, and
// refuses every order. It counts lookups and registrations.
func accountServer(t *testing.T, status int, problem string) (server *httptest.Server, lookups, registrations *atomic.Int64) {
	t.Helper()

	var nonce atomic.Int64
	lookups, registrations = &atomic.Int64{}, &atomic.Int64{}

	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonce.Add(1)))

		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q,"revokeCert":%q,"keyChange":%q}`,
				server.URL+"/nonce", server.URL+"/account", server.URL+"/order", server.URL+"/revoke", server.URL+"/key")
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/account":
			var jws struct{ Payload string }
			json.NewDecoder(r.Body).Decode(&jws)
			payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)

			if strings.Contains(string(payload), `"onlyReturnExisting":true`) {
				lookups.Add(1)
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(status)
				fmt.Fprintf(w, `{"type":%q,"detail":"lookup answer","status":%d}`, problem, status)
				return
			}

			registrations.Add(1)
			w.Header().Set("Location", server.URL+"/account/1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"status":"valid"}`)
		default:
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"type":"urn:ietf:params:acme:error:unauthorized","detail":"no orders here","status":403}`)
		}
	}))
	t.Cleanup(server.Close)

	return server, lookups, registrations
}

// Only an account the server says doesn't exist is registered. Any other lookup error (an outage, a refusal) is
// returned, and the next request looks the account up again instead of making a second one.
func TestOnlyAMissingAccountIsRegistered(t *testing.T) {
	cases := map[string]struct {
		status        int
		problem       string
		registrations int64
	}{
		"account does not exist": {http.StatusBadRequest, acme.AccountDoesNotExistErrorType, 1},
		"server error":           {http.StatusInternalServerError, acme.ServerInternalErrorType, 0},
		"unauthorized":           {http.StatusForbidden, acme.UnauthorizedErrorType, 0},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			server, lookups, registrations := accountServer(t, c.status, c.problem)

			dir := t.TempDir()
			bundle := filepath.Join(dir, "ca.pem")
			os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o644)
			client := &Lego{Directory: server.URL + "/directory", CABundle: bundle, AccountDir: filepath.Join(dir, "account"), Webroot: filepath.Join(dir, "webroot")}
			os.MkdirAll(client.Webroot, 0o755)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			for range 2 {
				if _, err := client.Obtain(ctx, []string{"orchard.test"}, certs.ECDSAP256); err == nil {
					t.Fatal("Obtain succeeded against a server that refuses orders")
				}
			}

			if got := registrations.Load(); got != c.registrations {
				t.Errorf("registrations = %d, want %d", got, c.registrations)
			}
			if c.registrations == 0 && lookups.Load() != 2 {
				t.Errorf("lookups = %d, want one per request", lookups.Load())
			}
		})
	}
}
