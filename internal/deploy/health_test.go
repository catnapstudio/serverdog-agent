package deploy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

func TestAFailingHealthCheckFailsTheDeployButKeepsItLive(t *testing.T) {
	f := newFixture(t, func(s *site.Site) { s.HealthCheckPath = "/up" })

	var checked []string
	f.runner.HealthCheck = func(_ context.Context, url string) error {
		checked = append(checked, url)
		return errors.New("answered 500 Internal Server Error")
	}

	d := f.run(state.KindDeploy, "")

	if d.State != state.Failed || !d.WentLive || !strings.Contains(d.Error, "answered 500") {
		t.Fatalf("deployment = %+v", d)
	}
	if len(checked) == 0 || !strings.HasSuffix(checked[0], "/up") {
		t.Errorf("checked %v", checked)
	}

	f.runner.HealthCheck = func(context.Context, string) error { return nil }
	if d := f.run(state.KindDeploy, ""); d.State != state.Succeeded {
		t.Errorf("a passing check: %+v", d)
	}
}

func TestSiteHealthCheckGoesToThisServer(t *testing.T) {
	var host string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		if r.URL.Path == "/broken" {
			http.Error(w, "no", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	port := server.URL[strings.LastIndex(server.URL, ":"):]

	if err := SiteHealthCheck(context.Background(), "http://app.example.invalid"+port+"/up"); err != nil {
		t.Fatalf("err = %v", err)
	}
	if host != "app.example.invalid"+port {
		t.Errorf("Host = %q, want the site's domain", host)
	}
	if err := SiteHealthCheck(context.Background(), "http://app.example.invalid"+port+"/broken"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v, want the 500", err)
	}
}
