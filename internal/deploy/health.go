package deploy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// healthCheck requests the site's health check path once the deploy is live, and fails the deploy (which stays live)
// when it keeps answering 400 or more for HealthCheckFor.
func (j *job) healthCheck(ctx context.Context) error {
	if j.s.HealthCheckPath == "" || !j.s.HasWebsite() || j.r.HealthCheck == nil {
		return nil
	}

	url := "http://" + j.s.DirectoryName() + j.s.HealthCheckPath
	j.logf("\n==> Checking %s\n", url)

	deadline := time.Now().Add(j.r.HealthCheckFor)

	for {
		err := j.r.HealthCheck(ctx, url)
		if err == nil {
			j.logf("It answered.\n")
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("The deploy is live, but %s %v. Roll back if the site is broken.", url, err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(j.r.ProbeEvery):
		}
	}
}

// healthClient sends every request to this server's own Nginx, whatever the domain resolves to, and follows the
// site's redirects to https there too. The certificate isn't checked: the domain may not point here yet.
var healthClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// SiteHealthCheck answers nil when this server serves rawURL with a status under 400.
func SiteHealthCheck(ctx context.Context, rawURL string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}

	response, err := healthClient.Do(request)
	if err != nil {
		return fmt.Errorf("didn't answer (%v)", err)
	}
	defer response.Body.Close()

	if response.StatusCode >= 400 {
		return fmt.Errorf("answered %s", response.Status)
	}

	return nil
}
