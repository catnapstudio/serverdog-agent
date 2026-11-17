package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/databases"
	"github.com/catnapstudio/serverdog-agent/internal/deploy"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/sites"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestSiteRoundTrip(t *testing.T) {
	original := &agentv1.Site{
		Id:      "abcdefghijkl",
		Preset:  "nextjs",
		Runtime: agentv1.Runtime_RUNTIME_NODE,
		Domains: []*agentv1.Domain{
			{Name: "orchard.com", Redirect: agentv1.Redirect_REDIRECT_TO_WWW, Primary: true},
			{Name: "orchard.dev", Wildcards: true, Redirect: agentv1.Redirect_REDIRECT_NONE},
		},
		RepositoryUrl:        "git@github.com:a/b.git",
		Branch:               "main",
		EnvironmentFile:      ".env",
		SharedPaths:          []string{"storage"},
		DeployScript:         "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\n",
		ZeroDowntime:         true,
		EnvironmentInScript:  true,
		ReleasesToKeep:       5,
		DeployTimeoutMinutes: 30,
		NodeStartCommand:     "npm run start -- -H 127.0.0.1",
		User:                 "serverdog",
		ForceHttps:           true,
		Hsts:                 true,
		Processes:            []*agentv1.Process{{Id: "workerid2345", Name: "Worker", Command: "node worker.js", Count: 2, Directory: "app"}},
		Scheduler:            true,
		DeployOnPush:         true,
		AppDirectory:         "app",
		Name:                 "worker",
		NginxRules:           "location / {\n    return 204;\n}\n",
	}

	back := siteToProto(siteFromProto(original))
	// Read-only: the agent fills it in, and ignores it coming back.
	if !strings.Contains(back.NginxDefaultRules, "proxy_pass") {
		t.Errorf("default rules = %q", back.NginxDefaultRules)
	}
	back.NginxDefaultRules = ""

	if !proto.Equal(back, original) {
		t.Errorf("round trip =\n%v\nwant\n%v", back, original)
	}
}

func TestAgentOnlyFieldsAreIgnoredOnInput(t *testing.T) {
	s := siteFromProto(&agentv1.Site{Id: "abcdefghijkl", Revision: 9, Directory: "/etc", NginxCustomised: true, CreatedAt: "2020-01-01T00:00:00Z"})

	if s.Revision != 0 || s.Directory != "" || s.NginxCustomised || !s.CreatedAt.IsZero() {
		t.Errorf("site = %+v", s)
	}
}

func TestDeploymentToProto(t *testing.T) {
	started := time.Date(2026, 10, 16, 18, 12, 0, 0, time.UTC)
	d := deploymentToProto(state.Deployment{
		ID: "d", SiteID: "s", Kind: state.KindRollback, State: state.TimedOut, WentLive: true,
		Phases:    []state.Phase{{Name: state.PhaseAfterActivation, State: state.PhaseSkipped, StartedAt: started}},
		StartedAt: started,
	})

	if d.Kind != agentv1.DeploymentKind_DEPLOYMENT_KIND_ROLLBACK || d.State != agentv1.DeploymentState_DEPLOYMENT_STATE_TIMED_OUT || !d.WentLive {
		t.Errorf("d = %v", d)
	}
	if d.Phases[0].Phase != agentv1.Phase_PHASE_AFTER_ACTIVATION || d.Phases[0].State != agentv1.PhaseState_PHASE_STATE_SKIPPED || d.Phases[0].StartedAt != "2026-10-16T18:12:00Z" || d.Phases[0].FinishedAt != "" {
		t.Errorf("phase = %v", d.Phases[0])
	}
	if d.StartedAt != "2026-10-16T18:12:00Z" || d.FinishedAt != "" {
		t.Errorf("times = %s / %s", d.StartedAt, d.FinishedAt)
	}
}

func TestToStatus(t *testing.T) {
	cases := []struct {
		err  error
		code codes.Code
	}{
		{&site.InvalidError{Field: "domains", Reason: "bad"}, codes.InvalidArgument},
		{&state.DomainTakenError{Name: "a.com"}, codes.AlreadyExists},
		{fmt.Errorf("get: %w", state.ErrNotFound), codes.NotFound},
		{state.ErrStaleRevision, codes.FailedPrecondition},
		{sites.ErrStaleContent, codes.FailedPrecondition},
		{state.ErrDeployRunning, codes.FailedPrecondition},
		{deploy.ErrNoRepository, codes.FailedPrecondition},
		{sites.ErrNoHostKey, codes.FailedPrecondition},
		{sites.ErrHostKeyMoved, codes.FailedPrecondition},
		{&apply.Error{Summary: "nginx -t rejected the change.", Output: "emerg"}, codes.FailedPrecondition},
		{context.Canceled, codes.Canceled},
		{fmt.Errorf("wait: %w", context.DeadlineExceeded), codes.DeadlineExceeded},
		{errors.New("disk full"), codes.Internal},
	}

	for _, c := range cases {
		if got := status.Code(toStatus(c.err)); got != c.code {
			t.Errorf("toStatus(%v) = %s, want %s", c.err, got, c.code)
		}
	}

	if message := status.Convert(toStatus(&apply.Error{Summary: "nginx -t rejected the change.", Output: "emerg"})).Message(); message != "nginx -t rejected the change.\n\nemerg" {
		t.Errorf("message = %q", message)
	}

	if message := status.Convert(toStatus(deploy.ErrNoRepository)).Message(); message != "This site has no repository yet. Add one in its settings, then deploy." {
		t.Errorf("no repository message = %q", message)
	}
}

func TestToStatusReportsACancelBeforeADatabaseFailure(t *testing.T) {
	failure := &databases.Error{Summary: "MariaDB couldn't create the database.", Output: "killed"}

	for want, err := range map[codes.Code]error{
		codes.Canceled:         fmt.Errorf("%w: %w", failure, context.Canceled),
		codes.DeadlineExceeded: fmt.Errorf("%w: %w", failure, context.DeadlineExceeded),
		codes.Internal:         failure,
	} {
		if got := status.Code(toStatus(err)); got != want {
			t.Errorf("toStatus(%v) = %s, want %s", err, got, want)
		}
	}
}
