package deploy

import (
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/state"
)

func TestSummaryLeavesOutAMissingCommit(t *testing.T) {
	cases := []struct {
		commit, message, final, want string
	}{
		{"a1b2c3d4e5", "Fix totals\nbody", state.Succeeded, "Deployed a1b2c3d: Fix totals"},
		{"", "", state.Succeeded, "Deployed."},
		{"a1b2c3d4e5", "", state.Failed, "Deploy of a1b2c3d failed: build broke"},
		{"", "", state.Failed, "Deploy failed: build broke"},
	}

	for _, c := range cases {
		j := &job{d: state.Deployment{Kind: state.KindDeploy, Commit: c.commit, CommitMessage: c.message}}

		if got := j.summary(c.final, "build broke"); got != c.want {
			t.Errorf("summary(%q, %q) = %q, want %q", c.commit, c.final, got, c.want)
		}
	}
}
