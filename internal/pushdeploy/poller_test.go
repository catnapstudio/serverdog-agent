package pushdeploy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/gitsource"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

type fixture struct {
	store    *state.Store
	poller   *Poller
	head     string
	headErr  error
	running  bool
	deployed []string
}

func newFixture(t *testing.T, sites ...site.Site) *fixture {
	t.Helper()

	store, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	for _, s := range sites {
		if _, err := store.PutSite(s, 0, time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	f := &fixture{store: store}
	f.poller = &Poller{
		Store:       store,
		Credentials: func(context.Context, string) (gitsource.Credentials, error) { return gitsource.Credentials{}, nil },
		Head: func(context.Context, string, string, gitsource.Credentials) (string, error) {
			return f.head, f.headErr
		},
		Deploy: func(_ context.Context, siteID, actor string) (state.Deployment, bool, error) {
			if actor != Actor {
				t.Errorf("deployed as %q", actor)
			}
			if f.running {
				return state.Deployment{}, true, nil
			}
			f.deployed = append(f.deployed, siteID)
			return state.Deployment{ID: "d" + siteID}, false, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	return f
}

func onPush(id string) site.Site {
	return site.Site{ID: id, Runtime: site.PHP, RepositoryURL: "git@github.com:me/app.git", Branch: "main", DeployOnPush: true}
}

func (f *fixture) recordDeploy(t *testing.T, siteID, kind, commit, outcome string) {
	t.Helper()

	err := f.store.CreateDeployment(state.Deployment{ID: siteID + commit + kind, SiteID: siteID, Kind: kind, State: outcome, Commit: commit, StartedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeploysWhenTheBranchMovesAndOnlyOnce(t *testing.T) {
	f := newFixture(t, onPush("site1"))
	f.recordDeploy(t, "site1", state.KindDeploy, "aaa", state.Succeeded)

	f.head = "aaa"
	f.poller.Check(context.Background())
	if len(f.deployed) != 0 {
		t.Fatalf("deployed the commit already live: %v", f.deployed)
	}

	f.head = "bbb"
	f.poller.Check(context.Background())
	f.poller.Check(context.Background())
	if len(f.deployed) != 1 {
		t.Fatalf("want one deploy of the new commit, got %v", f.deployed)
	}
}

func TestAFailedDeployIsNotRetried(t *testing.T) {
	f := newFixture(t, onPush("site1"))
	f.recordDeploy(t, "site1", state.KindDeploy, "bbb", state.Failed)
	f.recordDeploy(t, "site1", state.KindRollback, "aaa", state.Succeeded)

	f.head = "bbb"
	f.poller.Check(context.Background())
	if len(f.deployed) != 0 {
		t.Fatalf("redeployed a commit whose deploy failed, or counted the rollback: %v", f.deployed)
	}
}

func TestARunningDeployIsCheckedAgainLater(t *testing.T) {
	f := newFixture(t, onPush("site1"))
	f.head, f.running = "bbb", true
	f.poller.Check(context.Background())

	f.running = false
	f.poller.Check(context.Background())
	if len(f.deployed) != 1 {
		t.Fatalf("want a deploy once the running one ended, got %v", f.deployed)
	}
}

func TestSkipsSitesWithoutDeployOnPushAndSurvivesErrors(t *testing.T) {
	off := onPush("site2")
	off.DeployOnPush = false
	f := newFixture(t, onPush("site1"), off)

	f.head, f.headErr = "", errors.New("keyNotAdded: Permission denied (publickey)")
	f.poller.Check(context.Background())
	if f.poller.problems["site1"] == "" {
		t.Error("the repository problem wasn't kept")
	}

	f.head, f.headErr = "bbb", nil
	f.poller.Check(context.Background())
	if len(f.deployed) != 1 || f.deployed[0] != "site1" {
		t.Fatalf("want only site1 deployed, got %v", f.deployed)
	}
	if f.poller.problems["site1"] != "" {
		t.Error("the problem wasn't cleared once the repository answered")
	}
}
