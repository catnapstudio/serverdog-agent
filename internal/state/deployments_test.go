package state

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func deployment(id, siteID string, started time.Time) Deployment {
	return Deployment{
		ID: id, SiteID: siteID, Kind: KindDeploy, State: Running, Actor: "Mac",
		Phases:    []Phase{{Name: PhaseFetch, State: PhasePending}},
		Marker:    "nonce",
		StartedAt: started,
	}
}

func TestOnlyOneRunningDeploymentPerSite(t *testing.T) {
	store := open(t)

	if err := store.CreateDeployment(deployment("d1", "s1", now)); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateDeployment(deployment("d2", "s1", now)); !errors.Is(err, ErrDeployRunning) {
		t.Fatalf("err = %v, want ErrDeployRunning", err)
	}
	if err := store.CreateDeployment(deployment("d3", "s2", now)); err != nil {
		t.Fatalf("other site blocked: %v", err)
	}

	running, ok, err := store.RunningDeployment("s1")
	if err != nil || !ok || running.ID != "d1" {
		t.Fatalf("running = %+v %v %v", running, ok, err)
	}

	if _, err := store.UpdateDeployment("d1", func(d *Deployment) {
		d.State = Succeeded
		d.FinishedAt = now.Add(time.Minute)
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.CreateDeployment(deployment("d4", "s1", now.Add(2*time.Minute))); err != nil {
		t.Fatalf("finished deploy still blocks: %v", err)
	}
}

func TestUpdateDeploymentRoundTripsPhases(t *testing.T) {
	store := open(t)
	store.CreateDeployment(deployment("d1", "s1", now))

	updated, err := store.UpdateDeployment("d1", func(d *Deployment) {
		d.Phases[0].State = PhaseDone
		d.Phases[0].Note = "main at abc1234"
		d.Commit = "abc1234"
		d.WentLive = true
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := store.GetDeployment("d1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Phases[0].State != PhaseDone || got.Phases[0].Note != "main at abc1234" || !got.WentLive || got.Commit != updated.Commit {
		t.Errorf("got = %+v", got)
	}
	if !got.StartedAt.Equal(now) || !got.FinishedAt.IsZero() {
		t.Errorf("times = %v / %v", got.StartedAt, got.FinishedAt)
	}
}

func TestListAndPruneDeployments(t *testing.T) {
	store := open(t)

	for i := range 5 {
		d := deployment(string(rune('a'+i)), "s1", now.Add(time.Duration(i)*time.Minute))
		d.State = Succeeded
		d.Commit = "c" + string(rune('a'+i))
		d.Release = "r" + string(rune('a'+i))
		d.WentLive = true
		if err := store.CreateDeployment(d); err != nil {
			t.Fatal(err)
		}
	}

	list, err := store.ListDeployments("s1", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || list[0].ID != "e" {
		t.Errorf("list = %v", ids(list))
	}

	removed, err := store.PruneDeployments("s1", 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 3 {
		t.Errorf("removed = %v", removed)
	}

	before, err := store.DeployedBefore("s1", "ce", "zz")
	if err != nil || !before {
		t.Errorf("DeployedBefore = %v %v", before, err)
	}

	commit, _, err := store.ReleaseCommit("s1", "rd")
	if err != nil || commit != "cd" {
		t.Errorf("ReleaseCommit = %q %v", commit, err)
	}
}

func ids(list []Deployment) []string {
	var out []string
	for _, d := range list {
		out = append(out, d.ID)
	}

	return out
}

func TestDeploymentsOrderByTimeWithinTheSameSecond(t *testing.T) {
	store := open(t)

	for _, d := range []Deployment{
		deployment("a", "s1", now),
		deployment("b", "s1", now.Add(500*time.Millisecond)),
		deployment("c", "s1", now.Add(time.Second)),
	} {
		d.State = Succeeded
		if err := store.CreateDeployment(d); err != nil {
			t.Fatal(err)
		}
	}

	list, err := store.ListDeployments("s1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(list); len(got) != 3 || got[0] != "c" || got[1] != "b" || got[2] != "a" {
		t.Errorf("list = %v, want [c b a]", got)
	}

	removed, err := store.PruneDeployments("s1", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 || removed[0] != "b" || removed[1] != "a" {
		t.Errorf("removed = %v, want [b a]", removed)
	}

	left, _ := store.ListDeployments("s1", 10)
	if got := ids(left); len(got) != 1 || got[0] != "c" {
		t.Errorf("left = %v", got)
	}
}

func TestReleasesThatWentLive(t *testing.T) {
	store := open(t)

	for i, d := range []struct {
		id, site, kind, release string
		live                    bool
	}{
		{"d1", "s1", KindDeploy, "20261016-170000", true},
		{"d2", "s1", KindDeploy, "20261016-170001", false},
		{"d3", "s1", KindRollback, "20261016-170002", true},
		{"d4", "s2", KindDeploy, "20261016-170003", true},
		{"d5", "s1", KindDeploy, "", true},
	} {
		created := deployment(d.id, d.site, now.Add(time.Duration(i)*time.Second))
		created.Kind, created.Release, created.WentLive, created.State = d.kind, d.release, d.live, Succeeded
		if err := store.CreateDeployment(created); err != nil {
			t.Fatal(err)
		}
	}

	got, err := store.ReleasesThatWentLive("s1")
	if err != nil || len(got) != 2 || !got["20261016-170000"] || !got["20261016-170002"] {
		t.Errorf("ReleasesThatWentLive = %v %v", got, err)
	}
}

// A release still on the server can be rolled back to only while a row says it went live, so pruning the history
// keeps those rows however old they are.
func TestPruneKeepsWentLiveRowsOfKeptReleases(t *testing.T) {
	store := open(t)

	for i, d := range []struct {
		id, release string
		live        bool
	}{
		{"a", "20261016-170000", true},
		{"b", "20261016-170001", false},
		{"c", "20261016-170002", true},
		{"d", "", false},
		{"e", "20261016-170004", true},
	} {
		created := deployment(d.id, "s1", now.Add(time.Duration(i)*time.Minute))
		created.Release, created.WentLive, created.State = d.release, d.live, Succeeded
		if err := store.CreateDeployment(created); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := store.PruneDeployments("s1", 1, []string{"20261016-170000", "20261016-170001", "20261016-170004"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"d", "c", "b"}; !slices.Equal(removed, want) {
		t.Errorf("removed = %v, want %v", removed, want)
	}

	left, _ := store.ListDeployments("s1", 10)
	if got := ids(left); !slices.Equal(got, []string{"e", "a"}) {
		t.Errorf("left = %v, want [e a]", got)
	}

	wentLive, err := store.ReleasesThatWentLive("s1")
	if err != nil || len(wentLive) != 2 || !wentLive["20261016-170000"] || !wentLive["20261016-170004"] {
		t.Errorf("ReleasesThatWentLive = %v %v", wentLive, err)
	}
}

func TestADeploymentKeepsTheScriptItStartedWith(t *testing.T) {
	store := open(t)

	d := deployment("d1", "s1", now)
	d.Script = "$CREATE_RELEASE()\necho built\n$ACTIVATE_RELEASE()\n"
	if err := store.CreateDeployment(d); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateDeployment("d1", func(d *Deployment) { d.State = Succeeded }); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetDeployment("d1")
	if err != nil || got.Script != d.Script {
		t.Errorf("script = %q %v, want %q", got.Script, err, d.Script)
	}
}
