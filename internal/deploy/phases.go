package deploy

import (
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/deployscript"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

var titles = map[string]string{
	state.PhasePrepare:         "Running the script before $CREATE_RELEASE()",
	state.PhaseFetch:           "Fetching the repository",
	state.PhaseCheckOut:        "Checking out the release",
	state.PhaseLinkShared:      "Linking shared paths",
	state.PhaseBuild:           "Running the deploy script",
	state.PhaseActivate:        "Activating the release",
	state.PhaseAfterActivation: "Running the script after $ACTIVATE_RELEASE()",
	state.PhaseCleanUp:         "Cleaning up old releases",
}

// PlannedPhases lists the phases a deployment will go through, all pending, so the app can show them up front.
func PlannedPhases(s site.Site, kind string) []state.Phase {
	var names []string

	switch {
	case kind == state.KindRollback:
		names = []string{state.PhaseActivate}
	case !s.ZeroDowntime && !s.HasRepository():
		names = []string{state.PhaseBuild}
	case !s.ZeroDowntime:
		names = []string{state.PhaseFetch, state.PhaseBuild}
	default:
		segments, _ := deployscript.Split(s.DeployScript)
		if !blank(segments.Before) {
			names = append(names, state.PhasePrepare)
		}
		names = append(names, state.PhaseFetch, state.PhaseCheckOut, state.PhaseLinkShared, state.PhaseBuild, state.PhaseActivate)
		if !blank(segments.After) {
			names = append(names, state.PhaseAfterActivation)
		}
		names = append(names, state.PhaseCleanUp)
	}

	phases := make([]state.Phase, len(names))
	for i, name := range names {
		phases[i] = state.Phase{Name: name, State: state.PhasePending}
	}

	return phases
}

func blank(text string) bool { return strings.TrimSpace(text) == "" }

func setPhase(d *state.Deployment, name, phaseState string, now time.Time) {
	for i := range d.Phases {
		if d.Phases[i].Name != name {
			continue
		}

		d.Phases[i].State = phaseState
		switch phaseState {
		case state.PhaseRunning:
			d.Phases[i].StartedAt = now
		case state.PhaseDone, state.PhaseFailed:
			d.Phases[i].FinishedAt = now
		}
	}
}

func setNote(d *state.Deployment, name, note string) {
	for i := range d.Phases {
		if d.Phases[i].Name == name {
			d.Phases[i].Note = note
		}
	}
}
