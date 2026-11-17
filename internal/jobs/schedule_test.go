package jobs

import (
	"testing"
	"time"
)

func TestScheduleMatches(t *testing.T) {
	// Friday 13 November 2026, 14:30.
	at := func(day, hour, minute int) time.Time { return time.Date(2026, 11, day, hour, minute, 0, 0, time.UTC) }

	cases := []struct {
		schedule string
		when     time.Time
		want     bool
	}{
		{"* * * * *", at(13, 14, 30), true},
		{"*/15 * * * *", at(13, 14, 30), true},
		{"*/15 * * * *", at(13, 14, 31), false},
		{"5/15 * * * *", at(13, 14, 35), true},
		{"0 9-17 * * mon-fri", at(13, 9, 0), true},
		{"0 9-17 * * mon-fri", at(14, 9, 0), false},
		{"0 0 * * 7", at(15, 0, 0), true},
		{"30 14 1 * fri", at(13, 14, 30), true}, // both days restricted: either matches
		{"30 14 1 * *", at(13, 14, 30), false},
		{"0 0 1 jan *", time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"@daily", at(13, 0, 0), true},
		{"@daily", at(13, 0, 1), false},
		{"@hourly", at(13, 14, 0), true},
		{"0,30 * * * *", at(13, 14, 30), true},
	}

	for _, c := range cases {
		spec, ok := ParseSchedule(c.schedule)
		if !ok {
			t.Errorf("%q didn't parse", c.schedule)
			continue
		}
		if got := spec.Matches(c.when); got != c.want {
			t.Errorf("%q at %v = %v, want %v", c.schedule, c.when, got, c.want)
		}
	}

	for _, bad := range []string{"@reboot", "60 * * * *", "* * *", "*/0 * * * *", "5-1 * * * *", "* * * foo *"} {
		if _, ok := ParseSchedule(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}
