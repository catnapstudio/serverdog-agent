package jobs

import (
	"strconv"
	"strings"
	"time"
)

// Spec is a parsed cron schedule: the minutes, hours, days, months and weekdays it fires on.
type Spec struct {
	minute, hour, dom, month, dow uint64
	// Cron fires when either day field matches if both are restricted, and on both otherwise.
	domStar, dowStar bool
}

var macroFields = map[string]string{
	"@hourly":   "0 * * * *",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@weekly":   "0 0 * * 0",
	"@monthly":  "0 0 1 * *",
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
}

var (
	monthNames = []string{"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}
	dayNames   = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}
)

// ParseSchedule reads what ValidSchedule accepts. It returns false for @reboot, which has no times, and for
// anything it can't read.
func ParseSchedule(schedule string) (Spec, bool) {
	if fields, ok := macroFields[schedule]; ok {
		schedule = fields
	}

	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return Spec{}, false
	}

	var spec Spec
	var ok [5]bool
	spec.minute, ok[0] = parseField(fields[0], 0, 59, nil)
	spec.hour, ok[1] = parseField(fields[1], 0, 23, nil)
	spec.dom, ok[2] = parseField(fields[2], 1, 31, nil)
	spec.month, ok[3] = parseField(fields[3], 1, 12, monthNames)
	spec.dow, ok[4] = parseField(fields[4], 0, 7, dayNames)
	for _, fine := range ok {
		if !fine {
			return Spec{}, false
		}
	}

	// 7 is Sunday too.
	if spec.dow&(1<<7) != 0 {
		spec.dow |= 1
	}
	spec.domStar = fields[2] == "*" || strings.HasPrefix(fields[2], "*/")
	spec.dowStar = fields[4] == "*" || strings.HasPrefix(fields[4], "*/")

	return spec, true
}

// Matches tells whether cron fires in t's minute, read in t's location.
func (s Spec) Matches(t time.Time) bool {
	if s.minute&(1<<t.Minute()) == 0 || s.hour&(1<<t.Hour()) == 0 || s.month&(1<<int(t.Month())) == 0 {
		return false
	}

	dom := s.dom&(1<<t.Day()) != 0
	dow := s.dow&(1<<int(t.Weekday())) != 0
	if !s.domStar && !s.dowStar {
		return dom || dow
	}

	return dom && dow
}

func parseField(field string, low, high int, names []string) (uint64, bool) {
	var bits uint64

	for _, item := range strings.Split(field, ",") {
		rangePart, stepPart, stepped := strings.Cut(item, "/")
		step := 1
		if stepped {
			n, err := strconv.Atoi(stepPart)
			if err != nil || n < 1 {
				return 0, false
			}
			step = n
		}

		first, last := low, high
		if rangePart != "*" {
			from, to, isRange := strings.Cut(rangePart, "-")
			var ok bool
			if first, ok = value(from, low, high, names); !ok {
				return 0, false
			}
			last = first
			if isRange {
				if last, ok = value(to, low, high, names); !ok || last < first {
					return 0, false
				}
			} else if stepped {
				// "5/15" runs from 5 to the end, as in Vixie cron.
				last = high
			}
		}

		for v := first; v <= last; v += step {
			bits |= 1 << v
		}
	}

	return bits, true
}

func value(text string, low, high int, names []string) (int, bool) {
	for i, name := range names {
		if strings.EqualFold(text, name) {
			return i + low, true
		}
	}

	n, err := strconv.Atoi(text)
	if err != nil || n < low || n > high {
		return 0, false
	}

	return n, true
}
