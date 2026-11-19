package advisories

import "strings"

// Compare orders two Debian package versions as dpkg does: negative when a is older, zero when equal, positive when
// newer. "1.0~rc1" is older than "1.0", and an epoch ("2:") outranks everything after it.
func Compare(a, b string) int {
	aEpoch, aUpstream, aRevision := split(a)
	bEpoch, bUpstream, bRevision := split(b)

	if c := compareDigits(aEpoch, bEpoch); c != 0 {
		return c
	}
	if c := compareParts(aUpstream, bUpstream); c != 0 {
		return c
	}

	return compareParts(aRevision, bRevision)
}

func split(version string) (epoch, upstream, revision string) {
	epoch, upstream, found := strings.Cut(version, ":")
	if !found {
		epoch, upstream = "0", version
	}
	if index := strings.LastIndex(upstream, "-"); index >= 0 {
		upstream, revision = upstream[:index], upstream[index+1:]
	}

	return epoch, upstream, revision
}

func compareDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return len(a) - len(b)
	}

	return strings.Compare(a, b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// order is a character's weight outside a run of digits: "~" before the end, the end before letters, letters before
// everything else.
func order(c byte) int {
	switch {
	case c == 0 || isDigit(c):
		return 0
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// compareParts is dpkg's verrevcmp: alternating runs of non-digits, compared by order, and digits, compared as numbers.
func compareParts(a, b string) int {
	at := func(s string, i int) byte {
		if i < len(s) {
			return s[i]
		}
		return 0
	}

	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			if ac, bc := order(at(a, i)), order(at(b, j)); ac != bc {
				return ac - bc
			}
			i, j = i+1, j+1
		}

		startA, startB := i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if c := compareDigits(a[startA:i], b[startB:j]); c != 0 {
			return c
		}
	}

	return 0
}
