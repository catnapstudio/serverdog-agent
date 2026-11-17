// Package dotenv reads .env files for deploy scripts, covering what Laravel's and Node's loaders agree on:
// comments, "export " prefixes, single quotes (literal), double quotes (with \n, \" and \\ escapes),
// quoted values that span lines, trailing " #" comments on unquoted values, a leading UTF-8 BOM and CRLF line
// endings.
//
// ${NAME} references are expanded the way Laravel's phpdotenv v5 does, so a value means the same to a site's
// PHP, to its Node start script and to its deploy script:
//   - Only ${NAME} counts, with NAME made of letters, digits, "_" and ".". A bare $VAR is never expanded, so
//     "pa$word" is safe.
//   - Unquoted and double-quoted values expand. Single-quoted values are literal, and \$ inside double quotes
//     gives a literal $.
//   - A reference sees only keys assigned earlier in the same file, and the last earlier assignment wins. The
//     process environment is never read, so the result depends on the file alone.
//   - An undefined or later key leaves ${NAME} as written. A defined but empty key gives "". ${NAME:-default}
//     is not supported and stays as written.
//   - Expansion is one pass, right to left. Substituted text is not scanned again, so A=${A} stays literal.
package dotenv

import (
	"regexp"
	"strings"
)

var (
	key       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)
	shellName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	reference = regexp.MustCompile(`^\$\{([A-Za-z0-9_.]+)\}`)
)

// Parse returns each valid assignment as "KEY=value", in file order, with ${NAME} references expanded as the
// package comment describes. Invalid lines are skipped.
func Parse(content []byte) []string {
	var assignments []string

	known := map[string]string{}

	lines := strings.Split(strings.TrimPrefix(string(content), "\uFEFF"), "\n")

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(strings.TrimSuffix(lines[i], "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		line = strings.TrimPrefix(line, "export ")

		name, value, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !ok || !key.MatchString(name) {
			continue
		}

		raw := strings.TrimSpace(value)
		parsed, live, closed := parseValue(raw)
		for !closed && i+1 < len(lines) {
			i++
			raw += "\n" + strings.TrimSuffix(lines[i], "\r")
			parsed, live, closed = parseValue(raw)
		}

		value = resolve(parsed, live, known)
		known[name] = value

		assignments = append(assignments, name+"="+value)
	}

	return assignments
}

// parseValue returns the value written in raw, the byte offsets in that value of the "$" that may start a
// reference, and whether raw ended the value. Only a quoted value can be unfinished. Single-quoted values and
// an escaped \$ have no such offsets.
func parseValue(raw string) (string, []int, bool) {
	switch {
	case strings.HasPrefix(raw, `"`):
		var value strings.Builder
		var live []int
		for i := 1; i < len(raw); i++ {
			switch c := raw[i]; {
			case c == '"':
				return value.String(), live, true
			case c == '\\' && i+1 < len(raw):
				i++
				switch raw[i] {
				case 'n':
					value.WriteByte('\n')
				case 'r':
					value.WriteByte('\r')
				case 't':
					value.WriteByte('\t')
				default:
					value.WriteByte(raw[i])
				}
			case c == '$':
				live = append(live, value.Len())
				value.WriteByte(c)
			default:
				value.WriteByte(c)
			}
		}
		return value.String(), live, false

	case strings.HasPrefix(raw, "'"):
		if end := strings.IndexByte(raw[1:], '\''); end >= 0 {
			return raw[1 : end+1], nil, true
		}
		return raw[1:], nil, false

	case strings.HasPrefix(raw, "#"):
		return "", nil, true

	default:
		if comment := strings.Index(raw, " #"); comment >= 0 {
			raw = raw[:comment]
		}
		value := strings.TrimSpace(raw)

		var live []int
		for i := 0; i < len(value); i++ {
			if value[i] == '$' {
				live = append(live, i)
			}
		}
		return value, live, true
	}
}

// resolve replaces the ${NAME} references that start at the live offsets of value with the values in known.
// Like phpdotenv it goes right to left, one pass, and never scans substituted text for references again, apart
// from the text that a reference to the left encloses ("${${N}}" works). A name known doesn't hold stays as written.
// maxValue is the longest value a reference may grow a line to. The file is the site user's, the reader is root.
const maxValue = 64 * 1024

func resolve(value string, live []int, known map[string]string) string {
	for n := len(live) - 1; n >= 0; n-- {
		start := live[n]

		match := reference.FindStringSubmatch(value[start:])
		if match == nil {
			continue
		}

		replacement, ok := known[match[1]]
		if !ok {
			continue
		}

		// A few lines of references to each other double in size at every step. Past this the rest stay as written.
		if len(value)+len(replacement) > maxValue {
			break
		}

		value = value[:start] + replacement + value[start+len(match[0]):]
	}

	return value
}

// Exports returns shell "export" lines for assignments ("KEY=value", as Parse returns them). Keys that are not
// shell names and keys isSet reports as already set are skipped. Values are single-quoted, so sh reads them literally.
func Exports(assignments []string, isSet func(key string) bool) string {
	var lines []string

	for _, assignment := range assignments {
		name, value, ok := strings.Cut(assignment, "=")
		if !ok || !shellName.MatchString(name) || isSet(name) {
			continue
		}

		lines = append(lines, "export "+name+"="+shellQuote(value))
	}

	return strings.Join(lines, "\n")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
