package dotenv

import (
	"regexp"
	"strings"
)

var plainValue = regexp.MustCompile(`^[A-Za-z0-9_./:@+-]*$`)

// Set gives key the value in an env file, keeping everything else (comments, order, CRLF, "export "). Every
// assignment of key is replaced, including one whose quoted value spans lines; a missing key is appended.
// A "$" in the value is written as \$, so Parse never expands what Set wrote.
func Set(content []byte, key, value string) []byte {
	text := strings.TrimPrefix(string(content), "\uFEFF")
	bom := len(text) != len(content)

	newline := "\n"
	if strings.Contains(text, "\r\n") {
		newline = "\r\n"
	}

	encoded := value
	if !plainValue.MatchString(value) {
		encoded = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, `$`, `\$`).Replace(value) + `"`
	}

	lines := strings.Split(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	var out []string
	found := false

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSuffix(lines[i], "\r")
		trimmed := strings.TrimSpace(line)
		export := strings.HasPrefix(trimmed, "export ")

		name, raw, ok := strings.Cut(strings.TrimPrefix(trimmed, "export "), "=")
		if !ok || strings.HasPrefix(trimmed, "#") || strings.TrimSpace(name) != key {
			out = append(out, line)
			continue
		}

		raw = strings.TrimSpace(raw)
		for _, _, closed := parseValue(raw); !closed && i+1 < len(lines); _, _, closed = parseValue(raw) {
			i++
			raw += "\n" + strings.TrimSuffix(lines[i], "\r")
		}

		prefix := ""
		if export {
			prefix = "export "
		}
		out = append(out, prefix+key+"="+encoded)
		found = true
	}

	if !found {
		out = append(out, key+"="+encoded)
	}

	result := strings.Join(out, newline) + newline
	if bom {
		result = "\uFEFF" + result
	}

	return []byte(result)
}
