package databases

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/network"
)

// allowInHBA lets r.From log in to r's PostgreSQL database with a password, with a line each at the end of
// pg_hba.conf, then reloads it. Lines already there are kept.
//
// shortcut: deleting the database or user leaves its lines, which then match nothing; tidy them if they pile up.
func (c Creator) allowInHBA(ctx context.Context, e engine, r Request) error {
	summary := "PostgreSQL couldn't let the other servers in."

	output, err := c.runFor(ctx, e, "SHOW hba_file;\n", "", summary)
	if err != nil {
		return err
	}
	file := strings.TrimSpace(output)

	content, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	text := string(content)
	existing := strings.Split(text, "\n")
	for _, from := range r.From {
		line := fmt.Sprintf("host %s %s %s/32 scram-sha-256 # serverdog", r.Name, r.User, from)
		if contains(existing, line) {
			continue
		}
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += line + "\n"
	}
	if text == string(content) {
		return nil
	}

	if err := network.ReplaceFile(file, []byte(text)); err != nil {
		return err
	}

	_, err = c.runFor(ctx, e, "SELECT pg_reload_conf();\n", "", summary)

	return err
}

func contains(lines []string, line string) bool {
	for _, l := range lines {
		if strings.TrimSpace(l) == line {
			return true
		}
	}

	return false
}
