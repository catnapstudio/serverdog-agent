package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/nginx"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// hasPlaceholder reports whether the site still serves its placeholder page. Root only looks; the site user wrote it.
func hasPlaceholder(p paths.Paths, s site.Site) bool {
	info, err := os.Lstat(filepath.Join(p.File(paths.Placeholder(s.Directory)), "index.html"))

	return err == nil && info.Mode().IsRegular()
}

// releaseConfig is the Nginx change that takes the site off its placeholder page: none once it serves releases.
// A customised config gets none either, so the log says why the site may still point at the placeholder folder.
func (j *job) releaseConfig(ctx context.Context) ([]apply.File, error) {
	if !j.placeholder {
		return nil, nil
	}
	if j.r.ReleaseConfig == nil {
		return nil, errors.New("This deploy can't take the site off its placeholder page.")
	}

	files, err := j.r.ReleaseConfig(ctx, j.s.ID, j.caps)
	if err != nil {
		return nil, fmt.Errorf("Couldn't render the Nginx config that serves the release: %w", err)
	}

	if len(files) == 0 {
		j.logf("The Nginx config is customised, so ServerDog left it unchanged. If it still serves the placeholder folder, point it at the release or reset it to the generated config.\n")
	}

	return files, nil
}

// leavePlaceholder runs fn, the steps that take the site off its placeholder page, under the apply lock (see
// holdToLeavePlaceholder), then deletes the folder the page was moved to.
func (j *job) leavePlaceholder(ctx context.Context, fn func(apply.Applier) error) error {
	err := j.holdToLeavePlaceholder(ctx, fn)
	j.deleteRetiredPlaceholder(context.WithoutCancel(ctx))

	return err
}

// holdToLeavePlaceholder runs fn under the apply lock: rendering the config that serves the releases, applying it, and
// moving the page aside. The agent holds the same lock from rendering a site's config to saving what it rendered from,
// such as a certificate it activates. So a config the agent writes meanwhile is either saved before this renders from
// the store, or rendered after the page is gone and serves the releases too. What the server runs is detected before
// the lock, since that waits on version commands. The caller deletes the folder the page was moved to once the lock is
// free (deleteRetiredPlaceholder): the site user decides how big it is, and other sites' changes wait for the lock.
// A deploy that doesn't leave the placeholder runs fn without the lock.
func (j *job) holdToLeavePlaceholder(ctx context.Context, fn func(apply.Applier) error) error {
	if !j.placeholder {
		return fn(j.r.Applier)
	}

	if j.r.Capabilities != nil {
		j.caps = j.r.Capabilities(ctx)
	}

	return j.r.Applier.Hold(ctx, fn)
}

// serveReleases points Nginx at the site's releases instead of its placeholder page (PHP, Static and in-place sites),
// through the Applier leavePlaceholder holds.
func (j *job) serveReleases(ctx context.Context, applier apply.Applier) error {
	files, err := j.releaseConfig(ctx)
	if err != nil || len(files) == 0 {
		return err
	}

	if _, err := applier.Apply(ctx, apply.Plan{Files: files, Checks: []system.Command{nginx.Check}, Reloads: []system.Command{nginx.Reload}}); err != nil {
		return fmt.Errorf("Nginx couldn't switch from the placeholder page to the release: %w", err)
	}

	j.logf("Nginx now serves the release instead of the placeholder page.\n")

	return nil
}

// retirePlaceholderScript runs as the site user. Arguments: the placeholder folder, the name it moves to.
const retirePlaceholderScript = `rename($ARGV[0], $ARGV[1]) or die "rename: $!\n";`

// retiredPlaceholder is where removePlaceholder moves the page: a name of this deploy's own, so it never meets a folder
// an earlier deploy left behind.
func (j *job) retiredPlaceholder() string {
	return filepath.Join(j.dir, ".placeholder-removed-"+j.d.ID)
}

// removePlaceholder takes the placeholder page away as the site user once a release is live, in one rename whatever the
// folder holds; leavePlaceholder deletes the renamed folder after the apply lock. While the page exists, ServerDog would
// serve it again the next time it writes the site's config, so a failure fails the deploy.
func (j *job) removePlaceholder(ctx context.Context) error {
	if !j.placeholder {
		return nil
	}

	if err := j.run(ctx, j.dir, "perl", "-e", retirePlaceholderScript, "--", j.r.Paths.File(paths.Placeholder(j.s.Directory)), j.retiredPlaceholder()); err != nil {
		return fmt.Errorf("The release is live, but the placeholder page couldn't be removed: %w", err)
	}

	j.placeholder, j.retired = false, true
	j.logf("Removed the placeholder page.\n")

	return nil
}

// deleteRetiredPlaceholder deletes the folder removePlaceholder moved the page to, as the site user, if this deploy
// moved it. Nothing reads that folder, so a failure is only logged.
func (j *job) deleteRetiredPlaceholder(ctx context.Context) {
	if !j.retired {
		return
	}
	j.retired = false

	if err := j.remove(ctx, j.retiredPlaceholder()); err != nil {
		j.logf("Couldn't delete the old placeholder folder %s: %v\n", j.retiredPlaceholder(), err)
	}
}
