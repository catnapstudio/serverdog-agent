package deploy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/dotenv"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/phpfpm"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/userfs"
)

// fetch updates the bare mirror in repo/ and records the branch's latest commit.
func (j *job) fetch(ctx context.Context) error {
	repo := filepath.Join(j.dir, "repo")

	if _, err := os.Stat(filepath.Join(repo, "HEAD")); err != nil {
		if err := j.run(ctx, j.dir, "git", "clone", "--mirror", "--quiet", j.s.RepositoryURL, repo); err != nil {
			return fmt.Errorf("Couldn't clone the repository. Check the deploy key with Test Access.")
		}
	} else {
		if err := j.run(ctx, repo, "git", "remote", "set-url", "origin", j.s.RepositoryURL); err != nil {
			return err
		}
		if err := j.run(ctx, repo, "git", "fetch", "--prune", "--quiet", "origin"); err != nil {
			return fmt.Errorf("Couldn't fetch the repository. Check the deploy key with Test Access.")
		}
	}

	return j.resolve(ctx, repo, "refs/heads/"+j.s.Branch)
}

// resolve records the commit ref points at, with its author and message.
func (j *job) resolve(ctx context.Context, gitDir, ref string) error {
	commit, err := j.output(ctx, gitDir, "git", "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	if err != nil || commit == "" {
		return fmt.Errorf("The branch %s doesn't exist in the repository.", j.s.Branch)
	}

	info, _ := j.output(ctx, gitDir, "git", "log", "-1", "--format=%an%x1f%s", commit)
	author, message, _ := strings.Cut(info, "\x1f")

	j.redeploy, _ = j.r.Store.DeployedBefore(j.s.ID, commit, j.d.ID)

	j.update(func(d *state.Deployment) {
		d.Commit, d.CommitAuthor, d.CommitMessage = commit, author, message
		setNote(d, state.PhaseFetch, fmt.Sprintf("%s at %s", j.s.Branch, short(commit)))
	})
	j.logf("%s is at %s: %s\n", j.s.Branch, short(commit), message)

	return nil
}

// checkOut exports the commit into a new release directory, without .git.
func (j *job) checkOut(ctx context.Context) error {
	j.releaseName = releaseName(j.r.Now(), j.releasesDir())
	j.release = filepath.Join(j.releasesDir(), j.releaseName)

	j.update(func(d *state.Deployment) {
		d.Release = j.releaseName
		setNote(d, state.PhaseCheckOut, "releases/"+j.releaseName)
	})

	const script = `mkdir -p "$3" && git -C "$1" archive --format=tar "$2" | tar -x -f - -C "$3"`

	return j.run(ctx, j.dir, "bash", "-o", "pipefail", "-c", script, "bash", filepath.Join(j.dir, "repo"), j.d.Commit, j.release)
}

// releaseName is the UTC time, with -2, -3… when a release with that name exists.
func releaseName(now time.Time, dir string) string {
	base := now.UTC().Format("20060102-150405")
	name := base

	for i := 2; ; i++ {
		if _, err := os.Lstat(filepath.Join(dir, name)); os.IsNotExist(err) {
			return name
		}
		name = fmt.Sprintf("%s-%d", base, i)
	}
}

// linkScript runs as the site user. Arguments: release, shared, environment file, then pairs of (path, relative link target).
// It never follows a symlink: every directory above a path is created one component at a time, and a component
// that already is a symlink (a repository can contain any symlink) stops the deploy before anything is moved or removed.
const linkScript = `set -eu
release="$1"; shared="$2"; env_file="$3"; shift 3

refuse() {
  echo "$1 goes through a symlink or a file in the repository; ServerDog won't follow it."
  exit 1
}

safe_dirs() {
  cur="$1"; rest="$2"
  while [ -n "$rest" ]; do
    seg="${rest%%/*}"
    case "$rest" in
      */*) rest="${rest#*/}" ;;
      *) rest="" ;;
    esac
    cur="$cur/$seg"
    if [ -L "$cur" ]; then
      refuse "$3"
    fi
    if [ ! -d "$cur" ]; then
      if [ -e "$cur" ]; then
        refuse "$3"
      fi
      mkdir "$cur"
    fi
  done
}

while [ "$#" -gt 0 ]; do
  p="$1"; target="$2"; shift 2
  in_release="$release/$p"; in_shared="$shared/$p"
  parent=""
  case "$p" in
    */*) parent="${p%/*}" ;;
  esac
  safe_dirs "$release" "$parent" "$p"
  safe_dirs "$shared" "$parent" "$p"
  if [ ! -e "$in_shared" ] && [ ! -L "$in_shared" ]; then
    if [ -e "$in_release" ] && [ ! -L "$in_release" ]; then
      mv "$in_release" "$in_shared"
      echo "Moved $p into shared/, where it stays from now on."
    elif [ "$p" = "$env_file" ]; then
      (umask 077 && : > "$in_shared")
      echo "Created an empty shared/$p."
    else
      mkdir -p "$in_shared"
      echo "Created shared/$p."
    fi
  fi
  if [ "$p" = "$env_file" ] && [ -f "$in_shared" ] && [ ! -L "$in_shared" ]; then
    chmod 600 "$in_shared"
  fi
  rm -rf "$in_release"
  ln -s "$target" "$in_release"
done
`

// linkShared replaces each shared path in the release with a relative symlink into shared/,
// seeding shared/ from the release the first time.
func (j *job) linkShared(ctx context.Context) error {
	linked := j.s.Linked()
	shared := filepath.Join(j.dir, "shared")
	args := []string{"-c", linkScript, "sh", j.release, shared, j.s.EnvironmentFile}

	for _, p := range linked {
		target, err := filepath.Rel(filepath.Dir(filepath.Join(j.release, p)), filepath.Join(shared, p))
		if err != nil {
			return err
		}
		args = append(args, p, target)
	}

	j.update(func(d *state.Deployment) { setNote(d, state.PhaseLinkShared, strings.Join(linked, ", ")) })

	return j.run(ctx, j.dir, "sh", args...)
}

// scriptRunner is bash's -c argument. The segment itself arrives in SERVERDOG_SCRIPT, because /proc/<pid>/cmdline is
// readable by every user and a script may hold secrets. It takes the segment out of the environment, makes bash print
// "\x1eserverdog:<marker>:<command>" before each command for the app's progress (except for the eval running the
// segment), and evals the segment: the DEBUG trap and set -e apply inside eval, and bash numbers its lines from 1,
// so they match the editor.
const scriptRunner = `__serverdog_script=$SERVERDOG_SCRIPT; unset SERVERDOG_SCRIPT; ` +
	`__serverdog_mark() { [ "$BASH_COMMAND" = 'eval "$__serverdog_script"' ] && return; printf '\036serverdog:%s:%s\n' "$SERVERDOG_MARKER" "${BASH_COMMAND//$'\n'/ }"; }; ` +
	`trap __serverdog_mark DEBUG; eval "$__serverdog_script"`

// script runs one segment of the deploy script as the site user in dir.
func (j *job) script(ctx context.Context, text, dir, releaseDir string) error {
	if blank(text) {
		return nil
	}

	env, err := j.scriptEnv(ctx, releaseDir)
	if err != nil {
		return err
	}

	_, err = j.r.Exec.Run(ctx, system.Command{
		Name:   "bash",
		Args:   []string{"--noprofile", "--norc", "-eo", "pipefail", "-c", scriptRunner},
		Dir:    dir,
		Env:    append(env, "SERVERDOG_SCRIPT="+text),
		User:   j.asUser(),
		Stdout: j.r.Out,
	})
	if code, ok := system.ExitCode(err); ok && code > 0 {
		return fmt.Errorf("The deploy script failed with exit code %d.", code)
	}

	return err
}

func (j *job) environmentPath() string {
	if j.s.ZeroDowntime {
		return filepath.Join(j.dir, "shared", j.s.EnvironmentFile)
	}

	return filepath.Join(j.dir, "current", j.s.EnvironmentFile)
}

// scriptEnv is the base environment, then the site's .env when allowed (minus SERVERDOG_ variables and BASH_ENV), then the SERVERDOG_ variables.
func (j *job) scriptEnv(ctx context.Context, releaseDir string) ([]string, error) {
	env := j.baseEnv()

	if j.s.EnvironmentInScript && j.s.EnvironmentFile != "" {
		content, ok, err := userfs.FS{Runner: j.r.Exec, User: j.asUser()}.ReadFile(ctx, j.environmentPath())
		if err != nil {
			return nil, err
		}
		if ok {
			for _, assignment := range dotenv.Parse(content) {
				name, _, _ := strings.Cut(assignment, "=")
				if strings.HasPrefix(name, "SERVERDOG_") || name == "BASH_ENV" {
					continue
				}
				env = append(env, assignment)
			}
		}
	}

	redeploy := "0"
	if j.redeploy {
		redeploy = "1"
	}

	env = append(env,
		"SERVERDOG_SITE_ROOT="+j.dir,
		"SERVERDOG_SITE_PATH="+filepath.Join(j.dir, "current"),
		"SERVERDOG_SITE_BRANCH="+j.s.Branch,
		"SERVERDOG_SITE_ID="+j.s.ID,
		"SERVERDOG_SITE_USER="+j.s.User,
		"SERVERDOG_DEPLOYMENT_ID="+j.d.ID,
		"SERVERDOG_DEPLOY_COMMIT="+j.d.Commit,
		"SERVERDOG_DEPLOY_AUTHOR="+j.d.CommitAuthor,
		"SERVERDOG_DEPLOY_MESSAGE="+j.d.CommitMessage,
		"SERVERDOG_MANUAL_DEPLOY=1",
		"SERVERDOG_REDEPLOY="+redeploy,
		"SERVERDOG_SHARED="+filepath.Join(j.dir, "shared"),
		"SERVERDOG_MARKER="+j.d.Marker,
	)

	if releaseDir != "" {
		env = append(env, "SERVERDOG_RELEASE_DIRECTORY="+releaseDir)
	}

	if j.s.Runtime == site.PHP {
		env = append(env,
			"SERVERDOG_PHP="+phpfpm.Binary(j.s.PHPVersion),
			"SERVERDOG_COMPOSER="+filepath.Join(j.r.Paths.File(paths.PHPHelperBin(j.s.PHPVersion)), "composer"),
		)
	}

	return env, nil
}
