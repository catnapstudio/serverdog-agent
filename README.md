# serverdog-agent

The open-source agent that [ServerDog](https://serverdog.app) installs on the servers it manages. ServerDog is a Mac app; this is the only part of it that runs on your server, and it is here so you can read what it does.

## How it runs

- One Go binary, `/usr/local/bin/serverdog-agent`, started by systemd as root.
- It listens only on a Unix socket, `/run/serverdog/agent.sock`, with mode `0600`. It opens no network port.
- The Mac app reaches the socket by forwarding it over your own SSH connection. Whoever can't log in as root over SSH can't talk to the agent.
- It has no account, sends nothing to ServerDog's makers and never updates itself. The app uploads a new binary over SSH when you choose to update.

## What it does

Everything is done on request from the app, as root for system configuration and as the site's own Linux user for anything inside a site's home.

- **Sites:** Nginx configuration, PHP-FPM pools, Node services, a placeholder page until the first deploy, redirects and password protection.
- **Deploys:** fetch a repository with a per-site read-only deploy key, run the site's deploy script as the site's user, switch releases with zero downtime, roll back, and deploy when a branch gets a new commit.
- **Certificates:** Let's Encrypt over HTTP-01, renewal, signing requests and uploaded certificates.
- **Databases:** create databases and users on MySQL, MariaDB or PostgreSQL, and back them up to an S3-compatible bucket.
- **Processes and jobs:** queue workers and other long-running processes as systemd units, scheduled jobs through cron.
- **The server:** the UFW firewall, SSH keys, PHP versions and settings, system services, automatic updates, a private network between servers, logs, load and disk history, and checks for common problems.

Each deploy runs in its own systemd unit, so it survives an agent restart or update.

## Connections it makes

The agent accepts none. It makes these, and only for the feature named:

| To | When |
|---|---|
| A site's Git host (`git`, `ssh-keyscan`) | Deploying, testing access, trusting a host key |
| Let's Encrypt | Issuing and renewing certificates |
| A domain's nameservers, and the domain itself over HTTP | Checking that a domain points at the server |
| Package repositories (apt) | Installing a PHP version, applying updates |
| GitHub's release downloads | Installing FrankenPHP for Laravel Octane |
| The bucket you configure | Database backups |
| The webhooks you configure (Slack, Discord or your own) | Deploy results and alerts |

A site's deploy script and the site itself make their own connections; those are yours, not the agent's.

## The protocol

The app and the agent speak gRPC over the socket. The services and messages are in [`proto/serverdog/agent/v1`](proto/serverdog/agent/v1).

The agent reports a protocol number, a single integer that goes up whenever the API gains something. The app reads it and only offers what the agent on that server supports, so a newer app keeps working with an older agent. What each number added is listed in [`internal/version/version.go`](internal/version/version.go).

Errors follow one convention: the first line of the status message is a one-sentence summary, and anything after a blank line is detail, such as the output of `nginx -t`.

## Build

    make generate   # regenerate Go code from proto/ (needs buf)
    make test
    make dist       # dist/serverdog-agent-linux-{amd64,arm64} and SHA256SUMS

To see which build a server runs, read the agent's start line in `journalctl -u serverdog-agent`, which gives its version and commit, and compare `sha256sum /usr/local/bin/serverdog-agent` with a build of that tag.

## Test

    make test         # unit tests; no root needed
    make pebbletest   # the ACME client against a local Pebble
    make vmtest       # the real-system tests on Ubuntu 24.04 and 26.04 Lima VMs

## Security

Please report a vulnerability privately to support@serverdog.app, not in a public issue.

## License

Apache-2.0
