#!/usr/bin/env bash
# Runs the vmtest suite as root on a Lima VM. Usage: scripts/vm-test.sh <ubuntu-24.04|ubuntu-26.04> [test flags]
# Test flags (e.g. -test.run TestNodeSite) go to the test binary; without any, the VM is restarted afterwards to check
# the port guard is attached at boot.
# The VM is kept for the next run; delete it with: limactl delete -f serverdog-agent-<template without dots>
set -euo pipefail

TEMPLATE="${1:?usage: scripts/vm-test.sh <ubuntu-24.04|ubuntu-26.04> [test flags]}"
shift
NAME="serverdog-agent-${TEMPLATE//./}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
OUT="$ROOT/dist/vm"

mkdir -p "$OUT"
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -o "$OUT/serverdog-agent" ./cmd/serverdog-agent)
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go test -c -tags vmtest -o "$OUT/integration.test" ./internal/integration)

if ! limactl list --quiet | grep -qx "$NAME"; then
  limactl create --name "$NAME" --cpus 2 --memory 4 --disk 20 --tty=false "template://$TEMPLATE"
fi
limactl start --tty=false "$NAME"

limactl copy "$OUT/serverdog-agent" "$NAME:/tmp/serverdog-agent"
limactl copy "$OUT/integration.test" "$NAME:/tmp/integration.test"
limactl copy "$ROOT/deploy/serverdog-agent.service" "$NAME:/tmp/serverdog-agent.service"
limactl copy "$ROOT/internal/integration/prepare.sh" "$NAME:/tmp/prepare.sh"

limactl shell "$NAME" sudo bash /tmp/prepare.sh
limactl shell "$NAME" sudo /tmp/integration.test -test.v -test.timeout 20m "$@"

if [ "$#" -eq 0 ]; then
  # A forced stop is a power cut: files written in the last seconds, like the agent's unit, would come back empty.
  limactl shell "$NAME" sync
  limactl stop --force "$NAME"
  limactl start --tty=false "$NAME"
  # /tmp may be a tmpfs that the restart emptied.
  limactl copy "$OUT/integration.test" "$NAME:/tmp/integration.test"
  limactl shell "$NAME" sudo env SERVERDOG_AFTER_REBOOT=1 /tmp/integration.test -test.v -test.run '^(TestPortGuardIsAttachedAtBoot|TestServicesStartBeforeTheirPrivateAddressExists)$'
fi
