#!/usr/bin/env bash
# Runs the acmeclient tests against a local Pebble (Let's Encrypt's test server). Usage: scripts/pebble-test.sh
set -euo pipefail

VERSION=v2.10.1
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/dist/pebble"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
SRC="$DIR/pebble-${VERSION#v}"

mkdir -p "$DIR"
if [ ! -x "$DIR/pebble" ]; then
  curl -fsSL "https://github.com/letsencrypt/pebble/releases/download/$VERSION/pebble-$OS-$ARCH.tar.gz" | tar -xz -C "$DIR"
  cp "$DIR/pebble-$OS-$ARCH/$OS/$ARCH/pebble" "$DIR/pebble"
  chmod +x "$DIR/pebble"
  curl -fsSL "https://github.com/letsencrypt/pebble/archive/refs/tags/$VERSION.tar.gz" | tar -xz -C "$DIR"
fi

(cd "$SRC" && PEBBLE_VA_ALWAYS_VALID=1 PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 exec "$DIR/pebble" -config test/config/pebble-config.json > "$DIR/pebble.log" 2>&1) &
PEBBLE=$!
trap 'kill "$PEBBLE" 2> /dev/null || true' EXIT

for _ in $(seq 1 50); do
  curl -fsk https://localhost:14000/dir > /dev/null 2>&1 && break
  sleep 0.2
done

cd "$ROOT"
PEBBLE_DIRECTORY=https://localhost:14000/dir PEBBLE_CA="$SRC/test/certs/pebble.minica.pem" go test -tags pebble -count=1 ./internal/acmeclient
