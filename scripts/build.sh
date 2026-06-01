#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p .cache/go-build bin

if [ -d web ]; then
  (cd web && npm install && npm run build)
fi

GOCACHE="$ROOT/.cache/go-build" CGO_ENABLED=0 go build -buildvcs=false -o "$ROOT/bin/retract" ./cmd/retract

printf 'built %s\n' "$ROOT/bin/retract"
