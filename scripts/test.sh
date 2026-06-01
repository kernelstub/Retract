#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p .cache/go-build

if [ -d web ] && [ -f web/package.json ]; then
  (cd web && npm install && npm run build)
fi

GOCACHE="$ROOT/.cache/go-build" CGO_ENABLED=0 go test ./...
GOCACHE="$ROOT/.cache/go-build" CGO_ENABLED=0 go build -buildvcs=false -o /tmp/retract-check ./cmd/retract

printf 'tests and build check passed\n'
