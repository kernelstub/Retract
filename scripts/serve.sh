#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

TARGET="${1:-}"
OUT="${2:-output}"
ADDR="${3:-127.0.0.1:8787}"

if [ -z "$TARGET" ]; then
  printf 'usage: scripts/serve.sh <file> [output-dir] [addr]\n' >&2
  exit 2
fi

if [ ! -x "$ROOT/bin/retract" ]; then
  "$ROOT/scripts/build.sh"
fi

"$ROOT/bin/retract" "$TARGET" --full --verbose -o "$OUT" --serve --addr "$ADDR"
