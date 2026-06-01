#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

TARGET="${1:-}"
OUT="${2:-output}"

if [ -z "$TARGET" ]; then
  printf 'usage: scripts/analyze.sh <file> [output-dir]\n' >&2
  exit 2
fi

if [ ! -x "$ROOT/bin/retract" ]; then
  "$ROOT/scripts/build.sh"
fi

"$ROOT/bin/retract" "$TARGET" --full --verbose -o "$OUT"
