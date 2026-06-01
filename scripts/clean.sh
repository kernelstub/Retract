#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

rm -rf bin web/dist
printf 'removed generated binaries and web build\n'
