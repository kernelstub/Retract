# Development

## Requirements

- Go 1.22 or newer
- Node.js and npm

## Build

```sh
scripts/build.sh
```

This builds the web UI and the Go binary:

```text
bin/retract
```

## Test

```sh
scripts/test.sh
```

The test script builds the web UI, runs Go tests, and performs a Go build check.

## Manual Commands

Build frontend:

```sh
cd web
npm install
npm run build
```

Run Go tests:

```sh
GOCACHE="$PWD/.cache/go-build" CGO_ENABLED=0 go test ./...
```

Build Go binary:

```sh
GOCACHE="$PWD/.cache/go-build" CGO_ENABLED=0 go build -buildvcs=false -o bin/retract ./cmd/retract
```

## Scripts

```text
scripts/build.sh    build web UI and Go binary
scripts/test.sh     build web UI, run Go tests, and run Go build check
scripts/analyze.sh  analyze a target with --full --verbose
scripts/serve.sh    analyze a target and serve the web UI
scripts/clean.sh    remove generated binary and web build
```

## Repository Layout

```text
cmd/retract       CLI entry point
pkg/api           report schema
internal/analyzer analysis orchestration
internal/formats  binary parsers
internal/disasm   disassembly
internal/cfg      CFG and function discovery
internal/re       RE inference
internal/deep     deep workspace analysis
internal/vulns    vulnerability heuristics
internal/output   artifact writer
internal/reports  report renderers
internal/webui    local web server
web               frontend
scripts           build and workflow scripts
docs              documentation
```

## Documentation Updates

When adding a user-facing flag, artifact, output directory, or analysis pass, update:

- `README.md`
- `docs/USAGE.md`
- `docs/OUTPUT.md`
- `docs/ARCHITECTURE.md`
- `docs/DEEP_ANALYSIS.md` if it affects deep analysis
