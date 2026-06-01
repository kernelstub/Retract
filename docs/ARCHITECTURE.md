# Architecture

`retract` is a standalone static-analysis pipeline. The CLI reads a target file, detects or forces a format, runs format-specific parsers, performs common analysis passes, and writes a report bundle.

## Pipeline

```text
target file
  |
  v
cmd/retract
  |
  v
internal/analyzer
  |
  +-- format parsing
  |     +-- PE
  |     +-- ELF
  |     +-- Mach-O
  |     +-- raw
  |
  +-- strings
  +-- entropy
  +-- disassembly
  +-- CFG and function recovery
  +-- reverse-engineering inference
  +-- vulnerability heuristics
  +-- deep analysis database
  |
  v
internal/output
  |
  +-- JSON
  +-- CSV
  +-- Markdown
  +-- DOT
  +-- C-like source
  +-- web bundle
```

## Main Packages

### `cmd/retract`

CLI entry point. Defines flags, normalizes arguments, starts analysis, and optionally serves the report.

### `pkg/api`

Shared public schema for options, findings, metadata, sections, imports, symbols, deep analysis, project database, and final reports.

### `internal/analyzer`

Pipeline coordinator. It reads the input, detects the format, invokes parsers and analysis passes, computes risk, and calls the output writer.

### `internal/formats`

Native parsers for executable formats:

- `pe`: PE headers, directories, sections, imports, exports, resources, TLS, relocations, debug, certificate, load config, overlay, mitigations.
- `elf`: ELF headers, sections, dynamic imports, exports, architecture, endian, entry point.
- `macho`: Mach-O headers, sections, imported symbols, exports, architecture.

### `internal/disasm`

x86/x64 disassembly logic for entry-point analysis.

### `internal/cfg`

Builds basic blocks, function summaries, CFG JSON, and Graphviz DOT output.

### `internal/re`

Reverse-engineering inference:

- function metrics
- inferred variables
- inferred types
- struct candidates
- xrefs

### `internal/deep`

Workspace-level analysis:

- memory map
- byte patterns
- instruction stats
- control-flow metrics
- API surface
- IOC rollup
- triage tasks
- detection rules
- search index
- hex bookmarks and pattern hits
- data-flow records
- graph relationships
- saved project database

### `internal/vulns`

Static vulnerability heuristics for exploitability review and audit prioritization.

### `internal/output`

Writes the complete artifact bundle.

### `internal/webui`

Serves the generated report and copies the built React frontend into the report directory.

### `web`

React/Vite/Tailwind web workbench.

## Design Notes

- Analysis is static. Target binaries are not executed.
- External RE tools are not required.
- Outputs are designed for both human review and machine ingestion.
- The report schema is centralized in `pkg/api`.
- Format-specific parsers feed a common normalized model.
