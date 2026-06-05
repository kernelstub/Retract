# retract

The project is designed for defensive reverse engineering, malware triage, exploitability review, and binary metadata inspection.

<img width="1640" height="856" alt="image" src="https://github.com/user-attachments/assets/9a9bdb22-7ded-485f-9c54-ad6600125299" />


## Features

- Binary loading for PE, ELF, Mach-O, and raw files.
- PE analysis for headers, sections, imports, exports, TLS, relocations, certificates, debug directory, resources, load configuration, overlay, and mitigations.
- ELF and Mach-O parsing for headers, sections, symbols, imports, exports, architecture, entry point, entropy, and suspicious section traits.
- String extraction for UTF-8-compatible and UTF-16LE strings with automatic categorization.
- Entropy analysis, byte histogram, high-entropy region detection, and section maps.
- x86/x64 entry-point disassembly, CFG generation, function recovery, call graph, and pseudocode output.
- Reverse-engineering inference for variables, types, structures, xrefs, function metrics, auto annotations, function tags, jump-table candidates, API call sites, string references, stack frames, basic-block notes, decompiler hints, function clusters, hot paths, patch points, calling-convention guesses, unpacking hints, propagated type hints, analysis timelines, capability scoring, anti-analysis indicators, crypto indicators, persistence indicators, syscall hints, and recovered C-like source.
- Vulnerability-oriented static heuristics for unsafe APIs, memory permissions, missing mitigations, packed code, UAF/OOB/BOF review surfaces, taint surfaces, and audit-priority functions.
- Deep-analysis database with memory map, API surface, IOC rollup, detection rules, search index, def-use chains, taint traces, graph analysis, hex bookmarks, RE workspace annotations, call-site/reference maps, indicator families, capability matrices, and project state.
- RE-tool export helpers for labels, comments, bookmarks, and command scripts targeting map-file, radare2/Rizin, Ghidra-oriented TSV, and IDA IDC workflows.
- React/Vite web workbench served locally with `--serve`.
- JSON, CSV, Markdown, DOT, text, C-like source, YARA-like, and STIX-lite outputs.

## Install

Requirements:

- Go 1.22 or newer
- Node.js and npm for building the web UI

Build the final binary:

```sh
scripts/build.sh
```

The binary is written to:

```text
bin/retract
```

Verify:

```sh
bin/retract --version
```

## Quick Start

Analyze a file:

```sh
bin/retract sample.exe
```

Run deeper analysis:

```sh
bin/retract sample.exe --full --verbose
```

Write output to a specific directory:

```sh
bin/retract sample.exe --full -o cases
```

Serve the generated web UI:

```sh
bin/retract sample.exe --full --serve --addr 127.0.0.1:8787
```

Use the helper script:

```sh
scripts/analyze.sh sample.exe output
scripts/serve.sh sample.exe output 127.0.0.1:8787
```

## CLI

```text
Usage:
  retract <file> [options]

Core:
  -o <dir>              Output directory (default: output)
  --format <name>       Force format: auto, pe, elf, macho, raw
  --json                Print JSON report to stdout
  --quiet               Suppress the console summary
  --verbose             Include top findings in the console summary
  --version             Print version
  --case <id>           Case or ticket identifier to embed in reports
  --serve               Serve the generated report in a local web UI
  --addr <host:port>    Address for --serve

Analysis depth:
  --full                Deeper defaults for entropy and disassembly
  --min-string <n>      Minimum string length
  --no-disasm           Skip disassembly, functions, and CFG
  --disasm-bytes <n>    Max bytes to disassemble from entry point
  --window <n>          Entropy sliding window size
  --step <n>            Entropy sliding window step

Artifacts:
  --no-visuals          Skip entropy/section/histogram PNGs
```

More examples are in [docs/USAGE.md](docs/USAGE.md).

## Output Layout

By default, `retract` writes:

```text
output/<filename>/
```

Important directories:

- `reports/`: executive, triage, technical, indicators, vulnerabilities, reverse-engineering, and full JSON reports.
- `metadata/`: hashes, format intelligence, and binary summary.
- `headers/`: parsed executable headers and security metadata.
- `sections/`: section table and dumped section bytes.
- `imports/`, `exports/`: API and symbol surfaces.
- `strings/`: categorized string extraction.
- `entropy/`: file, section, sliding-window, high-entropy, and byte histogram data.
- `disassembly/`, `control_flow/`, `functions/`, `pseudocode/`, `source/`: code analysis artifacts.
- `symbols/`: inferred variables, types, structures, and xrefs.
- `deep/`: advanced analysis database artifacts.
- `project/`: saved project database.
- `web/`: generated web workbench bundle.

Detailed artifact documentation is in [docs/OUTPUT.md](docs/OUTPUT.md).

## Architecture

`retract` is organized as a modular analysis pipeline:

```text
cmd/retract      CLI entry point
pkg/api          public report schema and options
internal/analyzer orchestration pipeline
internal/formats PE, ELF, Mach-O, raw format parsing
internal/disasm  x86/x64 disassembly
internal/cfg     basic blocks, functions, CFG, DOT
internal/re      reverse-engineering inference
internal/deep    workspace database, graph, data-flow, hex, search index
internal/vulns   vulnerability-oriented static heuristics
internal/output  artifact writer
internal/reports markdown, text, STIX-lite, YARA-like reports
internal/webui   local report server and web bundle integration
web              React/Vite/Tailwind frontend
scripts          build, test, analyze, serve, clean helpers
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Scripts

```sh
scripts/build.sh
scripts/test.sh
scripts/analyze.sh <file> [output-dir]
scripts/serve.sh <file> [output-dir] [addr]
scripts/clean.sh
```

## Safety

`retract` performs static analysis. It does not execute analyzed binaries.
