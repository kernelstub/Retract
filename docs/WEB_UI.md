# Web UI

The web UI is a local report workbench built with React, Vite, Tailwind, and local shadcn-style components.

## Serve

```sh
bin/retract sample.exe --full --serve --addr 127.0.0.1:8787
```

Open:

```text
http://127.0.0.1:8787
```

## Generated Bundle

The built frontend is copied into:

```text
output/<filename>/web/
```

The server exposes:

```text
/              web UI
/api/report    reports/report.json
/files/        report artifact file browser
```

## Views

- Overview
- Triage
- File Info
- Hashes
- Protections
- Sections
- Imports
- Strings
- Embedded
- Disassembly / C
- Symbols
- Visualize
- Vulnerabilities
- Deep Analysis
- Explorer
- Artifacts

## Markdown Reader

Markdown reports can be opened from the web UI in an in-browser modal reader.

## Static Use

The generated `web/index.html` can be opened from the output directory, but the best experience is through `--serve` because `/api/report` and `/files/` are available.
