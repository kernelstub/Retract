# Deep Analysis

The `deep/` directory contains the normalized workspace-level analysis used by the web UI and downstream tooling.

## Memory Map

Files:

```text
deep/memory_map.json
deep/memory_map.csv
```

Contains:

- section or region name
- kind
- file offset
- file size
- virtual address
- virtual size
- permissions
- entropy
- notes

## API Surface

Files:

```text
deep/api_surface.json
deep/api_surface.csv
```

Contains categorized imported APIs with count, DLLs, representative functions, and risk level.

## Search Index

Files:

```text
deep/search_index.json
deep/search_index.csv
```

Contains searchable records for:

- sections
- imports
- exports
- strings
- functions
- xrefs
- vulnerabilities

## Hex Analysis

Files:

```text
deep/hex_analysis.json
deep/hex_bookmarks.csv
deep/hex_search_hits.csv
```

Contains:

- section bookmarks
- string bookmarks
- binary pattern hits
- address mappings

## Data Flow

Files:

```text
deep/data_flow.json
deep/def_use_chains.csv
deep/taint_traces.csv
```

Contains:

- register access observations
- def-use chains
- import-level taint traces from source primitives to sink primitives

## Graph Analysis

File:

```text
deep/graph_analysis.json
```

Contains:

- callers
- callees
- recursive call hints
- reachable functions
- dominator hints
- loop and back-edge hints

## Project Database

File:

```text
project/retract_project.json
```

Contains:

- sample metadata
- functions
- symbols
- inferred types
- struct candidates
- labels
- comments
- xrefs
- graph state

## Analyst Workflow

File:

```text
deep/analyst_workflow.md
```

Contains generated triage tasks, API surface summary, and detection-rule evidence.
