# Output

By default:

```text
output/<filename>/
```

## Top-Level Directories

```text
control_flow/
deep/
disassembly/
entropy/
exports/
functions/
headers/
imports/
metadata/
pseudocode/
project/
raw/
reports/
resources/
sections/
signatures/
source/
strings/
symbols/
visuals/
vulnerabilities/
web/
yara_like/
```

## Important Files

### Reports

- `reports/report.json`: complete structured report.
- `reports/summary.md`: compact analyst summary.
- `reports/triage.md`: first-read triage checklist.
- `reports/executive.md`: concise risk summary.
- `reports/technical.md`: technical details.
- `reports/indicators.md`: hashes and extracted indicators.
- `reports/vulnerabilities.md`: vulnerability-oriented review.
- `reports/reverse_engineering.md`: RE notebook.
- `reports/evidence_index.md`: artifact index.
- `reports/recommendations.md`: follow-up actions.
- `reports/report.txt`: plain text report.

### Metadata

- `metadata/metadata.json`
- `metadata/file_info.json`
- `metadata/binary.json`
- `metadata/hashes.txt`

### Format Data

- `headers/*.json`
- `sections/sections.json`
- `sections/sections.csv`
- `sections/*.bin`
- `imports/imports.json`
- `imports/imports.csv`
- `imports/dll_summary.csv`
- `exports/exports.json`
- `exports/exports.csv`

### Strings

- `strings/all_strings.txt`
- `strings/ascii.txt`
- `strings/unicode.txt`
- `strings/urls.txt`
- `strings/domains.txt`
- `strings/ips.txt`
- `strings/registry_keys.txt`
- `strings/paths.txt`
- `strings/suspicious.txt`
- `strings/string_summary.json`

### Entropy

- `entropy/file_entropy.json`
- `entropy/section_entropy.json`
- `entropy/sliding_entropy.csv`
- `entropy/high_entropy_regions.csv`
- `entropy/byte_histogram.csv`

### Code Analysis

- `disassembly/entry.asm`
- `disassembly/functions/*.asm`
- `control_flow/cfg.json`
- `control_flow/cfg.dot`
- `functions/functions.json`
- `functions/functions.csv`
- `functions/function_insights.json`
- `functions/function_insights.csv`
- `functions/call_graph.json`
- `pseudocode/*.c`
- `source/reconstructed.c`
- `source/functions/*.c`

### Symbols and Xrefs

- `symbols/inferred_variables.json`
- `symbols/inferred_types.json`
- `symbols/struct_candidates.json`
- `symbols/xrefs.json`
- `symbols/xrefs.csv`

### Deep Analysis

- `deep/deep_analysis.json`
- `deep/memory_map.json`
- `deep/memory_map.csv`
- `deep/byte_patterns.json`
- `deep/byte_patterns.csv`
- `deep/instruction_stats.json`
- `deep/control_flow_metrics.json`
- `deep/api_surface.json`
- `deep/api_surface.csv`
- `deep/iocs.json`
- `deep/triage_tasks.json`
- `deep/triage_tasks.csv`
- `deep/detection_rules.json`
- `deep/detection_rules.csv`
- `deep/search_index.json`
- `deep/search_index.csv`
- `deep/hex_analysis.json`
- `deep/hex_bookmarks.csv`
- `deep/hex_search_hits.csv`
- `deep/data_flow.json`
- `deep/def_use_chains.csv`
- `deep/taint_traces.csv`
- `deep/graph_analysis.json`
- `deep/analyst_workflow.md`

### Project Database

- `project/retract_project.json`

This file contains a saved project-style database with functions, symbols, types, structs, labels, comments, xrefs, and graph state.

### Detection and Sharing

- `signatures/heuristics.json`
- `signatures/capabilities.json`
- `signatures/suspicious_findings.md`
- `signatures/attack_surface.md`
- `yara_like/indicators.yaralike`
- `raw/stix_lite.json`
