## 2026-06-04

### Added

- Added a stronger x86/x64 disassembly path with REX and ModRM-aware decoding for common instructions, stack operands, conditional branches, indirect calls, and indirect jumps.
- Added a more capable C-like decompiler that recovers stack locals, labels, branch conditions, calls, arithmetic, bitwise operations, and richer function metadata.
- Added reverse-engineering workspace artifacts used by common RE tools:
  - `deep/function_tags.json` and `deep/function_tags.csv` for auto tags such as leaf functions, wrappers, parser/state-machine candidates, no-return candidates, and large stack frames.
  - `deep/annotations.json` and `deep/annotations.csv` for auto comments and notebook-style analyst notes.
  - `deep/jump_tables.json` and `deep/jump_tables.csv` for indirect branch and dense-branch jump-table candidates.
- Added additional RE-tool style datasets:
  - `deep/api_call_sites.json` and `deep/api_call_sites.csv` for resolved imported API call sites and likely calling-convention argument registers.
  - `deep/string_references.json` and `deep/string_references.csv` for instruction-to-string/data reference candidates.
  - `deep/stack_frames.json` and `deep/stack_frames.csv` for per-function stack frame summaries, locals, arguments, and saved registers.
  - `deep/basic_block_notes.json` and `deep/basic_block_notes.csv` for CFG block annotations such as terminal blocks, branches, and loop backedges.
  - `deep/decompiler_hints.json` and `deep/decompiler_hints.csv` for address-level hints such as zeroing idioms, condition sources, call-site review points, address calculations, and undecoded bytes.
- Added advanced RE triage artifacts:
  - `deep/function_clusters.json` and `deep/function_clusters.csv` for SimHash and function-shape clustering.
  - `deep/hot_paths.json` and `deep/hot_paths.csv` for ranked manual-audit paths.
  - `deep/patch_points.json` and `deep/patch_points.csv` for conditional branch, call-site, padding, and breakpoint patch candidates.
  - `deep/calling_conventions.json` and `deep/calling_conventions.csv` for calling-convention and argument-storage guesses.
  - `deep/unpacking_hints.json` and `deep/unpacking_hints.csv` for high-entropy, WX, overlay, loader, and self-modifying-code guidance.
  - `deep/type_hints.json` and `deep/type_hints.csv` for propagated type hints from API calls and string references.
- Added advanced triage and indicator panes:
  - `deep/timeline.json` and `deep/timeline.csv` for ordered analysis events.
  - `deep/capability_matrix.json` and `deep/capability_matrix.csv` for scored capability rollups.
  - `deep/anti_analysis.json` and `deep/anti_analysis.csv` for anti-debug, VM, sandbox, and tool-detection signals.
  - `deep/crypto_indicators.json` and `deep/crypto_indicators.csv` for crypto APIs and constants.
  - `deep/persistence_indicators.json` and `deep/persistence_indicators.csv` for registry, service, scheduled-task, startup, and file persistence hints.
  - `deep/syscall_indicators.json` and `deep/syscall_indicators.csv` for syscall, interrupt, segment-register, and low-level execution hints.
- Extended `project/retract_project.json` with function tags, annotations, jump-table candidates, API call sites, string references, stack frames, block notes, decompiler hints, function clusters, hot paths, patch points, calling conventions, unpacking hints, and type hints.
- Added external RE-tool helper exports:
  - `project/labels.map` for address-to-name mappings.
  - `project/rizin_radare2.r2` for radare2/Rizin labels and comments.
  - `project/ghidra_bookmarks.tsv` for bookmark/comment style imports.
  - `project/ida_names_comments.idc` for IDA-style names and comments.
- Added focused tests for ModRM stack/branch decoding, decompiler recovery of locals, labels, and conditions, and RE workspace artifact generation.

### Changed

- Expanded `reports/reverse_engineering.md` to include function tags, jump-table candidates, auto annotations, call sites, string references, stack frames, decompiler hints, hot paths, function clusters, patch points, unpacking hints, calling-convention guesses, and propagated type hints.
- Expanded `deep/analyst_workflow.md` to include RE workspace tags, jump-table candidates, call sites, string references, hot paths, unpacking hints, and function clusters.
- Added the advanced RE Workspace view to the React web UI and surfaced hot paths, patch points, API call sites, calling conventions, clusters, unpacking hints, type hints, and decompiler hints.
- Expanded the React RE Workspace and Deep views with timeline, capability matrix, and indicator panes.
- Added an Advanced RE section to the fallback generated web index.
- Updated README and output documentation to list the new reverse-engineering artifacts.

### Verification

- Ran the Go test suite with a workspace-safe cache:

```sh
GOCACHE=/tmp/retract-gocache CGO_ENABLED=0 go test ./...
```
