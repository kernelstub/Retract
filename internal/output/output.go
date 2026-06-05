package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"retract/internal/cfg"
	"retract/internal/decompiler"
	"retract/internal/entropy"
	"retract/internal/formats/pe"
	"retract/internal/reports"
	"retract/internal/utils"
	"retract/internal/visuals"
	"retract/internal/webui"
	"retract/pkg/api"
)

type Bundle struct {
	Report  api.AnalysisReport
	PE      *pe.File
	Windows []entropy.Window
	Root    string
	Data    []byte
	Visuals bool
}

func Write(b Bundle) error {
	dirs := []string{"metadata", "headers", "sections", "imports", "exports", "strings", "entropy", "disassembly/functions", "functions", "control_flow", "pseudocode", "source/functions", "symbols", "deep", "project", "resources/extracted", "resources/icons", "signatures", "yara_like", "reports", "raw", "visuals", "vulnerabilities", "web"}
	for _, d := range dirs {
		p, err := utils.SafeJoin(b.Root, d)
		if err != nil {
			return err
		}
		if err := utils.EnsureDir(p); err != nil {
			return err
		}
	}
	if err := writeJSON(b.Root, "metadata/metadata.json", b.Report.Metadata); err != nil {
		return err
	}
	_ = writeJSON(b.Root, "metadata/file_info.json", b.Report.FileInfo)
	_ = writeJSON(b.Root, "metadata/binary.json", b.Report.Binary)
	if err := writeText(b.Root, "metadata/hashes.txt", fmt.Sprintf("MD5    %s\nSHA1   %s\nSHA256 %s\nSHA512 %s\n", b.Report.Metadata.MD5, b.Report.Metadata.SHA1, b.Report.Metadata.SHA256, b.Report.Metadata.SHA512)); err != nil {
		return err
	}
	if b.PE != nil {
		_ = writeJSON(b.Root, "headers/dos_header.json", b.PE.Headers.DOS)
		_ = writeJSON(b.Root, "headers/coff_header.json", b.PE.Headers.COFF)
		_ = writeJSON(b.Root, "headers/optional_header.json", b.PE.Headers.Optional)
		_ = writeJSON(b.Root, "headers/data_directories.json", b.PE.Headers.Optional.DataDirectories)
	}
	_ = writeJSON(b.Root, "sections/sections.json", b.Report.Sections)
	_ = writeSectionsCSV(b.Root, b.Report.Sections)
	_ = writeSectionBins(b.Root, b.PE)
	_ = writeJSON(b.Root, "imports/imports.json", b.Report.Imports)
	_ = writeImportsCSV(b.Root, b.Report.Imports)
	_ = writeImportDLLSummaryCSV(b.Root, b.Report.Imports)
	_ = writeJSON(b.Root, "imports/import_summary.json", b.Report.ImportSummary)
	_ = writeText(b.Root, "imports/suspicious_imports.md", reports.FindingsMarkdown(filterFindings(b.Report.Findings, "import")))
	_ = writeJSON(b.Root, "exports/exports.json", b.Report.Exports)
	_ = writeExportsCSV(b.Root, b.Report.Exports)
	_ = writeJSON(b.Root, "headers/security_features.json", b.Report.Security)
	_ = writeJSON(b.Root, "headers/debug_directory.json", b.Report.DebugEntries)
	_ = writeJSON(b.Root, "headers/certificate.json", b.Report.Certificate)
	_ = writeJSON(b.Root, "headers/overlay.json", b.Report.Overlay)
	_ = writeJSON(b.Root, "headers/load_config.json", b.Report.LoadConfig)
	_ = writeStrings(b.Root, b.Report.Strings)
	_ = writeJSON(b.Root, "strings/string_summary.json", b.Report.StringSummary)
	_ = writeJSON(b.Root, "entropy/file_entropy.json", b.Report.Entropy)
	_ = writeJSON(b.Root, "entropy/section_entropy.json", b.Report.Sections)
	_ = writeSlidingCSV(b.Root, b.Windows)
	_ = writeHighEntropyCSV(b.Root, b.Windows)
	_ = writeHistogramCSV(b.Root, b.Report.ByteHistogram)
	_ = writeDisassembly(b.Root, b.Report.Instructions)
	_ = writeJSON(b.Root, "functions/functions.json", b.Report.Functions)
	_ = writeJSON(b.Root, "functions/function_insights.json", b.Report.FunctionInsights)
	_ = writeJSON(b.Root, "functions/call_graph.json", callGraph(b.Report.Functions))
	_ = writeFunctionsCSV(b.Root, b.Report.Functions)
	_ = writeFunctionInsightsCSV(b.Root, b.Report.FunctionInsights)
	_ = writeJSON(b.Root, "symbols/inferred_variables.json", b.Report.InferredVariables)
	_ = writeJSON(b.Root, "symbols/inferred_types.json", b.Report.InferredTypes)
	_ = writeJSON(b.Root, "symbols/struct_candidates.json", b.Report.StructCandidates)
	_ = writeJSON(b.Root, "symbols/xrefs.json", b.Report.Xrefs)
	_ = writeXrefsCSV(b.Root, b.Report.Xrefs)
	_ = writeDeepAnalysis(b.Root, b.Report.DeepAnalysis)
	_ = writeJSON(b.Root, "control_flow/cfg.json", b.Report.Blocks)
	_ = writeText(b.Root, "control_flow/cfg.dot", cfg.DOT(b.Report.Blocks))
	_ = writePseudocode(b.Root, b.Report.Functions, b.Report.Instructions)
	_ = writeSource(b.Root, b.Report)
	_ = writeJSON(b.Root, "signatures/heuristics.json", b.Report.Findings)
	_ = writeJSON(b.Root, "signatures/capabilities.json", b.Report.Capabilities)
	_ = writeJSON(b.Root, "signatures/finding_summary.json", b.Report.FindingSummary)
	_ = writeJSON(b.Root, "signatures/function_fingerprints.json", b.Report.DeepAnalysis.Fingerprints)
	_ = writeJSON(b.Root, "signatures/signature_matches.json", b.Report.DeepAnalysis.Signatures)
	_ = writeFunctionFingerprintsCSV(b.Root, b.Report.DeepAnalysis.Fingerprints)
	_ = writeSignatureMatchesCSV(b.Root, b.Report.DeepAnalysis.Signatures)
	_ = writeText(b.Root, "signatures/suspicious_findings.md", reports.FindingsMarkdown(b.Report.Findings))
	_ = writeText(b.Root, "signatures/attack_surface.md", reports.AttackSurface(b.Report))
	_ = writeText(b.Root, "yara_like/indicators.yaralike", reports.YaraLike(b.Report))
	_ = writeJSON(b.Root, "reports/report.json", b.Report)
	_ = writeText(b.Root, "reports/summary.md", reports.Markdown(b.Report))
	_ = writeText(b.Root, "reports/triage.md", reports.Triage(b.Report))
	_ = writeText(b.Root, "reports/executive.md", reports.Executive(b.Report))
	_ = writeText(b.Root, "reports/technical.md", reports.Technical(b.Report))
	_ = writeText(b.Root, "reports/indicators.md", reports.Indicators(b.Report))
	_ = writeText(b.Root, "reports/evidence_index.md", reports.EvidenceIndex(b.Report))
	_ = writeText(b.Root, "reports/recommendations.md", reports.Recommendations(b.Report))
	_ = writeText(b.Root, "reports/vulnerabilities.md", reports.Vulnerabilities(b.Report))
	_ = writeText(b.Root, "reports/reverse_engineering.md", reports.ReverseEngineering(b.Report))
	_ = writeText(b.Root, "reports/report.txt", reports.Text(b.Report))
	_ = writeJSON(b.Root, "vulnerabilities/vulnerabilities.json", b.Report.Vulnerabilities)
	_ = writeVulnerabilitiesCSV(b.Root, b.Report.Vulnerabilities)
	_ = writeText(b.Root, "vulnerabilities/vulnerabilities.md", reports.Vulnerabilities(b.Report))
	_ = writeJSON(b.Root, "raw/manifest.json", artifactManifest())
	_ = writeJSON(b.Root, "raw/embedded_artifacts.json", b.Report.EmbeddedArtifacts)
	_ = writeEmbeddedArtifactsCSV(b.Root, b.Report.EmbeddedArtifacts)
	_ = writeText(b.Root, "raw/hex_preview.txt", hexPreview(b.Data, 4096))
	_ = writeJSON(b.Root, "raw/stix_lite.json", reports.STIXLite(b.Report))
	if b.Visuals {
		_ = visuals.WriteAll(b.Root, b.Data, b.Report.Sections, b.Windows)
	}
	if b.PE != nil {
		if res := b.PE.ResourceDirectoryBytes(); len(res) > 0 {
			_ = writeBytes(b.Root, "resources/resource_directory.bin", res)
		}
	}
	_ = webui.WriteIndex(b.Root, b.Report)
	return nil
}

func writeJSON(root, rel string, v any) error {
	p, err := utils.SafeJoin(root, rel)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(b, '\n'), 0o644)
}

func writeText(root, rel, s string) error {
	p, err := utils.SafeJoin(root, rel)
	if err != nil {
		return err
	}
	return os.WriteFile(p, []byte(s), 0o644)
}

func writeCSV(root, rel string, header []string, rows [][]string) error {
	p, err := utils.SafeJoin(root, rel)
	if err != nil {
		return err
	}
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write(header)
	_ = w.WriteAll(rows)
	w.Flush()
	return w.Error()
}

func writeSectionsCSV(root string, sections []api.Section) error {
	rows := [][]string{}
	for _, s := range sections {
		rows = append(rows, []string{s.Name, fmt.Sprintf("0x%x", s.VirtualAddress), fmt.Sprintf("0x%x", s.RawOffset), fmt.Sprintf("%d", s.VirtualSize), fmt.Sprintf("%d", s.RawSize), s.Permissions, fmt.Sprintf("%.4f", s.Entropy), strings.Join(s.Suspicious, "; ")})
	}
	return writeCSV(root, "sections/sections.csv", []string{"name", "virtual_address", "raw_offset", "virtual_size", "raw_size", "permissions", "entropy", "suspicious"}, rows)
}

func writeImportsCSV(root string, imports []api.ImportFunction) error {
	rows := [][]string{}
	for _, i := range imports {
		rows = append(rows, []string{i.DLL, i.Name, fmt.Sprintf("%d", i.Ordinal), i.Address, strings.Join(i.Category, "; ")})
	}
	return writeCSV(root, "imports/imports.csv", []string{"dll", "name", "ordinal", "address", "categories"}, rows)
}

func writeImportDLLSummaryCSV(root string, imports []api.ImportFunction) error {
	counts := map[string]int{}
	for _, imp := range imports {
		counts[imp.DLL]++
	}
	rows := [][]string{}
	for dll, count := range counts {
		rows = append(rows, []string{dll, fmt.Sprintf("%d", count)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	return writeCSV(root, "imports/dll_summary.csv", []string{"dll", "import_count"}, rows)
}

func writeExportsCSV(root string, exports []api.ExportFunction) error {
	rows := [][]string{}
	for _, e := range exports {
		rows = append(rows, []string{e.Name, fmt.Sprintf("%d", e.Ordinal), e.RVA})
	}
	return writeCSV(root, "exports/exports.csv", []string{"name", "ordinal", "rva"}, rows)
}

func writeFunctionsCSV(root string, functions []api.Function) error {
	rows := [][]string{}
	for _, f := range functions {
		rows = append(rows, []string{f.Name, f.Start, f.End, fmt.Sprintf("%d", f.Size), fmt.Sprintf("%d", f.Blocks), strings.Join(f.Calls, "; ")})
	}
	return writeCSV(root, "functions/functions.csv", []string{"name", "start", "end", "size", "blocks", "calls"}, rows)
}

func writeFunctionInsightsCSV(root string, insights []api.FunctionInsight) error {
	rows := [][]string{}
	for _, f := range insights {
		rows = append(rows, []string{f.Name, f.Start, fmt.Sprintf("%d", f.InstructionCount), fmt.Sprintf("%d", f.CallCount), fmt.Sprintf("%d", f.BranchCount), fmt.Sprintf("%d", f.ReturnCount), fmt.Sprintf("%d", f.EstimatedStack), fmt.Sprintf("%d", f.Complexity), strings.Join(f.RiskNotes, "; ")})
	}
	return writeCSV(root, "functions/function_insights.csv", []string{"name", "start", "instructions", "calls", "branches", "returns", "estimated_stack", "complexity", "risk_notes"}, rows)
}

func writeXrefsCSV(root string, xrefs []api.Xref) error {
	rows := [][]string{}
	for _, x := range xrefs {
		rows = append(rows, []string{x.From, x.To, x.Kind, x.Evidence})
	}
	return writeCSV(root, "symbols/xrefs.csv", []string{"from", "to", "kind", "evidence"}, rows)
}

func writeDeepAnalysis(root string, deep api.DeepAnalysis) error {
	_ = writeJSON(root, "deep/deep_analysis.json", deep)
	_ = writeJSON(root, "deep/memory_map.json", deep.MemoryMap)
	_ = writeJSON(root, "deep/byte_patterns.json", deep.BytePatterns)
	_ = writeJSON(root, "deep/instruction_stats.json", deep.InstructionStats)
	_ = writeJSON(root, "deep/control_flow_metrics.json", deep.ControlFlowMetrics)
	_ = writeJSON(root, "deep/api_surface.json", deep.APISurface)
	_ = writeJSON(root, "deep/iocs.json", deep.IOCs)
	_ = writeJSON(root, "deep/triage_tasks.json", deep.TriageTasks)
	_ = writeJSON(root, "deep/detection_rules.json", deep.DetectionRules)
	_ = writeJSON(root, "deep/search_index.json", deep.SearchIndex)
	_ = writeJSON(root, "deep/hex_analysis.json", deep.Hex)
	_ = writeJSON(root, "deep/data_flow.json", deep.DataFlow)
	_ = writeJSON(root, "deep/graph_analysis.json", deep.Graph)
	_ = writeJSON(root, "deep/fingerprints.json", deep.Fingerprints)
	_ = writeJSON(root, "deep/signatures.json", deep.Signatures)
	_ = writeJSON(root, "deep/function_tags.json", deep.FunctionTags)
	_ = writeJSON(root, "deep/annotations.json", deep.Annotations)
	_ = writeJSON(root, "deep/jump_tables.json", deep.JumpTables)
	_ = writeJSON(root, "deep/api_call_sites.json", deep.APICallSites)
	_ = writeJSON(root, "deep/string_references.json", deep.StringRefs)
	_ = writeJSON(root, "deep/stack_frames.json", deep.StackFrames)
	_ = writeJSON(root, "deep/basic_block_notes.json", deep.BlockNotes)
	_ = writeJSON(root, "deep/decompiler_hints.json", deep.DecompilerHints)
	_ = writeJSON(root, "deep/function_clusters.json", deep.FunctionClusters)
	_ = writeJSON(root, "deep/hot_paths.json", deep.HotPaths)
	_ = writeJSON(root, "deep/patch_points.json", deep.PatchPoints)
	_ = writeJSON(root, "deep/calling_conventions.json", deep.CallingConventions)
	_ = writeJSON(root, "deep/unpacking_hints.json", deep.UnpackingHints)
	_ = writeJSON(root, "deep/type_hints.json", deep.TypeHints)
	_ = writeJSON(root, "deep/timeline.json", deep.Timeline)
	_ = writeJSON(root, "deep/capability_matrix.json", deep.CapabilityMatrix)
	_ = writeJSON(root, "deep/anti_analysis.json", deep.AntiAnalysis)
	_ = writeJSON(root, "deep/crypto_indicators.json", deep.CryptoIndicators)
	_ = writeJSON(root, "deep/persistence_indicators.json", deep.Persistence)
	_ = writeJSON(root, "deep/syscall_indicators.json", deep.SyscallIndicators)
	_ = writeJSON(root, "project/retract_project.json", deep.Project)
	_ = writeREToolExports(root, deep.Project)
	_ = writeMemoryMapCSV(root, deep.MemoryMap)
	_ = writeBytePatternsCSV(root, deep.BytePatterns)
	_ = writeAPISurfaceCSV(root, deep.APISurface)
	_ = writeTriageTasksCSV(root, deep.TriageTasks)
	_ = writeDetectionRulesCSV(root, deep.DetectionRules)
	_ = writeSearchIndexCSV(root, deep.SearchIndex)
	_ = writeHexBookmarksCSV(root, deep.Hex.Bookmarks)
	_ = writeHexSearchHitsCSV(root, deep.Hex.SearchHits)
	_ = writeDataFlowCSV(root, deep.DataFlow)
	_ = writeFunctionFingerprintsCSV(root, deep.Fingerprints)
	_ = writeSignatureMatchesCSV(root, deep.Signatures)
	_ = writeFunctionTagsCSV(root, deep.FunctionTags)
	_ = writeAnnotationsCSV(root, deep.Annotations)
	_ = writeJumpTablesCSV(root, deep.JumpTables)
	_ = writeAPICallSitesCSV(root, deep.APICallSites)
	_ = writeStringRefsCSV(root, deep.StringRefs)
	_ = writeStackFramesCSV(root, deep.StackFrames)
	_ = writeBasicBlockNotesCSV(root, deep.BlockNotes)
	_ = writeDecompilerHintsCSV(root, deep.DecompilerHints)
	_ = writeFunctionClustersCSV(root, deep.FunctionClusters)
	_ = writeHotPathsCSV(root, deep.HotPaths)
	_ = writePatchPointsCSV(root, deep.PatchPoints)
	_ = writeCallingConventionsCSV(root, deep.CallingConventions)
	_ = writeUnpackingHintsCSV(root, deep.UnpackingHints)
	_ = writeTypeHintsCSV(root, deep.TypeHints)
	_ = writeTimelineCSV(root, deep.Timeline)
	_ = writeCapabilityMatrixCSV(root, deep.CapabilityMatrix)
	_ = writeIndicatorHitsCSV(root, "deep/anti_analysis.csv", deep.AntiAnalysis)
	_ = writeIndicatorHitsCSV(root, "deep/crypto_indicators.csv", deep.CryptoIndicators)
	_ = writeIndicatorHitsCSV(root, "deep/persistence_indicators.csv", deep.Persistence)
	_ = writeIndicatorHitsCSV(root, "deep/syscall_indicators.csv", deep.SyscallIndicators)
	_ = writeText(root, "deep/analyst_workflow.md", deepMarkdown(deep))
	return nil
}

func writeMemoryMapCSV(root string, regions []api.MemoryRegion) error {
	rows := [][]string{}
	for _, r := range regions {
		rows = append(rows, []string{r.Name, r.Kind, fmt.Sprintf("0x%x", r.FileOffset), fmt.Sprintf("%d", r.FileSize), r.VirtualAddr, fmt.Sprintf("%d", r.VirtualSize), r.Permissions, fmt.Sprintf("%.4f", r.Entropy), strings.Join(r.Notes, "; ")})
	}
	return writeCSV(root, "deep/memory_map.csv", []string{"name", "kind", "file_offset", "file_size", "virtual_address", "virtual_size", "permissions", "entropy", "notes"}, rows)
}

func writeBytePatternsCSV(root string, patterns []api.BytePattern) error {
	rows := [][]string{}
	for _, p := range patterns {
		rows = append(rows, []string{p.Pattern, fmt.Sprintf("%d", p.Size), fmt.Sprintf("%d", p.Count), fmt.Sprintf("%.8f", p.Ratio)})
	}
	return writeCSV(root, "deep/byte_patterns.csv", []string{"pattern", "size", "count", "ratio"}, rows)
}

func writeAPISurfaceCSV(root string, surface []api.APISurfaceEntry) error {
	rows := [][]string{}
	for _, s := range surface {
		rows = append(rows, []string{s.Category, fmt.Sprintf("%d", s.Count), strings.Join(s.DLLs, "; "), strings.Join(s.Functions, "; "), s.Risk})
	}
	return writeCSV(root, "deep/api_surface.csv", []string{"category", "count", "dlls", "functions", "risk"}, rows)
}

func writeTriageTasksCSV(root string, tasks []api.TriageTask) error {
	rows := [][]string{}
	for _, t := range tasks {
		rows = append(rows, []string{t.Priority, t.Title, t.Why, strings.Join(t.Actions, "; "), strings.Join(t.Artifacts, "; ")})
	}
	return writeCSV(root, "deep/triage_tasks.csv", []string{"priority", "title", "why", "actions", "artifacts"}, rows)
}

func writeDetectionRulesCSV(root string, rules []api.DetectionRule) error {
	rows := [][]string{}
	for _, r := range rules {
		rows = append(rows, []string{r.Name, r.Severity, fmt.Sprintf("%t", r.Matched), strings.Join(r.Evidence, "; "), r.Confidence})
	}
	return writeCSV(root, "deep/detection_rules.csv", []string{"name", "severity", "matched", "evidence", "confidence"}, rows)
}

func writeSearchIndexCSV(root string, entries []api.SearchEntry) error {
	rows := [][]string{}
	for _, e := range entries {
		rows = append(rows, []string{e.Kind, e.Name, e.Value, e.Location, strings.Join(e.Tags, "; ")})
	}
	return writeCSV(root, "deep/search_index.csv", []string{"kind", "name", "value", "location", "tags"}, rows)
}

func writeHexBookmarksCSV(root string, bookmarks []api.HexBookmark) error {
	rows := [][]string{}
	for _, b := range bookmarks {
		rows = append(rows, []string{b.Name, fmt.Sprintf("0x%x", b.Offset), fmt.Sprintf("%d", b.Size), b.Kind, b.Description, strings.Join(b.Tags, "; ")})
	}
	return writeCSV(root, "deep/hex_bookmarks.csv", []string{"name", "offset", "size", "kind", "description", "tags"}, rows)
}

func writeHexSearchHitsCSV(root string, hits []api.HexSearchHit) error {
	rows := [][]string{}
	for _, h := range hits {
		rows = append(rows, []string{h.Query, h.Kind, fmt.Sprintf("0x%x", h.Offset), fmt.Sprintf("%d", h.Size), h.Preview})
	}
	return writeCSV(root, "deep/hex_search_hits.csv", []string{"query", "kind", "offset", "size", "preview"}, rows)
}

func writeDataFlowCSV(root string, flow api.DataFlowAnalysis) error {
	rows := [][]string{}
	for _, c := range flow.DefUseChains {
		rows = append(rows, []string{c.Function, c.Register, c.Def, strings.Join(c.Uses, "; ")})
	}
	if err := writeCSV(root, "deep/def_use_chains.csv", []string{"function", "register", "def", "uses"}, rows); err != nil {
		return err
	}
	rows = [][]string{}
	for _, t := range flow.TaintTraces {
		rows = append(rows, []string{t.Source, t.Sink, strings.Join(t.Path, " -> "), t.Reason, t.Severity})
	}
	return writeCSV(root, "deep/taint_traces.csv", []string{"source", "sink", "path", "reason", "severity"}, rows)
}

func writeFunctionFingerprintsCSV(root string, fps []api.FunctionFingerprint) error {
	rows := [][]string{}
	for _, f := range fps {
		rows = append(rows, []string{f.Function, f.Start, f.End, f.InstructionHash, f.MnemonicHash, f.SimHash, fmt.Sprintf("%d", f.Size), fmt.Sprintf("%d", f.Instructions), strings.Join(f.Calls, "; "), strings.Join(f.Mnemonics, "; ")})
	}
	return writeCSV(root, "signatures/function_fingerprints.csv", []string{"function", "start", "end", "instruction_hash", "mnemonic_hash", "simhash", "size", "instructions", "calls", "mnemonics"}, rows)
}

func writeSignatureMatchesCSV(root string, sigs []api.SignatureMatch) error {
	rows := [][]string{}
	for _, s := range sigs {
		rows = append(rows, []string{s.Name, s.Kind, s.Confidence, s.Severity, strings.Join(s.Evidence, "; "), strings.Join(s.Tags, "; ")})
	}
	return writeCSV(root, "signatures/signature_matches.csv", []string{"name", "kind", "confidence", "severity", "evidence", "tags"}, rows)
}

func writeFunctionTagsCSV(root string, tags []api.FunctionTag) error {
	rows := [][]string{}
	for _, t := range tags {
		rows = append(rows, []string{t.Function, t.Start, t.Tag, t.Confidence, strings.Join(t.Evidence, "; ")})
	}
	return writeCSV(root, "deep/function_tags.csv", []string{"function", "start", "tag", "confidence", "evidence"}, rows)
}

func writeAnnotationsCSV(root string, annotations []api.REAnnotation) error {
	rows := [][]string{}
	for _, a := range annotations {
		rows = append(rows, []string{a.Address, a.Function, a.Kind, a.Severity, a.Text, strings.Join(a.Tags, "; ")})
	}
	return writeCSV(root, "deep/annotations.csv", []string{"address", "function", "kind", "severity", "text", "tags"}, rows)
}

func writeJumpTablesCSV(root string, jumpTables []api.JumpTableCandidate) error {
	rows := [][]string{}
	for _, jt := range jumpTables {
		rows = append(rows, []string{jt.Function, jt.Address, jt.Base, fmt.Sprintf("%d", jt.Entries), jt.Confidence, strings.Join(jt.Evidence, "; ")})
	}
	return writeCSV(root, "deep/jump_tables.csv", []string{"function", "address", "base", "entries", "confidence", "evidence"}, rows)
}

func writeAPICallSitesCSV(root string, callSites []api.APICallSite) error {
	rows := [][]string{}
	for _, cs := range callSites {
		rows = append(rows, []string{cs.Function, cs.Address, cs.API, strings.Join(cs.Category, "; "), strings.Join(cs.Arguments, "; "), cs.Confidence, cs.Evidence})
	}
	return writeCSV(root, "deep/api_call_sites.csv", []string{"function", "address", "api", "category", "arguments", "confidence", "evidence"}, rows)
}

func writeStringRefsCSV(root string, refs []api.StringReference) error {
	rows := [][]string{}
	for _, ref := range refs {
		rows = append(rows, []string{ref.Function, ref.Address, fmt.Sprintf("0x%x", ref.Offset), ref.Kind, ref.String, strings.Join(ref.Tags, "; "), ref.Confidence, ref.Evidence})
	}
	return writeCSV(root, "deep/string_references.csv", []string{"function", "address", "offset", "kind", "string", "tags", "confidence", "evidence"}, rows)
}

func writeStackFramesCSV(root string, frames []api.StackFrameLayout) error {
	rows := [][]string{}
	for _, frame := range frames {
		rows = append(rows, []string{frame.Function, fmt.Sprintf("0x%x", frame.FrameSize), fmt.Sprintf("%d", len(frame.Locals)), fmt.Sprintf("%d", len(frame.Arguments)), strings.Join(frame.SavedRegisters, "; "), strings.Join(frame.Evidence, "; ")})
	}
	return writeCSV(root, "deep/stack_frames.csv", []string{"function", "frame_size", "locals", "arguments", "saved_registers", "evidence"}, rows)
}

func writeBasicBlockNotesCSV(root string, notes []api.BasicBlockNote) error {
	rows := [][]string{}
	for _, note := range notes {
		rows = append(rows, []string{note.BlockID, note.Start, note.End, note.Kind, note.Severity, note.Text, strings.Join(note.Edges, "; ")})
	}
	return writeCSV(root, "deep/basic_block_notes.csv", []string{"block_id", "start", "end", "kind", "severity", "text", "edges"}, rows)
}

func writeDecompilerHintsCSV(root string, hints []api.DecompilerHint) error {
	rows := [][]string{}
	for _, hint := range hints {
		rows = append(rows, []string{hint.Function, hint.Address, hint.Kind, hint.Hint, hint.Confidence, hint.Evidence})
	}
	return writeCSV(root, "deep/decompiler_hints.csv", []string{"function", "address", "kind", "hint", "confidence", "evidence"}, rows)
}

func writeFunctionClustersCSV(root string, clusters []api.FunctionCluster) error {
	rows := [][]string{}
	for _, c := range clusters {
		rows = append(rows, []string{c.ID, c.Kind, strings.Join(c.Functions, "; "), fmt.Sprintf("%.4f", c.Score), c.Confidence, strings.Join(c.Evidence, "; ")})
	}
	return writeCSV(root, "deep/function_clusters.csv", []string{"id", "kind", "functions", "score", "confidence", "evidence"}, rows)
}

func writeHotPathsCSV(root string, paths []api.HotPath) error {
	rows := [][]string{}
	for _, p := range paths {
		rows = append(rows, []string{fmt.Sprintf("%d", p.Rank), p.Function, p.Start, fmt.Sprintf("%d", p.Score), strings.Join(p.Reasons, "; "), strings.Join(p.Artifacts, "; ")})
	}
	return writeCSV(root, "deep/hot_paths.csv", []string{"rank", "function", "start", "score", "reasons", "artifacts"}, rows)
}

func writePatchPointsCSV(root string, points []api.PatchPoint) error {
	rows := [][]string{}
	for _, p := range points {
		rows = append(rows, []string{p.Address, p.Function, p.Kind, p.Bytes, fmt.Sprintf("%d", p.Size), p.Risk, p.Confidence, strings.Join(p.Evidence, "; ")})
	}
	return writeCSV(root, "deep/patch_points.csv", []string{"address", "function", "kind", "bytes", "size", "risk", "confidence", "evidence"}, rows)
}

func writeCallingConventionsCSV(root string, guesses []api.CallingConventionGuess) error {
	rows := [][]string{}
	for _, g := range guesses {
		rows = append(rows, []string{g.Function, g.Start, g.Convention, strings.Join(g.ArgumentStorage, "; "), g.ReturnStorage, g.Confidence, strings.Join(g.Evidence, "; ")})
	}
	return writeCSV(root, "deep/calling_conventions.csv", []string{"function", "start", "convention", "arguments", "return", "confidence", "evidence"}, rows)
}

func writeUnpackingHintsCSV(root string, hints []api.UnpackingHint) error {
	rows := [][]string{}
	for _, h := range hints {
		rows = append(rows, []string{h.Region, h.Address, h.Kind, h.Priority, strings.Join(h.Actions, "; "), strings.Join(h.Evidence, "; "), h.Confidence})
	}
	return writeCSV(root, "deep/unpacking_hints.csv", []string{"region", "address", "kind", "priority", "actions", "evidence", "confidence"}, rows)
}

func writeTypeHintsCSV(root string, hints []api.TypePropagationHint) error {
	rows := [][]string{}
	for _, h := range hints {
		rows = append(rows, []string{h.Function, h.Address, h.Symbol, h.Type, h.Source, h.Confidence, strings.Join(h.Evidence, "; ")})
	}
	return writeCSV(root, "deep/type_hints.csv", []string{"function", "address", "symbol", "type", "source", "confidence", "evidence"}, rows)
}

func writeTimelineCSV(root string, events []api.AnalysisTimelineEvent) error {
	rows := [][]string{}
	for _, e := range events {
		rows = append(rows, []string{fmt.Sprintf("%d", e.Order), e.Phase, e.Title, e.Detail, e.Severity, strings.Join(e.Artifacts, "; ")})
	}
	return writeCSV(root, "deep/timeline.csv", []string{"order", "phase", "title", "detail", "severity", "artifacts"}, rows)
}

func writeCapabilityMatrixCSV(root string, entries []api.CapabilityMatrixEntry) error {
	rows := [][]string{}
	for _, e := range entries {
		rows = append(rows, []string{e.Capability, fmt.Sprintf("%d", e.Score), strings.Join(e.Signals, "; "), strings.Join(e.Artifacts, "; ")})
	}
	return writeCSV(root, "deep/capability_matrix.csv", []string{"capability", "score", "signals", "artifacts"}, rows)
}

func writeIndicatorHitsCSV(root, rel string, hits []api.IndicatorHit) error {
	rows := [][]string{}
	for _, h := range hits {
		rows = append(rows, []string{h.Kind, h.Name, h.Location, h.Function, h.Severity, h.Confidence, strings.Join(h.Evidence, "; ")})
	}
	return writeCSV(root, rel, []string{"kind", "name", "location", "function", "severity", "confidence", "evidence"}, rows)
}

func writeREToolExports(root string, project api.ProjectDatabase) error {
	var labels, r2, ghidra, idc strings.Builder
	idc.WriteString("#include <idc.idc>\n\nstatic main(void) {\n")
	for _, fn := range project.Functions {
		if fn.Start == "" {
			continue
		}
		name := safeSymbol(fn.Name)
		fmt.Fprintf(&labels, "%s %s\n", fn.Start, name)
		fmt.Fprintf(&r2, "af+ %s %d %s\n", fn.Start, fn.Size, name)
		fmt.Fprintf(&r2, "f sym.%s = %d @ %s\n", name, fn.Size, fn.Start)
		fmt.Fprintf(&idc, "  MakeName(%s, \"%s\");\n", idcAddr(fn.Start), idcEscape(name))
	}
	for _, label := range project.Labels {
		if label.Location == "" || label.Name == "" {
			continue
		}
		name := safeSymbol(label.Name)
		fmt.Fprintf(&labels, "%s %s\n", label.Location, name)
		fmt.Fprintf(&r2, "f label.%s @ %s\n", name, label.Location)
		fmt.Fprintf(&idc, "  MakeName(%s, \"%s\");\n", idcAddr(label.Location), idcEscape(name))
	}
	for _, comment := range project.Comments {
		if comment.Location == "" || comment.Value == "" {
			continue
		}
		text := strings.ReplaceAll(comment.Value, "\n", " ")
		fmt.Fprintf(&r2, "CCu %s @ %s\n", r2Escape(text), comment.Location)
		fmt.Fprintf(&ghidra, "%s\t%s\t%s\t%s\n", comment.Location, comment.Kind, comment.Name, text)
		fmt.Fprintf(&idc, "  MakeComm(%s, \"%s\");\n", idcAddr(comment.Location), idcEscape(text))
	}
	for _, a := range project.Annotations {
		if a.Address == "" || a.Text == "" {
			continue
		}
		text := strings.ReplaceAll(a.Text, "\n", " ")
		fmt.Fprintf(&r2, "CCu %s @ %s\n", r2Escape(text), a.Address)
		fmt.Fprintf(&ghidra, "%s\t%s\t%s\t%s\n", a.Address, a.Kind, a.Function, text)
		fmt.Fprintf(&idc, "  MakeComm(%s, \"%s\");\n", idcAddr(a.Address), idcEscape(text))
	}
	idc.WriteString("}\n")
	_ = writeText(root, "project/labels.map", labels.String())
	_ = writeText(root, "project/rizin_radare2.r2", r2.String())
	_ = writeText(root, "project/ghidra_bookmarks.tsv", "address\tcategory\tfunction\ttext\n"+ghidra.String())
	return writeText(root, "project/ida_names_comments.idc", idc.String())
}

func deepMarkdown(deep api.DeepAnalysis) string {
	var b strings.Builder
	b.WriteString("# Deep Analysis Workflow\n\n")
	b.WriteString("## Triage Tasks\n\n")
	for _, t := range deep.TriageTasks {
		fmt.Fprintf(&b, "- **%s** %s: %s\n", t.Priority, t.Title, t.Why)
		for _, a := range t.Actions {
			fmt.Fprintf(&b, "  - %s\n", a)
		}
	}
	b.WriteString("\n## API Surface\n\n")
	b.WriteString("| Category | Risk | Count | DLLs |\n|---|---:|---:|---|\n")
	for _, s := range deep.APISurface {
		fmt.Fprintf(&b, "| %s | %s | %d | %s |\n", s.Category, s.Risk, s.Count, strings.Join(s.DLLs, ", "))
	}
	b.WriteString("\n## Detection Rules\n\n")
	for _, r := range deep.DetectionRules {
		fmt.Fprintf(&b, "- [%t] **%s** (%s/%s): %s\n", r.Matched, r.Name, r.Severity, r.Confidence, strings.Join(r.Evidence, "; "))
	}
	b.WriteString("\n## Signatures\n\n")
	for _, s := range deep.Signatures {
		fmt.Fprintf(&b, "- **%s** `%s` confidence=%s severity=%s evidence=%s\n", s.Kind, s.Name, s.Confidence, s.Severity, strings.Join(s.Evidence, "; "))
	}
	b.WriteString("\n## Function Fingerprints\n\n")
	for i, f := range deep.Fingerprints {
		if i >= 50 {
			fmt.Fprintf(&b, "- %d additional fingerprints omitted from markdown; see `signatures/function_fingerprints.csv`.\n", len(deep.Fingerprints)-i)
			break
		}
		fmt.Fprintf(&b, "- `%s` %s simhash=%s instructions=%d\n", f.Function, f.Start, f.SimHash, f.Instructions)
	}
	b.WriteString("\n## Reverse Engineering Workspace\n\n")
	for i, t := range deep.FunctionTags {
		if i >= 50 {
			fmt.Fprintf(&b, "- %d additional function tags omitted from markdown; see `deep/function_tags.csv`.\n", len(deep.FunctionTags)-i)
			break
		}
		fmt.Fprintf(&b, "- `%s` tag=%s confidence=%s evidence=%s\n", t.Function, t.Tag, t.Confidence, strings.Join(t.Evidence, "; "))
	}
	for i, jt := range deep.JumpTables {
		if i >= 25 {
			fmt.Fprintf(&b, "- %d additional jump-table candidates omitted from markdown; see `deep/jump_tables.csv`.\n", len(deep.JumpTables)-i)
			break
		}
		fmt.Fprintf(&b, "- jump table candidate `%s` at %s confidence=%s evidence=%s\n", jt.Function, jt.Address, jt.Confidence, strings.Join(jt.Evidence, "; "))
	}
	b.WriteString("\n## Call Sites and References\n\n")
	for i, cs := range deep.APICallSites {
		if i >= 40 {
			fmt.Fprintf(&b, "- %d additional API call sites omitted from markdown; see `deep/api_call_sites.csv`.\n", len(deep.APICallSites)-i)
			break
		}
		fmt.Fprintf(&b, "- `%s` calls `%s` at %s categories=%s\n", cs.Function, cs.API, cs.Address, strings.Join(cs.Category, ", "))
	}
	for i, ref := range deep.StringRefs {
		if i >= 40 {
			fmt.Fprintf(&b, "- %d additional string references omitted from markdown; see `deep/string_references.csv`.\n", len(deep.StringRefs)-i)
			break
		}
		fmt.Fprintf(&b, "- `%s` references string at 0x%x from %s: `%s`\n", ref.Function, ref.Offset, ref.Address, ref.String)
	}
	b.WriteString("\n## Advanced RE Triage\n\n")
	for i, path := range deep.HotPaths {
		if i >= 30 {
			fmt.Fprintf(&b, "- %d additional hot paths omitted from markdown; see `deep/hot_paths.csv`.\n", len(deep.HotPaths)-i)
			break
		}
		fmt.Fprintf(&b, "- #%d `%s` score=%d reasons=%s\n", path.Rank, path.Function, path.Score, strings.Join(path.Reasons, "; "))
	}
	for i, hint := range deep.UnpackingHints {
		if i >= 30 {
			fmt.Fprintf(&b, "- %d additional unpacking hints omitted from markdown; see `deep/unpacking_hints.csv`.\n", len(deep.UnpackingHints)-i)
			break
		}
		fmt.Fprintf(&b, "- `%s` %s priority=%s confidence=%s evidence=%s\n", hint.Region, hint.Kind, hint.Priority, hint.Confidence, strings.Join(hint.Evidence, "; "))
	}
	for i, cluster := range deep.FunctionClusters {
		if i >= 20 {
			fmt.Fprintf(&b, "- %d additional clusters omitted from markdown; see `deep/function_clusters.csv`.\n", len(deep.FunctionClusters)-i)
			break
		}
		fmt.Fprintf(&b, "- cluster `%s` kind=%s functions=%s\n", cluster.ID, cluster.Kind, strings.Join(cluster.Functions, ", "))
	}
	b.WriteString("\n## Capability and Indicators\n\n")
	for i, cap := range deep.CapabilityMatrix {
		if i >= 30 {
			fmt.Fprintf(&b, "- %d additional capability rows omitted from markdown; see `deep/capability_matrix.csv`.\n", len(deep.CapabilityMatrix)-i)
			break
		}
		fmt.Fprintf(&b, "- `%s` score=%d signals=%s\n", cap.Capability, cap.Score, strings.Join(cap.Signals, "; "))
	}
	for i, hit := range append(append(append(deep.AntiAnalysis, deep.CryptoIndicators...), deep.Persistence...), deep.SyscallIndicators...) {
		if i >= 40 {
			b.WriteString("- additional indicators omitted from markdown; see `deep/*_indicators.csv`.\n")
			break
		}
		fmt.Fprintf(&b, "- `%s` %s at %s confidence=%s evidence=%s\n", hit.Kind, hit.Name, hit.Location, hit.Confidence, strings.Join(hit.Evidence, "; "))
	}
	return b.String()
}

func writeEmbeddedArtifactsCSV(root string, artifacts []api.EmbeddedArtifact) error {
	rows := [][]string{}
	for _, a := range artifacts {
		rows = append(rows, []string{fmt.Sprintf("0x%x", a.Offset), a.Type, a.Description})
	}
	return writeCSV(root, "raw/embedded_artifacts.csv", []string{"offset", "type", "description"}, rows)
}

func writeSlidingCSV(root string, wins []entropy.Window) error {
	rows := [][]string{}
	for _, w := range wins {
		rows = append(rows, []string{fmt.Sprintf("%d", w.Offset), fmt.Sprintf("%d", w.Size), fmt.Sprintf("%.4f", w.Entropy), fmt.Sprintf("%t", w.High)})
	}
	return writeCSV(root, "entropy/sliding_entropy.csv", []string{"offset", "size", "entropy", "high"}, rows)
}

func writeHighEntropyCSV(root string, wins []entropy.Window) error {
	rows := [][]string{}
	for _, w := range wins {
		if !w.High {
			continue
		}
		rows = append(rows, []string{fmt.Sprintf("0x%x", w.Offset), fmt.Sprintf("%d", w.Size), fmt.Sprintf("%.4f", w.Entropy)})
	}
	return writeCSV(root, "entropy/high_entropy_regions.csv", []string{"offset", "size", "entropy"}, rows)
}

func writeHistogramCSV(root string, hist []int) error {
	rows := [][]string{}
	for i, v := range hist {
		rows = append(rows, []string{fmt.Sprintf("%d", i), fmt.Sprintf("0x%02x", i), fmt.Sprintf("%d", v)})
	}
	return writeCSV(root, "entropy/byte_histogram.csv", []string{"byte_decimal", "byte_hex", "count"}, rows)
}

func writeStrings(root string, hits []api.StringHit) error {
	var all, ascii, uni strings.Builder
	cats := map[string]*strings.Builder{"urls.txt": {}, "ips.txt": {}, "domains.txt": {}, "registry_keys.txt": {}, "paths.txt": {}, "suspicious.txt": {}}
	for _, h := range hits {
		line := fmt.Sprintf("0x%x\t%s\t%s\n", h.Offset, h.Encoding, h.Value)
		all.WriteString(line)
		if h.Encoding == "utf-16le" {
			uni.WriteString(line)
		} else {
			ascii.WriteString(line)
		}
		for _, t := range h.Tags {
			switch t {
			case "url":
				cats["urls.txt"].WriteString(line)
			case "ip":
				cats["ips.txt"].WriteString(line)
			case "domain":
				cats["domains.txt"].WriteString(line)
			case "registry":
				cats["registry_keys.txt"].WriteString(line)
			case "path":
				cats["paths.txt"].WriteString(line)
			case "suspicious", "command", "crypto", "mutex-like", "user-agent":
				cats["suspicious.txt"].WriteString(line)
			}
		}
	}
	_ = writeText(root, "strings/all_strings.txt", all.String())
	_ = writeText(root, "strings/ascii.txt", ascii.String())
	_ = writeText(root, "strings/unicode.txt", uni.String())
	for name, b := range cats {
		_ = writeText(root, filepath.Join("strings", name), b.String())
	}
	return nil
}

func writeDisassembly(root string, ins []api.Instruction) error {
	var b strings.Builder
	for _, in := range ins {
		fmt.Fprintf(&b, "%s: %-16s %-8s %s\n", in.Address, in.Bytes, in.Mnemonic, in.Operand)
	}
	_ = writeText(root, "disassembly/entry.asm", b.String())
	return writeText(root, "disassembly/functions/entry.asm", b.String())
}

func writePseudocode(root string, fns []api.Function, ins []api.Instruction) error {
	if len(fns) == 0 {
		return nil
	}
	for _, fn := range fns {
		_ = writeText(root, filepath.Join("pseudocode", fn.Name+".c"), decompiler.Pseudocode(fn, ins))
	}
	return nil
}

func writeSource(root string, report api.AnalysisReport) error {
	_ = writeText(root, "source/reconstructed.c", decompiler.ReconstructC(report))
	for _, fn := range report.Functions {
		_ = writeText(root, filepath.Join("source/functions", safeArtifactName(fn.Name)+".c"), decompiler.Pseudocode(fn, report.Instructions))
	}
	return nil
}

func writeVulnerabilitiesCSV(root string, vulns []api.VulnerabilityFinding) error {
	rows := [][]string{}
	for _, v := range vulns {
		rows = append(rows, []string{v.ID, v.Severity, v.Category, v.Title, v.Evidence, v.Impact, v.Recommendation})
	}
	return writeCSV(root, "vulnerabilities/vulnerabilities.csv", []string{"id", "severity", "category", "title", "evidence", "impact", "recommendation"}, rows)
}

func writeSectionBins(root string, f *pe.File) error {
	if f == nil {
		return nil
	}
	for _, s := range f.Headers.Sections {
		name := s.Name
		if name == "" {
			name = fmt.Sprintf("section_%x", s.VirtualAddress)
		}
		name = safeArtifactName(name)
		data := f.RVASlice(s.VirtualAddress, s.SizeOfRawData)
		_ = writeBytes(root, filepath.Join("sections", name+".bin"), data)
	}
	return nil
}

func safeArtifactName(name string) string {
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, name)
	name = strings.Trim(name, "_")
	if name == "" || name == "." {
		return "section"
	}
	return name
}

func writeBytes(root, rel string, b []byte) error {
	p, err := utils.SafeJoin(root, rel)
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
}

func callGraph(fns []api.Function) map[string][]string {
	out := map[string][]string{}
	for _, f := range fns {
		out[f.Start] = f.Calls
	}
	return out
}

func filterFindings(findings []api.Finding, needle string) []api.Finding {
	var out []api.Finding
	for _, f := range findings {
		if strings.Contains(f.Category, needle) {
			out = append(out, f)
		}
	}
	return out
}

func artifactManifest() map[string]string {
	return map[string]string{
		"reports/triage.md":                    "first analyst read",
		"reports/executive.md":                 "management summary",
		"reports/technical.md":                 "deep technical report",
		"reports/indicators.md":                "indicators and pivots",
		"reports/report.json":                  "complete machine-readable report",
		"headers/security_features.json":       "PE mitigation flags",
		"imports/imports.csv":                  "import table",
		"strings/suspicious.txt":               "categorized suspicious strings",
		"signatures/function_fingerprints.csv": "function-level hashes for matching and diffing",
		"signatures/signature_matches.csv":     "native signature and capability matches",
		"deep/function_tags.csv":               "auto tags for leaf, wrapper, parser, no-return, and stack-heavy functions",
		"deep/annotations.csv":                 "auto comments and analyst notes suitable for import into RE tooling",
		"deep/jump_tables.csv":                 "indirect branch and dense-branch jump-table candidates",
		"deep/api_call_sites.csv":              "resolved imported API call sites with likely argument registers",
		"deep/string_references.csv":           "instruction-to-string/data reference candidates",
		"deep/stack_frames.csv":                "per-function stack frame summaries with locals and saved registers",
		"deep/basic_block_notes.csv":           "CFG block notes for terminals, branches, and loop backedges",
		"deep/decompiler_hints.csv":            "address-level hints for decompiler and manual review",
		"deep/function_clusters.csv":           "function similarity and shape clusters",
		"deep/hot_paths.csv":                   "ranked functions for audit and triage",
		"deep/patch_points.csv":                "branch, call, padding, and breakpoint patch-point candidates",
		"deep/calling_conventions.csv":         "calling convention and argument storage guesses",
		"deep/unpacking_hints.csv":             "packer, overlay, loader, and self-modifying-code guidance",
		"deep/type_hints.csv":                  "propagated type hints from APIs and string references",
		"deep/timeline.csv":                    "ordered analysis timeline",
		"deep/capability_matrix.csv":           "scored capability rollup",
		"deep/anti_analysis.csv":               "anti-debug, sandbox, VM, and tool-detection indicators",
		"deep/crypto_indicators.csv":           "crypto APIs and constants",
		"deep/persistence_indicators.csv":      "registry, service, scheduled task, startup, and file persistence hints",
		"deep/syscall_indicators.csv":          "syscall, interrupt, segment-register, and low-level execution hints",
		"project/labels.map":                   "address-to-name map for external tooling",
		"project/rizin_radare2.r2":             "radare2/Rizin command script for labels and comments",
		"project/ghidra_bookmarks.tsv":         "TSV bookmarks/comments for Ghidra-oriented workflows",
		"project/ida_names_comments.idc":       "IDC helper script for IDA-style names and comments",
		"entropy/sliding_entropy.csv":          "sliding-window entropy data",
		"visuals/entropy_timeline.png":         "entropy visualization",
		"control_flow/cfg.dot":                 "Graphviz control-flow graph",
	}
}

func safeSymbol(name string) string {
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
			return r
		}
		return '_'
	}, name)
	name = strings.Trim(name, "_")
	if name == "" {
		return "unnamed"
	}
	return name
}

func idcAddr(addr string) string {
	if strings.HasPrefix(addr, "0x") {
		return addr
	}
	return "0x0"
}

func idcEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

func r2Escape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\n", " ")
	return strconvQuote(s)
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func hexPreview(data []byte, maxBytes int) string {
	if maxBytes <= 0 || maxBytes > len(data) {
		maxBytes = len(data)
	}
	var b strings.Builder
	for off := 0; off < maxBytes; off += 16 {
		end := off + 16
		if end > maxBytes {
			end = maxBytes
		}
		fmt.Fprintf(&b, "%08x  ", off)
		for i := off; i < off+16; i++ {
			if i < end {
				fmt.Fprintf(&b, "%02x ", data[i])
			} else {
				b.WriteString("   ")
			}
			if i == off+7 {
				b.WriteByte(' ')
			}
		}
		b.WriteString(" |")
		for i := off; i < end; i++ {
			c := data[i]
			if c < 0x20 || c > 0x7e {
				c = '.'
			}
			b.WriteByte(c)
		}
		b.WriteString("|\n")
	}
	return b.String()
}
