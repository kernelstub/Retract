package reports

import (
	"fmt"
	"sort"
	"strings"

	"retract/pkg/api"
)

func Markdown(r api.AnalysisReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# retract analysis: %s\n\n", r.Metadata.Filename)
	if r.CaseID != "" {
		fmt.Fprintf(&b, "- Case: `%s`\n", r.CaseID)
	}
	fmt.Fprintf(&b, "- Type: %s\n- Architecture: %s\n- Size: %d bytes\n- Entry point: %s\n- SHA256: `%s`\n\n", r.Metadata.FileType, r.Metadata.Arch, r.Metadata.Size, r.Metadata.EntryPoint, r.Metadata.SHA256)
	fmt.Fprintf(&b, "- Risk: **%s** (%d/100)\n\n", r.RiskLevel, r.RiskScore)
	if len(r.Security) > 0 {
		fmt.Fprintf(&b, "## PE security features\n\n")
		for _, key := range []string{"aslr_dynamic_base", "dep_nx_compat", "control_flow_guard", "high_entropy_va", "no_seh", "appcontainer"} {
			fmt.Fprintf(&b, "- %s: `%t`\n", key, r.Security[key])
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "## Sections\n\n| Name | VA | Raw | Perms | Entropy |\n| --- | ---: | ---: | --- | ---: |\n")
	for _, s := range r.Sections {
		fmt.Fprintf(&b, "| %s | 0x%x | 0x%x | %s | %.2f |\n", s.Name, s.VirtualAddress, s.RawOffset, s.Permissions, s.Entropy)
	}
	fmt.Fprintf(&b, "\n## Imports\n\n%d imports across DLLs.\n\n", len(r.Imports))
	fmt.Fprintf(&b, "## Findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("No notable heuristic findings.\n")
	} else {
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "- **%s** `%s`: %s\n", f.Severity, f.Category, f.Message)
		}
	}
	return b.String()
}

func Text(r api.AnalysisReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "retract analysis: %s\n", r.Metadata.Filename)
	fmt.Fprintf(&b, "type=%s arch=%s size=%d entry=%s sha256=%s\n", r.Metadata.FileType, r.Metadata.Arch, r.Metadata.Size, r.Metadata.EntryPoint, r.Metadata.SHA256)
	fmt.Fprintf(&b, "risk=%s score=%d/100\n", r.RiskLevel, r.RiskScore)
	fmt.Fprintf(&b, "sections=%d imports=%d exports=%d strings=%d functions=%d findings=%d\n", len(r.Sections), len(r.Imports), len(r.Exports), len(r.Strings), len(r.Functions), len(r.Findings))
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "[%s] %s: %s\n", f.Severity, f.Category, f.Message)
	}
	return b.String()
}

func Executive(r api.AnalysisReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Executive Summary\n\n")
	if r.CaseID != "" {
		fmt.Fprintf(&b, "**Case:** `%s`\n\n", r.CaseID)
	}
	fmt.Fprintf(&b, "**Sample:** `%s`\n\n", r.Metadata.Filename)
	fmt.Fprintf(&b, "**Risk:** %s (%d/100)\n\n", strings.ToUpper(r.RiskLevel), r.RiskScore)
	fmt.Fprintf(&b, "## Key observations\n\n")
	fmt.Fprintf(&b, "- Format: %s, architecture: %s, entry point: `%s`.\n", r.Metadata.FileType, r.Metadata.Arch, r.Metadata.EntryPoint)
	fmt.Fprintf(&b, "- SHA256: `%s`.\n", r.Metadata.SHA256)
	fmt.Fprintf(&b, "- Sections: %d, imports: %d, strings: %d, functions discovered: %d.\n", len(r.Sections), len(r.Imports), len(r.Strings), len(r.Functions))
	if r.Overlay.Present {
		fmt.Fprintf(&b, "- Overlay present at offset `0x%x`, size %d bytes, entropy %.2f.\n", r.Overlay.Offset, r.Overlay.Size, r.Overlay.Entropy)
	}
	if r.Certificate.Present {
		fmt.Fprintf(&b, "- Certificate table present at file offset `0x%x`, size %d bytes.\n", r.Certificate.FileOffset, r.Certificate.Size)
	}
	fmt.Fprintf(&b, "\n## Severity counts\n\n")
	for _, sev := range []string{"high", "medium", "info"} {
		fmt.Fprintf(&b, "- %s: %d\n", sev, r.FindingSummary[sev])
	}
	fmt.Fprintf(&b, "\n## Recommended next steps\n\n")
	b.WriteString("- Review `reports/triage.md` and `signatures/suspicious_findings.md`.\n")
	b.WriteString("- Inspect entropy visuals for packing or encrypted payload regions.\n")
	b.WriteString("- Validate suspicious imports against expected application behavior.\n")
	b.WriteString("- If this is a production incident, preserve the sample hash and generated report bundle as evidence.\n")
	return b.String()
}

func Technical(r api.AnalysisReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Technical Analysis\n\n")
	if r.CaseID != "" {
		fmt.Fprintf(&b, "**Case:** `%s`\n\n", r.CaseID)
	}
	fmt.Fprintf(&b, "## Metadata\n\n")
	fmt.Fprintf(&b, "| Field | Value |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| Filename | `%s` |\n", r.Metadata.Filename)
	fmt.Fprintf(&b, "| Size | %d bytes |\n", r.Metadata.Size)
	fmt.Fprintf(&b, "| Type | %s |\n", r.Metadata.FileType)
	fmt.Fprintf(&b, "| Architecture | %s |\n", r.Metadata.Arch)
	fmt.Fprintf(&b, "| Entry point | `%s` |\n", r.Metadata.EntryPoint)
	fmt.Fprintf(&b, "| Compile timestamp | `%s` |\n", r.Metadata.CompileTime)
	fmt.Fprintf(&b, "| SHA256 | `%s` |\n", r.Metadata.SHA256)
	fmt.Fprintf(&b, "\n## PE mitigations\n\n")
	for _, key := range []string{"aslr_dynamic_base", "dep_nx_compat", "control_flow_guard", "high_entropy_va", "no_seh", "appcontainer", "terminal_server_aware"} {
		fmt.Fprintf(&b, "- %s: `%t`\n", key, r.Security[key])
	}
	fmt.Fprintf(&b, "\n## Sections\n\n| Name | VA | Raw offset | Raw size | Perms | Entropy | Notes |\n| --- | ---: | ---: | ---: | --- | ---: | --- |\n")
	for _, s := range r.Sections {
		fmt.Fprintf(&b, "| %s | `0x%x` | `0x%x` | %d | %s | %.2f | %s |\n", s.Name, s.VirtualAddress, s.RawOffset, s.RawSize, s.Permissions, s.Entropy, strings.Join(s.Suspicious, "; "))
	}
	fmt.Fprintf(&b, "\n## Directories and tables\n\n")
	fmt.Fprintf(&b, "- Relocation blocks: %d\n", len(r.Relocations))
	fmt.Fprintf(&b, "- TLS callbacks: %d\n", len(r.TLSCallbacks))
	fmt.Fprintf(&b, "- Debug entries: %d\n", len(r.DebugEntries))
	fmt.Fprintf(&b, "- Resources present: `%t`\n", r.Resources.Present)
	fmt.Fprintf(&b, "- Certificate present: `%t`\n", r.Certificate.Present)
	fmt.Fprintf(&b, "- Load config present: `%t`\n", r.LoadConfig.Present)
	if r.LoadConfig.Present {
		fmt.Fprintf(&b, "- Load config guard flags: `%s`\n", r.LoadConfig.GuardFlags)
	}
	fmt.Fprintf(&b, "- Embedded artifacts: %d\n", len(r.EmbeddedArtifacts))
	if len(r.DebugEntries) > 0 {
		fmt.Fprintf(&b, "\n## Debug entries\n\n| Type | Size | RVA | File offset | PDB |\n| --- | ---: | ---: | ---: | --- |\n")
		for _, d := range r.DebugEntries {
			fmt.Fprintf(&b, "| %s | %d | `%s` | `%s` | `%s` |\n", d.TypeName, d.Size, d.RVA, d.FileOffset, d.PDBPath)
		}
	}
	fmt.Fprintf(&b, "\n## Import categories\n\n")
	if len(r.ImportSummary) == 0 {
		b.WriteString("No categorized imports.\n")
	} else {
		for _, item := range sortedCounts(r.ImportSummary) {
			fmt.Fprintf(&b, "- %s: %d\n", item.Key, item.Value)
		}
	}
	fmt.Fprintf(&b, "\n## Capabilities\n\n")
	if len(r.Capabilities) == 0 {
		b.WriteString("No high-confidence capabilities inferred.\n")
	} else {
		for _, c := range r.Capabilities {
			fmt.Fprintf(&b, "- %s\n", c)
		}
	}
	fmt.Fprintf(&b, "\n## Deep analysis\n\n")
	fmt.Fprintf(&b, "- Memory regions: %d\n", len(r.DeepAnalysis.MemoryMap))
	fmt.Fprintf(&b, "- API surface categories: %d\n", len(r.DeepAnalysis.APISurface))
	fmt.Fprintf(&b, "- Triage tasks: %d\n", len(r.DeepAnalysis.TriageTasks))
	fmt.Fprintf(&b, "- Instruction total: %d, unique mnemonics: %d\n", r.DeepAnalysis.InstructionStats.Total, r.DeepAnalysis.InstructionStats.UniqueMnemonics)
	fmt.Fprintf(&b, "- CFG: functions=%d blocks=%d edges=%d max_complexity=%d avg_complexity=%.2f\n", r.DeepAnalysis.ControlFlowMetrics.Functions, r.DeepAnalysis.ControlFlowMetrics.BasicBlocks, r.DeepAnalysis.ControlFlowMetrics.Edges, r.DeepAnalysis.ControlFlowMetrics.MaxFunctionComplexity, r.DeepAnalysis.ControlFlowMetrics.AvgFunctionComplexity)
	return b.String()
}

func Indicators(r api.AnalysisReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Indicators\n\n")
	fmt.Fprintf(&b, "## Hashes\n\n")
	fmt.Fprintf(&b, "- MD5: `%s`\n- SHA1: `%s`\n- SHA256: `%s`\n- SHA512: `%s`\n\n", r.Metadata.MD5, r.Metadata.SHA1, r.Metadata.SHA256, r.Metadata.SHA512)
	writeTaggedStrings(&b, r.Strings, "url", "URLs")
	writeTaggedStrings(&b, r.Strings, "domain", "Domains")
	writeTaggedStrings(&b, r.Strings, "ip", "IP addresses")
	writeTaggedStrings(&b, r.Strings, "registry", "Registry keys")
	writeTaggedStrings(&b, r.Strings, "command", "Commands")
	return b.String()
}

func EvidenceIndex(r api.AnalysisReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Evidence Index\n\n")
	fmt.Fprintf(&b, "| Artifact | Purpose |\n| --- | --- |\n")
	rows := map[string]string{
		"`metadata/metadata.json`":          "sample metadata and hashes",
		"`headers/*.json`":                  "parsed PE headers, mitigations, debug/certificate metadata",
		"`sections/sections.csv`":           "section table with entropy and permissions",
		"`imports/imports.csv`":             "imported DLLs/functions with categories",
		"`strings/*.txt`":                   "extracted and categorized strings",
		"`entropy/sliding_entropy.csv`":     "sliding-window entropy measurements",
		"`visuals/*.png`":                   "entropy, byte histogram, and section map images",
		"`disassembly/entry.asm`":           "entry-point linear disassembly",
		"`control_flow/cfg.dot`":            "Graphviz control-flow graph",
		"`deep/deep_analysis.json`":         "enterprise deep-analysis rollup",
		"`deep/analyst_workflow.md`":        "prioritized analyst workflow and API surface",
		"`deep/memory_map.csv`":             "file and virtual memory map with entropy and notes",
		"`deep/api_surface.csv`":            "categorized API surface and risk buckets",
		"`deep/triage_tasks.csv`":           "machine-generated reverse-engineering task list",
		"`deep/function_tags.csv`":          "auto tags for leaf, wrapper, parser, no-return, and stack-heavy functions",
		"`deep/annotations.csv`":            "auto comments suitable for RE-tool import or analyst notebooks",
		"`deep/jump_tables.csv`":            "indirect branch and dense-branch jump-table candidates",
		"`deep/api_call_sites.csv`":         "resolved imported API call sites with likely argument registers",
		"`deep/string_references.csv`":      "instruction-to-string/data reference candidates",
		"`deep/stack_frames.csv`":           "per-function stack frame summaries",
		"`deep/basic_block_notes.csv`":      "CFG notes for terminal blocks, branches, and loop backedges",
		"`deep/decompiler_hints.csv`":       "address-level hints for manual decompiler review",
		"`deep/function_clusters.csv`":      "function similarity and shape clusters",
		"`deep/hot_paths.csv`":              "ranked audit and triage functions",
		"`deep/patch_points.csv`":           "branch, call, padding, and breakpoint patch-point candidates",
		"`deep/calling_conventions.csv`":    "calling convention and argument storage guesses",
		"`deep/unpacking_hints.csv`":        "packer, overlay, loader, and self-modifying-code guidance",
		"`deep/type_hints.csv`":             "propagated type hints from APIs and string references",
		"`deep/timeline.csv`":               "ordered analysis events",
		"`deep/capability_matrix.csv`":      "scored capability rollup",
		"`deep/anti_analysis.csv`":          "anti-debug, sandbox, VM, and tool-detection indicators",
		"`deep/crypto_indicators.csv`":      "crypto API and constant indicators",
		"`deep/persistence_indicators.csv`": "registry, service, scheduled-task, startup, and file persistence hints",
		"`deep/syscall_indicators.csv`":     "syscall, interrupt, segment-register, and low-level execution hints",
		"`reports/report.json`":             "complete structured report",
		"`signatures/attack_surface.md`":    "behavior and capability mapping",
		"`yara_like/indicators.yaralike`":   "starter detection rule",
	}
	for k, v := range rows {
		fmt.Fprintf(&b, "| %s | %s |\n", k, v)
	}
	return b.String()
}

func AttackSurface(r api.AnalysisReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Attack Surface and Behavior Map\n\n")
	if len(r.Capabilities) == 0 {
		b.WriteString("No high-confidence capabilities inferred.\n")
		return b.String()
	}
	for _, c := range r.Capabilities {
		fmt.Fprintf(&b, "- %s\n", c)
	}
	fmt.Fprintf(&b, "\n## Import category evidence\n\n")
	if len(r.ImportSummary) == 0 {
		b.WriteString("No categorized imports.\n")
	} else {
		for _, item := range sortedCounts(r.ImportSummary) {
			fmt.Fprintf(&b, "- %s: %d imports\n", item.Key, item.Value)
		}
	}
	return b.String()
}

func Recommendations(r api.AnalysisReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Recommendations\n\n")
	fmt.Fprintf(&b, "Risk: **%s** (%d/100)\n\n", r.RiskLevel, r.RiskScore)
	if r.RiskLevel == "high" {
		b.WriteString("- Treat this sample as high priority until manually cleared.\n")
		b.WriteString("- Escalate to malware reverse engineering for focused unpacking and behavior confirmation.\n")
	} else if r.RiskLevel == "medium" {
		b.WriteString("- Perform manual review of high-entropy regions and suspicious imports.\n")
		b.WriteString("- Correlate extracted indicators with endpoint, proxy, DNS, and EDR telemetry.\n")
	} else {
		b.WriteString("- Preserve generated artifacts and review only if the sample is tied to a relevant alert.\n")
	}
	if r.Overlay.Present {
		b.WriteString("- Inspect overlay data; appended payloads, installers, or signatures can hide there.\n")
	}
	if len(r.TLSCallbacks) > 0 {
		b.WriteString("- Prioritize TLS callback review because code may run before the nominal entry point.\n")
	}
	if !r.Security["aslr_dynamic_base"] || !r.Security["control_flow_guard"] {
		b.WriteString("- Note missing exploit mitigations when assessing provenance and build quality.\n")
	}
	if r.Entropy != nil {
		b.WriteString("- Use `entropy/high_entropy_regions.csv` and `visuals/entropy_timeline.png` to guide unpacking work.\n")
	}
	return b.String()
}

func Vulnerabilities(r api.AnalysisReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Vulnerability Review\n\n")
	if len(r.Vulnerabilities) == 0 {
		b.WriteString("No vulnerability-oriented heuristics fired. This does not prove the binary is vulnerability-free.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "| Severity | ID | Category | Title | Evidence |\n| --- | --- | --- | --- | --- |\n")
	for _, v := range r.Vulnerabilities {
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s | `%s` |\n", v.Severity, v.ID, v.Category, v.Title, escapeTable(v.Evidence))
	}
	fmt.Fprintf(&b, "\n## Details\n\n")
	for _, v := range r.Vulnerabilities {
		fmt.Fprintf(&b, "### %s: %s\n\n", v.ID, v.Title)
		fmt.Fprintf(&b, "- Severity: **%s**\n", v.Severity)
		fmt.Fprintf(&b, "- Category: `%s`\n", v.Category)
		fmt.Fprintf(&b, "- Evidence: `%s`\n", v.Evidence)
		fmt.Fprintf(&b, "- Impact: %s\n", v.Impact)
		fmt.Fprintf(&b, "- Recommendation: %s\n\n", v.Recommendation)
	}
	return b.String()
}

func ReverseEngineering(r api.AnalysisReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Reverse Engineering Notebook\n\n")
	fmt.Fprintf(&b, "## Function Metrics\n\n")
	fmt.Fprintf(&b, "| Function | Start | Instructions | Calls | Branches | Complexity | Stack | Notes |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n")
	for _, f := range r.FunctionInsights {
		fmt.Fprintf(&b, "| %s | `%s` | %d | %d | %d | %d | 0x%x | %s |\n", f.Name, f.Start, f.InstructionCount, f.CallCount, f.BranchCount, f.Complexity, f.EstimatedStack, strings.Join(f.RiskNotes, "; "))
	}
	fmt.Fprintf(&b, "\n## Inferred Types\n\n")
	if len(r.InferredTypes) == 0 {
		b.WriteString("No type candidates inferred.\n")
	} else {
		for _, t := range r.InferredTypes {
			fmt.Fprintf(&b, "- **%s** (%s, %s): %s\n", t.Name, t.Kind, t.Confidence, strings.Join(t.Evidence, "; "))
		}
	}
	fmt.Fprintf(&b, "\n## Struct Candidates\n\n")
	if len(r.StructCandidates) == 0 {
		b.WriteString("No struct candidates inferred.\n")
	} else {
		for _, s := range r.StructCandidates {
			fmt.Fprintf(&b, "### %s\n\n- Confidence: `%s`\n- Size: `%d`\n- Evidence: %s\n\n", s.Name, s.Confidence, s.Size, strings.Join(s.Evidence, "; "))
			for _, field := range s.Fields {
				fmt.Fprintf(&b, "- `%s`\n", field)
			}
			b.WriteByte('\n')
		}
	}
	fmt.Fprintf(&b, "\n## Function Tags\n\n")
	if len(r.DeepAnalysis.FunctionTags) == 0 {
		b.WriteString("No function tags generated.\n")
	} else {
		fmt.Fprintf(&b, "| Function | Tag | Confidence | Evidence |\n| --- | --- | --- | --- |\n")
		for _, t := range r.DeepAnalysis.FunctionTags {
			fmt.Fprintf(&b, "| `%s` | %s | %s | `%s` |\n", t.Function, t.Tag, t.Confidence, escapeTable(strings.Join(t.Evidence, "; ")))
		}
	}
	fmt.Fprintf(&b, "\n## Jump Table Candidates\n\n")
	if len(r.DeepAnalysis.JumpTables) == 0 {
		b.WriteString("No jump-table candidates generated.\n")
	} else {
		fmt.Fprintf(&b, "| Function | Address | Confidence | Evidence |\n| --- | ---: | --- | --- |\n")
		for _, jt := range r.DeepAnalysis.JumpTables {
			fmt.Fprintf(&b, "| `%s` | `%s` | %s | `%s` |\n", jt.Function, jt.Address, jt.Confidence, escapeTable(strings.Join(jt.Evidence, "; ")))
		}
	}
	fmt.Fprintf(&b, "\n## Auto Annotations\n\n")
	if len(r.DeepAnalysis.Annotations) == 0 {
		b.WriteString("No auto annotations generated.\n")
	} else {
		limitAnnotations := len(r.DeepAnalysis.Annotations)
		if limitAnnotations > 100 {
			limitAnnotations = 100
		}
		fmt.Fprintf(&b, "| Address | Function | Kind | Severity | Text |\n| --- | --- | --- | --- | --- |\n")
		for _, a := range r.DeepAnalysis.Annotations[:limitAnnotations] {
			fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s | `%s` |\n", a.Address, a.Function, a.Kind, a.Severity, escapeTable(a.Text))
		}
		if len(r.DeepAnalysis.Annotations) > limitAnnotations {
			fmt.Fprintf(&b, "\n%d additional annotations omitted from markdown; see `deep/annotations.csv`.\n", len(r.DeepAnalysis.Annotations)-limitAnnotations)
		}
	}
	fmt.Fprintf(&b, "\n## API Call Sites\n\n")
	if len(r.DeepAnalysis.APICallSites) == 0 {
		b.WriteString("No imported API call sites resolved from decoded calls.\n")
	} else {
		limitCalls := len(r.DeepAnalysis.APICallSites)
		if limitCalls > 100 {
			limitCalls = 100
		}
		fmt.Fprintf(&b, "| Function | Address | API | Category |\n| --- | ---: | --- | --- |\n")
		for _, cs := range r.DeepAnalysis.APICallSites[:limitCalls] {
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s |\n", cs.Function, cs.Address, escapeTable(cs.API), strings.Join(cs.Category, ", "))
		}
		if len(r.DeepAnalysis.APICallSites) > limitCalls {
			fmt.Fprintf(&b, "\n%d additional API call sites omitted from markdown; see `deep/api_call_sites.csv`.\n", len(r.DeepAnalysis.APICallSites)-limitCalls)
		}
	}
	fmt.Fprintf(&b, "\n## Stack Frames\n\n")
	if len(r.DeepAnalysis.StackFrames) == 0 {
		b.WriteString("No stack frame layouts generated.\n")
	} else {
		fmt.Fprintf(&b, "| Function | Frame | Locals | Args | Saved Registers |\n| --- | ---: | ---: | ---: | --- |\n")
		for _, sf := range r.DeepAnalysis.StackFrames {
			fmt.Fprintf(&b, "| `%s` | `0x%x` | %d | %d | %s |\n", sf.Function, sf.FrameSize, len(sf.Locals), len(sf.Arguments), strings.Join(sf.SavedRegisters, ", "))
		}
	}
	fmt.Fprintf(&b, "\n## String Reference Candidates\n\n")
	if len(r.DeepAnalysis.StringRefs) == 0 {
		b.WriteString("No instruction-to-string references generated.\n")
	} else {
		limitRefs := len(r.DeepAnalysis.StringRefs)
		if limitRefs > 100 {
			limitRefs = 100
		}
		fmt.Fprintf(&b, "| Function | Address | Offset | String |\n| --- | ---: | ---: | --- |\n")
		for _, ref := range r.DeepAnalysis.StringRefs[:limitRefs] {
			fmt.Fprintf(&b, "| `%s` | `%s` | `0x%x` | `%s` |\n", ref.Function, ref.Address, ref.Offset, escapeTable(ref.String))
		}
		if len(r.DeepAnalysis.StringRefs) > limitRefs {
			fmt.Fprintf(&b, "\n%d additional string references omitted from markdown; see `deep/string_references.csv`.\n", len(r.DeepAnalysis.StringRefs)-limitRefs)
		}
	}
	fmt.Fprintf(&b, "\n## Decompiler Hints\n\n")
	if len(r.DeepAnalysis.DecompilerHints) == 0 {
		b.WriteString("No decompiler hints generated.\n")
	} else {
		limitHints := len(r.DeepAnalysis.DecompilerHints)
		if limitHints > 100 {
			limitHints = 100
		}
		fmt.Fprintf(&b, "| Function | Address | Kind | Hint |\n| --- | ---: | --- | --- |\n")
		for _, h := range r.DeepAnalysis.DecompilerHints[:limitHints] {
			fmt.Fprintf(&b, "| `%s` | `%s` | %s | `%s` |\n", h.Function, h.Address, h.Kind, escapeTable(h.Hint))
		}
		if len(r.DeepAnalysis.DecompilerHints) > limitHints {
			fmt.Fprintf(&b, "\n%d additional decompiler hints omitted from markdown; see `deep/decompiler_hints.csv`.\n", len(r.DeepAnalysis.DecompilerHints)-limitHints)
		}
	}
	fmt.Fprintf(&b, "\n## Advanced RE Triage\n\n")
	if len(r.DeepAnalysis.HotPaths) == 0 {
		b.WriteString("No hot-path ranking generated.\n")
	} else {
		fmt.Fprintf(&b, "| Rank | Function | Score | Reasons |\n| ---: | --- | ---: | --- |\n")
		for _, p := range r.DeepAnalysis.HotPaths[:minInt(len(r.DeepAnalysis.HotPaths), 50)] {
			fmt.Fprintf(&b, "| %d | `%s` | %d | `%s` |\n", p.Rank, p.Function, p.Score, escapeTable(strings.Join(p.Reasons, "; ")))
		}
	}
	fmt.Fprintf(&b, "\n## Function Clusters\n\n")
	if len(r.DeepAnalysis.FunctionClusters) == 0 {
		b.WriteString("No function clusters generated.\n")
	} else {
		fmt.Fprintf(&b, "| Cluster | Kind | Confidence | Functions |\n| --- | --- | --- | --- |\n")
		for _, c := range r.DeepAnalysis.FunctionClusters[:minInt(len(r.DeepAnalysis.FunctionClusters), 50)] {
			fmt.Fprintf(&b, "| `%s` | %s | %s | `%s` |\n", c.ID, c.Kind, c.Confidence, escapeTable(strings.Join(c.Functions, ", ")))
		}
	}
	fmt.Fprintf(&b, "\n## Patch Points and Unpacking\n\n")
	if len(r.DeepAnalysis.PatchPoints) == 0 && len(r.DeepAnalysis.UnpackingHints) == 0 {
		b.WriteString("No patch points or unpacking hints generated.\n")
	} else {
		fmt.Fprintf(&b, "| Kind | Address/Region | Risk/Priority | Evidence |\n| --- | --- | --- | --- |\n")
		for _, p := range r.DeepAnalysis.PatchPoints[:minInt(len(r.DeepAnalysis.PatchPoints), 60)] {
			fmt.Fprintf(&b, "| %s | `%s` | %s | `%s` |\n", p.Kind, p.Address, p.Risk, escapeTable(strings.Join(p.Evidence, "; ")))
		}
		for _, h := range r.DeepAnalysis.UnpackingHints[:minInt(len(r.DeepAnalysis.UnpackingHints), 40)] {
			fmt.Fprintf(&b, "| %s | `%s` | %s | `%s` |\n", h.Kind, h.Region, h.Priority, escapeTable(strings.Join(h.Evidence, "; ")))
		}
	}
	fmt.Fprintf(&b, "\n## Calling Conventions and Type Hints\n\n")
	if len(r.DeepAnalysis.CallingConventions) == 0 && len(r.DeepAnalysis.TypeHints) == 0 {
		b.WriteString("No calling convention or propagated type hints generated.\n")
	} else {
		fmt.Fprintf(&b, "| Function/Symbol | Kind | Value | Confidence |\n| --- | --- | --- | --- |\n")
		for _, cc := range r.DeepAnalysis.CallingConventions[:minInt(len(r.DeepAnalysis.CallingConventions), 60)] {
			fmt.Fprintf(&b, "| `%s` | calling convention | `%s %s` | %s |\n", cc.Function, cc.Convention, strings.Join(cc.ArgumentStorage, ", "), cc.Confidence)
		}
		for _, th := range r.DeepAnalysis.TypeHints[:minInt(len(r.DeepAnalysis.TypeHints), 60)] {
			fmt.Fprintf(&b, "| `%s` | type hint | `%s` | %s |\n", th.Symbol, th.Type, th.Confidence)
		}
	}
	fmt.Fprintf(&b, "\n## Cross Reference Samples\n\n")
	limit := len(r.Xrefs)
	if limit > 100 {
		limit = 100
	}
	fmt.Fprintf(&b, "| From | To | Kind | Evidence |\n| --- | --- | --- | --- |\n")
	for _, x := range r.Xrefs[:limit] {
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | `%s` |\n", x.From, escapeTable(x.To), x.Kind, escapeTable(x.Evidence))
	}
	fmt.Fprintf(&b, "\n## Reconstructed Source\n\nSee `source/reconstructed.c` and `source/functions/*.c`.\n")
	return b.String()
}

func STIXLite(r api.AnalysisReport) map[string]any {
	objects := []map[string]any{
		{
			"type":       "file",
			"name":       r.Metadata.Filename,
			"size":       r.Metadata.Size,
			"hashes":     map[string]string{"MD5": r.Metadata.MD5, "SHA-1": r.Metadata.SHA1, "SHA-256": r.Metadata.SHA256, "SHA-512": r.Metadata.SHA512},
			"extensions": map[string]any{"retract": map[string]any{"risk_level": r.RiskLevel, "risk_score": r.RiskScore, "capabilities": r.Capabilities}},
		},
	}
	for _, h := range r.Strings {
		if hasTag(h.Tags, "url") {
			objects = append(objects, map[string]any{"type": "url", "value": h.Value})
		}
		if hasTag(h.Tags, "domain") {
			objects = append(objects, map[string]any{"type": "domain-name", "value": h.Value})
		}
		if hasTag(h.Tags, "ip") {
			objects = append(objects, map[string]any{"type": "ipv4-addr", "value": h.Value})
		}
		if len(objects) >= 250 {
			break
		}
	}
	return map[string]any{
		"type":         "bundle",
		"spec_version": "2.1-lite",
		"producer":     "retract",
		"objects":      objects,
	}
}

func Triage(r api.AnalysisReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Triage: %s\n\n", r.Metadata.Filename)
	fmt.Fprintf(&b, "Risk: **%s** (%d/100)\n\n", r.RiskLevel, r.RiskScore)
	fmt.Fprintf(&b, "## Analyst checklist\n\n")
	b.WriteString("- Review `signatures/suspicious_findings.md` first.\n")
	b.WriteString("- Inspect `visuals/entropy_timeline.png` for packed or encrypted regions.\n")
	b.WriteString("- Compare `imports/imports.csv` against expected program behavior.\n")
	b.WriteString("- Search `strings/suspicious.txt` for commands, registry keys, crypto, user agents, and mutex-like values.\n")
	b.WriteString("- Open `control_flow/cfg.dot` around the entry function when disassembly is enabled.\n\n")
	if len(r.DeepAnalysis.TriageTasks) > 0 {
		fmt.Fprintf(&b, "## Generated task queue\n\n")
		for _, t := range r.DeepAnalysis.TriageTasks {
			fmt.Fprintf(&b, "- **%s** %s: %s\n", t.Priority, t.Title, t.Why)
			for _, a := range t.Actions {
				fmt.Fprintf(&b, "  - %s\n", a)
			}
		}
		b.WriteByte('\n')
	}
	if len(r.Security) > 0 {
		fmt.Fprintf(&b, "## PE mitigations\n\n")
		for _, key := range []string{"aslr_dynamic_base", "dep_nx_compat", "control_flow_guard", "high_entropy_va", "no_seh", "appcontainer"} {
			fmt.Fprintf(&b, "- %s: `%t`\n", key, r.Security[key])
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "## Top findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("No heuristic findings were produced.\n")
	} else {
		limit := len(r.Findings)
		if limit > 20 {
			limit = 20
		}
		for _, f := range r.Findings[:limit] {
			fmt.Fprintf(&b, "- **%s** `%s`: %s\n", f.Severity, f.Category, f.Message)
		}
	}
	fmt.Fprintf(&b, "\n## High-signal strings\n\n")
	n := 0
	for _, s := range r.Strings {
		if !strongString(s.Tags) {
			continue
		}
		fmt.Fprintf(&b, "- `0x%x` %s [%s] `%s`\n", s.Offset, s.Encoding, strings.Join(s.Tags, ", "), trim(s.Value, 120))
		n++
		if n >= 25 {
			break
		}
	}
	if n == 0 {
		b.WriteString("No categorized strings.\n")
	}
	return b.String()
}

func strongString(tags []string) bool {
	for _, t := range tags {
		switch t {
		case "url", "ip", "registry", "command", "crypto", "suspicious", "user-agent", "windows-api-like":
			return true
		}
	}
	return false
}

func writeTaggedStrings(b *strings.Builder, hits []api.StringHit, tag, title string) {
	fmt.Fprintf(b, "## %s\n\n", title)
	n := 0
	seen := map[string]bool{}
	for _, h := range hits {
		if !hasTag(h.Tags, tag) || seen[h.Value] {
			continue
		}
		seen[h.Value] = true
		fmt.Fprintf(b, "- `0x%x` `%s`\n", h.Offset, trim(h.Value, 180))
		n++
		if n >= 100 {
			break
		}
	}
	if n == 0 {
		b.WriteString("None found.\n")
	}
	b.WriteByte('\n')
}

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

func FindingsMarkdown(fs []api.Finding) string {
	if len(fs) == 0 {
		return "No matching findings.\n"
	}
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "- **%s** `%s`: %s\n", f.Severity, f.Category, f.Message)
	}
	return b.String()
}

func YaraLike(r api.AnalysisReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "rule retract_%s {\n", sanitize(r.Metadata.Filename))
	b.WriteString("  meta:\n")
	fmt.Fprintf(&b, "    sha256 = \"%s\"\n", r.Metadata.SHA256)
	b.WriteString("  strings:\n")
	n := 0
	for _, s := range r.Strings {
		if len(s.Tags) == 0 || len(s.Value) < 6 || len(s.Value) > 120 {
			continue
		}
		fmt.Fprintf(&b, "    $s%d = \"%s\"\n", n, escape(s.Value))
		n++
		if n >= 20 {
			break
		}
	}
	b.WriteString("  condition:\n")
	if n == 0 {
		b.WriteString("    false\n")
	} else {
		b.WriteString("    any of them\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, s)
	if s == "" {
		return "sample"
	}
	return s
}

func escape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func escapeTable(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return trim(s, 160)
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type countPair struct {
	Key   string
	Value int
}

func sortedCounts(m map[string]int) []countPair {
	out := make([]countPair, 0, len(m))
	for k, v := range m {
		out = append(out, countPair{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value == out[j].Value {
			return out[i].Key < out[j].Key
		}
		return out[i].Value > out[j].Value
	})
	return out
}
