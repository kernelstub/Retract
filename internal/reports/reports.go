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
		"`metadata/metadata.json`":        "sample metadata and hashes",
		"`headers/*.json`":                "parsed PE headers, mitigations, debug/certificate metadata",
		"`sections/sections.csv`":         "section table with entropy and permissions",
		"`imports/imports.csv`":           "imported DLLs/functions with categories",
		"`strings/*.txt`":                 "extracted and categorized strings",
		"`entropy/sliding_entropy.csv`":   "sliding-window entropy measurements",
		"`visuals/*.png`":                 "entropy, byte histogram, and section map images",
		"`disassembly/entry.asm`":         "entry-point linear disassembly",
		"`control_flow/cfg.dot`":          "Graphviz control-flow graph",
		"`deep/deep_analysis.json`":       "enterprise deep-analysis rollup",
		"`deep/analyst_workflow.md`":      "prioritized analyst workflow and API surface",
		"`deep/memory_map.csv`":           "file and virtual memory map with entropy and notes",
		"`deep/api_surface.csv`":          "categorized API surface and risk buckets",
		"`deep/triage_tasks.csv`":         "machine-generated reverse-engineering task list",
		"`reports/report.json`":           "complete structured report",
		"`signatures/attack_surface.md`":  "behavior and capability mapping",
		"`yara_like/indicators.yaralike`": "starter detection rule",
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
