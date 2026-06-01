package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"retract/internal/carve"
	"retract/internal/cfg"
	"retract/internal/deep"
	"retract/internal/disasm/x64"
	"retract/internal/disasm/x86"
	"retract/internal/entropy"
	"retract/internal/formats/elf"
	"retract/internal/formats/macho"
	"retract/internal/formats/pe"
	"retract/internal/intel"
	"retract/internal/output"
	reinsights "retract/internal/re"
	"retract/internal/signatures"
	rstrings "retract/internal/strings"
	"retract/internal/utils"
	"retract/internal/visuals"
	"retract/internal/vulns"
	"retract/pkg/api"
)

func Analyze(path string, opts api.Options) (api.AnalysisReport, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return api.AnalysisReport{}, "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return api.AnalysisReport{}, "", err
	}
	baseOut := opts.OutputDir
	if baseOut == "" {
		baseOut = "output"
	}
	root, err := utils.SafeJoin(baseOut, filepath.Base(path))
	if err != nil {
		return api.AnalysisReport{}, "", err
	}
	md5, sha1, sha256, sha512 := utils.Hashes(data)
	hashes := [4]string{md5, sha1, sha256, sha512}
	windowSize := opts.WindowSize
	if windowSize <= 0 {
		windowSize = 4096
	}
	windowStep := opts.WindowStep
	if windowStep <= 0 {
		windowStep = windowSize / 2
	}
	report := api.AnalysisReport{CaseID: opts.CaseID, Entropy: map[string]any{"whole_file": entropy.Shannon(data), "sliding_window_size": windowSize, "sliding_window_step": windowStep}}
	var peFile *pe.File
	format := opts.Format
	if format == "" || format == "auto" {
		format = detect(data)
	}
	switch format {
	case "pe":
		peFile, err = pe.Parse(data)
		if err != nil {
			return report, root, err
		}
		report.Metadata = peFile.Metadata(filepath.Base(path), info.Size(), hashes)
		report.Headers = peFile.Headers
		report.Sections = peFile.Sections
		report.Imports = peFile.Imports
		report.Exports = peFile.Exports
		report.Security = peFile.SecurityFeatures()
		report.Overlay = peFile.OverlayInfo()
		report.Relocations = peFile.Relocations()
		report.TLSCallbacks = peFile.TLSCallbacks()
		report.DebugEntries = peFile.DebugEntries()
		report.Certificate = peFile.CertificateInfo()
		report.Resources = peFile.ResourceInfo()
		report.LoadConfig = peFile.LoadConfigInfo()
		report.Findings = append(report.Findings, peFile.Findings...)
		if !opts.NoDisasm {
			report.Instructions = disassemblePE(peFile, opts.DisasmBytes)
			report.Blocks, report.Functions = cfg.Build(report.Instructions)
			report.Functions = enhanceFunctions(report.Functions, report.Instructions)
		}
	case "elf":
		elfFile, err := elf.Parse(data)
		if err != nil {
			return report, root, err
		}
		report.Metadata = elfFile.Metadata(filepath.Base(path), info.Size(), hashes)
		report.Headers = elfFile.Headers
		report.Sections = elfFile.Sections
		report.Imports = elfFile.Imports
		report.Exports = elfFile.Exports
		report.Findings = append(report.Findings, elfFile.Findings...)
	case "macho":
		machoFile, err := macho.Parse(data)
		if err != nil {
			return report, root, err
		}
		report.Metadata = machoFile.Metadata(filepath.Base(path), info.Size(), hashes)
		report.Headers = machoFile.Headers
		report.Sections = machoFile.Sections
		report.Imports = machoFile.Imports
		report.Exports = machoFile.Exports
		report.Findings = append(report.Findings, machoFile.Findings...)
	default:
		report.Metadata = api.FileMetadata{Filename: filepath.Base(path), Size: info.Size(), MD5: md5, SHA1: sha1, SHA256: sha256, SHA512: sha512, FileType: format, Endianness: "unknown"}
		report.Sections = rawSections(data)
		report.Findings = append(report.Findings, api.Finding{Severity: "info", Category: "format", Message: "raw binary analysis mode"})
	}
	min := opts.MinString
	if min == 0 {
		min = 4
	}
	report.Strings = rstrings.Extract(data, min)
	for _, a := range carve.Scan(data) {
		report.EmbeddedArtifacts = append(report.EmbeddedArtifacts, api.EmbeddedArtifact{Offset: a.Offset, Type: a.Type, Description: a.Desc})
	}
	report.FunctionInsights = reinsights.FunctionInsights(report.Functions, report.Instructions)
	report.InferredVariables = reinsights.Variables(report.Functions, report.Instructions)
	report.InferredTypes = reinsights.Types(report.Imports, report.Strings)
	report.StructCandidates = reinsights.Structs(report.InferredTypes, report.InferredVariables)
	report.Xrefs = reinsights.Xrefs(report.Imports, report.Strings, report.Instructions)
	windows := entropy.Sliding(data, windowSize, windowStep)
	report.Entropy["windows"] = windows
	report.ByteHistogram = visuals.ByteHistogram(data)
	report.Findings = append(report.Findings, signatures.Heuristics(report.Sections, report.Imports, report.Entropy["whole_file"].(float64), peFile != nil && peFile.OverlayOffset > 0)...)
	report.FindingSummary = findingSummary(report.Findings)
	report.ImportSummary = importSummary(report.Imports)
	report.StringSummary = stringSummary(report.Strings)
	report.Capabilities = capabilities(report.Imports, report.Strings, report.Security)
	report.Vulnerabilities = vulns.Analyze(report)
	report.VulnerabilitySummary = vulns.Summary(report.Vulnerabilities)
	report.FileInfo, report.Binary = intel.Build(data, report, peFile)
	report.RiskScore, report.RiskLevel = risk(report.Findings, report.Sections, report.Imports, report.Entropy["whole_file"].(float64))
	report.RiskScore, report.RiskLevel = applyVulnRisk(report.RiskScore, report.Vulnerabilities)
	report.DeepAnalysis = deep.Analyze(data, report)
	if err := output.Write(output.Bundle{Report: report, PE: peFile, Windows: windows, Root: root, Data: data, Visuals: !opts.NoVisuals}); err != nil {
		return report, root, err
	}
	if opts.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else if !opts.Quiet {
		fmt.Print(ConsoleSummary(report, root, opts.Verbose))
	}
	return report, root, nil
}

func detect(data []byte) string {
	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		return "pe"
	}
	if elf.Detect(data) {
		return "elf"
	}
	if macho.Detect(data) {
		return "macho"
	}
	return "raw"
}

func rawSections(data []byte) []api.Section {
	if len(data) == 0 {
		return nil
	}
	return []api.Section{{
		Name:        "raw",
		RawOffset:   0,
		RawSize:     uint32(len(data)),
		VirtualSize: uint32(len(data)),
		Permissions: "r",
		Entropy:     entropy.Shannon(data),
	}}
}

func disassemblePE(f *pe.File, maxBytes int) []api.Instruction {
	ep := f.Headers.Optional.AddressOfEntryPoint
	off, ok := f.RVAOffset(ep)
	if !ok {
		return nil
	}
	limit := 8192
	if maxBytes > 0 {
		limit = maxBytes
	}
	if off+limit > len(f.Data) {
		limit = len(f.Data) - off
	}
	base := f.Headers.Optional.ImageBase + uint64(ep)
	if pe.Arch(f.Headers.COFF.Machine) == "x86_64" {
		return x64.Decode(f.Data[off:off+limit], base, limit)
	}
	return x86.Decode(f.Data[off:off+limit], base, x86.Mode32, limit)
}

func risk(findings []api.Finding, sections []api.Section, imports []api.ImportFunction, fileEntropy float64) (int, string) {
	score := 0
	for _, f := range findings {
		switch f.Severity {
		case "high":
			score += 18
		case "medium":
			score += 9
		default:
			score += 2
		}
	}
	if fileEntropy >= 7.2 {
		score += 18
	}
	for _, s := range sections {
		if s.Entropy >= 7.2 {
			score += 8
		}
		if len(s.Suspicious) > 0 {
			score += len(s.Suspicious) * 6
		}
	}
	for _, imp := range imports {
		score += len(imp.Category)
	}
	if score > 100 {
		score = 100
	}
	level := "low"
	if score >= 70 {
		level = "high"
	} else if score >= 35 {
		level = "medium"
	}
	return score, level
}

func applyVulnRisk(score int, vulns []api.VulnerabilityFinding) (int, string) {
	for _, v := range vulns {
		switch v.Severity {
		case "high":
			score += 10
		case "medium":
			score += 5
		case "info":
			score += 1
		}
	}
	if score > 100 {
		score = 100
	}
	level := "low"
	if score >= 70 {
		level = "high"
	} else if score >= 35 {
		level = "medium"
	}
	return score, level
}

func findingSummary(findings []api.Finding) map[string]int {
	out := map[string]int{"high": 0, "medium": 0, "info": 0}
	for _, f := range findings {
		if _, ok := out[f.Severity]; !ok {
			out[f.Severity] = 0
		}
		out[f.Severity]++
	}
	return out
}

func importSummary(imports []api.ImportFunction) map[string]int {
	out := map[string]int{}
	for _, imp := range imports {
		for _, cat := range imp.Category {
			out[cat]++
		}
	}
	return out
}

func stringSummary(stringsFound []api.StringHit) map[string]int {
	out := map[string]int{"total": len(stringsFound)}
	for _, s := range stringsFound {
		out[s.Encoding]++
		for _, tag := range s.Tags {
			out[tag]++
		}
	}
	return out
}

func capabilities(imports []api.ImportFunction, stringsFound []api.StringHit, security map[string]bool) []string {
	seen := map[string]bool{}
	add := func(v string) {
		if v != "" {
			seen[v] = true
		}
	}
	for _, imp := range imports {
		for _, cat := range imp.Category {
			switch cat {
			case "networking":
				add("network communication")
			case "process injection":
				add("process injection or remote execution")
			case "anti-debugging":
				add("anti-debugging")
			case "dynamic loading":
				add("runtime API resolution")
			case "cryptography":
				add("cryptography")
			case "registry operations":
				add("registry access")
			case "persistence":
				add("persistence primitives")
			case "privilege escalation":
				add("token or privilege manipulation")
			case "memory allocation":
				add("dynamic memory permission changes")
			}
		}
	}
	for _, s := range stringsFound {
		for _, tag := range s.Tags {
			switch tag {
			case "url", "domain", "ip":
				add("network indicators in strings")
			case "registry":
				add("registry indicators in strings")
			case "command":
				add("command execution strings")
			case "crypto":
				add("crypto-related strings")
			case "user-agent":
				add("HTTP user-agent strings")
			}
		}
	}
	if security != nil {
		if !security["aslr_dynamic_base"] {
			add("no ASLR dynamic base flag")
		}
		if !security["control_flow_guard"] {
			add("no Control Flow Guard flag")
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func enhanceFunctions(existing []api.Function, ins []api.Instruction) []api.Function {
	if len(ins) == 0 {
		return existing
	}
	seen := map[string]bool{}
	out := make([]api.Function, 0, len(existing)+16)
	for _, fn := range existing {
		seen[fn.Start] = true
		out = append(out, fn)
	}
	index := map[string]int{}
	for i, in := range ins {
		index[in.Address] = i
	}
	for _, in := range ins {
		if in.Kind != "call" || in.Target == "" || seen[in.Target] {
			continue
		}
		startIdx, ok := index[in.Target]
		if !ok {
			continue
		}
		endIdx := startIdx
		calls := []string{}
		for j := startIdx; j < len(ins) && j < startIdx+512; j++ {
			endIdx = j
			if ins[j].Kind == "call" && ins[j].Target != "" {
				calls = appendUnique(calls, ins[j].Target)
			}
			if ins[j].Kind == "return" {
				break
			}
		}
		fn := api.Function{
			Name:   "sub_" + strings.TrimPrefix(in.Target, "0x"),
			Start:  in.Target,
			End:    ins[endIdx].Address,
			Size:   estimateSize(in.Target, ins[endIdx].Address),
			Calls:  calls,
			Blocks: 1,
		}
		out = append(out, fn)
		seen[fn.Start] = true
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

func appendUnique(values []string, v string) []string {
	for _, existing := range values {
		if existing == v {
			return values
		}
	}
	return append(values, v)
}

func estimateSize(start, end string) uint64 {
	a, errA := strconv.ParseUint(strings.TrimPrefix(start, "0x"), 16, 64)
	b, errB := strconv.ParseUint(strings.TrimPrefix(end, "0x"), 16, 64)
	if errA != nil || errB != nil || b < a {
		return 0
	}
	return b - a + 1
}

func ConsoleSummary(r api.AnalysisReport, root string, verbose bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nretract analysis complete\n")
	fmt.Fprintf(&b, "-------------------------\n")
	if r.CaseID != "" {
		fmt.Fprintf(&b, "case       %s\n", r.CaseID)
	}
	fmt.Fprintf(&b, "sample     %s\n", r.Metadata.Filename)
	fmt.Fprintf(&b, "output     %s\n", root)
	fmt.Fprintf(&b, "format     %s / %s / entry %s\n", r.Metadata.FileType, r.Metadata.Arch, r.Metadata.EntryPoint)
	fmt.Fprintf(&b, "size       %s (%d bytes)\n", humanBytes(r.Metadata.Size), r.Metadata.Size)
	fmt.Fprintf(&b, "risk       %s (%d/100)    findings high=%d medium=%d info=%d    vulns high=%d medium=%d info=%d\n", strings.ToUpper(r.RiskLevel), r.RiskScore, r.FindingSummary["high"], r.FindingSummary["medium"], r.FindingSummary["info"], r.VulnerabilitySummary["high"], r.VulnerabilitySummary["medium"], r.VulnerabilitySummary["info"])
	fmt.Fprintf(&b, "surface    sections=%d imports=%d exports=%d strings=%d functions=%d cfg_blocks=%d\n", len(r.Sections), len(r.Imports), len(r.Exports), len(r.Strings), len(r.Functions), len(r.Blocks))
	fmt.Fprintf(&b, "deep       api_cats=%d tasks=%d rules=%d instr=%d max_complexity=%d iocs=%d\n", len(r.DeepAnalysis.APISurface), len(r.DeepAnalysis.TriageTasks), len(r.DeepAnalysis.DetectionRules), r.DeepAnalysis.InstructionStats.Total, r.DeepAnalysis.ControlFlowMetrics.MaxFunctionComplexity, r.DeepAnalysis.IOCs.TotalTagged)
	fmt.Fprintf(&b, "pe         reloc_blocks=%d tls_callbacks=%d debug_entries=%d overlay=%t certificate=%t resources=%t load_config=%t\n", len(r.Relocations), len(r.TLSCallbacks), len(r.DebugEntries), r.Overlay.Present, r.Certificate.Present, r.Resources.Present, r.LoadConfig.Present)
	fmt.Fprintf(&b, "mitigate   aslr=%t dep=%t cfg=%t high_entropy_va=%t\n", r.Security["aslr_dynamic_base"], r.Security["dep_nx_compat"], r.Security["control_flow_guard"], r.Security["high_entropy_va"])
	if len(r.Capabilities) > 0 {
		fmt.Fprintf(&b, "capability %s\n", strings.Join(firstN(r.Capabilities, 5), ", "))
	}
	fmt.Fprintf(&b, "\nopen next\n")
	fmt.Fprintf(&b, "  reports/triage.md        first-read analyst checklist\n")
	fmt.Fprintf(&b, "  reports/executive.md     concise business summary\n")
	fmt.Fprintf(&b, "  reports/technical.md     deep PE and behavior details\n")
	fmt.Fprintf(&b, "  reports/indicators.md    hashes and extracted pivots\n")
	fmt.Fprintf(&b, "  deep/analyst_workflow.md generated task queue and API surface\n")
	fmt.Fprintf(&b, "  visuals/entropy_timeline.png\n")
	if verbose && len(r.Findings) > 0 {
		b.WriteString("\nfindings\n")
		limit := len(r.Findings)
		if limit > 12 {
			limit = 12
		}
		for _, f := range r.Findings[:limit] {
			fmt.Fprintf(&b, "  %-6s %-22s %s\n", f.Severity, f.Category, f.Message)
		}
	}
	b.WriteByte('\n')
	return b.String()
}

func firstN(values []string, n int) []string {
	if len(values) <= n {
		return values
	}
	return values[:n]
}

func humanBytes(v int64) string {
	units := []string{"B", "KB", "MB", "GB"}
	f := float64(v)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", v, units[i])
	}
	return fmt.Sprintf("%.2f %s", f, units[i])
}
