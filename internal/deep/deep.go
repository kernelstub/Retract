package deep

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"retract/internal/entropy"
	"retract/pkg/api"
)

func Analyze(data []byte, report api.AnalysisReport) api.DeepAnalysis {
	iocs := iocs(report.Strings)
	graph := graphAnalysis(report)
	fingerprints := functionFingerprints(data, report)
	signatures := signatureMatches(report, fingerprints)
	deep := api.DeepAnalysis{
		MemoryMap:          memoryMap(data, report),
		BytePatterns:       bytePatterns(data),
		InstructionStats:   instructionStats(report.Instructions),
		ControlFlowMetrics: controlFlowMetrics(report),
		APISurface:         apiSurface(report.Imports),
		IOCs:               iocs,
		DetectionRules:     detectionRules(report),
		SearchIndex:        searchIndex(report),
		Hex:                hexAnalysis(data, report),
		DataFlow:           dataFlow(report),
		Graph:              graph,
		Fingerprints:       fingerprints,
		Signatures:         signatures,
		Project:            projectDatabase(report, graph, fingerprints, signatures),
	}
	deep.TriageTasks = triageTasks(report, iocs)
	return deep
}

func memoryMap(data []byte, report api.AnalysisReport) []api.MemoryRegion {
	var out []api.MemoryRegion
	for _, s := range report.Sections {
		notes := append([]string{}, s.Suspicious...)
		if s.RawSize == 0 {
			notes = append(notes, "zero raw size")
		}
		if s.VirtualSize > s.RawSize && s.RawSize > 0 {
			notes = append(notes, "virtual size exceeds raw size")
		}
		out = append(out, api.MemoryRegion{
			Name:        s.Name,
			Kind:        "section",
			FileOffset:  int(s.RawOffset),
			FileSize:    int(s.RawSize),
			VirtualAddr: fmt.Sprintf("0x%x", s.VirtualAddress),
			VirtualSize: s.VirtualSize,
			Permissions: s.Permissions,
			Entropy:     s.Entropy,
			Notes:       notes,
		})
	}
	if report.Overlay.Present {
		out = append(out, api.MemoryRegion{
			Name:       "overlay",
			Kind:       "overlay",
			FileOffset: report.Overlay.Offset,
			FileSize:   report.Overlay.Size,
			Entropy:    report.Overlay.Entropy,
			Notes:      []string{"data outside mapped sections"},
		})
	}
	if len(out) == 0 && len(data) > 0 {
		out = append(out, api.MemoryRegion{Name: "raw", Kind: "file", FileOffset: 0, FileSize: len(data), Entropy: entropy.Shannon(data)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FileOffset < out[j].FileOffset })
	return out
}

func bytePatterns(data []byte) []api.BytePattern {
	var out []api.BytePattern
	for _, n := range []int{1, 2, 3, 4} {
		counts := map[string]int{}
		total := 0
		for i := 0; i+n <= len(data); i++ {
			counts[fmt.Sprintf("% x", data[i:i+n])]++
			total++
			if total > 2_000_000 && n > 1 {
				break
			}
		}
		type pair struct {
			p string
			c int
		}
		var pairs []pair
		for p, c := range counts {
			if n > 1 && c < 3 {
				continue
			}
			pairs = append(pairs, pair{p: p, c: c})
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].c > pairs[j].c })
		limit := 12
		if len(pairs) < limit {
			limit = len(pairs)
		}
		for i := 0; i < limit; i++ {
			ratio := 0.0
			if total > 0 {
				ratio = float64(pairs[i].c) / float64(total)
			}
			out = append(out, api.BytePattern{Pattern: pairs[i].p, Size: n, Count: pairs[i].c, Ratio: ratio})
		}
	}
	return out
}

func instructionStats(ins []api.Instruction) api.InstructionStats {
	stats := api.InstructionStats{
		Total:      len(ins),
		Mnemonics:  map[string]int{},
		Categories: map[string]int{},
		Registers:  map[string]int{},
	}
	regs := []string{"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip", "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"}
	for _, in := range ins {
		m := strings.ToLower(in.Mnemonic)
		stats.Mnemonics[m]++
		stats.Categories[instructionCategory(m)]++
		op := strings.ToLower(in.Operand)
		for _, r := range regs {
			if strings.Contains(op, r) {
				stats.Registers[r]++
			}
		}
		if m == "syscall" || strings.HasPrefix(m, "int") || strings.Contains(op, "fs:") || strings.Contains(op, "gs:") {
			stats.Interesting = append(stats.Interesting, fmt.Sprintf("%s %s %s", in.Address, in.Mnemonic, in.Operand))
		}
	}
	stats.UniqueMnemonics = len(stats.Mnemonics)
	if len(stats.Interesting) > 50 {
		stats.Interesting = stats.Interesting[:50]
	}
	return stats
}

func instructionCategory(m string) string {
	switch {
	case m == "call":
		return "call"
	case strings.HasPrefix(m, "j"):
		return "branch"
	case m == "ret":
		return "return"
	case strings.HasPrefix(m, "mov") || strings.HasPrefix(m, "lea"):
		return "data_movement"
	case strings.HasPrefix(m, "cmp") || strings.HasPrefix(m, "test"):
		return "compare"
	case strings.HasPrefix(m, "push") || strings.HasPrefix(m, "pop"):
		return "stack"
	case strings.HasPrefix(m, "add") || strings.HasPrefix(m, "sub") || strings.HasPrefix(m, "xor") || strings.HasPrefix(m, "or") || strings.HasPrefix(m, "and"):
		return "arithmetic_logic"
	default:
		return "other"
	}
}

func controlFlowMetrics(report api.AnalysisReport) api.ControlFlowMetrics {
	m := api.ControlFlowMetrics{Functions: len(report.Functions), BasicBlocks: len(report.Blocks)}
	for _, b := range report.Blocks {
		m.Edges += len(b.Edges)
	}
	for _, f := range report.FunctionInsights {
		m.Calls += f.CallCount
		m.Branches += f.BranchCount
		m.Returns += f.ReturnCount
		m.AvgFunctionComplexity += float64(f.Complexity)
		if f.Complexity > m.MaxFunctionComplexity {
			m.MaxFunctionComplexity = f.Complexity
		}
	}
	if len(report.FunctionInsights) > 0 {
		m.AvgFunctionComplexity /= float64(len(report.FunctionInsights))
	}
	return m
}

func apiSurface(imports []api.ImportFunction) []api.APISurfaceEntry {
	type bucket struct {
		count int
		dlls  map[string]bool
		funcs map[string]bool
	}
	buckets := map[string]*bucket{}
	for _, imp := range imports {
		cats := imp.Category
		if len(cats) == 0 {
			cats = []string{"uncategorized"}
		}
		for _, cat := range cats {
			b := buckets[cat]
			if b == nil {
				b = &bucket{dlls: map[string]bool{}, funcs: map[string]bool{}}
				buckets[cat] = b
			}
			b.count++
			b.dlls[imp.DLL] = true
			if imp.Name != "" {
				b.funcs[imp.DLL+"!"+imp.Name] = true
			}
		}
	}
	var out []api.APISurfaceEntry
	for cat, b := range buckets {
		out = append(out, api.APISurfaceEntry{Category: cat, Count: b.count, DLLs: keys(b.dlls), Functions: limitStrings(keys(b.funcs), 30), Risk: apiRisk(cat, b.count)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Risk == out[j].Risk {
			return out[i].Count > out[j].Count
		}
		return riskRank(out[i].Risk) > riskRank(out[j].Risk)
	})
	return out
}

func iocs(stringsFound []api.StringHit) api.IOCSummary {
	var out api.IOCSummary
	add := func(dst *[]string, value string) {
		if value == "" || contains(*dst, value) || len(*dst) >= 200 {
			return
		}
		*dst = append(*dst, value)
	}
	for _, s := range stringsFound {
		if len(s.Tags) > 0 {
			out.TotalTagged++
		}
		for _, tag := range s.Tags {
			switch tag {
			case "url":
				add(&out.URLs, s.Value)
			case "domain":
				add(&out.Domains, s.Value)
			case "ip":
				add(&out.IPs, s.Value)
			case "registry":
				add(&out.Registry, s.Value)
			case "path":
				add(&out.Paths, s.Value)
			case "secret":
				add(&out.Secrets, s.Value)
			case "user-agent":
				add(&out.UserAgents, s.Value)
			case "command":
				add(&out.Commands, s.Value)
			}
		}
	}
	return out
}

func triageTasks(report api.AnalysisReport, iocs api.IOCSummary) []api.TriageTask {
	var tasks []api.TriageTask
	add := func(priority, title, why string, actions, artifacts []string) {
		tasks = append(tasks, api.TriageTask{Priority: priority, Title: title, Why: why, Actions: actions, Artifacts: artifacts})
	}
	if report.RiskScore >= 70 {
		add("P0", "Escalate high-risk sample", fmt.Sprintf("risk score is %d/%s", report.RiskScore, report.RiskLevel), []string{"Open executive report", "Review high/medium vulnerability findings", "Validate packer and entropy signals"}, []string{"reports/executive.md", "vulnerabilities/vulnerabilities.md"})
	}
	if report.Metadata.FileType == "PE" && (!report.Security["aslr_dynamic_base"] || !report.Security["control_flow_guard"]) {
		add("P1", "Review exploit mitigation gaps", "static PE flags indicate missing hardening controls", []string{"Confirm compiler/linker flags", "Map missing mitigations to exploitability assumptions"}, []string{"headers/security_features.json", "headers/load_config.json"})
	}
	if len(iocs.URLs)+len(iocs.Domains)+len(iocs.IPs) > 0 {
		add("P1", "Pivot network indicators", "network-like strings were extracted", []string{"Review URLs/domains/IPs", "Check reputation in controlled environment"}, []string{"strings/urls.txt", "strings/domains.txt", "strings/ips.txt"})
	}
	for _, s := range report.Sections {
		if s.Entropy >= 7.2 {
			add("P1", "Unpack or carve high-entropy code/data", s.Name+" has high entropy", []string{"Inspect section bytes", "Compare section permissions", "Run dynamic unpacking workflow if authorized"}, []string{"sections/sections.json", "entropy/high_entropy_regions.csv"})
			break
		}
	}
	add("P2", "Review reconstructed C and CFG", "static decompilation is approximate but useful for triage", []string{"Open recovered C", "Inspect highest-complexity functions", "Trace xrefs into suspicious imports"}, []string{"source/reconstructed.c", "control_flow/cfg.dot", "symbols/xrefs.csv"})
	return tasks
}

func detectionRules(report api.AnalysisReport) []api.DetectionRule {
	rules := []api.DetectionRule{
		rule("Packed or encrypted region", "medium", hasHighEntropySection(report.Sections), evidenceHighEntropy(report.Sections), "medium"),
		rule("Writable executable memory surface", "high", hasImportCategory(report.Imports, "memory allocation"), []string{"VirtualAlloc/VirtualProtect/Heap allocation style imports"}, "medium"),
		rule("Network-capable artifact", "medium", hasCapability(report.Capabilities, "network"), []string{"network import category or network strings"}, "medium"),
		rule("Anti-debug or analysis friction", "high", hasImportCategory(report.Imports, "anti-debugging"), []string{"anti-debugging imports detected"}, "high"),
		rule("Missing modern exploit mitigations", "medium", report.Metadata.FileType == "PE" && (!report.Security["aslr_dynamic_base"] || !report.Security["control_flow_guard"]), []string{"ASLR or CFG absent"}, "high"),
		rule("Embedded payload candidate", "medium", len(report.EmbeddedArtifacts) > 0, []string{fmt.Sprintf("%d embedded artifacts", len(report.EmbeddedArtifacts))}, "medium"),
	}
	return rules
}

func searchIndex(report api.AnalysisReport) []api.SearchEntry {
	var out []api.SearchEntry
	add := func(kind, name, value, location string, tags ...string) {
		if name == "" && value == "" {
			return
		}
		out = append(out, api.SearchEntry{Kind: kind, Name: name, Value: value, Location: location, Tags: tags})
	}
	for _, s := range report.Sections {
		add("section", s.Name, fmt.Sprintf("va=0x%x raw=0x%x size=%d entropy=%.2f flags=%s", s.VirtualAddress, s.RawOffset, s.RawSize, s.Entropy, s.Flags), fmt.Sprintf("0x%x", s.RawOffset), s.Suspicious...)
	}
	for _, imp := range report.Imports {
		add("import", imp.DLL+"!"+imp.Name, strings.Join(imp.Category, ", "), imp.Address, imp.Category...)
	}
	for _, exp := range report.Exports {
		add("export", exp.Name, exp.RVA, exp.RVA)
	}
	for _, str := range report.Strings {
		add("string", str.Value, str.Encoding, fmt.Sprintf("0x%x", str.Offset), str.Tags...)
		if len(out) > 25000 {
			break
		}
	}
	for _, fn := range report.FunctionInsights {
		add("function", fn.Name, fmt.Sprintf("complexity=%d instructions=%d calls=%d branches=%d", fn.Complexity, fn.InstructionCount, fn.CallCount, fn.BranchCount), fn.Start, fn.RiskNotes...)
	}
	for _, x := range report.Xrefs {
		add("xref", x.From+" -> "+x.To, x.Evidence, x.From, x.Kind)
	}
	for _, v := range report.Vulnerabilities {
		add("vulnerability", v.ID, v.Title+" "+v.Evidence, "", v.Severity, v.Category)
	}
	return out
}

func hexAnalysis(data []byte, report api.AnalysisReport) api.HexAnalysis {
	var out api.HexAnalysis
	for _, r := range memoryMap(data, report) {
		out.AddressMappings = append(out.AddressMappings, api.AddressMapping{Name: r.Name, FileOffset: r.FileOffset, VirtualAddress: r.VirtualAddr, Size: r.FileSize})
		out.Bookmarks = append(out.Bookmarks, api.HexBookmark{Name: r.Name, Offset: r.FileOffset, Size: r.FileSize, Kind: r.Kind, Description: strings.Join(r.Notes, "; "), Tags: r.Notes})
	}
	for _, s := range report.Strings {
		if len(s.Tags) == 0 {
			continue
		}
		out.Bookmarks = append(out.Bookmarks, api.HexBookmark{Name: trimName(s.Value), Offset: s.Offset, Size: len(s.Value), Kind: "string", Description: strings.Join(s.Tags, ", "), Tags: s.Tags})
		if len(out.Bookmarks) > 2000 {
			break
		}
	}
	patterns := map[string][]byte{
		"MZ":     {'M', 'Z'},
		"PE":     {'P', 'E', 0, 0},
		"ELF":    {0x7f, 'E', 'L', 'F'},
		"ZIP":    {'P', 'K', 3, 4},
		"PNG":    {0x89, 'P', 'N', 'G'},
		"NULL16": make([]byte, 16),
	}
	for name, pat := range patterns {
		for _, off := range findPattern(data, pat, 256) {
			out.SearchHits = append(out.SearchHits, api.HexSearchHit{Query: name, Kind: "binary", Offset: off, Size: len(pat), Preview: previewBytes(data, off, 32)})
		}
	}
	return out
}

func dataFlow(report api.AnalysisReport) api.DataFlowAnalysis {
	var out api.DataFlowAnalysis
	registers := []string{"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip", "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"}
	funcByAddr := funcNameForInstructions(report.Functions)
	lastDef := map[string]api.RegisterAccess{}
	chains := map[string]*api.DefUseChain{}
	for _, in := range report.Instructions {
		fn := funcByAddr(in.Address)
		m := strings.ToLower(in.Mnemonic)
		op := strings.ToLower(in.Operand)
		for _, reg := range registers {
			if !strings.Contains(op, reg) {
				continue
			}
			access := "use"
			if writesRegister(m, op, reg) {
				access = "def"
			}
			ra := api.RegisterAccess{Function: fn, Address: in.Address, Register: reg, Access: access, Instruction: strings.TrimSpace(in.Mnemonic + " " + in.Operand)}
			out.RegisterAccesses = append(out.RegisterAccesses, ra)
			key := fn + "\x00" + reg
			if access == "def" {
				lastDef[key] = ra
				chains[key+"\x00"+in.Address] = &api.DefUseChain{Function: fn, Register: reg, Def: in.Address}
				continue
			}
			if def, ok := lastDef[key]; ok {
				c := chains[key+"\x00"+def.Address]
				if c != nil {
					c.Uses = append(c.Uses, in.Address)
				}
			}
		}
		if len(out.RegisterAccesses) > 50000 {
			break
		}
	}
	for _, c := range chains {
		if len(c.Uses) > 0 {
			out.DefUseChains = append(out.DefUseChains, *c)
		}
	}
	sort.Slice(out.DefUseChains, func(i, j int) bool { return out.DefUseChains[i].Def < out.DefUseChains[j].Def })
	if len(out.DefUseChains) > 10000 {
		out.DefUseChains = out.DefUseChains[:10000]
	}
	out.TaintTraces = taintTraces(report)
	return out
}

func graphAnalysis(report api.AnalysisReport) api.GraphAnalysis {
	g := api.GraphAnalysis{Callers: map[string][]string{}, Callees: map[string][]string{}, DominatorHints: map[string][]string{}}
	for _, fn := range report.Functions {
		g.Reachable = append(g.Reachable, fn.Name)
		for _, call := range fn.Calls {
			g.Callees[fn.Name] = appendUniqueString(g.Callees[fn.Name], call)
			g.Callers[call] = appendUniqueString(g.Callers[call], fn.Name)
			if call == fn.Start || call == fn.Name {
				g.Recursive = appendUniqueString(g.Recursive, fn.Name)
			}
		}
	}
	for _, b := range report.Blocks {
		for _, edge := range b.Edges {
			if edge <= b.ID {
				g.Loops = appendUniqueString(g.Loops, b.ID+" -> "+edge)
			}
			g.DominatorHints[edge] = appendUniqueString(g.DominatorHints[edge], b.ID)
		}
	}
	sort.Strings(g.Reachable)
	return g
}

func functionFingerprints(data []byte, report api.AnalysisReport) []api.FunctionFingerprint {
	var out []api.FunctionFingerprint
	for _, fn := range report.Functions {
		body := instructionsForFunction(fn, report.Instructions)
		if len(body) == 0 {
			continue
		}
		var raw, mnem strings.Builder
		counts := map[string]int{}
		for _, in := range body {
			m := strings.ToLower(strings.TrimSpace(in.Mnemonic))
			raw.WriteString(in.Bytes)
			raw.WriteByte('|')
			raw.WriteString(m)
			raw.WriteByte(' ')
			raw.WriteString(normalizeOperand(in.Operand))
			raw.WriteByte('\n')
			mnem.WriteString(m)
			mnem.WriteByte(';')
			counts[m]++
		}
		mnemonics := keysInt(counts)
		out = append(out, api.FunctionFingerprint{
			Function:        fn.Name,
			Start:           fn.Start,
			End:             fn.End,
			InstructionHash: sha256Hex(raw.String()),
			MnemonicHash:    sha256Hex(mnem.String()),
			SimHash:         simHash64(counts),
			Size:            fn.Size,
			Instructions:    len(body),
			Calls:           append([]string{}, fn.Calls...),
			Mnemonics:       mnemonics,
		})
	}
	if len(out) == 0 {
		out = sectionFingerprints(data, report)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

func sectionFingerprints(data []byte, report api.AnalysisReport) []api.FunctionFingerprint {
	var out []api.FunctionFingerprint
	for _, s := range report.Sections {
		if s.RawSize == 0 || int(s.RawOffset) >= len(data) {
			continue
		}
		end := int(s.RawOffset + s.RawSize)
		if end > len(data) {
			end = len(data)
		}
		chunk := data[int(s.RawOffset):end]
		if len(chunk) == 0 {
			continue
		}
		tokens := byteNGramCounts(chunk, 4, 4096)
		name := "section_" + strings.Trim(s.Name, ".")
		if name == "section_" {
			name = fmt.Sprintf("section_%x", s.RawOffset)
		}
		out = append(out, api.FunctionFingerprint{
			Function:        name,
			Start:           fmt.Sprintf("file+0x%x", s.RawOffset),
			End:             fmt.Sprintf("file+0x%x", end-1),
			InstructionHash: sha256Bytes(chunk),
			MnemonicHash:    sha256Hex(strings.Join(keysInt(tokens), ";")),
			SimHash:         simHash64(tokens),
			Size:            uint64(len(chunk)),
			Instructions:    0,
			Mnemonics:       keysInt(tokens),
		})
	}
	return out
}

func signatureMatches(report api.AnalysisReport, fps []api.FunctionFingerprint) []api.SignatureMatch {
	var out []api.SignatureMatch
	add := func(name, kind, confidence, severity string, evidence, tags []string) {
		if name == "" {
			return
		}
		out = append(out, api.SignatureMatch{Name: name, Kind: kind, Confidence: confidence, Severity: severity, Evidence: evidence, Tags: tags})
	}
	for _, s := range report.Sections {
		if s.Entropy >= 7.2 {
			add("high entropy section", "packer", "medium", "medium", []string{fmt.Sprintf("%s entropy %.2f", s.Name, s.Entropy)}, []string{"packing", "entropy"})
		}
		if strings.Contains(s.Permissions, "x") && strings.Contains(s.Permissions, "w") {
			add("writable executable section", "memory-permission", "high", "high", []string{s.Name + " has write+execute permissions"}, []string{"exploitability", "self-modifying-code"})
		}
	}
	if report.Overlay.Present {
		add("overlay payload candidate", "container", "medium", "medium", []string{fmt.Sprintf("overlay offset=0x%x size=%d entropy=%.2f", report.Overlay.Offset, report.Overlay.Size, report.Overlay.Entropy)}, []string{"overlay", "payload"})
	}
	for _, surface := range apiSurface(report.Imports) {
		if surface.Risk == "high" || surface.Risk == "medium" {
			add(surface.Category+" API surface", "library-family", "medium", surface.Risk, surface.Functions, []string{"imports", surface.Category})
		}
	}
	for _, cap := range report.Capabilities {
		add(cap, "capability", "medium", "", []string{"capability inferred from imports and strings"}, []string{"capability"})
	}
	for _, f := range fps {
		if f.Instructions >= 250 {
			add("large function fingerprint", "function", "low", "info", []string{f.Function + " " + f.Start + " instructions=" + fmt.Sprint(f.Instructions), "simhash=" + f.SimHash}, []string{"function", "audit-priority"})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].Name < out[j].Name
		}
		return out[i].Kind < out[j].Kind
	})
	return dedupeSignatures(out)
}

func projectDatabase(report api.AnalysisReport, graph api.GraphAnalysis, fps []api.FunctionFingerprint, sigs []api.SignatureMatch) api.ProjectDatabase {
	var symbols, labels, comments []api.SearchEntry
	for _, fn := range report.Functions {
		symbols = append(symbols, api.SearchEntry{Kind: "function", Name: fn.Name, Value: fn.Start, Location: fn.Start})
		labels = append(labels, api.SearchEntry{Kind: "label", Name: fn.Name, Value: "auto function label", Location: fn.Start})
	}
	for _, imp := range report.Imports {
		symbols = append(symbols, api.SearchEntry{Kind: "import", Name: imp.DLL + "!" + imp.Name, Value: strings.Join(imp.Category, ", "), Location: imp.Address})
	}
	for _, f := range report.Findings {
		comments = append(comments, api.SearchEntry{Kind: "finding", Name: f.Category, Value: f.Message, Tags: []string{f.Severity}})
	}
	return api.ProjectDatabase{
		SchemaVersion: 1,
		CaseID:        report.CaseID,
		Sample:        report.Metadata,
		Functions:     report.Functions,
		Symbols:       symbols,
		Types:         report.InferredTypes,
		Structs:       report.StructCandidates,
		Labels:        labels,
		Comments:      comments,
		Xrefs:         report.Xrefs,
		Graph:         graph,
		Fingerprints:  fps,
		Signatures:    sigs,
	}
}

func instructionsForFunction(fn api.Function, ins []api.Instruction) []api.Instruction {
	start := parseHex(fn.Start)
	end := parseHex(fn.End)
	var out []api.Instruction
	for _, in := range ins {
		addr := parseHex(in.Address)
		if addr >= start && (end == 0 || addr <= end) {
			out = append(out, in)
		}
	}
	return out
}

func normalizeOperand(op string) string {
	fields := strings.Fields(strings.ToLower(op))
	for i, f := range fields {
		if strings.HasPrefix(f, "0x") || strings.ContainsAny(f, "0123456789") {
			fields[i] = "imm"
		}
	}
	return strings.Join(fields, " ")
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha256Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func byteNGramCounts(data []byte, n, max int) map[string]int {
	out := map[string]int{}
	if n <= 0 || len(data) < n {
		return out
	}
	limit := len(data) - n + 1
	if max > 0 && limit > max {
		limit = max
	}
	for i := 0; i < limit; i++ {
		out[fmt.Sprintf("% x", data[i:i+n])]++
	}
	return out
}

func simHash64(counts map[string]int) string {
	var acc [64]int
	for token, weight := range counts {
		sum := sha256.Sum256([]byte(token))
		v := binary.LittleEndian.Uint64(sum[:8])
		for i := 0; i < 64; i++ {
			if v&(1<<i) != 0 {
				acc[i] += weight
			} else {
				acc[i] -= weight
			}
		}
	}
	var out uint64
	for i, v := range acc {
		if v >= 0 {
			out |= 1 << i
		}
	}
	return fmt.Sprintf("%016x", out)
}

func keysInt(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 24 {
		out = out[:24]
	}
	return out
}

func dedupeSignatures(in []api.SignatureMatch) []api.SignatureMatch {
	seen := map[string]bool{}
	var out []api.SignatureMatch
	for _, s := range in {
		key := s.Kind + "\x00" + s.Name + "\x00" + strings.Join(s.Evidence, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}

func rule(name, severity string, matched bool, evidence []string, confidence string) api.DetectionRule {
	if !matched {
		evidence = nil
	}
	return api.DetectionRule{Name: name, Severity: severity, Matched: matched, Evidence: evidence, Confidence: confidence}
}

func hasHighEntropySection(sections []api.Section) bool {
	for _, s := range sections {
		if s.Entropy >= 7.2 {
			return true
		}
	}
	return false
}

func evidenceHighEntropy(sections []api.Section) []string {
	var out []string
	for _, s := range sections {
		if s.Entropy >= 7.2 {
			out = append(out, fmt.Sprintf("%s entropy %.2f", s.Name, s.Entropy))
		}
	}
	return out
}

func hasImportCategory(imports []api.ImportFunction, category string) bool {
	for _, imp := range imports {
		for _, cat := range imp.Category {
			if cat == category {
				return true
			}
		}
	}
	return false
}

func hasCapability(caps []string, needle string) bool {
	for _, cap := range caps {
		if strings.Contains(strings.ToLower(cap), needle) {
			return true
		}
	}
	return false
}

func apiRisk(category string, count int) string {
	switch category {
	case "process injection", "anti-debugging", "privilege escalation":
		return "high"
	case "memory allocation", "dynamic loading", "networking", "persistence":
		return "medium"
	default:
		if count >= 20 {
			return "medium"
		}
		return "info"
	}
}

func riskRank(r string) int {
	switch r {
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func limitStrings(in []string, n int) []string {
	if len(in) > n {
		return in[:n]
	}
	return in
}

func contains(values []string, needle string) bool {
	for _, v := range values {
		if v == needle {
			return true
		}
	}
	return false
}

func findPattern(data, pattern []byte, limit int) []int {
	if len(pattern) == 0 || len(data) < len(pattern) {
		return nil
	}
	var out []int
	start := 0
	for len(out) < limit {
		idx := bytes.Index(data[start:], pattern)
		if idx < 0 {
			break
		}
		off := start + idx
		out = append(out, off)
		start = off + 1
	}
	return out
}

func previewBytes(data []byte, off, size int) string {
	if off < 0 || off >= len(data) {
		return ""
	}
	end := off + size
	if end > len(data) {
		end = len(data)
	}
	return fmt.Sprintf("% x", data[off:end])
}

func trimName(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}

func funcNameForInstructions(functions []api.Function) func(string) string {
	type span struct {
		name  string
		start uint64
		end   uint64
	}
	var spans []span
	for _, f := range functions {
		start := parseHex(f.Start)
		end := parseHex(f.End)
		spans = append(spans, span{name: f.Name, start: start, end: end})
	}
	return func(addr string) string {
		a := parseHex(addr)
		for _, s := range spans {
			if a >= s.start && (s.end == 0 || a <= s.end) {
				return s.name
			}
		}
		return "unknown"
	}
}

func parseHex(s string) uint64 {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	var v uint64
	_, _ = fmt.Sscanf(s, "%x", &v)
	return v
}

func writesRegister(mnemonic, operand, reg string) bool {
	if !(strings.HasPrefix(mnemonic, "mov") || strings.HasPrefix(mnemonic, "lea") || strings.HasPrefix(mnemonic, "xor") || strings.HasPrefix(mnemonic, "add") || strings.HasPrefix(mnemonic, "sub") || strings.HasPrefix(mnemonic, "pop")) {
		return false
	}
	first := operand
	if idx := strings.Index(first, ","); idx >= 0 {
		first = first[:idx]
	}
	return strings.Contains(first, reg)
}

func taintTraces(report api.AnalysisReport) []api.TaintTrace {
	var sources, sinks []api.ImportFunction
	for _, imp := range report.Imports {
		name := strings.ToLower(imp.Name)
		if inAny(name, "recv", "readfile", "internetreadfile", "getenv", "getcommandline", "scanf") {
			sources = append(sources, imp)
		}
		if inAny(name, "memcpy", "strcpy", "strcat", "sprintf", "system", "createprocess", "writeprocessmemory") {
			sinks = append(sinks, imp)
		}
	}
	var out []api.TaintTrace
	for _, src := range sources {
		for _, sink := range sinks {
			severity := "medium"
			if inAny(strings.ToLower(sink.Name), "system", "createprocess", "writeprocessmemory", "strcpy", "sprintf") {
				severity = "high"
			}
			out = append(out, api.TaintTrace{
				Source:   src.DLL + "!" + src.Name,
				Sink:     sink.DLL + "!" + sink.Name,
				Path:     []string{"import-source", "manual-dataflow-required", "import-sink"},
				Reason:   "source and sink primitives coexist; static import-level taint requires call-site confirmation",
				Severity: severity,
			})
			if len(out) >= 200 {
				return out
			}
		}
	}
	return out
}

func inAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func appendUniqueString(values []string, v string) []string {
	for _, existing := range values {
		if existing == v {
			return values
		}
	}
	return append(values, v)
}
