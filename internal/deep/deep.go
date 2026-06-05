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
	functionTags := functionTags(report, graph)
	annotations := annotations(report, functionTags)
	jumpTables := jumpTables(report)
	apiCallSites := apiCallSites(report)
	stringRefs := stringReferences(report)
	stackFrames := stackFrames(report)
	blockNotes := basicBlockNotes(report)
	decompilerHints := decompilerHints(report)
	functionClusters := functionClusters(report, fingerprints)
	hotPaths := hotPaths(report, functionTags, apiCallSites, stringRefs)
	patchPoints := patchPoints(report)
	callingConventions := callingConventions(report, stackFrames)
	unpackingHints := unpackingHints(report)
	typeHints := typePropagationHints(report, apiCallSites, stringRefs)
	timeline := analysisTimeline(report)
	capabilityMatrix := capabilityMatrix(report, apiCallSites, stringRefs, unpackingHints)
	antiAnalysisHits := antiAnalysisIndicators(report, apiCallSites)
	cryptoHits := cryptoIndicators(report)
	persistenceHits := persistenceIndicators(report, apiCallSites)
	syscallHits := syscallIndicators(report)
	deep := api.DeepAnalysis{
		MemoryMap:          memoryMap(data, report),
		BytePatterns:       bytePatterns(data),
		InstructionStats:   instructionStats(report.Instructions),
		ControlFlowMetrics: controlFlowMetrics(report),
		APISurface:         apiSurface(report.Imports),
		IOCs:               iocs,
		DetectionRules:     detectionRules(report),
		SearchIndex:        searchIndex(report, functionTags, annotations, jumpTables, apiCallSites, stringRefs, stackFrames, blockNotes, decompilerHints, functionClusters, hotPaths, patchPoints, callingConventions, unpackingHints, typeHints, timeline, capabilityMatrix, antiAnalysisHits, cryptoHits, persistenceHits, syscallHits),
		Hex:                hexAnalysis(data, report),
		DataFlow:           dataFlow(report),
		Graph:              graph,
		Fingerprints:       fingerprints,
		Signatures:         signatures,
		FunctionTags:       functionTags,
		Annotations:        annotations,
		JumpTables:         jumpTables,
		APICallSites:       apiCallSites,
		StringRefs:         stringRefs,
		StackFrames:        stackFrames,
		BlockNotes:         blockNotes,
		DecompilerHints:    decompilerHints,
		FunctionClusters:   functionClusters,
		HotPaths:           hotPaths,
		PatchPoints:        patchPoints,
		CallingConventions: callingConventions,
		UnpackingHints:     unpackingHints,
		TypeHints:          typeHints,
		Timeline:           timeline,
		CapabilityMatrix:   capabilityMatrix,
		AntiAnalysis:       antiAnalysisHits,
		CryptoIndicators:   cryptoHits,
		Persistence:        persistenceHits,
		SyscallIndicators:  syscallHits,
		Project:            projectDatabase(report, graph, fingerprints, signatures, functionTags, annotations, jumpTables, apiCallSites, stringRefs, stackFrames, blockNotes, decompilerHints, functionClusters, hotPaths, patchPoints, callingConventions, unpackingHints, typeHints, timeline, capabilityMatrix, antiAnalysisHits, cryptoHits, persistenceHits, syscallHits),
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

func searchIndex(report api.AnalysisReport, functionTags []api.FunctionTag, annotations []api.REAnnotation, jumpTables []api.JumpTableCandidate, apiCallSites []api.APICallSite, stringRefs []api.StringReference, stackFrames []api.StackFrameLayout, blockNotes []api.BasicBlockNote, decompilerHints []api.DecompilerHint, functionClusters []api.FunctionCluster, hotPaths []api.HotPath, patchPoints []api.PatchPoint, callingConventions []api.CallingConventionGuess, unpackingHints []api.UnpackingHint, typeHints []api.TypePropagationHint, timeline []api.AnalysisTimelineEvent, capabilityMatrix []api.CapabilityMatrixEntry, antiAnalysisHits []api.IndicatorHit, cryptoHits []api.IndicatorHit, persistenceHits []api.IndicatorHit, syscallHits []api.IndicatorHit) []api.SearchEntry {
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
	for _, t := range functionTags {
		add("function-tag", t.Function, t.Tag+" "+strings.Join(t.Evidence, "; "), t.Start, t.Confidence)
	}
	for _, a := range annotations {
		add("annotation", a.Function, a.Text, a.Address, append([]string{a.Kind, a.Severity}, a.Tags...)...)
	}
	for _, jt := range jumpTables {
		add("jump-table", jt.Function, strings.Join(jt.Evidence, "; "), jt.Address, jt.Confidence)
	}
	for _, cs := range apiCallSites {
		add("api-call-site", cs.API, strings.Join(cs.Category, ", "), cs.Address, append([]string{cs.Function, cs.Confidence}, cs.Category...)...)
	}
	for _, ref := range stringRefs {
		add("string-reference", ref.String, ref.Evidence, ref.Address, append([]string{ref.Kind, ref.Confidence}, ref.Tags...)...)
	}
	for _, frame := range stackFrames {
		add("stack-frame", frame.Function, fmt.Sprintf("frame_size=0x%x locals=%d args=%d saved=%s", frame.FrameSize, len(frame.Locals), len(frame.Arguments), strings.Join(frame.SavedRegisters, ",")), "", "stack")
	}
	for _, note := range blockNotes {
		add("basic-block-note", note.BlockID, note.Text, note.Start, note.Kind, note.Severity)
	}
	for _, hint := range decompilerHints {
		add("decompiler-hint", hint.Function, hint.Hint, hint.Address, hint.Kind, hint.Confidence)
	}
	for _, cluster := range functionClusters {
		add("function-cluster", cluster.ID, strings.Join(cluster.Functions, ", "), "", cluster.Kind, cluster.Confidence)
	}
	for _, path := range hotPaths {
		add("hot-path", path.Function, strings.Join(path.Reasons, "; "), path.Start, fmt.Sprintf("score:%d", path.Score))
	}
	for _, pp := range patchPoints {
		add("patch-point", pp.Function, pp.Kind+" "+strings.Join(pp.Evidence, "; "), pp.Address, pp.Risk, pp.Confidence)
	}
	for _, cc := range callingConventions {
		add("calling-convention", cc.Function, cc.Convention+" "+strings.Join(cc.ArgumentStorage, ", "), cc.Start, cc.Confidence)
	}
	for _, u := range unpackingHints {
		add("unpacking-hint", u.Region, strings.Join(u.Evidence, "; "), u.Address, u.Priority, u.Kind, u.Confidence)
	}
	for _, t := range typeHints {
		add("type-propagation", t.Symbol, t.Type+" from "+t.Source, t.Address, t.Function, t.Confidence)
	}
	for _, event := range timeline {
		add("timeline", event.Title, event.Detail, "", event.Phase, event.Severity)
	}
	for _, cap := range capabilityMatrix {
		add("capability-matrix", cap.Capability, strings.Join(cap.Signals, "; "), "", fmt.Sprintf("score:%d", cap.Score))
	}
	for _, hit := range append(append(append(antiAnalysisHits, cryptoHits...), persistenceHits...), syscallHits...) {
		add("indicator", hit.Name, strings.Join(hit.Evidence, "; "), hit.Location, hit.Kind, hit.Severity, hit.Confidence)
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

func functionTags(report api.AnalysisReport, graph api.GraphAnalysis) []api.FunctionTag {
	var out []api.FunctionTag
	add := func(fn api.Function, tag, confidence string, evidence ...string) {
		out = append(out, api.FunctionTag{Function: fn.Name, Start: fn.Start, Tag: tag, Confidence: confidence, Evidence: evidence})
	}
	insights := map[string]api.FunctionInsight{}
	for _, insight := range report.FunctionInsights {
		insights[insight.Name] = insight
	}
	for _, fn := range report.Functions {
		body := instructionsForFunction(fn, report.Instructions)
		insight := insights[fn.Name]
		if len(fn.Calls) == 0 {
			add(fn, "leaf", "medium", "no recovered call edges")
		}
		if insight.ReturnCount == 0 {
			add(fn, "noreturn-candidate", "low", "no return decoded in function range")
		}
		if insight.Complexity >= 12 || insight.BranchCount >= 10 {
			add(fn, "state-machine-or-parser", "medium", fmt.Sprintf("complexity=%d branches=%d", insight.Complexity, insight.BranchCount))
		}
		if insight.EstimatedStack >= 0x200 {
			add(fn, "large-stack-frame", "medium", fmt.Sprintf("estimated stack frame 0x%x", insight.EstimatedStack))
		}
		if isThunk(body) {
			add(fn, "thunk-or-wrapper", "medium", "short function dominated by a jump or call")
		}
		for _, loop := range graph.Loops {
			if strings.Contains(loop, strings.TrimPrefix(fn.Start, "0x")) {
				add(fn, "loop-owner", "low", loop)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Function == out[j].Function {
			return out[i].Tag < out[j].Tag
		}
		return out[i].Function < out[j].Function
	})
	return out
}

func annotations(report api.AnalysisReport, tags []api.FunctionTag) []api.REAnnotation {
	var out []api.REAnnotation
	add := func(addr, fn, kind, text, severity string, tags ...string) {
		out = append(out, api.REAnnotation{Address: addr, Function: fn, Kind: kind, Text: text, Severity: severity, Tags: tags})
	}
	for _, t := range tags {
		add(t.Start, t.Function, "function-tag", t.Tag+": "+strings.Join(t.Evidence, "; "), severityForTag(t.Tag), t.Tag, t.Confidence)
	}
	for _, x := range report.Xrefs {
		if x.Kind == "code-call" {
			add(x.From, "", "xref", "call edge to "+x.To, "info", "xref", "call")
		}
	}
	for _, v := range report.Vulnerabilities {
		add("", "", "vulnerability", v.ID+": "+v.Title+" ("+v.Evidence+")", v.Severity, v.Category)
	}
	for _, s := range report.Sections {
		if len(s.Suspicious) > 0 {
			add(fmt.Sprintf("0x%x", s.VirtualAddress), "", "section-note", s.Name+": "+strings.Join(s.Suspicious, "; "), "medium", "section")
		}
	}
	if len(out) > 5000 {
		out = out[:5000]
	}
	return out
}

func jumpTables(report api.AnalysisReport) []api.JumpTableCandidate {
	var out []api.JumpTableCandidate
	funcByAddr := funcNameForInstructions(report.Functions)
	for _, in := range report.Instructions {
		m := strings.ToLower(in.Mnemonic)
		op := strings.ToLower(in.Operand)
		if m != "jmp" && !(in.Kind == "jump" || in.Kind == "branch") {
			continue
		}
		if strings.Contains(op, "[") && (strings.Contains(op, "*") || strings.Contains(op, "rip") || strings.Contains(op, "rax") || strings.Contains(op, "eax")) {
			out = append(out, api.JumpTableCandidate{
				Function:   funcByAddr(in.Address),
				Address:    in.Address,
				Base:       in.Operand,
				Confidence: "medium",
				Evidence:   []string{strings.TrimSpace(in.Mnemonic + " " + in.Operand), "indirect branch through memory/register expression"},
			})
		}
	}
	for _, fn := range report.FunctionInsights {
		if fn.BranchCount >= 12 && fn.Complexity >= 12 {
			out = append(out, api.JumpTableCandidate{
				Function:   fn.Name,
				Address:    fn.Start,
				Entries:    fn.BranchCount,
				Confidence: "low",
				Evidence:   []string{fmt.Sprintf("dense branch fanout: branches=%d complexity=%d", fn.BranchCount, fn.Complexity)},
			})
		}
	}
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out
}

func apiCallSites(report api.AnalysisReport) []api.APICallSite {
	importByAddr := map[string]api.ImportFunction{}
	for _, imp := range report.Imports {
		if imp.Address != "" {
			importByAddr[strings.ToLower(imp.Address)] = imp
		}
	}
	funcByAddr := funcNameForInstructions(report.Functions)
	var out []api.APICallSite
	for _, in := range report.Instructions {
		if in.Kind != "call" {
			continue
		}
		imp, ok := importByAddr[strings.ToLower(in.Target)]
		if !ok {
			imp, ok = importByAddr[strings.ToLower(in.Operand)]
		}
		if !ok {
			continue
		}
		apiName := imp.DLL + "!" + imp.Name
		if imp.Name == "" {
			apiName = fmt.Sprintf("%s!ordinal_%d", imp.DLL, imp.Ordinal)
		}
		out = append(out, api.APICallSite{
			Function:   funcByAddr(in.Address),
			Address:    in.Address,
			API:        apiName,
			Category:   append([]string{}, imp.Category...),
			Arguments:  []string{"rcx", "rdx", "r8", "r9", "stack"},
			Confidence: "medium",
			Evidence:   strings.TrimSpace(in.Mnemonic + " " + in.Operand),
		})
	}
	return out
}

func stringReferences(report api.AnalysisReport) []api.StringReference {
	if len(report.Strings) == 0 || len(report.Instructions) == 0 {
		return nil
	}
	byAddr := map[uint64]api.StringHit{}
	for _, s := range report.Strings {
		byAddr[uint64(s.Offset)] = s
		for _, sec := range report.Sections {
			start := int(sec.RawOffset)
			end := start + int(sec.RawSize)
			if s.Offset >= start && s.Offset < end {
				va := uint64(sec.VirtualAddress) + uint64(s.Offset-start)
				byAddr[va] = s
			}
		}
	}
	funcByAddr := funcNameForInstructions(report.Functions)
	seen := map[string]bool{}
	var out []api.StringReference
	for _, in := range report.Instructions {
		m := strings.ToLower(in.Mnemonic)
		if !(strings.HasPrefix(m, "mov") || strings.HasPrefix(m, "lea") || m == "push" || m == "call") {
			continue
		}
		for _, v := range hexValues(in.Operand) {
			s, ok := byAddr[v]
			if !ok {
				continue
			}
			key := in.Address + "\x00" + fmt.Sprint(s.Offset)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, api.StringReference{
				Function:   funcByAddr(in.Address),
				Address:    in.Address,
				String:     trimName(s.Value),
				Offset:     s.Offset,
				Kind:       "data-reference",
				Tags:       append([]string{}, s.Tags...),
				Confidence: "medium",
				Evidence:   strings.TrimSpace(in.Mnemonic + " " + in.Operand),
			})
			if len(out) >= 5000 {
				return out
			}
		}
	}
	return out
}

func stackFrames(report api.AnalysisReport) []api.StackFrameLayout {
	varsByFn := map[string][]api.InferredVariable{}
	for _, v := range report.InferredVariables {
		varsByFn[v.Function] = append(varsByFn[v.Function], v)
	}
	insights := map[string]api.FunctionInsight{}
	for _, insight := range report.FunctionInsights {
		insights[insight.Name] = insight
	}
	var out []api.StackFrameLayout
	for _, fn := range report.Functions {
		frame := api.StackFrameLayout{Function: fn.Name, FrameSize: insights[fn.Name].EstimatedStack}
		body := instructionsForFunction(fn, report.Instructions)
		for _, in := range body {
			if in.Mnemonic == "push" && isRegister(strings.ToLower(in.Operand)) {
				frame.SavedRegisters = appendUniqueString(frame.SavedRegisters, strings.ToLower(in.Operand))
			}
			if in.Mnemonic == "sub" && strings.Contains(strings.ToLower(in.Operand), "sp") {
				frame.Evidence = appendUniqueString(frame.Evidence, strings.TrimSpace(in.Address+" "+in.Mnemonic+" "+in.Operand))
			}
		}
		for _, v := range varsByFn[fn.Name] {
			storage := strings.ToLower(v.Storage + " " + v.Name)
			if strings.Contains(storage, "+") || strings.Contains(storage, "arg") {
				frame.Arguments = append(frame.Arguments, v)
			} else {
				frame.Locals = append(frame.Locals, v)
			}
		}
		if frame.FrameSize > 0 || len(frame.Locals) > 0 || len(frame.Arguments) > 0 || len(frame.SavedRegisters) > 0 {
			out = append(out, frame)
		}
	}
	return out
}

func basicBlockNotes(report api.AnalysisReport) []api.BasicBlockNote {
	var out []api.BasicBlockNote
	for _, b := range report.Blocks {
		switch {
		case len(b.Edges) == 0:
			out = append(out, api.BasicBlockNote{BlockID: b.ID, Start: b.Start, End: b.End, Kind: "terminal", Text: "basic block has no outgoing CFG edges", Severity: "info", Edges: b.Edges})
		case len(b.Edges) >= 2:
			out = append(out, api.BasicBlockNote{BlockID: b.ID, Start: b.Start, End: b.End, Kind: "branch", Text: "basic block branches to multiple successors", Severity: "info", Edges: b.Edges})
		}
		for _, edge := range b.Edges {
			if edge <= b.ID {
				out = append(out, api.BasicBlockNote{BlockID: b.ID, Start: b.Start, End: b.End, Kind: "loop-backedge", Text: "edge points to an earlier or same block", Severity: "medium", Edges: b.Edges})
				break
			}
		}
	}
	return out
}

func decompilerHints(report api.AnalysisReport) []api.DecompilerHint {
	funcByAddr := funcNameForInstructions(report.Functions)
	var out []api.DecompilerHint
	for i, in := range report.Instructions {
		m := strings.ToLower(in.Mnemonic)
		ops := strings.Split(strings.ReplaceAll(strings.ToLower(in.Operand), " ", ""), ",")
		add := func(kind, hint, confidence string) {
			out = append(out, api.DecompilerHint{Function: funcByAddr(in.Address), Address: in.Address, Kind: kind, Hint: hint, Confidence: confidence, Evidence: strings.TrimSpace(in.Mnemonic + " " + in.Operand)})
		}
		if m == "xor" && len(ops) == 2 && ops[0] == ops[1] {
			add("zeroing", ops[0]+" is set to zero", "high")
		}
		if m == "lea" {
			add("address-calculation", "operand likely computes an address rather than dereferencing memory", "medium")
		}
		if m == "db" {
			add("undecoded", "byte was not decoded; verify instruction boundary or architecture mode", "medium")
		}
		if (m == "cmp" || m == "test") && i+1 < len(report.Instructions) && report.Instructions[i+1].Kind == "branch" {
			add("condition-source", "comparison feeds following conditional branch at "+report.Instructions[i+1].Address, "medium")
		}
		if in.Kind == "call" {
			add("call-site", "inspect calling convention arguments before this call", "medium")
		}
		if len(out) >= 10000 {
			return out
		}
	}
	return out
}

func functionClusters(report api.AnalysisReport, fps []api.FunctionFingerprint) []api.FunctionCluster {
	buckets := map[string][]string{}
	evidence := map[string][]string{}
	for _, fp := range fps {
		key := fp.SimHash
		if key == "" {
			key = fp.MnemonicHash
		}
		if key == "" {
			continue
		}
		buckets[key] = append(buckets[key], fp.Function)
		evidence[key] = appendUniqueString(evidence[key], fmt.Sprintf("%s instructions=%d size=%d", fp.Function, fp.Instructions, fp.Size))
	}
	shapeBuckets := map[string][]string{}
	for _, fn := range report.FunctionInsights {
		key := fmt.Sprintf("shape:calls=%d:branches=%d:stack=%d", fn.CallCount, fn.BranchCount, fn.EstimatedStack/0x20)
		shapeBuckets[key] = append(shapeBuckets[key], fn.Name)
	}
	var out []api.FunctionCluster
	for key, values := range buckets {
		if len(values) < 2 {
			continue
		}
		out = append(out, api.FunctionCluster{ID: "simhash_" + key, Kind: "similarity", Functions: values, Score: 1.0, Confidence: "medium", Evidence: evidence[key]})
	}
	for key, values := range shapeBuckets {
		if len(values) < 3 {
			continue
		}
		out = append(out, api.FunctionCluster{ID: strings.ReplaceAll(key, ":", "_"), Kind: "shape", Functions: values, Score: float64(len(values)), Confidence: "low", Evidence: []string{key}})
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i].Functions) > len(out[j].Functions) })
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

func hotPaths(report api.AnalysisReport, tags []api.FunctionTag, callSites []api.APICallSite, stringRefs []api.StringReference) []api.HotPath {
	tagByFn := map[string][]string{}
	for _, t := range tags {
		tagByFn[t.Function] = append(tagByFn[t.Function], t.Tag)
	}
	callsByFn := map[string]int{}
	for _, cs := range callSites {
		callsByFn[cs.Function]++
	}
	stringsByFn := map[string]int{}
	for _, ref := range stringRefs {
		stringsByFn[ref.Function]++
	}
	var out []api.HotPath
	for _, fn := range report.FunctionInsights {
		score := fn.Complexity*3 + fn.CallCount*2 + fn.BranchCount*2 + callsByFn[fn.Name]*4 + stringsByFn[fn.Name]
		reasons := []string{fmt.Sprintf("complexity=%d", fn.Complexity), fmt.Sprintf("calls=%d", fn.CallCount), fmt.Sprintf("branches=%d", fn.BranchCount)}
		for _, note := range fn.RiskNotes {
			score += 8
			reasons = append(reasons, note)
		}
		for _, tag := range tagByFn[fn.Name] {
			if tag == "state-machine-or-parser" || tag == "large-stack-frame" || tag == "noreturn-candidate" {
				score += 12
				reasons = append(reasons, tag)
			}
		}
		if score == 0 {
			continue
		}
		out = append(out, api.HotPath{Function: fn.Name, Start: fn.Start, Score: score, Reasons: reasons, Artifacts: []string{"source/functions/" + fn.Name + ".c", "functions/function_insights.csv", "deep/decompiler_hints.csv"}})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	for i := range out {
		out[i].Rank = i + 1
	}
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

func patchPoints(report api.AnalysisReport) []api.PatchPoint {
	funcByAddr := funcNameForInstructions(report.Functions)
	var out []api.PatchPoint
	for _, in := range report.Instructions {
		m := strings.ToLower(in.Mnemonic)
		switch {
		case in.Kind == "branch":
			out = append(out, api.PatchPoint{Address: in.Address, Function: funcByAddr(in.Address), Kind: "conditional-branch", Bytes: in.Bytes, Size: byteCount(in.Bytes), Risk: "medium", Confidence: "medium", Evidence: []string{strings.TrimSpace(in.Mnemonic + " " + in.Operand), "branch can alter validation/control-flow behavior"}})
		case in.Kind == "call":
			out = append(out, api.PatchPoint{Address: in.Address, Function: funcByAddr(in.Address), Kind: "call-site", Bytes: in.Bytes, Size: byteCount(in.Bytes), Risk: "medium", Confidence: "medium", Evidence: []string{strings.TrimSpace(in.Mnemonic + " " + in.Operand), "call target or return handling may be patch-relevant"}})
		case m == "int3" || m == "nop":
			out = append(out, api.PatchPoint{Address: in.Address, Function: funcByAddr(in.Address), Kind: "padding-or-breakpoint", Bytes: in.Bytes, Size: byteCount(in.Bytes), Risk: "low", Confidence: "high", Evidence: []string{strings.TrimSpace(in.Mnemonic + " " + in.Operand)}})
		}
		if len(out) >= 5000 {
			return out
		}
	}
	return out
}

func callingConventions(report api.AnalysisReport, frames []api.StackFrameLayout) []api.CallingConventionGuess {
	frameByFn := map[string]api.StackFrameLayout{}
	for _, frame := range frames {
		frameByFn[frame.Function] = frame
	}
	var out []api.CallingConventionGuess
	for _, fn := range report.Functions {
		body := instructionsForFunction(fn, report.Instructions)
		regs := usedArgRegisters(body)
		convention := "unknown"
		conf := "low"
		switch {
		case hasAny(regs, "rcx", "rdx", "r8", "r9"):
			convention, conf = "windows-x64-fastcall", "medium"
		case hasAny(regs, "rdi", "rsi", "rdx", "rcx", "r8", "r9"):
			convention, conf = "sysv-x64", "medium"
		case len(frameByFn[fn.Name].Arguments) > 0:
			convention, conf = "stack-arguments", "low"
		}
		if convention == "unknown" && len(body) == 0 {
			continue
		}
		out = append(out, api.CallingConventionGuess{Function: fn.Name, Start: fn.Start, Convention: convention, ArgumentStorage: regs, ReturnStorage: "rax/eax", Confidence: conf, Evidence: callingEvidence(body, regs)})
	}
	return out
}

func unpackingHints(report api.AnalysisReport) []api.UnpackingHint {
	var out []api.UnpackingHint
	for _, s := range report.Sections {
		if s.Entropy >= 7.2 {
			out = append(out, api.UnpackingHint{Region: s.Name, Address: fmt.Sprintf("0x%x", s.VirtualAddress), Kind: "high-entropy-region", Priority: "P1", Actions: []string{"inspect section bytes", "compare raw and virtual sizes", "attempt controlled dynamic unpacking if authorized"}, Evidence: []string{fmt.Sprintf("entropy %.2f", s.Entropy)}, Confidence: "medium"})
		}
		if strings.Contains(s.Permissions, "x") && strings.Contains(s.Permissions, "w") {
			out = append(out, api.UnpackingHint{Region: s.Name, Address: fmt.Sprintf("0x%x", s.VirtualAddress), Kind: "writable-executable-section", Priority: "P0", Actions: []string{"prioritize self-modifying code review", "trace writes into executable ranges"}, Evidence: []string{"section has write and execute permissions"}, Confidence: "high"})
		}
	}
	if report.Overlay.Present {
		out = append(out, api.UnpackingHint{Region: "overlay", Address: fmt.Sprintf("file+0x%x", report.Overlay.Offset), Kind: "overlay-payload", Priority: "P1", Actions: []string{"carve overlay", "check embedded signatures", "compare overlay entropy"}, Evidence: []string{fmt.Sprintf("size=%d entropy=%.2f", report.Overlay.Size, report.Overlay.Entropy)}, Confidence: "medium"})
	}
	for _, imp := range report.Imports {
		for _, cat := range imp.Category {
			if cat == "dynamic loading" || cat == "memory allocation" {
				out = append(out, api.UnpackingHint{Region: "imports", Kind: "loader-api-surface", Priority: "P2", Actions: []string{"trace allocation and dynamic import resolution call sites"}, Evidence: []string{imp.DLL + "!" + imp.Name}, Confidence: "low"})
				break
			}
		}
		if len(out) > 200 {
			break
		}
	}
	return out
}

func typePropagationHints(report api.AnalysisReport, callSites []api.APICallSite, stringRefs []api.StringReference) []api.TypePropagationHint {
	var out []api.TypePropagationHint
	for _, cs := range callSites {
		lower := strings.ToLower(cs.API)
		switch {
		case strings.Contains(lower, "createfile"):
			out = append(out, api.TypePropagationHint{Function: cs.Function, Address: cs.Address, Symbol: "rax", Type: "HANDLE", Source: cs.API, Confidence: "medium", Evidence: []string{"CreateFile-style API returns a HANDLE"}})
		case strings.Contains(lower, "virtualalloc") || strings.Contains(lower, "heapalloc"):
			out = append(out, api.TypePropagationHint{Function: cs.Function, Address: cs.Address, Symbol: "rax", Type: "void*", Source: cs.API, Confidence: "medium", Evidence: []string{"allocation API returns a pointer"}})
		case strings.Contains(lower, "getprocaddress"):
			out = append(out, api.TypePropagationHint{Function: cs.Function, Address: cs.Address, Symbol: "rax", Type: "FARPROC", Source: cs.API, Confidence: "medium", Evidence: []string{"dynamic API resolver return value"}})
		}
	}
	for _, ref := range stringRefs {
		typ := "char*"
		if contains(ref.Tags, "url") {
			typ = "char* url"
		} else if contains(ref.Tags, "registry") {
			typ = "char* registry_path"
		} else if contains(ref.Tags, "path") {
			typ = "char* filesystem_path"
		}
		out = append(out, api.TypePropagationHint{Function: ref.Function, Address: ref.Address, Symbol: fmt.Sprintf("file+0x%x", ref.Offset), Type: typ, Source: "string-reference", Confidence: ref.Confidence, Evidence: []string{ref.String}})
		if len(out) >= 2000 {
			return out
		}
	}
	return out
}

func analysisTimeline(report api.AnalysisReport) []api.AnalysisTimelineEvent {
	var out []api.AnalysisTimelineEvent
	add := func(phase, title, detail, severity string, artifacts ...string) {
		out = append(out, api.AnalysisTimelineEvent{Order: len(out) + 1, Phase: phase, Title: title, Detail: detail, Severity: severity, Artifacts: artifacts})
	}
	add("load", "Identify file", report.Metadata.FileType+" "+report.Metadata.Arch+" entry="+report.Metadata.EntryPoint, "info", "metadata/metadata.json")
	add("map", "Map sections", fmt.Sprintf("%d sections, %d imports, %d exports", len(report.Sections), len(report.Imports), len(report.Exports)), "info", "sections/sections.csv", "imports/imports.csv")
	if report.Overlay.Present {
		add("container", "Overlay present", fmt.Sprintf("offset=0x%x size=%d entropy=%.2f", report.Overlay.Offset, report.Overlay.Size, report.Overlay.Entropy), "medium", "headers/overlay.json")
	}
	for _, s := range report.Sections {
		if s.Entropy >= 7.2 || strings.Contains(s.Permissions, "x") && strings.Contains(s.Permissions, "w") {
			add("unpack", "Suspicious section "+s.Name, fmt.Sprintf("entropy=%.2f perms=%s", s.Entropy, s.Permissions), "medium", "sections/sections.csv")
		}
	}
	if len(report.Instructions) > 0 {
		add("code", "Decode entry code", fmt.Sprintf("%d instructions, %d functions, %d blocks", len(report.Instructions), len(report.Functions), len(report.Blocks)), "info", "disassembly/entry.asm", "control_flow/cfg.dot")
	}
	if len(report.Vulnerabilities) > 0 {
		add("review", "Build vulnerability review queue", fmt.Sprintf("%d findings", len(report.Vulnerabilities)), "medium", "vulnerabilities/vulnerabilities.csv")
	}
	return out
}

func capabilityMatrix(report api.AnalysisReport, callSites []api.APICallSite, stringRefs []api.StringReference, unpacking []api.UnpackingHint) []api.CapabilityMatrixEntry {
	buckets := map[string]*api.CapabilityMatrixEntry{}
	add := func(cap string, score int, signal string, artifacts ...string) {
		e := buckets[cap]
		if e == nil {
			e = &api.CapabilityMatrixEntry{Capability: cap}
			buckets[cap] = e
		}
		e.Score += score
		e.Signals = appendUniqueString(e.Signals, signal)
		for _, artifact := range artifacts {
			e.Artifacts = appendUniqueString(e.Artifacts, artifact)
		}
	}
	for _, cap := range report.Capabilities {
		add(cap, 20, "capability inference", "signatures/capabilities.json")
	}
	for _, cs := range callSites {
		for _, cat := range cs.Category {
			add(cat, 8, cs.API+" at "+cs.Address, "deep/api_call_sites.csv")
		}
	}
	for _, ref := range stringRefs {
		for _, tag := range ref.Tags {
			add(tag+" strings", 3, ref.String, "deep/string_references.csv")
		}
	}
	for _, hint := range unpacking {
		add("packing or loader behavior", 12, hint.Kind+" "+hint.Region, "deep/unpacking_hints.csv")
	}
	var out []api.CapabilityMatrixEntry
	for _, e := range buckets {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

func antiAnalysisIndicators(report api.AnalysisReport, callSites []api.APICallSite) []api.IndicatorHit {
	var out []api.IndicatorHit
	for _, cs := range callSites {
		lower := strings.ToLower(cs.API)
		if inAny(lower, "isdebuggerpresent", "checkremotedebuggerpresent", "queryperformancecounter", "ntqueryinformationprocess", "outputdebugstring") {
			out = append(out, api.IndicatorHit{Kind: "anti-analysis", Name: cs.API, Location: cs.Address, Function: cs.Function, Severity: "medium", Confidence: "medium", Evidence: []string{cs.Evidence}})
		}
	}
	for _, s := range report.Strings {
		lower := strings.ToLower(s.Value)
		if inAny(lower, "ollydbg", "x64dbg", "wireshark", "procmon", "ida", "ghidra", "sandbox", "virtualbox", "vmware") {
			out = append(out, api.IndicatorHit{Kind: "anti-analysis-string", Name: trimName(s.Value), Location: fmt.Sprintf("file+0x%x", s.Offset), Severity: "medium", Confidence: "low", Evidence: []string{s.Encoding}})
		}
	}
	return out
}

func cryptoIndicators(report api.AnalysisReport) []api.IndicatorHit {
	var out []api.IndicatorHit
	constants := map[string]string{"0x9e3779b9": "TEA delta", "0x6a09e667": "SHA-256 IV", "0xbb67ae85": "SHA-256 IV", "0x67452301": "MD5/SHA1 IV", "0xefcdab89": "MD5/SHA1 IV"}
	for _, in := range report.Instructions {
		op := strings.ToLower(in.Operand)
		for needle, name := range constants {
			if strings.Contains(op, needle) {
				out = append(out, api.IndicatorHit{Kind: "crypto-constant", Name: name, Location: in.Address, Function: funcNameForInstructions(report.Functions)(in.Address), Severity: "info", Confidence: "medium", Evidence: []string{strings.TrimSpace(in.Mnemonic + " " + in.Operand)}})
			}
		}
	}
	for _, imp := range report.Imports {
		n := strings.ToLower(imp.Name)
		if inAny(n, "crypt", "bcrypt", "hash", "aes", "sha", "md5", "random") {
			out = append(out, api.IndicatorHit{Kind: "crypto-api", Name: imp.DLL + "!" + imp.Name, Location: imp.Address, Severity: "info", Confidence: "medium", Evidence: imp.Category})
		}
	}
	return out
}

func persistenceIndicators(report api.AnalysisReport, callSites []api.APICallSite) []api.IndicatorHit {
	var out []api.IndicatorHit
	for _, cs := range callSites {
		lower := strings.ToLower(cs.API)
		if inAny(lower, "regsetvalue", "createservice", "schtasks", "startup", "copyfile", "movefile") {
			out = append(out, api.IndicatorHit{Kind: "persistence-api", Name: cs.API, Location: cs.Address, Function: cs.Function, Severity: "medium", Confidence: "medium", Evidence: []string{cs.Evidence}})
		}
	}
	for _, s := range report.Strings {
		lower := strings.ToLower(s.Value)
		if inAny(lower, `\run`, `\runonce`, "currentversion\\run", "startup", "schtasks", "system32\\tasks") {
			out = append(out, api.IndicatorHit{Kind: "persistence-string", Name: trimName(s.Value), Location: fmt.Sprintf("file+0x%x", s.Offset), Severity: "medium", Confidence: "medium", Evidence: s.Tags})
		}
	}
	return out
}

func syscallIndicators(report api.AnalysisReport) []api.IndicatorHit {
	var out []api.IndicatorHit
	fnFor := funcNameForInstructions(report.Functions)
	for _, in := range report.Instructions {
		m := strings.ToLower(in.Mnemonic)
		op := strings.ToLower(in.Operand)
		if m == "syscall" || strings.HasPrefix(m, "int") || strings.Contains(op, "fs:") || strings.Contains(op, "gs:") {
			out = append(out, api.IndicatorHit{Kind: "low-level-execution", Name: m, Location: in.Address, Function: fnFor(in.Address), Severity: "medium", Confidence: "medium", Evidence: []string{strings.TrimSpace(in.Mnemonic + " " + in.Operand)}})
		}
	}
	return out
}

func projectDatabase(report api.AnalysisReport, graph api.GraphAnalysis, fps []api.FunctionFingerprint, sigs []api.SignatureMatch, tags []api.FunctionTag, annotations []api.REAnnotation, jumpTables []api.JumpTableCandidate, apiCallSites []api.APICallSite, stringRefs []api.StringReference, stackFrames []api.StackFrameLayout, blockNotes []api.BasicBlockNote, decompilerHints []api.DecompilerHint, functionClusters []api.FunctionCluster, hotPaths []api.HotPath, patchPoints []api.PatchPoint, callingConventions []api.CallingConventionGuess, unpackingHints []api.UnpackingHint, typeHints []api.TypePropagationHint, timeline []api.AnalysisTimelineEvent, capabilityMatrix []api.CapabilityMatrixEntry, antiAnalysisHits []api.IndicatorHit, cryptoHits []api.IndicatorHit, persistenceHits []api.IndicatorHit, syscallHits []api.IndicatorHit) api.ProjectDatabase {
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
	for _, a := range annotations {
		comments = append(comments, api.SearchEntry{Kind: a.Kind, Name: a.Function, Value: a.Text, Location: a.Address, Tags: append([]string{a.Severity}, a.Tags...)})
	}
	return api.ProjectDatabase{
		SchemaVersion:      1,
		CaseID:             report.CaseID,
		Sample:             report.Metadata,
		Functions:          report.Functions,
		Symbols:            symbols,
		Types:              report.InferredTypes,
		Structs:            report.StructCandidates,
		Labels:             labels,
		Comments:           comments,
		Xrefs:              report.Xrefs,
		Graph:              graph,
		Fingerprints:       fps,
		Signatures:         sigs,
		FunctionTags:       tags,
		Annotations:        annotations,
		JumpTables:         jumpTables,
		APICallSites:       apiCallSites,
		StringRefs:         stringRefs,
		StackFrames:        stackFrames,
		BlockNotes:         blockNotes,
		DecompilerHints:    decompilerHints,
		FunctionClusters:   functionClusters,
		HotPaths:           hotPaths,
		PatchPoints:        patchPoints,
		CallingConventions: callingConventions,
		UnpackingHints:     unpackingHints,
		TypeHints:          typeHints,
		Timeline:           timeline,
		CapabilityMatrix:   capabilityMatrix,
		AntiAnalysis:       antiAnalysisHits,
		CryptoIndicators:   cryptoHits,
		Persistence:        persistenceHits,
		SyscallIndicators:  syscallHits,
	}
}

func isThunk(ins []api.Instruction) bool {
	if len(ins) == 0 || len(ins) > 6 {
		return false
	}
	for _, in := range ins {
		if in.Kind == "jump" || in.Kind == "call" {
			return true
		}
	}
	return false
}

func severityForTag(tag string) string {
	switch tag {
	case "noreturn-candidate", "state-machine-or-parser", "large-stack-frame":
		return "medium"
	default:
		return "info"
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

func hexValues(s string) []uint64 {
	fields := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r == 'x')
	})
	var out []uint64
	for _, f := range fields {
		if !strings.HasPrefix(f, "0x") || len(f) <= 2 {
			continue
		}
		out = append(out, parseHex(f))
	}
	return out
}

func isRegister(s string) bool {
	switch s {
	case "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip",
		"eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15":
		return true
	default:
		return false
	}
}

func byteCount(s string) int {
	if strings.TrimSpace(s) == "" {
		return 0
	}
	return len(strings.Fields(s))
}

func usedArgRegisters(ins []api.Instruction) []string {
	argRegs := []string{"rcx", "rdx", "r8", "r9", "rdi", "rsi", "eax", "ecx", "edx"}
	seen := map[string]bool{}
	var out []string
	for i, in := range ins {
		if i >= 24 {
			break
		}
		op := strings.ToLower(in.Operand)
		for _, reg := range argRegs {
			if strings.Contains(op, reg) && !seen[reg] {
				seen[reg] = true
				out = append(out, reg)
			}
		}
	}
	sort.Strings(out)
	return out
}

func hasAny(values []string, needles ...string) bool {
	for _, v := range values {
		for _, n := range needles {
			if v == n {
				return true
			}
		}
	}
	return false
}

func callingEvidence(ins []api.Instruction, regs []string) []string {
	var out []string
	if len(regs) > 0 {
		out = append(out, "early register use: "+strings.Join(regs, ", "))
	}
	for _, in := range ins {
		if in.Kind == "return" {
			out = append(out, "return instruction observed at "+in.Address)
			break
		}
	}
	return out
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
