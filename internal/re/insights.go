package re

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"retract/pkg/api"
)

var stackRe = regexp.MustCompile(`(?i)\b(rsp|rbp|esp|ebp),?\s*0x([0-9a-f]+)`)

func FunctionInsights(functions []api.Function, ins []api.Instruction) []api.FunctionInsight {
	out := []api.FunctionInsight{}
	for _, fn := range functions {
		body := functionBody(fn, ins)
		item := api.FunctionInsight{Name: fn.Name, Start: fn.Start, InstructionCount: len(body), Complexity: 1}
		for _, in := range body {
			switch in.Kind {
			case "call":
				item.CallCount++
			case "branch":
				item.BranchCount++
				item.Complexity++
			case "return":
				item.ReturnCount++
			}
			if in.Mnemonic == "sub" && strings.Contains(strings.ToLower(in.Operand), "sp") {
				if v := parseLastHex(in.Operand); v > item.EstimatedStack {
					item.EstimatedStack = v
				}
			}
		}
		if item.EstimatedStack > 0x1000 {
			item.RiskNotes = append(item.RiskNotes, "large stack frame")
		}
		if item.BranchCount > 100 {
			item.RiskNotes = append(item.RiskNotes, "high branch density")
		}
		if item.ReturnCount == 0 {
			item.RiskNotes = append(item.RiskNotes, "no return observed in decoded range")
		}
		out = append(out, item)
	}
	return out
}

func Variables(functions []api.Function, ins []api.Instruction) []api.InferredVariable {
	vars := []api.InferredVariable{}
	seen := map[string]bool{}
	for _, fn := range functions {
		for _, in := range functionBody(fn, ins) {
			m := stackRe.FindStringSubmatch(in.Operand)
			if len(m) != 3 {
				continue
			}
			off, _ := strconv.ParseInt(m[2], 16, 64)
			name := fmt.Sprintf("local_%x", off)
			if strings.HasPrefix(strings.ToLower(m[1]), "e") || strings.HasPrefix(strings.ToLower(m[1]), "r") {
				name = fmt.Sprintf("stack_%x", off)
			}
			key := fn.Name + ":" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			vars = append(vars, api.InferredVariable{Function: fn.Name, Name: name, Storage: "[" + m[1] + "+/-0x" + m[2] + "]", Type: "uint64_t", Evidence: in.Address + " " + in.Mnemonic + " " + in.Operand})
		}
	}
	sort.Slice(vars, func(i, j int) bool {
		if vars[i].Function == vars[j].Function {
			return vars[i].Name < vars[j].Name
		}
		return vars[i].Function < vars[j].Function
	})
	return vars
}

func Types(imports []api.ImportFunction, stringsFound []api.StringHit) []api.InferredType {
	seen := map[string]api.InferredType{}
	add := func(name, kind, conf, ev string) {
		t := seen[name]
		if t.Name == "" {
			t = api.InferredType{Name: name, Kind: kind, Confidence: conf}
		}
		t.Evidence = appendUnique(t.Evidence, ev)
		seen[name] = t
	}
	for _, imp := range imports {
		n := strings.ToLower(imp.Name)
		switch {
		case strings.Contains(n, "messagebox"):
			add("HWND/LPCSTR UI strings", "windows-api-type", "medium", imp.DLL+"!"+imp.Name)
		case strings.Contains(n, "virtual"):
			add("void* memory region", "pointer", "medium", imp.DLL+"!"+imp.Name)
		case strings.Contains(n, "strlen") || strings.Contains(n, "str"):
			add("char* string buffer", "pointer", "medium", imp.DLL+"!"+imp.Name)
		case strings.Contains(n, "createfile") || strings.Contains(n, "readfile"):
			add("HANDLE file object", "windows-handle", "medium", imp.DLL+"!"+imp.Name)
		}
	}
	for _, s := range stringsFound {
		for _, tag := range s.Tags {
			switch tag {
			case "url":
				add("char* URL", "string", "high", fmt.Sprintf("string 0x%x", s.Offset))
			case "registry":
				add("char* registry path", "string", "high", fmt.Sprintf("string 0x%x", s.Offset))
			case "path":
				add("char* filesystem path", "string", "medium", fmt.Sprintf("string 0x%x", s.Offset))
			}
		}
	}
	out := make([]api.InferredType, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func Structs(types []api.InferredType, vars []api.InferredVariable) []api.StructCandidate {
	out := []api.StructCandidate{}
	if len(vars) > 0 {
		fields := []string{}
		for i, v := range vars {
			if i >= 32 {
				break
			}
			fields = append(fields, v.Type+" "+v.Name)
		}
		out = append(out, api.StructCandidate{Name: "stack_frame_candidate", Size: len(fields) * 8, Fields: fields, Confidence: "low", Evidence: []string{"stack-relative operands in decoded functions"}})
	}
	for _, t := range types {
		if strings.Contains(t.Name, "URL") || strings.Contains(t.Name, "path") {
			out = append(out, api.StructCandidate{Name: "configuration_candidate", Fields: []string{"char *value", "uint32_t length"}, Confidence: "low", Evidence: t.Evidence})
			break
		}
	}
	return out
}

func Xrefs(imports []api.ImportFunction, stringsFound []api.StringHit, ins []api.Instruction) []api.Xref {
	out := []api.Xref{}
	for _, in := range ins {
		if in.Kind == "call" && in.Target != "" {
			out = append(out, api.Xref{From: in.Address, To: in.Target, Kind: "code-call", Evidence: in.Mnemonic + " " + in.Operand})
		}
	}
	for _, imp := range imports {
		out = append(out, api.Xref{From: "import-table", To: imp.DLL + "!" + imp.Name, Kind: "import", Evidence: strings.Join(imp.Category, ", ")})
	}
	limit := 0
	for _, s := range stringsFound {
		if len(s.Tags) == 0 {
			continue
		}
		out = append(out, api.Xref{From: fmt.Sprintf("file+0x%x", s.Offset), To: trim(s.Value, 160), Kind: "string-" + strings.Join(s.Tags, "+"), Evidence: s.Encoding})
		limit++
		if limit >= 1000 {
			break
		}
	}
	return out
}

func functionBody(fn api.Function, ins []api.Instruction) []api.Instruction {
	start, ok1 := parseAddr(fn.Start)
	end, ok2 := parseAddr(fn.End)
	if !ok1 || !ok2 {
		return nil
	}
	out := []api.Instruction{}
	for _, in := range ins {
		addr, ok := parseAddr(in.Address)
		if ok && addr >= start && addr <= end {
			out = append(out, in)
		}
	}
	return out
}

func parseAddr(s string) (uint64, bool) {
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	return v, err == nil
}

func parseLastHex(s string) int {
	idx := strings.LastIndex(strings.ToLower(s), "0x")
	if idx < 0 {
		return 0
	}
	v, _ := strconv.ParseInt(s[idx+2:], 16, 64)
	return int(v)
}

func appendUnique(values []string, v string) []string {
	for _, existing := range values {
		if existing == v {
			return values
		}
	}
	return append(values, v)
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
