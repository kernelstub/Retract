package cfg

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"retract/pkg/api"
)

func Build(ins []api.Instruction) ([]api.BasicBlock, []api.Function) {
	if len(ins) == 0 {
		return nil, nil
	}
	leaders := map[string]bool{ins[0].Address: true}
	addrToIdx := map[string]int{}
	for i, in := range ins {
		addrToIdx[in.Address] = i
	}
	for i, in := range ins {
		if in.Target != "" {
			leaders[in.Target] = true
		}
		if (in.Kind == "branch" || in.Kind == "call") && i+1 < len(ins) {
			leaders[ins[i+1].Address] = true
		}
	}
	var starts []int
	for addr := range leaders {
		if idx, ok := addrToIdx[addr]; ok {
			starts = append(starts, idx)
		}
	}
	sort.Ints(starts)
	var blocks []api.BasicBlock
	for i, start := range starts {
		endIdx := len(ins) - 1
		if i+1 < len(starts) {
			endIdx = starts[i+1] - 1
		}
		b := api.BasicBlock{ID: fmt.Sprintf("bb_%s", strings.TrimPrefix(ins[start].Address, "0x")), Start: ins[start].Address, End: ins[endIdx].Address}
		last := ins[endIdx]
		if last.Target != "" && (last.Kind == "branch" || last.Kind == "jump") {
			b.Edges = append(b.Edges, blockID(last.Target))
		}
		if last.Kind == "branch" && endIdx+1 < len(ins) {
			b.Edges = append(b.Edges, blockID(ins[endIdx+1].Address))
		}
		blocks = append(blocks, b)
	}
	fn := api.Function{Name: "entry", Start: ins[0].Address, End: ins[len(ins)-1].Address, Size: addrDiff(ins[0].Address, ins[len(ins)-1].Address), Blocks: len(blocks)}
	seen := map[string]bool{}
	for _, in := range ins {
		if in.Kind == "call" && in.Target != "" && !seen[in.Target] {
			seen[in.Target] = true
			fn.Calls = append(fn.Calls, in.Target)
		}
	}
	return blocks, []api.Function{fn}
}

func DOT(blocks []api.BasicBlock) string {
	var b strings.Builder
	b.WriteString("digraph cfg {\n  node [shape=box];\n")
	for _, bb := range blocks {
		fmt.Fprintf(&b, "  %s [label=\"%s\\n%s-%s\"];\n", bb.ID, bb.ID, bb.Start, bb.End)
		for _, e := range bb.Edges {
			fmt.Fprintf(&b, "  %s -> %s;\n", bb.ID, e)
		}
	}
	b.WriteString("}\n")
	return b.String()
}

func blockID(addr string) string { return "bb_" + strings.TrimPrefix(addr, "0x") }

func addrDiff(a, b string) uint64 {
	aa, _ := strconv.ParseUint(strings.TrimPrefix(a, "0x"), 16, 64)
	bb, _ := strconv.ParseUint(strings.TrimPrefix(b, "0x"), 16, 64)
	if bb >= aa {
		return bb - aa + 1
	}
	return 0
}
