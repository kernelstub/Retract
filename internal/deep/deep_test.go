package deep

import (
	"testing"

	"retract/pkg/api"
)

func TestAnalyzeBuildsREWorkspaceArtifacts(t *testing.T) {
	report := api.AnalysisReport{
		Sections: []api.Section{{Name: ".rdata", RawOffset: 0, RawSize: 0x100, VirtualAddress: 0x1000}},
		Imports:  []api.ImportFunction{{DLL: "KERNEL32.dll", Name: "CreateFileA", Address: "0x2000", Category: []string{"filesystem"}}},
		Strings:  []api.StringHit{{Value: "C:\\temp\\sample.bin", Offset: 0x20, Encoding: "ascii", Tags: []string{"path"}}},
		Functions: []api.Function{{
			Name:  "entry",
			Start: "0x3000",
			End:   "0x3015",
			Calls: []string{"0x2000"},
		}},
		FunctionInsights:  []api.FunctionInsight{{Name: "entry", Start: "0x3000", InstructionCount: 5, CallCount: 1, BranchCount: 1, ReturnCount: 1, EstimatedStack: 0x20, Complexity: 2}},
		InferredVariables: []api.InferredVariable{{Function: "entry", Name: "local_8", Storage: "[rbp-0x8]", Type: "uint64_t", Evidence: "mov [rbp-0x8], rcx"}},
		Instructions: []api.Instruction{
			{Address: "0x3000", Mnemonic: "sub", Operand: "rsp, 0x20"},
			{Address: "0x3004", Mnemonic: "xor", Operand: "eax, eax"},
			{Address: "0x3006", Mnemonic: "mov", Operand: "rax, 0x1020"},
			{Address: "0x300b", Mnemonic: "call", Operand: "0x2000", Target: "0x2000", Kind: "call"},
			{Address: "0x3010", Mnemonic: "ret", Kind: "return"},
		},
		Blocks: []api.BasicBlock{{ID: "bb_3000", Start: "0x3000", End: "0x3010"}},
	}

	got := Analyze(make([]byte, 0x200), report)
	if len(got.APICallSites) != 1 {
		t.Fatalf("APICallSites len = %d, want 1", len(got.APICallSites))
	}
	if got.APICallSites[0].API != "KERNEL32.dll!CreateFileA" {
		t.Fatalf("api call site = %#v", got.APICallSites[0])
	}
	if len(got.StringRefs) != 1 {
		t.Fatalf("StringRefs len = %d, want 1", len(got.StringRefs))
	}
	if got.StringRefs[0].Offset != 0x20 {
		t.Fatalf("string ref = %#v", got.StringRefs[0])
	}
	if len(got.StackFrames) != 1 || got.StackFrames[0].FrameSize != 0x20 || len(got.StackFrames[0].Locals) != 1 {
		t.Fatalf("stack frames = %#v", got.StackFrames)
	}
	if len(got.BlockNotes) != 1 || got.BlockNotes[0].Kind != "terminal" {
		t.Fatalf("block notes = %#v", got.BlockNotes)
	}
	if len(got.DecompilerHints) == 0 {
		t.Fatal("expected decompiler hints")
	}
	if len(got.Project.APICallSites) != 1 || len(got.Project.StringRefs) != 1 || len(got.Project.StackFrames) != 1 {
		t.Fatalf("project database missing RE datasets: %#v", got.Project)
	}
	if len(got.HotPaths) == 0 {
		t.Fatal("expected hot paths")
	}
	if len(got.PatchPoints) == 0 {
		t.Fatal("expected patch points")
	}
	if len(got.CallingConventions) == 0 {
		t.Fatal("expected calling convention guesses")
	}
	if len(got.TypeHints) == 0 {
		t.Fatal("expected propagated type hints")
	}
	if len(got.Project.HotPaths) == 0 || len(got.Project.PatchPoints) == 0 || len(got.Project.TypeHints) == 0 {
		t.Fatalf("project database missing advanced RE datasets: %#v", got.Project)
	}
}
