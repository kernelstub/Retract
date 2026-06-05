package decompiler

import (
	"strings"
	"testing"

	"retract/pkg/api"
)

func TestPseudocodeRecoversStackLocalAndCondition(t *testing.T) {
	fn := api.Function{Name: "entry", Start: "0x1000", End: "0x1015"}
	ins := []api.Instruction{
		{Address: "0x1000", Mnemonic: "push", Operand: "rbp"},
		{Address: "0x1001", Mnemonic: "mov", Operand: "rbp, rsp"},
		{Address: "0x1004", Mnemonic: "sub", Operand: "rsp, 0x20"},
		{Address: "0x1008", Mnemonic: "mov", Operand: "[rbp-0x8], rcx"},
		{Address: "0x100c", Mnemonic: "cmp", Operand: "[rbp-0x8], 0x0"},
		{Address: "0x1011", Mnemonic: "je", Operand: "0x1014", Target: "0x1014", Kind: "branch"},
		{Address: "0x1013", Mnemonic: "ret", Kind: "return"},
		{Address: "0x1014", Mnemonic: "ret", Kind: "return"},
	}
	got := Pseudocode(fn, ins)
	checks := []string{
		"uint64_t local_8 = 0;",
		"local_8 = rcx;",
		"if (local_8 == 0x0) goto loc_1014;",
		"loc_1014:",
		"return rax;",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Fatalf("pseudocode missing %q:\n%s", want, got)
		}
	}
}
