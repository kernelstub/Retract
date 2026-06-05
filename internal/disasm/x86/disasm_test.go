package x86

import "testing"

func TestDecodeModRMStackAndBranch(t *testing.T) {
	code := []byte{
		0x55,             // push rbp
		0x48, 0x89, 0xe5, // mov rbp, rsp
		0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20
		0x48, 0x89, 0x4d, 0xf8, // mov [rbp-0x8], rcx
		0x48, 0x83, 0x7d, 0xf8, 0x00, // cmp [rbp-0x8], 0
		0x74, 0x01, // je +1
		0xc3, // ret
	}
	ins := Decode(code, 0x1000, Mode64, len(code))
	want := []struct {
		idx      int
		mnemonic string
		operand  string
		kind     string
	}{
		{0, "push", "rbp", ""},
		{1, "mov", "rbp, rsp", ""},
		{2, "sub", "rsp, 0x20", ""},
		{3, "mov", "[rbp-0x8], rcx", ""},
		{4, "cmp", "[rbp-0x8], 0x0", ""},
		{5, "je", "0x1014", "branch"},
		{6, "ret", "", "return"},
	}
	if len(ins) != len(want) {
		t.Fatalf("decoded %d instructions, want %d: %#v", len(ins), len(want), ins)
	}
	for _, w := range want {
		got := ins[w.idx]
		if got.Mnemonic != w.mnemonic || got.Operand != w.operand || got.Kind != w.kind {
			t.Fatalf("ins[%d] = %s %q kind=%q, want %s %q kind=%q", w.idx, got.Mnemonic, got.Operand, got.Kind, w.mnemonic, w.operand, w.kind)
		}
	}
}
