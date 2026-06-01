package main

import "testing"

func TestNormalizeArgsAllowsFlagsAfterTarget(t *testing.T) {
	flags, target, ok := normalizeArgs([]string{"sample.exe", "--no-disasm", "--min-string", "5", "--format=pe"})
	if !ok {
		t.Fatal("normalizeArgs() rejected valid arguments")
	}
	if target != "sample.exe" {
		t.Fatalf("target = %q", target)
	}
	want := []string{"-no-disasm", "-min-string", "5", "-format=pe"}
	if len(flags) != len(want) {
		t.Fatalf("flags = %#v", flags)
	}
	for i := range want {
		if flags[i] != want[i] {
			t.Fatalf("flags[%d] = %q, want %q", i, flags[i], want[i])
		}
	}
}
