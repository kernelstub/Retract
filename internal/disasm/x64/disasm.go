package x64

import (
	"retract/internal/disasm/x86"
	"retract/pkg/api"
)

func Decode(code []byte, base uint64, limit int) []api.Instruction {
	return x86.Decode(code, base, x86.Mode64, limit)
}
