package x86

import (
	"encoding/binary"
	"fmt"
	"strings"

	"retract/pkg/api"
)

type Mode int

const (
	Mode32 Mode = 32
	Mode64 Mode = 64
)

func Decode(code []byte, base uint64, mode Mode, limit int) []api.Instruction {
	if limit <= 0 || limit > len(code) {
		limit = len(code)
	}
	var out []api.Instruction
	for i := 0; i < limit; {
		addr := base + uint64(i)
		b := code[i]
		ins := api.Instruction{Address: fmt.Sprintf("0x%x", addr)}
		size := 1
		switch {
		case b == 0xc3:
			ins.Mnemonic, ins.Kind = "ret", "return"
		case b == 0xcc:
			ins.Mnemonic, ins.Kind = "int3", "trap"
		case b == 0x90:
			ins.Mnemonic = "nop"
		case b == 0x55:
			ins.Mnemonic, ins.Operand = "push", "ebp"
			if mode == Mode64 {
				ins.Operand = "rbp"
			}
		case b == 0x5d:
			ins.Mnemonic, ins.Operand = "pop", "ebp"
			if mode == Mode64 {
				ins.Operand = "rbp"
			}
		case b == 0xe8 && i+5 <= limit:
			rel := int32(binary.LittleEndian.Uint32(code[i+1:]))
			t := uint64(int64(addr+5) + int64(rel))
			ins.Mnemonic, ins.Operand, ins.Target, ins.Kind = "call", fmt.Sprintf("0x%x", t), fmt.Sprintf("0x%x", t), "call"
			size = 5
		case b == 0xe9 && i+5 <= limit:
			rel := int32(binary.LittleEndian.Uint32(code[i+1:]))
			t := uint64(int64(addr+5) + int64(rel))
			ins.Mnemonic, ins.Operand, ins.Target, ins.Kind = "jmp", fmt.Sprintf("0x%x", t), fmt.Sprintf("0x%x", t), "jump"
			size = 5
		case b == 0xeb && i+2 <= limit:
			rel := int8(code[i+1])
			t := uint64(int64(addr+2) + int64(rel))
			ins.Mnemonic, ins.Operand, ins.Target, ins.Kind = "jmp", fmt.Sprintf("0x%x", t), fmt.Sprintf("0x%x", t), "jump"
			size = 2
		case b >= 0x70 && b <= 0x7f && i+2 <= limit:
			names := []string{"jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"}
			rel := int8(code[i+1])
			t := uint64(int64(addr+2) + int64(rel))
			ins.Mnemonic, ins.Operand, ins.Target, ins.Kind = names[b-0x70], fmt.Sprintf("0x%x", t), fmt.Sprintf("0x%x", t), "branch"
			size = 2
		case b == 0x0f && i+6 <= limit && code[i+1] >= 0x80 && code[i+1] <= 0x8f:
			names := []string{"jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"}
			rel := int32(binary.LittleEndian.Uint32(code[i+2:]))
			t := uint64(int64(addr+6) + int64(rel))
			ins.Mnemonic, ins.Operand, ins.Target, ins.Kind = names[code[i+1]-0x80], fmt.Sprintf("0x%x", t), fmt.Sprintf("0x%x", t), "branch"
			size = 6
		case b == 0x68 && i+5 <= limit:
			ins.Mnemonic, ins.Operand = "push", fmt.Sprintf("0x%x", binary.LittleEndian.Uint32(code[i+1:]))
			size = 5
		case b >= 0xb8 && b <= 0xbf:
			regs32 := []string{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"}
			regs64 := []string{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"}
			reg := regs32[b-0xb8]
			immSize := 4
			if mode == Mode64 {
				reg = regs64[b-0xb8]
			}
			if i+1+immSize <= limit {
				ins.Mnemonic, ins.Operand = "mov", fmt.Sprintf("%s, 0x%x", reg, binary.LittleEndian.Uint32(code[i+1:]))
				size = 1 + immSize
			} else {
				ins.Mnemonic = "db"
			}
		case b == 0x48 && i+3 <= limit:
			ins = decodeRex(code, i, addr)
			if ins.Mnemonic != "" {
				size = rexSize(code, i, limit)
			} else {
				ins.Mnemonic = "db"
			}
		default:
			ins.Mnemonic = "db"
			ins.Operand = fmt.Sprintf("0x%02x", b)
		}
		ins.Bytes = byteString(code[i:min(i+size, limit)])
		out = append(out, ins)
		i += size
	}
	return out
}

func decodeRex(code []byte, i int, addr uint64) api.Instruction {
	if i+3 > len(code) {
		return api.Instruction{}
	}
	b := code[i+1]
	if b == 0x89 && code[i+2] == 0xe5 {
		return api.Instruction{Address: fmt.Sprintf("0x%x", addr), Mnemonic: "mov", Operand: "rbp, rsp"}
	}
	if b == 0x83 && i+4 <= len(code) && code[i+2] == 0xec {
		return api.Instruction{Address: fmt.Sprintf("0x%x", addr), Mnemonic: "sub", Operand: fmt.Sprintf("rsp, 0x%x", code[i+3])}
	}
	if b == 0x83 && i+4 <= len(code) && code[i+2] == 0xc4 {
		return api.Instruction{Address: fmt.Sprintf("0x%x", addr), Mnemonic: "add", Operand: fmt.Sprintf("rsp, 0x%x", code[i+3])}
	}
	return api.Instruction{}
}

func rexSize(code []byte, i, limit int) int {
	if i+4 <= limit && code[i+1] == 0x83 {
		return 4
	}
	if i+3 <= limit {
		return 3
	}
	return 1
}

func byteString(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, " ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
