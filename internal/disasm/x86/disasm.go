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

type rex struct {
	w bool
	r int
	x int
	b int
}

type modrm struct {
	mod  byte
	reg  int
	rm   int
	size int
	mem  string
}

func Decode(code []byte, base uint64, mode Mode, limit int) []api.Instruction {
	if limit <= 0 || limit > len(code) {
		limit = len(code)
	}
	var out []api.Instruction
	for i := 0; i < limit; {
		addr := base + uint64(i)
		start := i
		rx := rex{}
		if mode == Mode64 && i < limit && code[i] >= 0x40 && code[i] <= 0x4f {
			p := code[i]
			rx = rex{w: p&0x08 != 0, r: int((p >> 2) & 1), x: int((p >> 1) & 1), b: int(p & 1)}
			i++
		}
		if i >= limit {
			break
		}
		ins, size := decodeOne(code, i, addr, mode, rx, limit)
		if ins.Address == "" {
			ins.Address = fmt.Sprintf("0x%x", addr)
		}
		total := i + size - start
		if total <= 0 {
			total = 1
		}
		end := start + total
		if end > limit {
			end = limit
		}
		ins.Bytes = byteString(code[start:end])
		out = append(out, ins)
		i = end
	}
	return out
}

func decodeOne(code []byte, i int, addr uint64, mode Mode, rx rex, limit int) (api.Instruction, int) {
	b := code[i]
	ins := api.Instruction{Address: fmt.Sprintf("0x%x", addr)}
	switch {
	case b == 0xc3:
		ins.Mnemonic, ins.Kind = "ret", "return"
		return ins, 1
	case b == 0xcc:
		ins.Mnemonic, ins.Kind = "int3", "trap"
		return ins, 1
	case b == 0x90:
		ins.Mnemonic = "nop"
		return ins, 1
	case b >= 0x50 && b <= 0x57:
		ins.Mnemonic, ins.Operand = "push", regName(int(b-0x50)+rx.b*8, mode, mode == Mode64 || rx.w)
		return ins, 1
	case b >= 0x58 && b <= 0x5f:
		ins.Mnemonic, ins.Operand = "pop", regName(int(b-0x58)+rx.b*8, mode, mode == Mode64 || rx.w)
		return ins, 1
	case b == 0xe8 && i+5 <= limit:
		rel := int32(binary.LittleEndian.Uint32(code[i+1:]))
		t := uint64(int64(addr+5) + int64(rel))
		ins.Mnemonic, ins.Operand, ins.Target, ins.Kind = "call", fmt.Sprintf("0x%x", t), fmt.Sprintf("0x%x", t), "call"
		return ins, 5
	case b == 0xe9 && i+5 <= limit:
		rel := int32(binary.LittleEndian.Uint32(code[i+1:]))
		t := uint64(int64(addr+5) + int64(rel))
		ins.Mnemonic, ins.Operand, ins.Target, ins.Kind = "jmp", fmt.Sprintf("0x%x", t), fmt.Sprintf("0x%x", t), "jump"
		return ins, 5
	case b == 0xeb && i+2 <= limit:
		rel := int8(code[i+1])
		t := uint64(int64(addr+2) + int64(rel))
		ins.Mnemonic, ins.Operand, ins.Target, ins.Kind = "jmp", fmt.Sprintf("0x%x", t), fmt.Sprintf("0x%x", t), "jump"
		return ins, 2
	case b >= 0x70 && b <= 0x7f && i+2 <= limit:
		rel := int8(code[i+1])
		t := uint64(int64(addr+2) + int64(rel))
		ins.Mnemonic, ins.Operand, ins.Target, ins.Kind = jccName(b-0x70), fmt.Sprintf("0x%x", t), fmt.Sprintf("0x%x", t), "branch"
		return ins, 2
	case b == 0x0f && i+6 <= limit && code[i+1] >= 0x80 && code[i+1] <= 0x8f:
		rel := int32(binary.LittleEndian.Uint32(code[i+2:]))
		t := uint64(int64(addr+6) + int64(rel))
		ins.Mnemonic, ins.Operand, ins.Target, ins.Kind = jccName(code[i+1]-0x80), fmt.Sprintf("0x%x", t), fmt.Sprintf("0x%x", t), "branch"
		return ins, 6
	case b == 0x68 && i+5 <= limit:
		ins.Mnemonic, ins.Operand = "push", fmt.Sprintf("0x%x", binary.LittleEndian.Uint32(code[i+1:]))
		return ins, 5
	case b == 0x6a && i+2 <= limit:
		ins.Mnemonic, ins.Operand = "push", fmt.Sprintf("0x%x", int8(code[i+1]))
		return ins, 2
	case b >= 0xb8 && b <= 0xbf:
		immSize := 4
		reg := regName(int(b-0xb8)+rx.b*8, mode, rx.w)
		if i+1+immSize <= limit {
			ins.Mnemonic, ins.Operand = "mov", fmt.Sprintf("%s, 0x%x", reg, binary.LittleEndian.Uint32(code[i+1:]))
			return ins, 1 + immSize
		}
	case b == 0x89 || b == 0x8b || b == 0x8d || b == 0x31 || b == 0x39 || b == 0x3b || b == 0x85:
		return decodeModRM2(code, i, addr, mode, rx, limit, b)
	case b == 0x83 || b == 0x81 || b == 0xc7 || b == 0xff:
		return decodeGroup(code, i, addr, mode, rx, limit, b)
	}
	ins.Mnemonic = "db"
	ins.Operand = fmt.Sprintf("0x%02x", b)
	return ins, 1
}

func decodeModRM2(code []byte, i int, addr uint64, mode Mode, rx rex, limit int, op byte) (api.Instruction, int) {
	ins := api.Instruction{Address: fmt.Sprintf("0x%x", addr)}
	m, ok := parseModRM(code, i+1, addr, mode, rx, limit)
	if !ok {
		ins.Mnemonic, ins.Operand = "db", fmt.Sprintf("0x%02x", op)
		return ins, 1
	}
	reg := regName(m.reg+rx.r*8, mode, rx.w)
	rm := rmOperand(m, mode, rx.w)
	switch op {
	case 0x89:
		ins.Mnemonic, ins.Operand = "mov", fmt.Sprintf("%s, %s", rm, reg)
	case 0x8b:
		ins.Mnemonic, ins.Operand = "mov", fmt.Sprintf("%s, %s", reg, rm)
	case 0x8d:
		ins.Mnemonic, ins.Operand = "lea", fmt.Sprintf("%s, %s", reg, rm)
	case 0x31:
		ins.Mnemonic, ins.Operand = "xor", fmt.Sprintf("%s, %s", rm, reg)
	case 0x39:
		ins.Mnemonic, ins.Operand = "cmp", fmt.Sprintf("%s, %s", rm, reg)
	case 0x3b:
		ins.Mnemonic, ins.Operand = "cmp", fmt.Sprintf("%s, %s", reg, rm)
	case 0x85:
		ins.Mnemonic, ins.Operand = "test", fmt.Sprintf("%s, %s", rm, reg)
	}
	return ins, 1 + m.size
}

func decodeGroup(code []byte, i int, addr uint64, mode Mode, rx rex, limit int, op byte) (api.Instruction, int) {
	ins := api.Instruction{Address: fmt.Sprintf("0x%x", addr)}
	m, ok := parseModRM(code, i+1, addr, mode, rx, limit)
	if !ok {
		ins.Mnemonic, ins.Operand = "db", fmt.Sprintf("0x%02x", op)
		return ins, 1
	}
	dst := rmOperand(m, mode, rx.w)
	switch op {
	case 0x83:
		if i+1+m.size >= limit {
			break
		}
		imm := int8(code[i+1+m.size])
		names := map[int]string{0: "add", 1: "or", 4: "and", 5: "sub", 6: "xor", 7: "cmp"}
		ins.Mnemonic = names[m.reg]
		if ins.Mnemonic == "" {
			ins.Mnemonic = "grp83"
		}
		ins.Operand = fmt.Sprintf("%s, 0x%x", dst, uint8(imm))
		return ins, 2 + m.size
	case 0x81:
		if i+4+m.size >= limit {
			break
		}
		imm := binary.LittleEndian.Uint32(code[i+1+m.size:])
		names := map[int]string{0: "add", 1: "or", 4: "and", 5: "sub", 6: "xor", 7: "cmp"}
		ins.Mnemonic = names[m.reg]
		if ins.Mnemonic == "" {
			ins.Mnemonic = "grp81"
		}
		ins.Operand = fmt.Sprintf("%s, 0x%x", dst, imm)
		return ins, 5 + m.size
	case 0xc7:
		if i+4+m.size >= limit {
			break
		}
		ins.Mnemonic = "mov"
		ins.Operand = fmt.Sprintf("%s, 0x%x", dst, binary.LittleEndian.Uint32(code[i+1+m.size:]))
		return ins, 5 + m.size
	case 0xff:
		switch m.reg {
		case 0:
			ins.Mnemonic, ins.Operand = "inc", dst
		case 1:
			ins.Mnemonic, ins.Operand = "dec", dst
		case 2:
			ins.Mnemonic, ins.Operand, ins.Target, ins.Kind = "call", dst, dst, "call"
		case 4:
			ins.Mnemonic, ins.Operand, ins.Target, ins.Kind = "jmp", dst, dst, "jump"
		case 6:
			ins.Mnemonic, ins.Operand = "push", dst
		default:
			ins.Mnemonic, ins.Operand = "grpff", dst
		}
		return ins, 1 + m.size
	}
	ins.Mnemonic, ins.Operand = "db", fmt.Sprintf("0x%02x", op)
	return ins, 1
}

func parseModRM(code []byte, i int, addr uint64, mode Mode, rx rex, limit int) (modrm, bool) {
	if i >= limit {
		return modrm{}, false
	}
	b := code[i]
	m := modrm{mod: b >> 6, reg: int((b >> 3) & 7), rm: int(b&7) + rx.b*8, size: 1}
	if m.mod == 3 {
		return m, true
	}
	base := ""
	if mode == Mode64 {
		base = regName(m.rm, mode, true)
	} else {
		base = regName(m.rm, mode, false)
	}
	if m.rm&7 == 4 && i+m.size < limit {
		sib := code[i+m.size]
		m.size++
		baseIdx := int(sib&7) + rx.b*8
		indexIdx := int((sib>>3)&7) + rx.x*8
		scale := 1 << ((sib >> 6) & 3)
		base = regName(baseIdx, mode, true)
		if indexIdx&7 != 4 {
			base += fmt.Sprintf("+%s*%d", regName(indexIdx, mode, true), scale)
		}
	}
	disp := int64(0)
	switch m.mod {
	case 0:
		if mode == Mode64 && m.rm&7 == 5 {
			if i+m.size+4 > limit {
				return modrm{}, false
			}
			disp = int64(int32(binary.LittleEndian.Uint32(code[i+m.size:])))
			m.size += 4
			m.mem = fmt.Sprintf("[rip%s0x%x]", sign(disp), abs(disp))
			return m, true
		}
	case 1:
		if i+m.size+1 > limit {
			return modrm{}, false
		}
		disp = int64(int8(code[i+m.size]))
		m.size++
	case 2:
		if i+m.size+4 > limit {
			return modrm{}, false
		}
		disp = int64(int32(binary.LittleEndian.Uint32(code[i+m.size:])))
		m.size += 4
	}
	if disp == 0 {
		m.mem = fmt.Sprintf("[%s]", base)
	} else {
		m.mem = fmt.Sprintf("[%s%s0x%x]", base, sign(disp), abs(disp))
	}
	return m, true
}

func rmOperand(m modrm, mode Mode, wide bool) string {
	if m.mod == 3 {
		return regName(m.rm, mode, wide)
	}
	return m.mem
}

func regName(idx int, mode Mode, wide bool) string {
	idx &= 15
	regs64 := []string{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
	regs32 := []string{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"}
	if mode == Mode64 && wide {
		return regs64[idx]
	}
	return regs32[idx]
}

func jccName(v byte) string {
	names := []string{"jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"}
	return names[v&0xf]
}

func sign(v int64) string {
	if v < 0 {
		return "-"
	}
	return "+"
}

func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func byteString(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, " ")
}
