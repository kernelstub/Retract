package carve

import (
	"bytes"
	"encoding/binary"
)

type sig struct {
	Type  string
	Desc  string
	Magic []byte
}

var signatures = []sig{
	{"pe", "Windows PE/DOS executable header", []byte("MZ")},
	{"elf", "ELF executable/shared object", []byte{0x7f, 'E', 'L', 'F'}},
	{"zip", "ZIP/JAR/APK/Office archive", []byte{'P', 'K', 0x03, 0x04}},
	{"png", "PNG image", []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}},
	{"jpg", "JPEG image", []byte{0xff, 0xd8, 0xff}},
	{"pdf", "PDF document", []byte("%PDF-")},
	{"gzip", "Gzip stream", []byte{0x1f, 0x8b, 0x08}},
	{"rar", "RAR archive", []byte("Rar!\x1a\x07")},
	{"sqlite", "SQLite database", []byte("SQLite format 3\x00")},
	{"cab", "Microsoft Cabinet archive", []byte("MSCF")},
	{"7z", "7-Zip archive", []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}},
}

type Artifact struct {
	Offset int
	Type   string
	Desc   string
}

func Scan(data []byte) []Artifact {
	out := []Artifact{}
	seen := map[int]bool{}
	for _, s := range signatures {
		start := 0
		for {
			idx := bytes.Index(data[start:], s.Magic)
			if idx < 0 {
				break
			}
			off := start + idx
			start = off + 1
			if off == 0 || seen[off] {
				continue
			}
			if !validAt(data, off, s.Type) {
				continue
			}
			seen[off] = true
			out = append(out, Artifact{Offset: off, Type: s.Type, Desc: s.Desc})
			if len(out) >= 4096 {
				return out
			}
		}
	}
	return out
}

func validAt(data []byte, off int, typ string) bool {
	switch typ {
	case "pe":
		if off+0x40 > len(data) {
			return false
		}
		lfanew := int(binary.LittleEndian.Uint32(data[off+0x3c:]))
		return lfanew > 0 && lfanew < 0x100000 && off+lfanew+4 <= len(data) && string(data[off+lfanew:off+lfanew+4]) == "PE\x00\x00"
	case "elf":
		return off+0x14 <= len(data) && (data[off+4] == 1 || data[off+4] == 2) && (data[off+5] == 1 || data[off+5] == 2)
	case "zip":
		return off+30 <= len(data)
	case "png":
		return off+24 <= len(data) && string(data[off+12:off+16]) == "IHDR"
	default:
		return true
	}
}
