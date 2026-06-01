package pe

import (
	"encoding/binary"
	"testing"
)

func TestParseMinimalPE32(t *testing.T) {
	data := minimalPE32()
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := Arch(f.Headers.COFF.Machine); got != "x86" {
		t.Fatalf("Arch() = %q", got)
	}
	if f.Headers.Optional.AddressOfEntryPoint != 0x1000 {
		t.Fatalf("entry point = 0x%x", f.Headers.Optional.AddressOfEntryPoint)
	}
	if len(f.Sections) != 1 || f.Sections[0].Name != ".text" {
		t.Fatalf("sections = %#v", f.Sections)
	}
	off, ok := f.RVAOffset(0x1000)
	if !ok || off != 0x200 {
		t.Fatalf("RVAOffset(0x1000) = %x, %v", off, ok)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	if _, err := Parse([]byte("not a pe")); err == nil {
		t.Fatal("Parse() accepted malformed input")
	}
}

func minimalPE32() []byte {
	data := make([]byte, 0x400)
	binary.LittleEndian.PutUint16(data[0:], ImageDOSSignature)
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	off := 0x80
	binary.LittleEndian.PutUint32(data[off:], ImageNTSignature)
	coff := off + 4
	binary.LittleEndian.PutUint16(data[coff:], 0x14c)
	binary.LittleEndian.PutUint16(data[coff+2:], 1)
	binary.LittleEndian.PutUint32(data[coff+4:], 0x65000000)
	binary.LittleEndian.PutUint16(data[coff+16:], 0xe0)
	binary.LittleEndian.PutUint16(data[coff+18:], 0x010f)
	opt := coff + 20
	binary.LittleEndian.PutUint16(data[opt:], 0x10b)
	binary.LittleEndian.PutUint32(data[opt+16:], 0x1000)
	binary.LittleEndian.PutUint32(data[opt+28:], 0x400000)
	binary.LittleEndian.PutUint32(data[opt+32:], 0x1000)
	binary.LittleEndian.PutUint32(data[opt+36:], 0x200)
	binary.LittleEndian.PutUint32(data[opt+56:], 0x2000)
	binary.LittleEndian.PutUint16(data[opt+68:], 3)
	binary.LittleEndian.PutUint32(data[opt+92:], 16)
	sec := opt + 0xe0
	copy(data[sec:sec+8], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(data[sec+8:], 0x100)
	binary.LittleEndian.PutUint32(data[sec+12:], 0x1000)
	binary.LittleEndian.PutUint32(data[sec+16:], 0x200)
	binary.LittleEndian.PutUint32(data[sec+20:], 0x200)
	binary.LittleEndian.PutUint32(data[sec+36:], 0x60000020)
	copy(data[0x200:], []byte{0x55, 0x8b, 0xec, 0xc3})
	return data
}
