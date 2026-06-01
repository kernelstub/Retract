package elf

import (
	"bytes"
	stdelf "debug/elf"
	"fmt"
	"io"
	"strings"

	"retract/internal/entropy"
	"retract/internal/utils"
	"retract/pkg/api"
)

type File struct {
	Data     []byte
	File     *stdelf.File
	Headers  map[string]any
	Sections []api.Section
	Imports  []api.ImportFunction
	Exports  []api.ExportFunction
	Findings []api.Finding
}

func Detect(data []byte) bool {
	return len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F'
}

func Parse(data []byte) (*File, error) {
	f, err := stdelf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	out := &File{Data: data, File: f}
	out.Headers = map[string]any{
		"class":       f.Class.String(),
		"data":        f.Data.String(),
		"type":        f.Type.String(),
		"machine":     f.Machine.String(),
		"entry":       utils.Hex64(f.Entry),
		"osabi":       f.OSABI.String(),
		"abi_version": f.ABIVersion,
	}
	for _, s := range f.Sections {
		if s.Type == stdelf.SHT_NULL && s.Size == 0 {
			continue
		}
		out.Sections = append(out.Sections, section(data, s))
	}
	out.Imports = imports(f)
	out.Exports = exports(f)
	out.Findings = findings(f, out.Sections)
	return out, nil
}

func (f *File) Metadata(filename string, size int64, hashes [4]string) api.FileMetadata {
	return api.FileMetadata{
		Filename: filename, Size: size, MD5: hashes[0], SHA1: hashes[1], SHA256: hashes[2], SHA512: hashes[3],
		FileType: "ELF", Arch: f.File.Machine.String(), Endianness: endian(f.File.Data), EntryPoint: utils.Hex64(f.File.Entry),
	}
}

func section(data []byte, s *stdelf.Section) api.Section {
	raw := readSection(s)
	if len(raw) == 0 && s.Offset < uint64(len(data)) {
		end := s.Offset + s.Size
		if end > uint64(len(data)) {
			end = uint64(len(data))
		}
		raw = data[s.Offset:end]
	}
	perms := ""
	if s.Flags&stdelf.SHF_ALLOC != 0 {
		perms += "r"
	}
	if s.Flags&stdelf.SHF_WRITE != 0 {
		perms += "w"
	}
	if s.Flags&stdelf.SHF_EXECINSTR != 0 {
		perms += "x"
	}
	e := entropy.Shannon(raw)
	var susp []string
	if strings.Contains(perms, "w") && strings.Contains(perms, "x") {
		susp = append(susp, "section is both writable and executable")
	}
	if e >= 7.2 {
		susp = append(susp, fmt.Sprintf("high entropy %.2f", e))
	}
	return api.Section{
		Name: s.Name, VirtualAddress: uint32(s.Addr), VirtualSize: uint32(s.Size), RawOffset: uint32(s.Offset), RawSize: uint32(s.Size),
		Permissions: perms, Flags: s.Flags.String(), Characteristics: uint32(s.Type), Entropy: e, Suspicious: susp,
	}
}

func readSection(s *stdelf.Section) []byte {
	b, err := s.Data()
	if err != nil && err != io.EOF {
		return nil
	}
	return b
}

func imports(f *stdelf.File) []api.ImportFunction {
	var out []api.ImportFunction
	libs, _ := f.ImportedLibraries()
	dyn, _ := f.DynamicSymbols()
	for _, sym := range dyn {
		if sym.Section != stdelf.SHN_UNDEF {
			continue
		}
		dll := ""
		if len(libs) == 1 {
			dll = libs[0]
		}
		out = append(out, api.ImportFunction{DLL: dll, Name: sym.Name, Category: categorizeELF(sym.Name)})
	}
	return out
}

func exports(f *stdelf.File) []api.ExportFunction {
	var out []api.ExportFunction
	syms, _ := f.Symbols()
	dyn, _ := f.DynamicSymbols()
	syms = append(syms, dyn...)
	seen := map[string]bool{}
	for _, sym := range syms {
		if sym.Name == "" || sym.Section == stdelf.SHN_UNDEF || seen[sym.Name] {
			continue
		}
		bind := stdelf.ST_BIND(sym.Info)
		if bind != stdelf.STB_GLOBAL && bind != stdelf.STB_WEAK {
			continue
		}
		seen[sym.Name] = true
		out = append(out, api.ExportFunction{Name: sym.Name, RVA: utils.Hex64(sym.Value)})
	}
	return out
}

func findings(f *stdelf.File, sections []api.Section) []api.Finding {
	var out []api.Finding
	if f.Type == stdelf.ET_DYN {
		out = append(out, api.Finding{Severity: "info", Category: "elf", Message: "position-independent shared object / PIE-style ELF"})
	}
	for _, s := range sections {
		for _, note := range s.Suspicious {
			out = append(out, api.Finding{Severity: "medium", Category: "section", Message: s.Name + ": " + note})
		}
	}
	return out
}

func endian(d stdelf.Data) string {
	if d == stdelf.ELFDATA2LSB {
		return "little"
	}
	if d == stdelf.ELFDATA2MSB {
		return "big"
	}
	return "unknown"
}

func categorizeELF(name string) []string {
	n := strings.ToLower(name)
	var cats []string
	table := map[string][]string{
		"file operations":     {"open", "read", "write", "unlink", "rename"},
		"networking":          {"socket", "connect", "send", "recv", "getaddrinfo"},
		"memory allocation":   {"malloc", "calloc", "realloc", "free", "mmap", "mprotect"},
		"dynamic loading":     {"dlopen", "dlsym", "dlclose"},
		"process execution":   {"execve", "system", "fork", "clone", "posix_spawn"},
		"anti-debugging":      {"ptrace"},
		"cryptography":        {"crypto", "ssl", "sha", "aes", "rsa"},
		"privilege operation": {"setuid", "setgid", "capset"},
	}
	for cat, needles := range table {
		for _, needle := range needles {
			if strings.Contains(n, needle) {
				cats = append(cats, cat)
				break
			}
		}
	}
	return cats
}
