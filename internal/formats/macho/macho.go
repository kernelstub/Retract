package macho

import (
	"bytes"
	stdmacho "debug/macho"
	"fmt"
	"strings"

	"retract/internal/entropy"
	"retract/internal/utils"
	"retract/pkg/api"
)

type File struct {
	Data     []byte
	File     *stdmacho.File
	Headers  map[string]any
	Sections []api.Section
	Imports  []api.ImportFunction
	Exports  []api.ExportFunction
	Findings []api.Finding
}

func Detect(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	m := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	return m == 0xfeedface || m == 0xfeedfacf || m == 0xcafebabe || m == 0xcffaedfe || m == 0xcefaedfe
}

func Parse(data []byte) (*File, error) {
	f, err := stdmacho.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	out := &File{Data: data, File: f}
	out.Headers = map[string]any{
		"magic":    fmt.Sprintf("0x%x", f.Magic),
		"cpu":      f.Cpu.String(),
		"subcpu":   uint32(f.SubCpu),
		"type":     f.Type.String(),
		"commands": f.Ncmd,
		"flags":    fmt.Sprintf("0x%x", f.Flags),
	}
	for _, s := range f.Sections {
		out.Sections = append(out.Sections, section(data, s))
	}
	out.Imports = imports(f)
	out.Exports = exports(f)
	out.Findings = findings(out.Sections)
	return out, nil
}

func (f *File) Metadata(filename string, size int64, hashes [4]string) api.FileMetadata {
	return api.FileMetadata{
		Filename: filename, Size: size, MD5: hashes[0], SHA1: hashes[1], SHA256: hashes[2], SHA512: hashes[3],
		FileType: "Mach-O", Arch: f.File.Cpu.String(), Endianness: "little", EntryPoint: entryPoint(f.File),
	}
}

func section(data []byte, s *stdmacho.Section) api.Section {
	raw, _ := s.Data()
	if len(raw) == 0 && uint64(s.Offset) < uint64(len(data)) {
		end := uint64(s.Offset) + s.Size
		if end > uint64(len(data)) {
			end = uint64(len(data))
		}
		raw = data[int(s.Offset):int(end)]
	}
	perms := "r"
	if strings.HasPrefix(s.Seg, "__TEXT") {
		perms = "rx"
	} else if strings.HasPrefix(s.Seg, "__DATA") {
		perms = "rw"
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
		Name: s.Seg + "." + s.Name, VirtualAddress: uint32(s.Addr), VirtualSize: uint32(s.Size), RawOffset: s.Offset, RawSize: uint32(s.Size),
		Permissions: perms, Flags: fmt.Sprintf("0x%x", s.Flags), Characteristics: uint32(s.Flags), Entropy: e, Suspicious: susp,
	}
}

func imports(f *stdmacho.File) []api.ImportFunction {
	var out []api.ImportFunction
	libs, _ := f.ImportedLibraries()
	syms, _ := f.ImportedSymbols()
	for _, sym := range syms {
		dll := ""
		if len(libs) == 1 {
			dll = libs[0]
		}
		out = append(out, api.ImportFunction{DLL: dll, Name: sym, Category: categorizeMachO(sym)})
	}
	return out
}

func exports(f *stdmacho.File) []api.ExportFunction {
	var out []api.ExportFunction
	if f.Symtab == nil {
		return out
	}
	for _, sym := range f.Symtab.Syms {
		if sym.Name == "" || sym.Sect == 0 {
			continue
		}
		if sym.Type&0x01 == 0 {
			continue
		}
		out = append(out, api.ExportFunction{Name: sym.Name, RVA: utils.Hex64(sym.Value)})
	}
	return out
}

func findings(sections []api.Section) []api.Finding {
	var out []api.Finding
	for _, s := range sections {
		for _, note := range s.Suspicious {
			out = append(out, api.Finding{Severity: "medium", Category: "section", Message: s.Name + ": " + note})
		}
	}
	return out
}

func entryPoint(_ *stdmacho.File) string {
	return ""
}

func categorizeMachO(name string) []string {
	n := strings.ToLower(name)
	var cats []string
	table := map[string][]string{
		"file operations":     {"open", "read", "write", "unlink", "rename"},
		"networking":          {"socket", "connect", "send", "recv", "nw_", "cfnetwork"},
		"memory allocation":   {"malloc", "calloc", "realloc", "free", "vm_allocate", "mprotect"},
		"dynamic loading":     {"dlopen", "dlsym", "nslookup"},
		"process execution":   {"exec", "system", "posix_spawn", "fork"},
		"anti-debugging":      {"ptrace", "sysctl"},
		"cryptography":        {"crypto", "cccrypt", "sha", "aes", "rsa"},
		"privilege operation": {"setuid", "authorization"},
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
