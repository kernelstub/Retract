package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"

	"retract/internal/entropy"
	"retract/internal/utils"
	"retract/pkg/api"
)

const (
	ImageDOSSignature = 0x5a4d
	ImageNTSignature  = 0x00004550
	DirExport         = 0
	DirImport         = 1
	DirResource       = 2
	DirException      = 3
	DirCertificate    = 4
	DirReloc          = 5
	DirDebug          = 6
	DirTLS            = 9
	DirLoadConfig     = 10
)

type DOSHeader struct {
	Magic  uint16 `json:"magic"`
	Lfanew uint32 `json:"lfanew"`
}

type COFFHeader struct {
	Machine              uint16 `json:"machine"`
	NumberOfSections     uint16 `json:"number_of_sections"`
	TimeDateStamp        uint32 `json:"time_date_stamp"`
	PointerToSymbolTable uint32 `json:"pointer_to_symbol_table"`
	NumberOfSymbols      uint32 `json:"number_of_symbols"`
	SizeOfOptionalHeader uint16 `json:"size_of_optional_header"`
	Characteristics      uint16 `json:"characteristics"`
}

type DataDirectory struct {
	Name string `json:"name"`
	RVA  uint32 `json:"rva"`
	Size uint32 `json:"size"`
}

type OptionalHeader struct {
	Magic               uint16          `json:"magic"`
	PE32Plus            bool            `json:"pe32_plus"`
	AddressOfEntryPoint uint32          `json:"address_of_entry_point"`
	ImageBase           uint64          `json:"image_base"`
	SectionAlignment    uint32          `json:"section_alignment"`
	FileAlignment       uint32          `json:"file_alignment"`
	SizeOfImage         uint32          `json:"size_of_image"`
	Subsystem           uint16          `json:"subsystem"`
	DllCharacteristics  uint16          `json:"dll_characteristics"`
	NumberOfRvaAndSizes uint32          `json:"number_of_rva_and_sizes"`
	DataDirectories     []DataDirectory `json:"data_directories"`
}

type SectionHeader struct {
	Name             string `json:"name"`
	VirtualSize      uint32 `json:"virtual_size"`
	VirtualAddress   uint32 `json:"virtual_address"`
	SizeOfRawData    uint32 `json:"size_of_raw_data"`
	PointerToRawData uint32 `json:"pointer_to_raw_data"`
	Characteristics  uint32 `json:"characteristics"`
}

type Headers struct {
	DOS      DOSHeader       `json:"dos_header"`
	COFF     COFFHeader      `json:"coff_header"`
	Optional OptionalHeader  `json:"optional_header"`
	Sections []SectionHeader `json:"section_headers"`
}

type File struct {
	Data          []byte
	Headers       Headers
	Sections      []api.Section
	Imports       []api.ImportFunction
	Exports       []api.ExportFunction
	Findings      []api.Finding
	OverlayOffset int
}

func Parse(data []byte) (*File, error) {
	if len(data) < 0x40 {
		return nil, fmt.Errorf("file too small for PE")
	}
	r := bytes.NewReader(data)
	var mz uint16
	_ = binary.Read(r, binary.LittleEndian, &mz)
	if mz != ImageDOSSignature {
		return nil, fmt.Errorf("missing DOS MZ signature")
	}
	lfanew := binary.LittleEndian.Uint32(data[0x3c:0x40])
	if int(lfanew)+24 > len(data) {
		return nil, fmt.Errorf("invalid PE header offset")
	}
	if binary.LittleEndian.Uint32(data[lfanew:lfanew+4]) != ImageNTSignature {
		return nil, fmt.Errorf("missing PE signature")
	}
	coffOff := int(lfanew) + 4
	coff := COFFHeader{
		Machine:              binary.LittleEndian.Uint16(data[coffOff:]),
		NumberOfSections:     binary.LittleEndian.Uint16(data[coffOff+2:]),
		TimeDateStamp:        binary.LittleEndian.Uint32(data[coffOff+4:]),
		PointerToSymbolTable: binary.LittleEndian.Uint32(data[coffOff+8:]),
		NumberOfSymbols:      binary.LittleEndian.Uint32(data[coffOff+12:]),
		SizeOfOptionalHeader: binary.LittleEndian.Uint16(data[coffOff+16:]),
		Characteristics:      binary.LittleEndian.Uint16(data[coffOff+18:]),
	}
	optOff := coffOff + 20
	if optOff+int(coff.SizeOfOptionalHeader) > len(data) {
		return nil, fmt.Errorf("optional header extends past EOF")
	}
	opt, err := parseOptional(data[optOff : optOff+int(coff.SizeOfOptionalHeader)])
	if err != nil {
		return nil, err
	}
	secOff := optOff + int(coff.SizeOfOptionalHeader)
	sectionHeaders := []SectionHeader{}
	sections := []api.Section{}
	for i := 0; i < int(coff.NumberOfSections); i++ {
		off := secOff + i*40
		if off+40 > len(data) {
			break
		}
		name := sectionName(data[off : off+8])
		sh := SectionHeader{
			Name:             name,
			VirtualSize:      binary.LittleEndian.Uint32(data[off+8:]),
			VirtualAddress:   binary.LittleEndian.Uint32(data[off+12:]),
			SizeOfRawData:    binary.LittleEndian.Uint32(data[off+16:]),
			PointerToRawData: binary.LittleEndian.Uint32(data[off+20:]),
			Characteristics:  binary.LittleEndian.Uint32(data[off+36:]),
		}
		sectionHeaders = append(sectionHeaders, sh)
		raw := sliceAt(data, sh.PointerToRawData, sh.SizeOfRawData)
		susp := sectionFindings(sh, raw)
		sections = append(sections, api.Section{
			Name: name, VirtualAddress: sh.VirtualAddress, VirtualSize: sh.VirtualSize,
			RawOffset: sh.PointerToRawData, RawSize: sh.SizeOfRawData, Permissions: perms(sh.Characteristics), Flags: sectionFlags(sh.Characteristics), Characteristics: sh.Characteristics,
			Entropy: entropy.Shannon(raw), Suspicious: susp,
		})
	}
	f := &File{Data: data, Headers: Headers{
		DOS: DOSHeader{Magic: mz, Lfanew: lfanew}, COFF: coff, Optional: opt, Sections: sectionHeaders,
	}, Sections: sections}
	f.OverlayOffset = overlayOffset(data, sectionHeaders)
	f.Imports = f.parseImports()
	f.Exports = f.parseExports()
	f.Findings = f.detectFindings()
	return f, nil
}

func parseOptional(b []byte) (OptionalHeader, error) {
	if len(b) < 96 {
		return OptionalHeader{}, fmt.Errorf("optional header too small")
	}
	magic := binary.LittleEndian.Uint16(b)
	plus := magic == 0x20b
	if magic != 0x10b && magic != 0x20b {
		return OptionalHeader{}, fmt.Errorf("unsupported optional header magic 0x%x", magic)
	}
	o := OptionalHeader{Magic: magic, PE32Plus: plus, AddressOfEntryPoint: binary.LittleEndian.Uint32(b[16:]), SectionAlignment: binary.LittleEndian.Uint32(b[32:]), FileAlignment: binary.LittleEndian.Uint32(b[36:])}
	var ddOff int
	if plus {
		if len(b) < 112 {
			return o, fmt.Errorf("PE32+ optional header too small")
		}
		o.ImageBase = binary.LittleEndian.Uint64(b[24:])
		o.SizeOfImage = binary.LittleEndian.Uint32(b[56:])
		o.Subsystem = binary.LittleEndian.Uint16(b[68:])
		o.DllCharacteristics = binary.LittleEndian.Uint16(b[70:])
		o.NumberOfRvaAndSizes = binary.LittleEndian.Uint32(b[108:])
		ddOff = 112
	} else {
		o.ImageBase = uint64(binary.LittleEndian.Uint32(b[28:]))
		o.SizeOfImage = binary.LittleEndian.Uint32(b[56:])
		o.Subsystem = binary.LittleEndian.Uint16(b[68:])
		o.DllCharacteristics = binary.LittleEndian.Uint16(b[70:])
		o.NumberOfRvaAndSizes = binary.LittleEndian.Uint32(b[92:])
		ddOff = 96
	}
	names := []string{"export", "import", "resource", "exception", "certificate", "base_relocation", "debug", "architecture", "global_ptr", "tls", "load_config", "bound_import", "iat", "delay_import", "com_descriptor", "reserved"}
	n := int(o.NumberOfRvaAndSizes)
	if n > 16 {
		n = 16
	}
	for i := 0; i < n && ddOff+i*8+8 <= len(b); i++ {
		o.DataDirectories = append(o.DataDirectories, DataDirectory{Name: names[i], RVA: binary.LittleEndian.Uint32(b[ddOff+i*8:]), Size: binary.LittleEndian.Uint32(b[ddOff+i*8+4:])})
	}
	return o, nil
}

func (f *File) Metadata(filename string, size int64, hashes [4]string) api.FileMetadata {
	arch := Arch(f.Headers.COFF.Machine)
	ep := uint64(f.Headers.Optional.ImageBase) + uint64(f.Headers.Optional.AddressOfEntryPoint)
	return api.FileMetadata{Filename: filename, Size: size, MD5: hashes[0], SHA1: hashes[1], SHA256: hashes[2], SHA512: hashes[3], FileType: "PE", Arch: arch, Endianness: "little", Subsystem: Subsystem(f.Headers.Optional.Subsystem), EntryPoint: utils.Hex64(ep), CompileTime: time.Unix(int64(f.Headers.COFF.TimeDateStamp), 0).UTC().Format(time.RFC3339)}
}

func Arch(machine uint16) string {
	switch machine {
	case 0x14c:
		return "x86"
	case 0x8664:
		return "x86_64"
	case 0x1c0, 0x1c4:
		return "ARM"
	case 0xaa64:
		return "ARM64"
	default:
		return fmt.Sprintf("unknown(0x%x)", machine)
	}
}

func Subsystem(s uint16) string {
	switch s {
	case 1:
		return "native"
	case 2:
		return "windows_gui"
	case 3:
		return "windows_console"
	case 9:
		return "windows_ce"
	case 10:
		return "efi_application"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

func (f *File) SecurityFeatures() map[string]bool {
	ch := f.Headers.Optional.DllCharacteristics
	return map[string]bool{
		"high_entropy_va":       ch&0x0020 != 0,
		"aslr_dynamic_base":     ch&0x0040 != 0,
		"force_integrity":       ch&0x0080 != 0,
		"dep_nx_compat":         ch&0x0100 != 0,
		"no_isolation":          ch&0x0200 != 0,
		"no_seh":                ch&0x0400 != 0,
		"no_bind":               ch&0x0800 != 0,
		"appcontainer":          ch&0x1000 != 0,
		"wdm_driver":            ch&0x2000 != 0,
		"control_flow_guard":    ch&0x4000 != 0,
		"terminal_server_aware": ch&0x8000 != 0,
	}
}

func (f *File) ResourceDirectoryBytes() []byte {
	d, ok := f.Directory(DirResource)
	if !ok {
		return nil
	}
	return f.RVASlice(d.RVA, d.Size)
}

func (f *File) ResourceInfo() api.ResourceInfo {
	d, ok := f.Directory(DirResource)
	if !ok {
		return api.ResourceInfo{Present: false}
	}
	return api.ResourceInfo{Present: true, RVA: utils.Hex32(d.RVA), Size: d.Size}
}

func (f *File) LoadConfigInfo() api.LoadConfigInfo {
	d, ok := f.Directory(DirLoadConfig)
	if !ok {
		return api.LoadConfigInfo{Present: false}
	}
	info := api.LoadConfigInfo{Present: true, RVA: utils.Hex32(d.RVA), Size: d.Size}
	b := f.RVASlice(d.RVA, d.Size)
	if f.Headers.Optional.PE32Plus {
		if len(b) >= 0x98 {
			info.GuardFlags = utils.Hex32(binary.LittleEndian.Uint32(b[0x90:]))
		}
	} else {
		if len(b) >= 0x68 {
			info.GuardFlags = utils.Hex32(binary.LittleEndian.Uint32(b[0x64:]))
		}
	}
	return info
}

func (f *File) OverlayInfo() api.OverlayInfo {
	if f.OverlayOffset <= 0 || f.OverlayOffset >= len(f.Data) {
		return api.OverlayInfo{Present: false}
	}
	data := f.Data[f.OverlayOffset:]
	return api.OverlayInfo{Present: true, Offset: f.OverlayOffset, Size: len(data), Entropy: entropy.Shannon(data)}
}

func (f *File) CertificateInfo() api.CertificateInfo {
	d, ok := f.Directory(DirCertificate)
	if !ok {
		return api.CertificateInfo{Present: false}
	}
	info := api.CertificateInfo{Present: true, FileOffset: d.RVA, Size: d.Size}
	if int(d.RVA)+8 <= len(f.Data) {
		info.Revision = binary.LittleEndian.Uint16(f.Data[d.RVA+4:])
		info.CertificateType = binary.LittleEndian.Uint16(f.Data[d.RVA+6:])
	}
	return info
}

func (f *File) Relocations() []api.RelocationBlock {
	d, ok := f.Directory(DirReloc)
	if !ok {
		return nil
	}
	b := f.RVASlice(d.RVA, d.Size)
	var out []api.RelocationBlock
	for off := 0; off+8 <= len(b); {
		page := binary.LittleEndian.Uint32(b[off:])
		size := binary.LittleEndian.Uint32(b[off+4:])
		if page == 0 || size < 8 || off+int(size) > len(b) {
			break
		}
		count := int((size - 8) / 2)
		out = append(out, api.RelocationBlock{PageRVA: utils.Hex32(page), Count: count})
		off += int(size)
		if len(out) >= 10000 {
			break
		}
	}
	return out
}

func (f *File) TLSCallbacks() []string {
	d, ok := f.Directory(DirTLS)
	if !ok {
		return nil
	}
	h := f.RVASlice(d.RVA, d.Size)
	var callbacksVA uint64
	ptrSize := 4
	if f.Headers.Optional.PE32Plus {
		if len(h) < 32 {
			return nil
		}
		callbacksVA = binary.LittleEndian.Uint64(h[24:])
		ptrSize = 8
	} else {
		if len(h) < 20 {
			return nil
		}
		callbacksVA = uint64(binary.LittleEndian.Uint32(h[12:]))
	}
	if callbacksVA < f.Headers.Optional.ImageBase {
		return nil
	}
	rva := uint32(callbacksVA - f.Headers.Optional.ImageBase)
	off, ok := f.RVAOffset(rva)
	if !ok {
		return nil
	}
	var out []string
	for i := 0; off+i*ptrSize+ptrSize <= len(f.Data) && i < 256; i++ {
		var va uint64
		if ptrSize == 8 {
			va = binary.LittleEndian.Uint64(f.Data[off+i*ptrSize:])
		} else {
			va = uint64(binary.LittleEndian.Uint32(f.Data[off+i*ptrSize:]))
		}
		if va == 0 {
			break
		}
		out = append(out, utils.Hex64(va))
	}
	return out
}

func (f *File) DebugEntries() []api.DebugEntry {
	d, ok := f.Directory(DirDebug)
	if !ok {
		return nil
	}
	b := f.RVASlice(d.RVA, d.Size)
	var out []api.DebugEntry
	for off := 0; off+28 <= len(b); off += 28 {
		e := api.DebugEntry{
			TimeDateStamp: binary.LittleEndian.Uint32(b[off+4:]),
			MajorVersion:  binary.LittleEndian.Uint16(b[off+8:]),
			MinorVersion:  binary.LittleEndian.Uint16(b[off+10:]),
			Type:          binary.LittleEndian.Uint32(b[off+12:]),
			Size:          binary.LittleEndian.Uint32(b[off+16:]),
			RVA:           utils.Hex32(binary.LittleEndian.Uint32(b[off+20:])),
			FileOffset:    utils.Hex32(binary.LittleEndian.Uint32(b[off+24:])),
		}
		e.TypeName = debugType(e.Type)
		rawOff := binary.LittleEndian.Uint32(b[off+24:])
		if int(rawOff) < len(f.Data) {
			end := int(rawOff + e.Size)
			if end > len(f.Data) {
				end = len(f.Data)
			}
			parseCodeView(f.Data[rawOff:end], &e)
		}
		out = append(out, e)
	}
	return out
}

func (f *File) RVAOffset(rva uint32) (int, bool) {
	for _, s := range f.Headers.Sections {
		size := s.VirtualSize
		if s.SizeOfRawData > size {
			size = s.SizeOfRawData
		}
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+size {
			off := int(s.PointerToRawData + (rva - s.VirtualAddress))
			return off, off >= 0 && off < len(f.Data)
		}
	}
	if int(rva) < len(f.Data) {
		return int(rva), true
	}
	return 0, false
}

func (f *File) RVASlice(rva, size uint32) []byte {
	off, ok := f.RVAOffset(rva)
	if !ok {
		return nil
	}
	end := off + int(size)
	if end > len(f.Data) {
		end = len(f.Data)
	}
	if end < off {
		return nil
	}
	return f.Data[off:end]
}

func (f *File) Directory(i int) (DataDirectory, bool) {
	if i < 0 || i >= len(f.Headers.Optional.DataDirectories) {
		return DataDirectory{}, false
	}
	d := f.Headers.Optional.DataDirectories[i]
	return d, d.RVA != 0 && d.Size != 0
}

func (f *File) parseImports() []api.ImportFunction {
	d, ok := f.Directory(DirImport)
	if !ok {
		return nil
	}
	var out []api.ImportFunction
	off, ok := f.RVAOffset(d.RVA)
	if !ok {
		return nil
	}
	for idx := 0; off+20 <= len(f.Data) && idx < 4096; idx++ {
		desc := f.Data[off : off+20]
		orig := binary.LittleEndian.Uint32(desc[0:])
		nameRVA := binary.LittleEndian.Uint32(desc[12:])
		firstThunk := binary.LittleEndian.Uint32(desc[16:])
		if orig == 0 && nameRVA == 0 && firstThunk == 0 {
			break
		}
		dll := f.readCStringRVA(nameRVA, 256)
		thunk := orig
		if thunk == 0 {
			thunk = firstThunk
		}
		out = append(out, f.readThunkImports(dll, thunk)...)
		off += 20
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DLL == out[j].DLL {
			return out[i].Name < out[j].Name
		}
		return out[i].DLL < out[j].DLL
	})
	return out
}

func (f *File) readThunkImports(dll string, thunkRVA uint32) []api.ImportFunction {
	var out []api.ImportFunction
	off, ok := f.RVAOffset(thunkRVA)
	if !ok {
		return nil
	}
	step := 4
	ordMask := uint64(0x80000000)
	if f.Headers.Optional.PE32Plus {
		step = 8
		ordMask = 0x8000000000000000
	}
	for i := 0; off+step <= len(f.Data) && i < 8192; i++ {
		var val uint64
		if step == 8 {
			val = binary.LittleEndian.Uint64(f.Data[off:])
		} else {
			val = uint64(binary.LittleEndian.Uint32(f.Data[off:]))
		}
		if val == 0 {
			break
		}
		imp := api.ImportFunction{DLL: dll, Address: utils.Hex64(uint64(thunkRVA) + uint64(i*step) + f.Headers.Optional.ImageBase)}
		if val&ordMask != 0 {
			imp.Ordinal = uint16(val & 0xffff)
		} else {
			name := f.readCStringRVA(uint32(val)+2, 512)
			imp.Name = name
			imp.Category = CategorizeImport(name)
		}
		out = append(out, imp)
		off += step
	}
	return out
}

func (f *File) parseExports() []api.ExportFunction {
	d, ok := f.Directory(DirExport)
	if !ok {
		return nil
	}
	b := f.RVASlice(d.RVA, d.Size)
	if len(b) < 40 {
		return nil
	}
	base := binary.LittleEndian.Uint32(b[16:])
	nfunc := binary.LittleEndian.Uint32(b[20:])
	nnames := binary.LittleEndian.Uint32(b[24:])
	funcs := binary.LittleEndian.Uint32(b[28:])
	names := binary.LittleEndian.Uint32(b[32:])
	ords := binary.LittleEndian.Uint32(b[36:])
	var out []api.ExportFunction
	for i := uint32(0); i < nnames && i < 65535; i++ {
		nameRVABytes := f.RVASlice(names+i*4, 4)
		ordBytes := f.RVASlice(ords+i*2, 2)
		if len(nameRVABytes) < 4 || len(ordBytes) < 2 {
			break
		}
		name := f.readCStringRVA(binary.LittleEndian.Uint32(nameRVABytes), 512)
		ordIndex := uint32(binary.LittleEndian.Uint16(ordBytes))
		rva := uint32(0)
		if ordIndex < nfunc {
			rvaBytes := f.RVASlice(funcs+ordIndex*4, 4)
			if len(rvaBytes) == 4 {
				rva = binary.LittleEndian.Uint32(rvaBytes)
			}
		}
		out = append(out, api.ExportFunction{Name: name, Ordinal: uint16(base + ordIndex), RVA: utils.Hex32(rva)})
	}
	return out
}

func (f *File) readCStringRVA(rva uint32, max int) string {
	off, ok := f.RVAOffset(rva)
	if !ok {
		return ""
	}
	end := off
	for end < len(f.Data) && end-off < max && f.Data[end] != 0 {
		end++
	}
	return string(f.Data[off:end])
}

func CategorizeImport(name string) []string {
	n := strings.ToLower(name)
	cats := []string{}
	table := map[string][]string{
		"process injection":    {"createremotethread", "writeprocessmemory", "openprocess", "virtualallocex", "ntmapviewofsection", "queueuserapc"},
		"file operations":      {"createfile", "writefile", "readfile", "deletefile", "copyfile", "movefile"},
		"registry operations":  {"regopenkey", "regsetvalue", "regcreatekey", "regdelete"},
		"networking":           {"internetopen", "internetconnect", "httpsendrequest", "wsastartup", "connect", "send", "recv", "urldownloadtofile"},
		"cryptography":         {"crypt", "bcrypt", "cert", "hashdata"},
		"anti-debugging":       {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstring"},
		"persistence":          {"createservice", "startservice", "schtasks", "regsetvalue"},
		"privilege escalation": {"adjusttokenprivileges", "openprocesstoken", "lookupprivilegevalue"},
		"memory allocation":    {"virtualalloc", "virtualprotect", "virtualfree", "heapalloc", "heapfree", "rtlallocateheap"},
		"dynamic loading":      {"loadlibrary", "getprocaddress", "ldrload"},
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

func (f *File) detectFindings() []api.Finding {
	var out []api.Finding
	if f.OverlayOffset > 0 && f.OverlayOffset < len(f.Data) {
		out = append(out, api.Finding{Severity: "medium", Category: "overlay", Message: fmt.Sprintf("overlay data starts at file offset 0x%x", f.OverlayOffset)})
	}
	for _, s := range f.Sections {
		for _, v := range s.Suspicious {
			out = append(out, api.Finding{Severity: "medium", Category: "section", Message: s.Name + ": " + v})
		}
	}
	for _, imp := range f.Imports {
		for _, cat := range imp.Category {
			sev := "info"
			if cat == "process injection" || cat == "anti-debugging" {
				sev = "high"
			}
			out = append(out, api.Finding{Severity: sev, Category: "import:" + cat, Message: imp.DLL + "!" + imp.Name})
		}
	}
	if d, ok := f.Directory(DirTLS); ok {
		out = append(out, api.Finding{Severity: "medium", Category: "tls", Message: fmt.Sprintf("TLS directory present at RVA 0x%x size 0x%x", d.RVA, d.Size)})
	}
	if d, ok := f.Directory(DirDebug); ok {
		out = append(out, api.Finding{Severity: "info", Category: "debug", Message: fmt.Sprintf("debug directory present at RVA 0x%x size 0x%x", d.RVA, d.Size)})
	}
	if d, ok := f.Directory(DirCertificate); ok {
		out = append(out, api.Finding{Severity: "info", Category: "certificate", Message: fmt.Sprintf("certificate table present at file offset 0x%x size 0x%x", d.RVA, d.Size)})
	}
	return out
}

func sectionFindings(s SectionHeader, raw []byte) []string {
	var out []string
	p := perms(s.Characteristics)
	if strings.Contains(p, "x") && strings.Contains(p, "w") {
		out = append(out, "section is both executable and writable")
	}
	if e := entropy.Shannon(raw); e >= 7.2 {
		out = append(out, fmt.Sprintf("high entropy %.2f", e))
	}
	n := strings.ToLower(s.Name)
	if n == "" || strings.HasPrefix(n, "upx") || strings.Contains(n, "pack") || strings.Contains(n, "crypt") {
		out = append(out, "abnormal or packer-like section name")
	}
	return out
}

func sectionName(raw []byte) string {
	raw = bytes.TrimRight(raw, "\x00")
	if len(raw) == 0 {
		return ""
	}
	var b strings.Builder
	for _, c := range raw {
		if c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "\\x%02x", c)
	}
	return b.String()
}

func debugType(t uint32) string {
	switch t {
	case 1:
		return "coff"
	case 2:
		return "codeview"
	case 10:
		return "repro"
	case 12:
		return "vc_feature"
	case 13:
		return "pogo"
	case 16:
		return "mpx"
	case 20:
		return "ex_dllcharacteristics"
	default:
		return fmt.Sprintf("unknown_%d", t)
	}
}

func parseCodeView(b []byte, e *api.DebugEntry) {
	if len(b) < 4 {
		return
	}
	sig := string(b[:4])
	if sig != "RSDS" && sig != "NB10" {
		return
	}
	e.CodeViewSignature = sig
	start := 4
	if sig == "RSDS" {
		start = 24
	} else if sig == "NB10" {
		start = 16
	}
	if start >= len(b) {
		return
	}
	end := start
	for end < len(b) && b[end] != 0 {
		end++
	}
	e.PDBPath = string(b[start:end])
}

func perms(ch uint32) string {
	p := ""
	if ch&0x40000000 != 0 {
		p += "r"
	}
	if ch&0x80000000 != 0 {
		p += "w"
	}
	if ch&0x20000000 != 0 {
		p += "x"
	}
	return p
}

func sectionFlags(ch uint32) string {
	flags := []string{}
	table := []struct {
		bit  uint32
		name string
	}{
		{0x00000020, "code"},
		{0x00000040, "initialized_data"},
		{0x00000080, "uninitialized_data"},
		{0x02000000, "discardable"},
		{0x04000000, "not_cached"},
		{0x08000000, "not_paged"},
		{0x10000000, "shared"},
		{0x20000000, "execute"},
		{0x40000000, "read"},
		{0x80000000, "write"},
	}
	for _, item := range table {
		if ch&item.bit != 0 {
			flags = append(flags, item.name)
		}
	}
	return strings.Join(flags, ", ")
}

func overlayOffset(data []byte, sections []SectionHeader) int {
	maxEnd := 0
	for _, s := range sections {
		end := int(s.PointerToRawData + s.SizeOfRawData)
		if end > maxEnd && end <= len(data) {
			maxEnd = end
		}
	}
	if maxEnd > 0 && maxEnd < len(data) {
		return maxEnd
	}
	return 0
}

func sliceAt(data []byte, off, size uint32) []byte {
	if int(off) < 0 || int(off) >= len(data) {
		return nil
	}
	end := int(off + size)
	if end > len(data) {
		end = len(data)
	}
	if end < int(off) {
		return nil
	}
	return data[off:end]
}
