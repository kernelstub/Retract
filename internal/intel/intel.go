package intel

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"retract/internal/entropy"
	"retract/internal/formats/pe"
	"retract/pkg/api"
)

func Build(data []byte, r api.AnalysisReport, peFile *pe.File) (api.FileIntelligence, api.BinaryDetails) {
	info := api.FileIntelligence{
		Format:   r.Metadata.FileType,
		MIMEType: http.DetectContentType(data[:min(len(data), 512)]),
		ScanTime: time.Now().UTC().Format(time.RFC3339),
		LookupLinks: api.LookupLinks{
			VirusTotal:    "https://www.virustotal.com/gui/file/" + r.Metadata.SHA256,
			MalwareBazaar: "https://bazaar.abuse.ch/sample/" + r.Metadata.SHA256 + "/",
		},
	}
	bin := api.BinaryDetails{FileType: r.Metadata.FileType, Architecture: r.Metadata.Arch, Endian: r.Metadata.Endianness, EntryPoint: r.Metadata.EntryPoint}
	if peFile != nil {
		info.OperatingSystem = "Windows"
		bin.Mode = peMode(peFile)
		bin.ModuleAddress = fmt.Sprintf("0x%x", peFile.Headers.Optional.ImageBase)
		bin.ImageSize = peFile.Headers.Optional.SizeOfImage
	} else {
		info.OperatingSystem = osGuess(r.Metadata.FileType)
		bin.Mode = modeGuess(r.Metadata.Arch)
	}
	info.Protections = protections(r)
	info.Packer = packer(r)
	info.Compiler = compiler(r)
	info.Language = language(r)
	info.Libraries = libraries(r)
	info.Matches = matches(r)
	return info, bin
}

func protections(r api.AnalysisReport) []string {
	out := []string{}
	if r.Security["aslr_dynamic_base"] {
		out = append(out, "ASLR")
	}
	if r.Security["dep_nx_compat"] {
		out = append(out, "DEP/NX")
	}
	if r.Security["control_flow_guard"] {
		out = append(out, "Control Flow Guard")
	}
	if r.Security["high_entropy_va"] {
		out = append(out, "High Entropy VA")
	}
	if r.Certificate.Present {
		out = append(out, "Authenticode certificate table")
	}
	if len(out) == 0 {
		out = append(out, "No common PE hardening flags detected")
	}
	return out
}

func packer(r api.AnalysisReport) string {
	for _, s := range r.Sections {
		n := strings.ToLower(s.Name)
		if strings.Contains(n, "upx") {
			return "UPX-like section names"
		}
		if strings.Contains(n, "pack") || strings.Contains(n, "crypt") {
			return "packer-like section names"
		}
		if s.Entropy >= 7.2 && strings.Contains(s.Permissions, "x") {
			return "high-entropy executable section"
		}
	}
	if e, ok := r.Entropy["whole_file"].(float64); ok && e >= 7.2 {
		return "high whole-file entropy"
	}
	_ = entropy.Shannon(nil)
	return "not detected"
}

func compiler(r api.AnalysisReport) string {
	text := strings.ToLower(joinStrings(r.Strings, 6000))
	switch {
	case strings.Contains(text, "msvcp") || strings.Contains(text, "vcruntime") || hasDLL(r.Imports, "msvcp", "vcruntime"):
		return "Microsoft Visual C/C++"
	case strings.Contains(text, "mingw") || strings.Contains(text, "gcc"):
		return "GCC/MinGW"
	case strings.Contains(text, "clang"):
		return "Clang/LLVM"
	case strings.Contains(text, "go build") || strings.Contains(text, "runtime.g"):
		return "Go"
	case strings.Contains(text, "rust"):
		return "Rust"
	default:
		return "unknown"
	}
}

func language(r api.AnalysisReport) string {
	c := compiler(r)
	switch {
	case strings.Contains(c, "Go"):
		return "Go"
	case strings.Contains(c, "Rust"):
		return "Rust"
	case strings.Contains(c, "Visual") || strings.Contains(c, "GCC") || strings.Contains(c, "Clang"):
		return "C/C++"
	default:
		return "unknown"
	}
}

func libraries(r api.AnalysisReport) []string {
	seen := map[string]bool{}
	for _, imp := range r.Imports {
		if imp.DLL != "" {
			seen[imp.DLL] = true
		}
	}
	out := []string{}
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func matches(r api.AnalysisReport) []string {
	out := []string{}
	for _, f := range r.Findings {
		out = append(out, f.Severity+": "+f.Category+" - "+f.Message)
	}
	for _, v := range r.Vulnerabilities {
		out = append(out, v.Severity+": "+v.ID+" - "+v.Title)
	}
	for _, a := range r.EmbeddedArtifacts {
		out = append(out, fmt.Sprintf("embedded %s at 0x%x", a.Type, a.Offset))
	}
	if len(out) == 0 {
		out = append(out, "no heuristic matches")
	}
	return out
}

func peMode(f *pe.File) string {
	if f.Headers.Optional.PE32Plus {
		return "64-bit"
	}
	return "32-bit"
}

func osGuess(format string) string {
	switch format {
	case "pe":
		return "Windows"
	case "elf":
		return "Linux/Unix"
	case "macho":
		return "macOS/iOS"
	default:
		return "unknown"
	}
}

func modeGuess(arch string) string {
	if strings.Contains(arch, "64") {
		return "64-bit"
	}
	if arch != "" && arch != "unknown" {
		return "32-bit"
	}
	return "unknown"
}

func joinStrings(hits []api.StringHit, max int) string {
	var b strings.Builder
	for _, h := range hits {
		if b.Len()+len(h.Value) > max {
			break
		}
		b.WriteString(h.Value)
		b.WriteByte('\n')
	}
	return b.String()
}

func hasDLL(imports []api.ImportFunction, needles ...string) bool {
	for _, imp := range imports {
		d := strings.ToLower(imp.DLL)
		for _, n := range needles {
			if strings.Contains(d, n) {
				return true
			}
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
