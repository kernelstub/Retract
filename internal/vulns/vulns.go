package vulns

import (
	"fmt"
	"strings"

	"retract/pkg/api"
)

func Analyze(r api.AnalysisReport) []api.VulnerabilityFinding {
	var out []api.VulnerabilityFinding
	hasPrintfFamily := false
	hasAlloc := false
	hasFree := false
	hasCopy := false
	hasInput := false
	hasBounds := false
	hasIntegerParse := false
	hasFileOpen := false
	hasTemp := false
	hasEnv := false
	hasCrypto := false
	hasWeakCrypto := false
	hasRandom := false
	hasThreading := false
	for _, imp := range r.Imports {
		name := strings.ToLower(imp.Name)
		if in(name, "printf", "fprintf", "sprintf", "snprintf", "vprintf", "scanf", "sscanf") {
			hasPrintfFamily = true
		}
		if in(name, "malloc", "calloc", "realloc", "new", "heapalloc", "virtualalloc", "_znwm", "_znam") {
			hasAlloc = true
		}
		if in(name, "free", "delete", "heapfree", "virtualfree", "localfree", "_zdlpv", "_zdapv") {
			hasFree = true
		}
		if in(name, "memcpy", "memmove", "strcpy", "strncpy", "strcat", "sprintf", "readfile", "recv", "read", "fread", "copy_from_user") {
			hasCopy = true
		}
		if in(name, "recv", "wsarecv", "internetreadfile", "readfile", "read", "fread", "scanf", "getenv", "getcommandline", "argv", "accept") {
			hasInput = true
		}
		if in(name, "strlen", "sizeof", "strnlen") {
			hasBounds = true
		}
		if in(name, "atoi", "atol", "strtol", "strtoul", "strtoull", "scanf", "sscanf", "wcstol") {
			hasIntegerParse = true
		}
		if in(name, "open", "fopen", "createfile", "readfile", "writefile", "stat", "lstat", "access") {
			hasFileOpen = true
		}
		if in(name, "tmpnam", "tempnam", "mktemp", "gettemppath") {
			hasTemp = true
		}
		if in(name, "getenv", "putenv", "setenv", "getenvironmentvariable") {
			hasEnv = true
		}
		if in(name, "crypt", "encrypt", "decrypt", "hash", "md5", "sha1", "aes", "rsa", "ssl", "tls") {
			hasCrypto = true
		}
		if in(name, "md5", "sha1", "des_", "rc4", "crypt32", "rand", "srand") {
			hasWeakCrypto = true
		}
		if in(name, "rand", "srand", "random", "rtlgenrandom", "bcryptgenrandom", "getrandom", "arc4random") {
			hasRandom = true
		}
		if in(name, "pthread_create", "createthread", "beginthread", "mutex", "criticalsection", "interlocked") {
			hasThreading = true
		}
	}
	add := func(id, sev, cat, title, evidence, impact, rec string, refs ...string) {
		out = append(out, api.VulnerabilityFinding{
			ID: id, Severity: sev, Category: cat, Title: title, Evidence: evidence,
			Impact: impact, Recommendation: rec, References: refs,
		})
	}
	for _, imp := range r.Imports {
		name := strings.ToLower(imp.Name)
		full := imp.DLL + "!" + imp.Name
		switch {
		case in(name, "strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf", "sscanf"):
			add("VULN-BOF-UNSAFE-C-API", "high", "buffer-overflow", "Unsafe C runtime API imported", full, "Potential stack buffer overflow, heap overflow, or format parsing issue if reachable with attacker-controlled input.", "Audit call sites, replace with bounded APIs, and verify length checks.")
		case in(name, "alloca", "__chkstk", "vla"):
			add("VULN-STACK-DYNAMIC-ALLOC", "medium", "stack-safety", "Dynamic stack allocation primitive imported", full, "Attacker-influenced stack allocation sizes can cause stack exhaustion or overwrite adjacent stack data.", "Trace size arguments and enforce strict upper bounds.")
		case in(name, "memcpy", "memmove", "strncpy", "snprintf"):
			add("VULN-OOB-COPY-REVIEW", "medium", "out-of-bounds", "Memory copy/format API requires bounds review", full, "The API can still produce out-of-bounds reads or writes if size arguments are attacker-controlled or miscomputed.", "Review decompiled call sites and trace size arguments.")
		case in(name, "memcmp", "strcmp", "strncmp", "strstr", "memchr"):
			add("VULN-OOB-READ-REVIEW", "info", "out-of-bounds-read", "Memory/string read primitive requires bounds review", full, "Search and compare APIs can read out of bounds if string termination or length metadata is attacker-controlled.", "Validate buffer lifetime, terminators, and explicit length arguments.")
		case in(name, "system", "popen", "execl", "execv", "posix_spawn", "shellexecute", "createprocess", "winexec"):
			add("VULN-COMMAND-EXEC", "high", "command-execution", "Command execution primitive imported", full, "May enable command injection or unintended process launch if arguments are attacker-controlled.", "Trace argument construction and validate quoting, allowlists, and input boundaries.")
		case in(name, "dlopen", "dlsym", "loadlibrary", "getprocaddress"):
			add("VULN-DYNAMIC-LOADING", "medium", "dynamic-loading", "Dynamic loading primitive imported", full, "Can hide behavior and may be vulnerable to DLL search-order or plugin-loading issues.", "Review loaded library names, search paths, and signature/pinning behavior.")
		case in(name, "mmap", "mprotect", "virtualprotect", "virtualalloc", "virtualfree"):
			add("VULN-MEMORY-PERMISSIONS", "medium", "memory-permissions", "Dynamic memory permission primitive imported", full, "Executable memory or runtime permission changes complicate exploitability and packed-code analysis.", "Inspect call sites for RWX transitions, shellcode loaders, or JIT-like behavior.")
		case in(name, "recv", "recvfrom", "recvmsg", "wsarecv", "internetreadfile", "readfile", "read", "fread"):
			add("VULN-INPUT-SOURCE", "info", "input-surface", "Potential external input source imported", full, "Data from files or networks may reach parsers or memory-copy routines.", "Trace data flow from this API to buffers, parsers, and copy operations.")
		case in(name, "free", "heapfree", "localfree", "delete", "virtualfree", "_zdlpv", "_zdapv"):
			add("VULN-UAF-REVIEW", "medium", "use-after-free", "Free/deallocation primitive imported", full, "Use-after-free is possible when aliases survive object release or cleanup paths are complex.", "Trace object ownership, aliasing, and post-free call paths.")
		case in(name, "realloc"):
			add("VULN-REALLOC-REVIEW", "medium", "use-after-free", "Reallocation primitive imported", full, "Incorrect realloc handling can leak, double-free, or leave stale pointers.", "Check failure handling and pointer replacement semantics.")
		case in(name, "open", "fopen", "createfile", "deletefile", "movefile", "copyfile", "getfileattributes", "stat", "lstat", "access"):
			add("VULN-TOCTOU-FILE", "info", "race-condition", "Filesystem primitive imported", full, "Check-then-use file logic can introduce time-of-check/time-of-use races.", "Trace file path validation and subsequent open/delete/move operations.")
		case in(name, "tmpnam", "tempnam", "mktemp"):
			add("VULN-INSECURE-TEMPFILE", "high", "race-condition", "Insecure temporary file API imported", full, "Predictable temporary paths can allow symlink races, overwrite, or privilege-boundary issues.", "Use mkstemp/CreateFile with exclusive creation and restrictive permissions.")
		case in(name, "chmod", "chown", "setuid", "setgid", "seteuid", "setegid", "impersonate", "adjusttokenprivileges"):
			add("VULN-PRIVILEGE-BOUNDARY", "medium", "privilege-boundary", "Privilege or permission primitive imported", full, "Privilege transitions and permission changes can create escalation paths if order or validation is wrong.", "Audit caller trust, path ownership, and privilege drop/restore sequences.")
		case in(name, "atoi", "atol", "strtol", "strtoul", "strtoull", "wcstol"):
			add("VULN-INTEGER-PARSE-REVIEW", "medium", "integer-overflow", "Integer parsing primitive imported", full, "Parsed numeric input can underflow, overflow, truncate, or become a dangerous allocation/copy size.", "Check errno/end-pointer handling, range checks, signedness, and casts before allocation or indexing.")
		case in(name, "operator new", "_znwm", "_znam"):
			add("VULN-CPP-ALLOC-REVIEW", "info", "c++-lifetime", "C++ allocation primitive imported", full, "C++ object ownership bugs can produce UAF, double delete, leaks, and invalid downcasts.", "Map constructors, destructors, copy/move paths, and virtual dispatch ownership.")
		case in(name, "dynamic_cast", "__dynamic_cast", "typeinfo", "__cxa_throw", "__cxa_begin_catch"):
			add("VULN-CPP-TYPE-EXCEPTION-SURFACE", "info", "c++-runtime", "C++ RTTI/exception surface imported", full, "Complex RTTI and exception paths can hide object lifetime and type confusion bugs.", "Review exception cleanup paths, downcasts, and destructor ordering.")
		case in(name, "md5", "sha1", "des_", "rc4", "crypt", "rand", "srand"):
			add("VULN-WEAK-CRYPTO-RANDOM", "medium", "crypto", "Weak cryptography or randomness primitive imported", full, "Weak hashes, ciphers, or PRNGs can undermine authentication, integrity, or session secrets.", "Prefer modern primitives and CSPRNG APIs; confirm whether usage is security-sensitive.")
		case in(name, "loadlibrary"):
			add("VULN-DLL-HIJACK-REVIEW", "medium", "binary-loading", "Library loading primitive imported", full, "Relative or attacker-controlled DLL paths can allow DLL search-order hijacking.", "Verify absolute paths, SetDefaultDllDirectories, and signature checks.")
		}
	}
	if hasInput && hasCopy {
		add("VULN-INPUT-TO-COPY-SURFACE", "medium", "dataflow-review", "External input and memory-copy surfaces both present", "imports contain input and copy primitives", "Potential BOF/OOB paths exist if input sizes reach copy lengths without validation.", "Prioritize data-flow tracing from input APIs to copy APIs.")
	}
	if hasAlloc && hasFree {
		add("VULN-UAF-ALLOC-FREE-SURFACE", "medium", "use-after-free", "Allocator and deallocator surface present", "imports contain allocation and free primitives", "Manual ownership review is needed for UAF, double-free, and lifetime bugs.", "Map allocation sites to free sites and search for post-free dereferences.")
	}
	if hasCopy && !hasBounds {
		add("VULN-MISSING-BOUNDS-SIGNALS", "medium", "out-of-bounds", "Copy surface without obvious bounds-helper imports", "copy APIs present without clear length-helper imports", "May indicate manual or missing bounds validation.", "Review copy lengths and parser-controlled sizes in reconstructed C.")
	}
	if hasIntegerParse && (hasAlloc || hasCopy) {
		add("VULN-INT-TO-MEMORY-SURFACE", "high", "integer-overflow", "Integer parsing reaches allocation/copy surface candidate", "integer parsing and allocation/copy imports coexist", "Unchecked integer conversion can become undersized allocations, OOB writes, or OOB reads.", "Trace parsed values into allocation sizes, indexes, loop bounds, and copy lengths.")
	}
	if hasInput && hasFileOpen {
		add("VULN-PATH-INPUT-SURFACE", "medium", "path-traversal", "Input and filesystem APIs coexist", "input and filesystem primitives both present", "User-controlled paths may reach file operations and produce traversal, overwrite, symlink, or TOCTOU issues.", "Trace path normalization, canonicalization, root enforcement, and race windows.")
	}
	if hasTemp && hasFileOpen {
		add("VULN-TEMPFILE-FILESYSTEM-SURFACE", "high", "race-condition", "Temporary path and filesystem surfaces coexist", "temporary-file and file-operation APIs both present", "Temporary path creation may be exploitable through symlink/hardlink races or predictable names.", "Use exclusive open patterns and avoid name-only temporary APIs.")
	}
	if hasEnv && (hasCommandSurface(r.Imports) || hasFileOpen || hasAlloc) {
		add("VULN-ENV-TRUST-SURFACE", "medium", "input-validation", "Environment-variable input surface", "environment APIs coexist with command/file/memory operations", "Environment variables can cross privilege boundaries and alter paths, sizes, commands, or library loading.", "Treat environment values as attacker-controlled unless process ancestry is trusted.")
	}
	if hasCrypto && hasWeakCrypto {
		add("VULN-CRYPTO-DOWNGRADE-SURFACE", "medium", "crypto", "Weak and general crypto surfaces coexist", "weak crypto identifiers and crypto APIs present", "Legacy primitives may be used in security-sensitive paths or compatibility downgrade logic.", "Identify call sites and replace weak algorithms for authentication, integrity, or confidentiality.")
	}
	if hasRandom && hasWeakCrypto {
		add("VULN-PREDICTABLE-RANDOMNESS", "medium", "crypto", "Potential predictable randomness", "randomness and weak crypto primitives present", "Non-cryptographic PRNGs can make tokens, keys, IVs, or nonces predictable.", "Use platform CSPRNG APIs and verify seeding is not time/PID based.")
	}
	if hasThreading && (hasFree || hasFileOpen) {
		add("VULN-CONCURRENCY-LIFETIME-RACE", "medium", "race-condition", "Threading with lifetime or filesystem surface", "threading APIs coexist with free/file primitives", "Concurrent access can create UAF, double-free, TOCTOU, or shared-state races.", "Audit locking discipline, ownership transfer, and file check/use windows.")
	}
	for _, s := range r.Sections {
		if strings.Contains(s.Permissions, "x") && strings.Contains(s.Permissions, "w") {
			add("VULN-RWX-SECTION", "high", "binary-hardening", "Writable and executable section", s.Name, "RWX memory weakens exploit mitigations and may indicate unpacking or self-modifying code.", "Manually inspect section bytes and runtime write targets.")
		}
		if s.Entropy >= 7.2 && strings.Contains(s.Permissions, "x") {
			add("VULN-PACKED-CODE", "medium", "analysis-risk", "High-entropy executable section", fmt.Sprintf("%s entropy %.2f", s.Name, s.Entropy), "Packed or encrypted code can hide vulnerable or malicious logic from static review.", "Use entropy timeline and section dump to guide unpacking before source-level conclusions.")
		}
	}
	if r.Metadata.FileType == "PE" {
		if !r.Security["aslr_dynamic_base"] {
			add("VULN-NO-ASLR", "medium", "binary-hardening", "ASLR dynamic base flag is disabled", "DLLCharacteristics lacks DYNAMIC_BASE", "Predictable image bases can improve exploit reliability.", "Enable /DYNAMICBASE for production builds where compatible.")
		}
		if !r.Security["dep_nx_compat"] {
			add("VULN-NO-DEP", "high", "binary-hardening", "DEP/NX compatibility flag is disabled", "DLLCharacteristics lacks NX_COMPAT", "Executable stack/heap conditions may be easier to exploit.", "Enable /NXCOMPAT and audit any code requiring executable data pages.")
		}
		if !r.Security["control_flow_guard"] {
			add("VULN-NO-CFG", "medium", "binary-hardening", "Control Flow Guard flag is disabled", "DLLCharacteristics lacks GUARD_CF", "Indirect-call hijacking may be easier if memory corruption exists.", "Enable /guard:cf and review unsupported modules.")
		}
		if len(r.Relocations) == 0 && !r.Security["aslr_dynamic_base"] {
			add("VULN-FIXED-IMAGEBASE", "medium", "binary-hardening", "No relocations with ASLR disabled", "relocation table absent and DYNAMIC_BASE disabled", "A fixed image base can make ROP and memory-corruption exploitation more reliable.", "Enable relocations and ASLR for hardened production binaries.")
		}
	}
	if len(r.TLSCallbacks) > 0 {
		add("VULN-TLS-PREENTRY", "medium", "analysis-risk", "TLS callbacks execute before entry point", strings.Join(r.TLSCallbacks, ", "), "Important logic may run before the nominal entry point and evade simple audits.", "Prioritize TLS callback disassembly and pseudocode review.")
	}
	if r.Overlay.Present {
		add("VULN-OVERLAY-DATA", "medium", "analysis-risk", "Overlay data is present", fmt.Sprintf("offset=0x%x size=%d entropy=%.2f", r.Overlay.Offset, r.Overlay.Size, r.Overlay.Entropy), "Appended payloads or configuration may affect behavior and vulnerability exposure.", "Carve and classify overlay data separately.")
	}
	for _, a := range r.EmbeddedArtifacts {
		switch a.Type {
		case "pe", "elf":
			add("VULN-EMBEDDED-EXECUTABLE", "medium", "embedded-content", "Embedded executable artifact found", fmt.Sprintf("0x%x %s", a.Offset, a.Description), "Nested executables may contain secondary code, installers, plugins, or payloads outside the main control flow.", "Extract and analyze the embedded artifact independently.")
		case "zip", "7z", "rar", "cab":
			add("VULN-EMBEDDED-ARCHIVE", "info", "embedded-content", "Embedded archive artifact found", fmt.Sprintf("0x%x %s", a.Offset, a.Description), "Archives may contain additional attack surface, configuration, or staged content.", "Carve and inspect archive contents.")
		}
	}
	for _, h := range r.Strings {
		lower := strings.ToLower(h.Value)
		if hasPrintfFamily && credibleFormatString(h.Value) {
			add("VULN-FORMAT-STRING-EVIDENCE", "medium", "input-validation", "Format-string-like literal found", fmt.Sprintf("0x%x %q", h.Offset, trim(h.Value, 120)), "Format strings are vulnerable if attacker-controlled data is passed as the format argument.", "Find references to this string and audit printf-family call sites.")
		}
		if strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "apikey") {
			add("VULN-SECRET-LIKE-STRING", "medium", "secrets", "Secret-like string found", fmt.Sprintf("0x%x %q", h.Offset, trim(h.Value, 120)), "Hard-coded credentials or keys can expose systems if valid.", "Verify whether this is a real secret, test data, or benign UI text.")
		}
		if strings.Contains(lower, "deserialize") || strings.Contains(lower, "pickle") || strings.Contains(lower, "yaml.load") || strings.Contains(lower, "objectinputstream") {
			add("VULN-DESERIALIZATION-EVIDENCE", "medium", "deserialization", "Deserialization-related string found", fmt.Sprintf("0x%x %q", h.Offset, trim(h.Value, 120)), "Unsafe deserialization can lead to object injection or code execution depending on parser and trust boundary.", "Identify parser/library use and validate type allowlists.")
		}
		if strings.Contains(lower, "../") || strings.Contains(lower, "..\\") {
			add("VULN-PATH-TRAVERSAL-EVIDENCE", "medium", "path-traversal", "Traversal-like string found", fmt.Sprintf("0x%x %q", h.Offset, trim(h.Value, 120)), "Path traversal may be possible if user-controlled paths are normalized incorrectly.", "Trace path construction and canonicalization.")
		}
		if strings.Contains(lower, "%n") && hasPrintfFamily {
			add("VULN-FORMAT-N-WRITE-EVIDENCE", "high", "format-string", "Format string contains %n write primitive", fmt.Sprintf("0x%x %q", h.Offset, trim(h.Value, 120)), "%n writes through a pointer and is dangerous if format strings are attacker-influenced.", "Find references and confirm the format argument is constant and trusted.")
		}
		if in(lower, "select * from", "insert into", "update ", "delete from", " where ", "' or '1'='1") {
			add("VULN-SQL-LIKE-STRING", "medium", "injection", "SQL-like query string found", fmt.Sprintf("0x%x %q", h.Offset, trim(h.Value, 120)), "String-built SQL can become injection-prone if attacker input is concatenated.", "Trace query construction and verify prepared statements or strict binding.")
		}
		if in(lower, "<!doctype", "<!entity", "external entity", "xml_parse", "xmlread") {
			add("VULN-XXE-PARSER-EVIDENCE", "medium", "xxe", "XML parser/entity evidence found", fmt.Sprintf("0x%x %q", h.Offset, trim(h.Value, 120)), "XML external entity processing can expose local files or SSRF if not disabled.", "Verify parser flags disable DTDs and external entities.")
		}
		if in(lower, "http://", "ssl_verify_none", "verify=false", "insecure_skip_verify", "certificate verify failed") {
			add("VULN-TLS-VALIDATION-EVIDENCE", "medium", "transport-security", "Transport security validation string found", fmt.Sprintf("0x%x %q", h.Offset, trim(h.Value, 120)), "Cleartext URLs or disabled certificate validation can expose credentials or update channels.", "Confirm TLS verification, pinning expectations, and downgrade handling.")
		}
		if in(lower, ".zip", ".tar", ".gz", "extract", "unzip") && in(lower, "../", "..\\", "absolute path") {
			add("VULN-ARCHIVE-TRAVERSAL-EVIDENCE", "medium", "archive-slip", "Archive extraction traversal evidence", fmt.Sprintf("0x%x %q", h.Offset, trim(h.Value, 120)), "Archive extraction may allow path traversal if entries are not canonicalized.", "Audit extraction path joins and reject absolute or parent-directory entries.")
		}
		if in(lower, "double free", "use after free", "heap corruption", "stack smashing", "buffer overflow") {
			add("VULN-DIAGNOSTIC-STRING-EVIDENCE", "info", "diagnostic", "Memory-safety diagnostic string found", fmt.Sprintf("0x%x %q", h.Offset, trim(h.Value, 120)), "Diagnostic text can reveal defensive checks, sanitizer/runtime paths, or known memory safety concerns.", "Find xrefs to determine whether this is runtime hardening, logging, or reachable error handling.")
		}
	}
	for _, fn := range r.FunctionInsights {
		if fn.EstimatedStack > 0x1000 {
			add("VULN-STACK-EXHAUSTION-REVIEW", "medium", "stack-safety", "Large stack frame candidate", fmt.Sprintf("%s stack=0x%x", fn.Name, fn.EstimatedStack), "Large stack allocations can contribute to stack exhaustion or overflow-prone local buffers.", "Review local buffer sizes and all writes into stack storage.")
		}
		if fn.Complexity > 80 {
			add("VULN-COMPLEX-FUNCTION-REVIEW", "info", "audit-priority", "High complexity function", fmt.Sprintf("%s complexity=%d", fn.Name, fn.Complexity), "Highly branched functions are common sources of parser and state-machine bugs.", "Prioritize manual audit and targeted fuzzing.")
		}
	}
	return dedupe(out)
}

func credibleFormatString(s string) bool {
	if len(s) < 8 || len(s) > 240 {
		return false
	}
	if !(strings.Contains(s, "%s") || strings.Contains(s, "%n") || strings.Contains(s, "%x") || strings.Contains(s, "%d")) {
		return false
	}
	letters := 0
	spaces := 0
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			letters++
		}
		if r == ' ' || r == '\t' {
			spaces++
		}
	}
	return letters >= 5 && spaces > 0
}

func Summary(vs []api.VulnerabilityFinding) map[string]int {
	out := map[string]int{"critical": 0, "high": 0, "medium": 0, "info": 0}
	for _, v := range vs {
		out[v.Severity]++
	}
	return out
}

func in(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func hasCommandSurface(imports []api.ImportFunction) bool {
	for _, imp := range imports {
		name := strings.ToLower(imp.Name)
		if in(name, "system", "popen", "execl", "execv", "posix_spawn", "shellexecute", "createprocess", "winexec") {
			return true
		}
	}
	return false
}

func dedupe(in []api.VulnerabilityFinding) []api.VulnerabilityFinding {
	seen := map[string]bool{}
	out := []api.VulnerabilityFinding{}
	for _, v := range in {
		key := v.ID + "\x00" + v.Evidence
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, v)
	}
	return out
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
