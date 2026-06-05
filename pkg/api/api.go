package api

type Options struct {
	OutputDir   string
	JSON        bool
	MinString   int
	NoDisasm    bool
	Full        bool
	Format      string
	Quiet       bool
	Verbose     bool
	NoVisuals   bool
	WindowSize  int
	WindowStep  int
	DisasmBytes int
	CaseID      string
	Serve       bool
	ServeAddr   string
}

type Finding struct {
	Severity string `json:"severity"`
	Category string `json:"category"`
	Message  string `json:"message"`
}

type VulnerabilityFinding struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Title          string   `json:"title"`
	Evidence       string   `json:"evidence"`
	Impact         string   `json:"impact"`
	Recommendation string   `json:"recommendation"`
	References     []string `json:"references,omitempty"`
}

type OverlayInfo struct {
	Present bool    `json:"present"`
	Offset  int     `json:"offset,omitempty"`
	Size    int     `json:"size,omitempty"`
	Entropy float64 `json:"entropy,omitempty"`
}

type FileMetadata struct {
	Filename    string `json:"filename"`
	Size        int64  `json:"size"`
	MD5         string `json:"md5"`
	SHA1        string `json:"sha1"`
	SHA256      string `json:"sha256"`
	SHA512      string `json:"sha512"`
	FileType    string `json:"file_type"`
	Arch        string `json:"architecture"`
	Endianness  string `json:"endianness"`
	Subsystem   string `json:"subsystem,omitempty"`
	EntryPoint  string `json:"entry_point,omitempty"`
	CompileTime string `json:"compile_timestamp,omitempty"`
}

type LookupLinks struct {
	VirusTotal    string `json:"virustotal,omitempty"`
	MalwareBazaar string `json:"malwarebazaar,omitempty"`
}

type FileIntelligence struct {
	Format          string      `json:"format"`
	MIMEType        string      `json:"mime_type"`
	ScanTime        string      `json:"scan_time"`
	OperatingSystem string      `json:"operating_system"`
	Packer          string      `json:"packer,omitempty"`
	Compiler        string      `json:"compiler,omitempty"`
	Language        string      `json:"language,omitempty"`
	Libraries       []string    `json:"libraries,omitempty"`
	Protections     []string    `json:"protections,omitempty"`
	Matches         []string    `json:"matches,omitempty"`
	LookupLinks     LookupLinks `json:"lookup_links"`
}

type BinaryDetails struct {
	FileType      string `json:"file_type"`
	Architecture  string `json:"architecture"`
	Mode          string `json:"mode"`
	Endian        string `json:"endian"`
	ModuleAddress string `json:"module_address,omitempty"`
	ImageSize     uint32 `json:"image_size,omitempty"`
	EntryPoint    string `json:"entry_point,omitempty"`
}

type StringHit struct {
	Value    string   `json:"value"`
	Offset   int      `json:"offset"`
	Encoding string   `json:"encoding"`
	Tags     []string `json:"tags,omitempty"`
}

type Section struct {
	Name            string   `json:"name"`
	VirtualAddress  uint32   `json:"virtual_address"`
	VirtualSize     uint32   `json:"virtual_size"`
	RawOffset       uint32   `json:"raw_offset"`
	RawSize         uint32   `json:"raw_size"`
	Permissions     string   `json:"permissions"`
	Flags           string   `json:"flags,omitempty"`
	Characteristics uint32   `json:"characteristics,omitempty"`
	Entropy         float64  `json:"entropy"`
	Suspicious      []string `json:"suspicious,omitempty"`
}

type ImportFunction struct {
	DLL      string   `json:"dll"`
	Name     string   `json:"name,omitempty"`
	Ordinal  uint16   `json:"ordinal,omitempty"`
	Address  string   `json:"address,omitempty"`
	Category []string `json:"category,omitempty"`
}

type ExportFunction struct {
	Name    string `json:"name,omitempty"`
	Ordinal uint16 `json:"ordinal"`
	RVA     string `json:"rva"`
}

type Instruction struct {
	Address  string `json:"address"`
	Bytes    string `json:"bytes"`
	Mnemonic string `json:"mnemonic"`
	Operand  string `json:"operand,omitempty"`
	Target   string `json:"target,omitempty"`
	Kind     string `json:"kind,omitempty"`
}

type Function struct {
	Name   string   `json:"name"`
	Start  string   `json:"start"`
	End    string   `json:"end"`
	Size   uint64   `json:"size"`
	Calls  []string `json:"calls,omitempty"`
	Blocks int      `json:"blocks"`
}

type FunctionInsight struct {
	Name             string   `json:"name"`
	Start            string   `json:"start"`
	InstructionCount int      `json:"instruction_count"`
	CallCount        int      `json:"call_count"`
	BranchCount      int      `json:"branch_count"`
	ReturnCount      int      `json:"return_count"`
	EstimatedStack   int      `json:"estimated_stack,omitempty"`
	Complexity       int      `json:"complexity"`
	RiskNotes        []string `json:"risk_notes,omitempty"`
}

type InferredVariable struct {
	Function string `json:"function"`
	Name     string `json:"name"`
	Storage  string `json:"storage"`
	Type     string `json:"type"`
	Evidence string `json:"evidence"`
}

type InferredType struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence"`
}

type StructCandidate struct {
	Name       string   `json:"name"`
	Size       int      `json:"size,omitempty"`
	Fields     []string `json:"fields"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence"`
}

type Xref struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Kind     string `json:"kind"`
	Evidence string `json:"evidence"`
}

type EmbeddedArtifact struct {
	Offset      int    `json:"offset"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

type MemoryRegion struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	FileOffset  int      `json:"file_offset"`
	FileSize    int      `json:"file_size"`
	VirtualAddr string   `json:"virtual_address,omitempty"`
	VirtualSize uint32   `json:"virtual_size,omitempty"`
	Permissions string   `json:"permissions,omitempty"`
	Entropy     float64  `json:"entropy,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

type BytePattern struct {
	Pattern string  `json:"pattern"`
	Size    int     `json:"size"`
	Count   int     `json:"count"`
	Ratio   float64 `json:"ratio"`
}

type InstructionStats struct {
	Total           int            `json:"total"`
	UniqueMnemonics int            `json:"unique_mnemonics"`
	Mnemonics       map[string]int `json:"mnemonics"`
	Categories      map[string]int `json:"categories"`
	Registers       map[string]int `json:"registers,omitempty"`
	Interesting     []string       `json:"interesting,omitempty"`
}

type ControlFlowMetrics struct {
	Functions             int     `json:"functions"`
	BasicBlocks           int     `json:"basic_blocks"`
	Edges                 int     `json:"edges"`
	Calls                 int     `json:"calls"`
	Branches              int     `json:"branches"`
	Returns               int     `json:"returns"`
	MaxFunctionComplexity int     `json:"max_function_complexity"`
	AvgFunctionComplexity float64 `json:"avg_function_complexity"`
}

type APISurfaceEntry struct {
	Category  string   `json:"category"`
	Count     int      `json:"count"`
	DLLs      []string `json:"dlls"`
	Functions []string `json:"functions"`
	Risk      string   `json:"risk"`
}

type IOCSummary struct {
	URLs        []string `json:"urls,omitempty"`
	Domains     []string `json:"domains,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	Registry    []string `json:"registry,omitempty"`
	Paths       []string `json:"paths,omitempty"`
	Secrets     []string `json:"secrets,omitempty"`
	UserAgents  []string `json:"user_agents,omitempty"`
	Commands    []string `json:"commands,omitempty"`
	TotalTagged int      `json:"total_tagged"`
}

type TriageTask struct {
	Priority  string   `json:"priority"`
	Title     string   `json:"title"`
	Why       string   `json:"why"`
	Actions   []string `json:"actions"`
	Artifacts []string `json:"artifacts,omitempty"`
}

type DetectionRule struct {
	Name       string   `json:"name"`
	Severity   string   `json:"severity"`
	Matched    bool     `json:"matched"`
	Evidence   []string `json:"evidence,omitempty"`
	Confidence string   `json:"confidence"`
}

type FunctionFingerprint struct {
	Function        string   `json:"function"`
	Start           string   `json:"start"`
	End             string   `json:"end"`
	InstructionHash string   `json:"instruction_hash"`
	MnemonicHash    string   `json:"mnemonic_hash"`
	SimHash         string   `json:"simhash"`
	Size            uint64   `json:"size"`
	Instructions    int      `json:"instructions"`
	Calls           []string `json:"calls,omitempty"`
	Mnemonics       []string `json:"mnemonics,omitempty"`
}

type SignatureMatch struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Confidence string   `json:"confidence"`
	Severity   string   `json:"severity,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

type FunctionTag struct {
	Function   string   `json:"function"`
	Start      string   `json:"start,omitempty"`
	Tag        string   `json:"tag"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

type REAnnotation struct {
	Address  string   `json:"address,omitempty"`
	Function string   `json:"function,omitempty"`
	Kind     string   `json:"kind"`
	Text     string   `json:"text"`
	Severity string   `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

type JumpTableCandidate struct {
	Function   string   `json:"function"`
	Address    string   `json:"address"`
	Base       string   `json:"base,omitempty"`
	Entries    int      `json:"entries,omitempty"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

type APICallSite struct {
	Function   string   `json:"function"`
	Address    string   `json:"address"`
	API        string   `json:"api"`
	Category   []string `json:"category,omitempty"`
	Arguments  []string `json:"arguments,omitempty"`
	Confidence string   `json:"confidence"`
	Evidence   string   `json:"evidence,omitempty"`
}

type StringReference struct {
	Function   string   `json:"function,omitempty"`
	Address    string   `json:"address,omitempty"`
	String     string   `json:"string"`
	Offset     int      `json:"offset"`
	Kind       string   `json:"kind"`
	Tags       []string `json:"tags,omitempty"`
	Confidence string   `json:"confidence"`
	Evidence   string   `json:"evidence,omitempty"`
}

type StackFrameLayout struct {
	Function       string             `json:"function"`
	FrameSize      int                `json:"frame_size,omitempty"`
	Locals         []InferredVariable `json:"locals,omitempty"`
	Arguments      []InferredVariable `json:"arguments,omitempty"`
	SavedRegisters []string           `json:"saved_registers,omitempty"`
	Evidence       []string           `json:"evidence,omitempty"`
}

type BasicBlockNote struct {
	BlockID  string   `json:"block_id"`
	Start    string   `json:"start"`
	End      string   `json:"end"`
	Kind     string   `json:"kind"`
	Text     string   `json:"text"`
	Severity string   `json:"severity,omitempty"`
	Edges    []string `json:"edges,omitempty"`
}

type DecompilerHint struct {
	Function   string `json:"function"`
	Address    string `json:"address"`
	Kind       string `json:"kind"`
	Hint       string `json:"hint"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence,omitempty"`
}

type FunctionCluster struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Functions  []string `json:"functions"`
	Score      float64  `json:"score,omitempty"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

type HotPath struct {
	Rank      int      `json:"rank"`
	Function  string   `json:"function"`
	Start     string   `json:"start"`
	Score     int      `json:"score"`
	Reasons   []string `json:"reasons,omitempty"`
	Artifacts []string `json:"artifacts,omitempty"`
}

type PatchPoint struct {
	Address    string   `json:"address"`
	Function   string   `json:"function,omitempty"`
	Kind       string   `json:"kind"`
	Bytes      string   `json:"bytes,omitempty"`
	Size       int      `json:"size,omitempty"`
	Risk       string   `json:"risk,omitempty"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

type CallingConventionGuess struct {
	Function        string   `json:"function"`
	Start           string   `json:"start"`
	Convention      string   `json:"convention"`
	ArgumentStorage []string `json:"argument_storage,omitempty"`
	ReturnStorage   string   `json:"return_storage,omitempty"`
	Confidence      string   `json:"confidence"`
	Evidence        []string `json:"evidence,omitempty"`
}

type UnpackingHint struct {
	Region     string   `json:"region"`
	Address    string   `json:"address,omitempty"`
	Kind       string   `json:"kind"`
	Priority   string   `json:"priority"`
	Actions    []string `json:"actions,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	Confidence string   `json:"confidence"`
}

type TypePropagationHint struct {
	Function   string   `json:"function,omitempty"`
	Address    string   `json:"address,omitempty"`
	Symbol     string   `json:"symbol"`
	Type       string   `json:"type"`
	Source     string   `json:"source"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

type AnalysisTimelineEvent struct {
	Order     int      `json:"order"`
	Phase     string   `json:"phase"`
	Title     string   `json:"title"`
	Detail    string   `json:"detail,omitempty"`
	Artifacts []string `json:"artifacts,omitempty"`
	Severity  string   `json:"severity,omitempty"`
}

type CapabilityMatrixEntry struct {
	Capability string   `json:"capability"`
	Score      int      `json:"score"`
	Signals    []string `json:"signals,omitempty"`
	Artifacts  []string `json:"artifacts,omitempty"`
}

type IndicatorHit struct {
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	Location   string   `json:"location,omitempty"`
	Function   string   `json:"function,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

type SearchEntry struct {
	Kind     string   `json:"kind"`
	Name     string   `json:"name"`
	Value    string   `json:"value"`
	Location string   `json:"location,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

type HexBookmark struct {
	Name        string   `json:"name"`
	Offset      int      `json:"offset"`
	Size        int      `json:"size,omitempty"`
	Kind        string   `json:"kind"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type HexSearchHit struct {
	Query   string `json:"query"`
	Kind    string `json:"kind"`
	Offset  int    `json:"offset"`
	Size    int    `json:"size"`
	Preview string `json:"preview,omitempty"`
}

type AddressMapping struct {
	Name           string `json:"name"`
	FileOffset     int    `json:"file_offset"`
	VirtualAddress string `json:"virtual_address,omitempty"`
	Size           int    `json:"size"`
}

type HexAnalysis struct {
	Bookmarks       []HexBookmark    `json:"bookmarks,omitempty"`
	SearchHits      []HexSearchHit   `json:"search_hits,omitempty"`
	AddressMappings []AddressMapping `json:"address_mappings,omitempty"`
}

type RegisterAccess struct {
	Function    string `json:"function"`
	Address     string `json:"address"`
	Register    string `json:"register"`
	Access      string `json:"access"`
	Instruction string `json:"instruction"`
}

type DefUseChain struct {
	Function string   `json:"function"`
	Register string   `json:"register"`
	Def      string   `json:"def"`
	Uses     []string `json:"uses"`
}

type TaintTrace struct {
	Source   string   `json:"source"`
	Sink     string   `json:"sink"`
	Path     []string `json:"path"`
	Reason   string   `json:"reason"`
	Severity string   `json:"severity"`
}

type DataFlowAnalysis struct {
	RegisterAccesses []RegisterAccess `json:"register_accesses,omitempty"`
	DefUseChains     []DefUseChain    `json:"def_use_chains,omitempty"`
	TaintTraces      []TaintTrace     `json:"taint_traces,omitempty"`
}

type GraphAnalysis struct {
	Callers        map[string][]string `json:"callers,omitempty"`
	Callees        map[string][]string `json:"callees,omitempty"`
	Recursive      []string            `json:"recursive,omitempty"`
	Reachable      []string            `json:"reachable,omitempty"`
	DominatorHints map[string][]string `json:"dominator_hints,omitempty"`
	Loops          []string            `json:"loops,omitempty"`
}

type ProjectDatabase struct {
	SchemaVersion      int                      `json:"schema_version"`
	CaseID             string                   `json:"case_id,omitempty"`
	Sample             FileMetadata             `json:"sample"`
	Functions          []Function               `json:"functions,omitempty"`
	Symbols            []SearchEntry            `json:"symbols,omitempty"`
	Types              []InferredType           `json:"types,omitempty"`
	Structs            []StructCandidate        `json:"structs,omitempty"`
	Labels             []SearchEntry            `json:"labels,omitempty"`
	Comments           []SearchEntry            `json:"comments,omitempty"`
	Xrefs              []Xref                   `json:"xrefs,omitempty"`
	Graph              GraphAnalysis            `json:"graph"`
	Fingerprints       []FunctionFingerprint    `json:"fingerprints,omitempty"`
	Signatures         []SignatureMatch         `json:"signatures,omitempty"`
	FunctionTags       []FunctionTag            `json:"function_tags,omitempty"`
	Annotations        []REAnnotation           `json:"annotations,omitempty"`
	JumpTables         []JumpTableCandidate     `json:"jump_tables,omitempty"`
	APICallSites       []APICallSite            `json:"api_call_sites,omitempty"`
	StringRefs         []StringReference        `json:"string_references,omitempty"`
	StackFrames        []StackFrameLayout       `json:"stack_frames,omitempty"`
	BlockNotes         []BasicBlockNote         `json:"basic_block_notes,omitempty"`
	DecompilerHints    []DecompilerHint         `json:"decompiler_hints,omitempty"`
	FunctionClusters   []FunctionCluster        `json:"function_clusters,omitempty"`
	HotPaths           []HotPath                `json:"hot_paths,omitempty"`
	PatchPoints        []PatchPoint             `json:"patch_points,omitempty"`
	CallingConventions []CallingConventionGuess `json:"calling_conventions,omitempty"`
	UnpackingHints     []UnpackingHint          `json:"unpacking_hints,omitempty"`
	TypeHints          []TypePropagationHint    `json:"type_hints,omitempty"`
	Timeline           []AnalysisTimelineEvent  `json:"timeline,omitempty"`
	CapabilityMatrix   []CapabilityMatrixEntry  `json:"capability_matrix,omitempty"`
	AntiAnalysis       []IndicatorHit           `json:"anti_analysis,omitempty"`
	CryptoIndicators   []IndicatorHit           `json:"crypto_indicators,omitempty"`
	Persistence        []IndicatorHit           `json:"persistence_indicators,omitempty"`
	SyscallIndicators  []IndicatorHit           `json:"syscall_indicators,omitempty"`
}

type DeepAnalysis struct {
	MemoryMap          []MemoryRegion           `json:"memory_map,omitempty"`
	BytePatterns       []BytePattern            `json:"byte_patterns,omitempty"`
	InstructionStats   InstructionStats         `json:"instruction_stats"`
	ControlFlowMetrics ControlFlowMetrics       `json:"control_flow_metrics"`
	APISurface         []APISurfaceEntry        `json:"api_surface,omitempty"`
	IOCs               IOCSummary               `json:"iocs"`
	TriageTasks        []TriageTask             `json:"triage_tasks,omitempty"`
	DetectionRules     []DetectionRule          `json:"detection_rules,omitempty"`
	SearchIndex        []SearchEntry            `json:"search_index,omitempty"`
	Hex                HexAnalysis              `json:"hex"`
	DataFlow           DataFlowAnalysis         `json:"data_flow"`
	Graph              GraphAnalysis            `json:"graph"`
	Fingerprints       []FunctionFingerprint    `json:"fingerprints,omitempty"`
	Signatures         []SignatureMatch         `json:"signatures,omitempty"`
	FunctionTags       []FunctionTag            `json:"function_tags,omitempty"`
	Annotations        []REAnnotation           `json:"annotations,omitempty"`
	JumpTables         []JumpTableCandidate     `json:"jump_tables,omitempty"`
	APICallSites       []APICallSite            `json:"api_call_sites,omitempty"`
	StringRefs         []StringReference        `json:"string_references,omitempty"`
	StackFrames        []StackFrameLayout       `json:"stack_frames,omitempty"`
	BlockNotes         []BasicBlockNote         `json:"basic_block_notes,omitempty"`
	DecompilerHints    []DecompilerHint         `json:"decompiler_hints,omitempty"`
	FunctionClusters   []FunctionCluster        `json:"function_clusters,omitempty"`
	HotPaths           []HotPath                `json:"hot_paths,omitempty"`
	PatchPoints        []PatchPoint             `json:"patch_points,omitempty"`
	CallingConventions []CallingConventionGuess `json:"calling_conventions,omitempty"`
	UnpackingHints     []UnpackingHint          `json:"unpacking_hints,omitempty"`
	TypeHints          []TypePropagationHint    `json:"type_hints,omitempty"`
	Timeline           []AnalysisTimelineEvent  `json:"timeline,omitempty"`
	CapabilityMatrix   []CapabilityMatrixEntry  `json:"capability_matrix,omitempty"`
	AntiAnalysis       []IndicatorHit           `json:"anti_analysis,omitempty"`
	CryptoIndicators   []IndicatorHit           `json:"crypto_indicators,omitempty"`
	Persistence        []IndicatorHit           `json:"persistence_indicators,omitempty"`
	SyscallIndicators  []IndicatorHit           `json:"syscall_indicators,omitempty"`
	Project            ProjectDatabase          `json:"project"`
}

type BasicBlock struct {
	ID    string   `json:"id"`
	Start string   `json:"start"`
	End   string   `json:"end"`
	Edges []string `json:"edges,omitempty"`
}

type RelocationBlock struct {
	PageRVA string `json:"page_rva"`
	Count   int    `json:"count"`
}

type DebugEntry struct {
	Type              uint32 `json:"type"`
	TypeName          string `json:"type_name"`
	Size              uint32 `json:"size"`
	RVA               string `json:"rva"`
	FileOffset        string `json:"file_offset"`
	TimeDateStamp     uint32 `json:"time_date_stamp"`
	MajorVersion      uint16 `json:"major_version"`
	MinorVersion      uint16 `json:"minor_version"`
	CodeViewSignature string `json:"codeview_signature,omitempty"`
	PDBPath           string `json:"pdb_path,omitempty"`
}

type CertificateInfo struct {
	Present         bool   `json:"present"`
	FileOffset      uint32 `json:"file_offset,omitempty"`
	Size            uint32 `json:"size,omitempty"`
	Revision        uint16 `json:"revision,omitempty"`
	CertificateType uint16 `json:"certificate_type,omitempty"`
}

type ResourceInfo struct {
	Present bool   `json:"present"`
	RVA     string `json:"rva,omitempty"`
	Size    uint32 `json:"size,omitempty"`
}

type LoadConfigInfo struct {
	Present    bool   `json:"present"`
	RVA        string `json:"rva,omitempty"`
	Size       uint32 `json:"size,omitempty"`
	GuardFlags string `json:"guard_flags,omitempty"`
}

type AnalysisReport struct {
	Metadata             FileMetadata           `json:"metadata"`
	FileInfo             FileIntelligence       `json:"file_info"`
	Binary               BinaryDetails          `json:"binary"`
	Headers              any                    `json:"headers,omitempty"`
	Sections             []Section              `json:"sections,omitempty"`
	Imports              []ImportFunction       `json:"imports,omitempty"`
	Exports              []ExportFunction       `json:"exports,omitempty"`
	Strings              []StringHit            `json:"strings,omitempty"`
	Entropy              map[string]any         `json:"entropy,omitempty"`
	Instructions         []Instruction          `json:"instructions,omitempty"`
	Functions            []Function             `json:"functions,omitempty"`
	FunctionInsights     []FunctionInsight      `json:"function_insights,omitempty"`
	InferredVariables    []InferredVariable     `json:"inferred_variables,omitempty"`
	InferredTypes        []InferredType         `json:"inferred_types,omitempty"`
	StructCandidates     []StructCandidate      `json:"struct_candidates,omitempty"`
	Xrefs                []Xref                 `json:"xrefs,omitempty"`
	EmbeddedArtifacts    []EmbeddedArtifact     `json:"embedded_artifacts,omitempty"`
	Blocks               []BasicBlock           `json:"basic_blocks,omitempty"`
	Findings             []Finding              `json:"findings,omitempty"`
	RiskScore            int                    `json:"risk_score"`
	RiskLevel            string                 `json:"risk_level"`
	ByteHistogram        []int                  `json:"byte_histogram,omitempty"`
	Security             map[string]bool        `json:"security,omitempty"`
	Overlay              OverlayInfo            `json:"overlay"`
	Relocations          []RelocationBlock      `json:"relocations,omitempty"`
	TLSCallbacks         []string               `json:"tls_callbacks,omitempty"`
	DebugEntries         []DebugEntry           `json:"debug_entries,omitempty"`
	Certificate          CertificateInfo        `json:"certificate"`
	Resources            ResourceInfo           `json:"resources"`
	LoadConfig           LoadConfigInfo         `json:"load_config"`
	FindingSummary       map[string]int         `json:"finding_summary,omitempty"`
	ImportSummary        map[string]int         `json:"import_summary,omitempty"`
	StringSummary        map[string]int         `json:"string_summary,omitempty"`
	Capabilities         []string               `json:"capabilities,omitempty"`
	DeepAnalysis         DeepAnalysis           `json:"deep_analysis"`
	CaseID               string                 `json:"case_id,omitempty"`
	Vulnerabilities      []VulnerabilityFinding `json:"vulnerabilities,omitempty"`
	VulnerabilitySummary map[string]int         `json:"vulnerability_summary,omitempty"`
}
