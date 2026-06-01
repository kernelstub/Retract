import {
  Activity,
  BookOpen,
  Braces,
  Bug,
  ChevronRight,
  Code2,
  Command,
  Cpu,
  Database,
  FileCode2,
  FileText,
  GitBranch,
  Hexagon,
  ListTree,
  Moon,
  PanelBottom,
  PanelLeft,
  PanelRight,
  Radar,
  Search,
  Settings,
  Sigma,
  Sun,
  Terminal,
  Waypoints,
  X
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { CSSProperties, ReactNode } from "react";
import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./components/ui/card";
import { Input } from "./components/ui/input";
import { Table, Td, Th } from "./components/ui/table";
import { cn, formatBytes, hex, limit } from "./lib/utils";

type Report = {
  metadata: Record<string, any>;
  file_info?: Record<string, any>;
  binary?: Record<string, any>;
  sections?: any[];
  imports?: any[];
  exports?: any[];
  strings?: any[];
  findings?: any[];
  capabilities?: string[];
  vulnerabilities?: any[];
  functions?: any[];
  function_insights?: any[];
  inferred_variables?: any[];
  inferred_types?: any[];
  struct_candidates?: any[];
  xrefs?: any[];
  embedded_artifacts?: any[];
  byte_histogram?: Record<string, number> | number[];
  deep_analysis?: any;
  string_summary?: Record<string, number>;
  risk_score?: number;
  risk_level?: string;
};

type ViewID =
  | "overview"
  | "disassembly"
  | "decompiler"
  | "graph"
  | "hex"
  | "pe"
  | "strings"
  | "imports"
  | "exports"
  | "resources"
  | "functions"
  | "types"
  | "xrefs"
  | "signatures"
  | "project"
  | "vulns"
  | "deep"
  | "reports";

type Workspace = {
  active: ViewID;
  tabs: ViewID[];
  navOpen: boolean;
  inspectorOpen: boolean;
  bottomOpen: boolean;
  inspectorWidth: number;
  bottomHeight: number;
  theme: "dark" | "light";
};

const defaultWorkspace: Workspace = {
  active: "overview",
  tabs: ["overview", "disassembly", "decompiler", "hex", "signatures"],
  navOpen: true,
  inspectorOpen: true,
  bottomOpen: true,
  inspectorWidth: 340,
  bottomHeight: 230,
  theme: "dark"
};

const views: Record<ViewID, { title: string; icon: any; group: string; description: string }> = {
  overview: { title: "Overview", icon: Radar, group: "Workspace", description: "Risk, surface area, and triage posture" },
  disassembly: { title: "Disassembly", icon: Code2, group: "Code", description: "Assembly listing with instruction context" },
  decompiler: { title: "Decompiler", icon: FileCode2, group: "Code", description: "Recovered C-like pseudocode" },
  graph: { title: "Graphs", icon: GitBranch, group: "Code", description: "CFG, call graph, loops, and reachability" },
  functions: { title: "Functions", icon: Cpu, group: "Code", description: "Function metrics and audit priority" },
  types: { title: "Types", icon: Braces, group: "Code", description: "Recovered variables, structs, and type hints" },
  xrefs: { title: "References", icon: Waypoints, group: "Code", description: "Code, data, import, and string references" },
  hex: { title: "Hex Editor", icon: Hexagon, group: "Binary", description: "Hex, ASCII, bookmarks, and address mappings" },
  pe: { title: "Binary Explorer", icon: ListTree, group: "Binary", description: "Headers, sections, TLS, relocations, and certificates" },
  resources: { title: "Resources", icon: Database, group: "Binary", description: "Resources, debug directory, TLS, and certificates" },
  strings: { title: "Strings", icon: Sigma, group: "Data", description: "ASCII, UTF, indicators, and categories" },
  imports: { title: "Imports", icon: Terminal, group: "Data", description: "Imported APIs and categorized behavior" },
  exports: { title: "Exports", icon: FileText, group: "Data", description: "Exported symbols and RVAs" },
  signatures: { title: "Signatures", icon: Activity, group: "Analysis", description: "Fingerprints, matches, and capability signatures" },
  project: { title: "Project DB", icon: Database, group: "Analysis", description: "Symbols, labels, comments, types, and graph database" },
  vulns: { title: "Vulnerabilities", icon: Bug, group: "Security", description: "Static vulnerability review queue" },
  deep: { title: "Deep Analysis", icon: Database, group: "Security", description: "Data flow, API surface, IOCs, and triage tasks" },
  reports: { title: "Reports", icon: BookOpen, group: "Workspace", description: "Markdown reports and generated evidence" }
};

const reportLinks = [
  ["reports/triage.md", "Triage"],
  ["reports/executive.md", "Executive"],
  ["reports/technical.md", "Technical"],
  ["reports/indicators.md", "Indicators"],
  ["reports/vulnerabilities.md", "Vulnerabilities"],
  ["reports/reverse_engineering.md", "Reverse Engineering"],
  ["deep/analyst_workflow.md", "Analyst Workflow"]
];

export function App() {
  const [report, setReport] = useState<Report | null>(null);
  const [source, setSource] = useState("");
  const [asm, setAsm] = useState("");
  const [hexDump, setHexDump] = useState("");
  const [cfgDot, setCfgDot] = useState("");
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [palette, setPalette] = useState(false);
  const [markdown, setMarkdown] = useState<{ title: string; body: string } | null>(null);
  const [workspace, setWorkspace] = usePersistentWorkspace();

  useEffect(() => {
    document.documentElement.dataset.theme = workspace.theme;
    localStorage.setItem("retract-workspace-v2", JSON.stringify(workspace));
  }, [workspace]);

  useEffect(() => {
    fetchReport().then(setReport).catch((err) => setError(err instanceof Error ? err.message : String(err)));
    fetchText(["/files/source/reconstructed.c", "../source/reconstructed.c"]).then(setSource);
    fetchText(["/files/disassembly/entry.asm", "../disassembly/entry.asm"]).then(setAsm);
    fetchText(["/files/raw/hex_preview.txt", "../raw/hex_preview.txt"]).then(setHexDump);
    fetchText(["/files/control_flow/cfg.dot", "../control_flow/cfg.dot"]).then(setCfgDot);
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const key = event.key.toLowerCase();
      if ((event.ctrlKey || event.metaKey) && (key === "k" || key === "p")) {
        event.preventDefault();
        setPalette(true);
      }
      if ((event.ctrlKey || event.metaKey) && key === "b") {
        event.preventDefault();
        setWorkspace((w) => ({ ...w, navOpen: !w.navOpen }));
      }
      if ((event.ctrlKey || event.metaKey) && key === "j") {
        event.preventDefault();
        setWorkspace((w) => ({ ...w, bottomOpen: !w.bottomOpen }));
      }
      if (event.key === "Escape") {
        setPalette(false);
        setMarkdown(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const searchRows = useMemo(() => globalRows(report, query), [report, query]);

  if (error) return <EmptyState title="Unable to load report" detail={error} />;
  if (!report) return <EmptyState title="Loading workspace" detail="Reading report database and generated artifacts." />;

  const active = views[workspace.active];
  const meta = report.metadata ?? {};
  const info = report.file_info ?? {};
  const openView = (id: ViewID) => setWorkspace((w) => ({ ...w, active: id, tabs: w.tabs.includes(id) ? w.tabs : [...w.tabs, id] }));
  const closeTab = (id: ViewID) => setWorkspace((w) => {
    const tabs = w.tabs.filter((tab) => tab !== id);
    return { ...w, tabs: tabs.length ? tabs : ["overview"], active: w.active === id ? (tabs[0] ?? "overview") : w.active };
  });

  const appStyle = {
    gridTemplateColumns: `${workspace.navOpen ? "304px" : "56px"} minmax(0, 1fr) ${workspace.inspectorOpen ? `${workspace.inspectorWidth}px` : "44px"}`,
    gridTemplateRows: `44px minmax(0, 1fr) ${workspace.bottomOpen ? `${workspace.bottomHeight}px` : "36px"} 26px`,
    "--inspector-width": `${workspace.inspectorWidth}px`,
    "--bottom-height": `${workspace.bottomHeight + 26}px`
  } as CSSProperties;

  return (
    <div className="grid h-screen overflow-hidden bg-background text-foreground" style={appStyle}>
      <header className="col-span-3 flex min-w-0 items-center gap-3 border-b border-border bg-card px-3">
        <div className="flex min-w-[220px] items-center gap-2">
          <div className="grid h-7 w-7 place-items-center border border-border bg-background">
            <Radar className="h-4 w-4" />
          </div>
          <div className="leading-none">
            <div className="text-sm font-semibold">retract</div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">analysis workspace</div>
          </div>
        </div>
        <Button variant="outline" className="h-8 flex-1 justify-start text-muted-foreground" onClick={() => setPalette(true)}>
          <Command className="h-4 w-4" />
          Command, symbol, address, report
          <kbd className="ml-auto border border-border px-1.5 text-[10px]">Ctrl K</kbd>
        </Button>
        <div className="flex items-center gap-2">
          <Badge>{info.format ?? meta.file_type ?? "unknown"}</Badge>
          <Badge>{meta.architecture ?? "arch"}</Badge>
          <Button variant="ghost" size="icon" onClick={() => setWorkspace((w) => ({ ...w, theme: w.theme === "dark" ? "light" : "dark" }))}>
            {workspace.theme === "dark" ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
          </Button>
        </div>
      </header>

      <aside className="min-h-0 overflow-hidden border-r border-border bg-card">
        <Sidebar workspace={workspace} setWorkspace={setWorkspace} report={report} query={query} setQuery={setQuery} openView={openView} />
      </aside>

      <main className="flex min-h-0 min-w-0 flex-col overflow-hidden bg-background">
        <div className="flex h-9 items-center gap-1 border-b border-border px-3 text-xs text-muted-foreground">
          <span className="truncate">{meta.filename}</span>
          <ChevronRight className="h-3 w-3 shrink-0" />
          <span>{active.group}</span>
          <ChevronRight className="h-3 w-3 shrink-0" />
          <span className="text-foreground">{active.title}</span>
        </div>
        <div className="flex h-10 min-w-0 items-end gap-1 overflow-x-auto border-b border-border bg-card px-2">
          {workspace.tabs.map((id) => {
            const Icon = views[id].icon;
            return (
              <button
                key={id}
                className={cn(
                  "mb-[-1px] flex h-9 items-center gap-2 border border-border bg-secondary px-3 text-xs text-muted-foreground",
                  workspace.active === id && "border-b-background bg-background text-foreground"
                )}
                onClick={() => openView(id)}
              >
                <Icon className="h-3.5 w-3.5" />
                {views[id].title}
                <X className="h-3 w-3" onClick={(event) => { event.stopPropagation(); closeTab(id); }} />
              </button>
            );
          })}
        </div>
        <div className="min-h-0 flex-1 overflow-hidden p-3">
          <ViewFrame title={active.title} description={active.description}>
            <ViewSwitch active={workspace.active} report={report} source={source} asm={asm} hexDump={hexDump} cfgDot={cfgDot} openView={openView} openMarkdown={setMarkdown} />
          </ViewFrame>
        </div>
      </main>

      <aside className="min-h-0 overflow-hidden border-l border-border bg-card">
        <Inspector report={report} active={workspace.active} open={workspace.inspectorOpen} onToggle={() => setWorkspace((w) => ({ ...w, inspectorOpen: !w.inspectorOpen }))} />
      </aside>
      {workspace.inspectorOpen && (
        <ResizeHandle
          side="right"
          onDrag={(delta) => setWorkspace((w) => ({ ...w, inspectorWidth: clamp(w.inspectorWidth - delta, 260, 620) }))}
        />
      )}

      <section className="col-span-3 min-h-0 overflow-hidden border-t border-border bg-card">
        <BottomDock report={report} searchRows={searchRows} open={workspace.bottomOpen} onToggle={() => setWorkspace((w) => ({ ...w, bottomOpen: !w.bottomOpen }))} />
      </section>
      {workspace.bottomOpen && (
        <ResizeHandle
          side="bottom"
          onDrag={(delta) => setWorkspace((w) => ({ ...w, bottomHeight: clamp(w.bottomHeight - delta, 140, 520) }))}
        />
      )}

      <footer className="col-span-3 flex items-center gap-4 overflow-hidden bg-primary px-3 text-[11px] text-primary-foreground">
        <span>{info.format ?? meta.file_type}</span>
        <span>{formatBytes(meta.size)}</span>
        <span>entry {meta.entry_point ?? "unknown"}</span>
        <span>risk {report.risk_level ?? "unknown"} {report.risk_score ?? 0}/100</span>
        <span>{report.functions?.length ?? 0} functions</span>
        <span>{report.strings?.length ?? 0} strings</span>
      </footer>

      {palette && <CommandPalette report={report} query={query} setQuery={setQuery} openView={openView} onClose={() => setPalette(false)} openMarkdown={setMarkdown} />}
      {markdown && <MarkdownModal title={markdown.title} body={markdown.body} onClose={() => setMarkdown(null)} />}
    </div>
  );
}

function Sidebar({ workspace, setWorkspace, report, query, setQuery, openView }: {
  workspace: Workspace;
  setWorkspace: React.Dispatch<React.SetStateAction<Workspace>>;
  report: Report;
  query: string;
  setQuery: (v: string) => void;
  openView: (id: ViewID) => void;
}) {
  const meta = report.metadata ?? {};
  const grouped = groupViews();
  if (!workspace.navOpen) {
    return (
      <div className="flex h-full flex-col items-center gap-1 p-2">
        <Button title="Expand navigation" variant="ghost" size="icon" onClick={() => setWorkspace((w) => ({ ...w, navOpen: true }))}>
          <PanelLeft className="h-4 w-4" />
        </Button>
        {(Object.keys(views) as ViewID[]).map((id) => {
          const Icon = views[id].icon;
          return (
            <Button key={id} title={views[id].title} variant={workspace.active === id ? "default" : "ghost"} size="icon" onClick={() => openView(id)}>
              <Icon className="h-4 w-4" />
            </Button>
          );
        })}
      </div>
    );
  }
  return (
    <div className="flex h-full min-h-0 flex-col gap-3 p-3">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider">Workspace</div>
          <div className="text-xs text-muted-foreground">Reverse engineering suite</div>
        </div>
        <Button variant="ghost" size="icon" onClick={() => setWorkspace((w) => ({ ...w, navOpen: false }))}>
          <PanelLeft className="h-4 w-4" />
        </Button>
      </div>
      <div className="relative">
        <Search className="pointer-events-none absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
        <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Global search" className="h-9 pl-8" />
      </div>
      <Card>
        <CardContent className="space-y-2 p-3">
          <div className="truncate text-sm font-semibold">{meta.filename}</div>
          <div className="break-all font-mono text-[10px] text-muted-foreground">{meta.sha256}</div>
          <div className="flex flex-wrap gap-1">
            <Badge>{report.file_info?.packer ?? "not packed"}</Badge>
            <Badge>{report.file_info?.compiler ?? "compiler unknown"}</Badge>
          </div>
        </CardContent>
      </Card>
      <div className="min-h-0 flex-1 overflow-auto pr-1">
        {Object.entries(grouped).map(([group, ids]) => (
          <div key={group} className="mb-4">
            <div className="mb-1 px-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">{group}</div>
            <div className="grid gap-1">
              {ids.map((id) => {
                const Icon = views[id].icon;
                return (
                  <Button key={id} variant={workspace.active === id ? "default" : "ghost"} className="h-8 justify-start px-2" onClick={() => openView(id)}>
                    <Icon className="h-4 w-4" />
                    <span className="truncate">{views[id].title}</span>
                  </Button>
                );
              })}
            </div>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-3 gap-1 border-t border-border pt-3">
        <Button variant="outline" size="icon" onClick={() => setWorkspace((w) => ({ ...w, inspectorOpen: !w.inspectorOpen }))}><PanelRight className="h-4 w-4" /></Button>
        <Button variant="outline" size="icon" onClick={() => setWorkspace((w) => ({ ...w, bottomOpen: !w.bottomOpen }))}><PanelBottom className="h-4 w-4" /></Button>
        <Button variant="outline" size="icon"><Settings className="h-4 w-4" /></Button>
      </div>
    </div>
  );
}

function ViewFrame({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <Card className="flex h-full min-h-0 flex-col overflow-hidden">
      <CardHeader className="border-b border-border p-3">
        <div className="flex items-center justify-between gap-3">
          <div>
            <CardTitle>{title}</CardTitle>
            <p className="mt-1 text-xs text-muted-foreground">{description}</p>
          </div>
          <Badge>live report</Badge>
        </div>
      </CardHeader>
      <CardContent className="min-h-0 flex-1 overflow-hidden p-3">{children}</CardContent>
    </Card>
  );
}

function ViewSwitch(props: { active: ViewID; report: Report; source: string; asm: string; hexDump: string; cfgDot: string; openView: (id: ViewID) => void; openMarkdown: (m: { title: string; body: string }) => void }) {
  switch (props.active) {
    case "overview": return <OverviewView report={props.report} openView={props.openView} />;
    case "disassembly": return <DisassemblyView asm={props.asm} report={props.report} />;
    case "decompiler": return <DecompilerView source={props.source} report={props.report} />;
    case "graph": return <GraphView report={props.report} cfgDot={props.cfgDot} />;
    case "hex": return <HexView hexDump={props.hexDump} report={props.report} />;
    case "pe": return <BinaryExplorerView report={props.report} />;
    case "strings": return <StringsView report={props.report} />;
    case "imports": return <ImportsView report={props.report} />;
    case "exports": return <ExportsView report={props.report} />;
    case "resources": return <ResourcesView report={props.report} />;
    case "functions": return <FunctionsView report={props.report} />;
    case "types": return <TypesView report={props.report} />;
    case "xrefs": return <XrefsView report={props.report} />;
    case "signatures": return <SignaturesView report={props.report} />;
    case "project": return <ProjectView report={props.report} />;
    case "vulns": return <VulnsView report={props.report} />;
    case "deep": return <DeepView report={props.report} />;
    case "reports": return <ReportsView openMarkdown={props.openMarkdown} />;
    default: return <OverviewView report={props.report} openView={props.openView} />;
  }
}

function OverviewView({ report, openView }: { report: Report; openView: (id: ViewID) => void }) {
  const meta = report.metadata ?? {};
  const info = report.file_info ?? {};
  const deep = report.deep_analysis ?? {};
  return (
    <div className="grid h-full min-h-0 gap-3 overflow-auto lg:grid-rows-[auto_auto_minmax(0,1fr)]">
      <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_220px]">
        <Card className="bg-secondary/40">
          <CardContent className="p-5">
            <div className="text-xs uppercase tracking-widest text-muted-foreground">Current sample</div>
            <h1 className="mt-2 truncate text-2xl font-semibold">{meta.filename}</h1>
            <p className="mt-2 text-sm text-muted-foreground">{info.format ?? meta.file_type} · {meta.architecture} · {formatBytes(meta.size)} · {info.compiler ?? "compiler unknown"}</p>
            <div className="mt-4 flex flex-wrap gap-2">
              {(report.capabilities ?? []).slice(0, 8).map((cap) => <Badge key={cap}>{cap}</Badge>)}
            </div>
          </CardContent>
        </Card>
        <RiskCard score={report.risk_score ?? 0} level={report.risk_level ?? "unknown"} />
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        <Metric label="Sections" value={report.sections?.length ?? 0} />
        <Metric label="Imports" value={report.imports?.length ?? 0} />
        <Metric label="Strings" value={report.strings?.length ?? 0} />
        <Metric label="Functions" value={report.functions?.length ?? 0} />
        <Metric label="Vulns" value={report.vulnerabilities?.length ?? 0} />
        <Metric label="Signatures" value={deep.signatures?.length ?? 0} />
      </div>
      <div className="grid min-h-[360px] gap-3 xl:grid-cols-3">
        <BarCard title="Section Entropy" rows={(report.sections ?? []).map((s) => [s.name ?? "section", Number(s.entropy ?? 0)])} max={8} />
        <BarCard title="API Surface" rows={importCategoryRows(report.imports)} />
        <Card className="overflow-hidden">
          <CardHeader className="border-b border-border p-3"><CardTitle>Quick Actions</CardTitle></CardHeader>
          <CardContent className="grid gap-2 p-3">
            {(["disassembly", "decompiler", "hex", "graph", "signatures", "project", "vulns"] as ViewID[]).map((id) => {
              const Icon = views[id].icon;
              return <Button key={id} variant="outline" className="justify-start" onClick={() => openView(id)}><Icon className="h-4 w-4" />Open {views[id].title}</Button>;
            })}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function DisassemblyView({ asm, report }: { asm: string; report: Report }) {
  return <Split primary={<CodePane title="entry.asm" mode="asm" text={asm || "No disassembly available."} />} secondary={<SideRows title="Functions" rows={limit(report.function_insights, 120).map((f) => [f.start, f.name, `cc ${f.complexity}`])} />} />;
}

function DecompilerView({ source, report }: { source: string; report: Report }) {
  return <Split primary={<CodePane title="reconstructed.c" mode="c" text={source || "No recovered source available."} />} secondary={<SideRows title="Types and Structs" rows={[...(report.inferred_types ?? []).map((t) => [t.kind, t.name, t.confidence]), ...(report.struct_candidates ?? []).map((s) => ["struct", s.name, s.confidence])]} />} />;
}

function GraphView({ report, cfgDot }: { report: Report; cfgDot: string }) {
  const nodes = limit(report.functions?.length ? report.functions : report.deep_analysis?.fingerprints, 32);
  return (
    <Split
      primary={<div className="relative h-full overflow-hidden border border-border bg-background">
        <svg className="absolute inset-0 h-full w-full opacity-70">{nodes.map((_: any, i: number) => <line key={i} x1={`${12 + (i % 4) * 22}%`} y1={`${16 + Math.floor(i / 4) * 13}%`} x2={`${28 + (i % 4) * 18}%`} y2={`${27 + Math.floor(i / 4) * 11}%`} stroke="currentColor" strokeWidth="1" />)}</svg>
        {nodes.map((fn: any, index: number) => <div key={fn.name ?? fn.function ?? index} className="absolute min-w-36 border border-border bg-card p-2 font-mono text-[11px]" style={{ left: `${6 + (index % 4) * 23}%`, top: `${8 + Math.floor(index / 4) * 14}%` }}>{fn.name ?? fn.function}<div className="text-muted-foreground">{fn.start}</div></div>)}
      </div>}
      secondary={<CodePane title="cfg.dot" mode="plain" text={cfgDot || "No CFG DOT available."} />}
    />
  );
}

function HexView({ hexDump, report }: { hexDump: string; report: Report }) {
  const bookmarks = report.deep_analysis?.hex?.bookmarks ?? [];
  return <Split primary={<HexPane text={hexDump} />} secondary={<SideRows title="Bookmarks" rows={limit(bookmarks, 300).map((b: any) => [hex(b.offset), b.kind, b.name])} />} />;
}

function BinaryExplorerView({ report }: { report: Report }) {
  const info = report.file_info ?? {};
  const binary = report.binary ?? {};
  const tree = [
    ["Headers", `${info.format ?? "unknown"} ${binary.architecture ?? ""}`],
    ["Sections", `${report.sections?.length ?? 0} records`],
    ["Imports", `${report.imports?.length ?? 0} functions`],
    ["Exports", `${report.exports?.length ?? 0} functions`],
    ["Resources", String((report as any).resources?.present ?? false)],
    ["TLS", `${(report as any).tls_callbacks?.length ?? 0} callbacks`],
    ["Relocations", `${(report as any).relocations?.length ?? 0} blocks`],
    ["Certificates", String((report as any).certificate?.present ?? false)]
  ];
  return <Split primary={<DataTable headers={["Name", "Offset", "VA", "Size", "Flags", "Entropy"]} rows={(report.sections ?? []).map((s) => [s.name, hex(s.raw_offset), hex(s.virtual_address), s.raw_size, s.flags, Number(s.entropy ?? 0).toFixed(2)])} />} secondary={<SideRows title="Explorer" rows={tree} />} />;
}

function StringsView({ report }: { report: Report }) {
  return <DataTable headers={["Offset", "Encoding", "Tags", "Value"]} rows={limit(report.strings, 2000).map((s) => [hex(s.offset), s.encoding, (s.tags ?? []).join(", "), s.value])} />;
}

function ImportsView({ report }: { report: Report }) {
  return <DataTable headers={["DLL", "Name", "Ordinal", "Address", "Category"]} rows={(report.imports ?? []).map((i) => [i.dll, i.name, i.ordinal, i.address, (i.category ?? []).join(", ")])} />;
}

function ExportsView({ report }: { report: Report }) {
  return <DataTable headers={["Name", "Ordinal", "RVA"]} rows={(report.exports ?? []).map((e) => [e.name, e.ordinal, e.rva])} />;
}

function ResourcesView({ report }: { report: Report }) {
  const resources = (report as any).resources ?? {};
  const cert = (report as any).certificate ?? {};
  const debugEntries = (report as any).debug_entries ?? [];
  const tls = (report as any).tls_callbacks ?? [];
  return <GridTables tables={[
    { headers: ["Directory", "Present", "Location", "Size/Count"], rows: [["Resources", String(resources.present ?? false), resources.rva ?? "", resources.size ?? ""], ["Certificate", String(cert.present ?? false), hex(cert.file_offset), cert.size ?? ""], ["TLS Callbacks", String(tls.length > 0), tls.join(", "), tls.length], ["Debug Directory", String(debugEntries.length > 0), `${debugEntries.length} entries`, ""]] },
    { headers: ["Debug Type", "RVA", "File Offset", "Size", "PDB"], rows: debugEntries.map((d: any) => [d.type_name, d.rva, d.file_offset, d.size, d.pdb_path]) }
  ]} />;
}

function FunctionsView({ report }: { report: Report }) {
  return <DataTable headers={["Name", "Start", "Instructions", "Calls", "Branches", "Complexity", "Stack", "Risk Notes"]} rows={(report.function_insights ?? []).map((f) => [f.name, f.start, f.instruction_count, f.call_count, f.branch_count, f.complexity, f.estimated_stack, (f.risk_notes ?? []).join("; ")])} />;
}

function TypesView({ report }: { report: Report }) {
  return <GridTables tables={[
    { headers: ["Kind", "Name", "Confidence", "Evidence"], rows: (report.inferred_types ?? []).map((t) => [t.kind, t.name, t.confidence, (t.evidence ?? []).join("; ")]) },
    { headers: ["Struct", "Size", "Confidence", "Fields"], rows: (report.struct_candidates ?? []).map((s) => [s.name, s.size, s.confidence, (s.fields ?? []).join("; ")]) },
    { headers: ["Function", "Name", "Storage", "Type", "Evidence"], rows: (report.inferred_variables ?? []).map((v) => [v.function, v.name, v.storage, v.type, v.evidence]) }
  ]} />;
}

function XrefsView({ report }: { report: Report }) {
  return <DataTable headers={["From", "To", "Kind", "Evidence"]} rows={(report.xrefs ?? []).map((x) => [x.from, x.to, x.kind, x.evidence])} />;
}

function SignaturesView({ report }: { report: Report }) {
  const deep = report.deep_analysis ?? {};
  return <GridTables tables={[
    { headers: ["Name", "Kind", "Confidence", "Severity", "Evidence", "Tags"], rows: (deep.signatures ?? []).map((s: any) => [s.name, s.kind, s.confidence, s.severity, (s.evidence ?? []).join("; "), (s.tags ?? []).join(", ")]) },
    { headers: ["Function", "Start", "Instructions", "SimHash", "Instruction Hash", "Mnemonic Hash"], rows: (deep.fingerprints ?? []).map((f: any) => [f.function, f.start, f.instructions, f.simhash, f.instruction_hash, f.mnemonic_hash]) }
  ]} />;
}

function ProjectView({ report }: { report: Report }) {
  const project = report.deep_analysis?.project ?? {};
  return <GridTables tables={[
    { headers: ["Kind", "Name", "Value", "Location", "Tags"], rows: (project.symbols ?? []).map((s: any) => [s.kind, s.name, s.value, s.location, (s.tags ?? []).join(", ")]) },
    { headers: ["Kind", "Name", "Value", "Location", "Tags"], rows: (project.labels ?? []).map((s: any) => [s.kind, s.name, s.value, s.location, (s.tags ?? []).join(", ")]) },
    { headers: ["Kind", "Name", "Comment", "Location", "Tags"], rows: (project.comments ?? []).map((s: any) => [s.kind, s.name, s.value, s.location, (s.tags ?? []).join(", ")]) },
    { headers: ["From", "To", "Kind", "Evidence"], rows: (project.xrefs ?? []).map((x: any) => [x.from, x.to, x.kind, x.evidence]) }
  ]} />;
}

function VulnsView({ report }: { report: Report }) {
  return <DataTable headers={["Severity", "ID", "Category", "Title", "Evidence", "Recommendation"]} rows={(report.vulnerabilities ?? []).map((v) => [v.severity, v.id, v.category, v.title, v.evidence, v.recommendation])} />;
}

function DeepView({ report }: { report: Report }) {
  const deep = report.deep_analysis ?? {};
  return <GridTables tables={[
    { headers: ["Task", "Priority", "Why"], rows: (deep.triage_tasks ?? []).map((t: any) => [t.title, t.priority, t.why]) },
    { headers: ["API Category", "Risk", "Count", "DLLs"], rows: (deep.api_surface ?? []).map((a: any) => [a.category, a.risk, a.count, (a.dlls ?? []).join(", ")]) },
    { headers: ["Memory", "Kind", "Offset", "Size", "Entropy"], rows: (deep.memory_map ?? []).map((m: any) => [m.name, m.kind, hex(m.file_offset), m.file_size, Number(m.entropy ?? 0).toFixed(2)]) },
    { headers: ["Source", "Sink", "Severity", "Reason"], rows: (deep.data_flow?.taint_traces ?? []).map((t: any) => [t.source, t.sink, t.severity, t.reason]) }
  ]} />;
}

function ReportsView({ openMarkdown }: { openMarkdown: (m: { title: string; body: string }) => void }) {
  return (
    <div className="grid content-start gap-3 overflow-auto sm:grid-cols-2 xl:grid-cols-3">
      {reportLinks.map(([path, title]) => (
        <button key={path} className="border border-border bg-card p-4 text-left hover:bg-accent hover:text-accent-foreground" onClick={() => openMarkdownFile(path, title, openMarkdown)}>
          <FileText className="mb-4 h-5 w-5" />
          <div className="font-semibold">{title}</div>
          <div className="mt-1 text-xs text-muted-foreground">{path}</div>
        </button>
      ))}
    </div>
  );
}

function Inspector({ report, active, open, onToggle }: { report: Report; active: ViewID; open: boolean; onToggle: () => void }) {
  if (!open) return <Button variant="ghost" className="h-full w-full" onClick={onToggle}><PanelRight className="h-4 w-4" /></Button>;
  const meta = report.metadata ?? {};
  const deep = report.deep_analysis ?? {};
  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <div className="flex h-10 items-center justify-between border-b border-border px-3">
        <div className="text-xs font-semibold uppercase tracking-wider">Inspector</div>
        <Button variant="ghost" size="icon" onClick={onToggle}><PanelRight className="h-4 w-4" /></Button>
      </div>
      <div className="min-h-0 flex-1 space-y-3 overflow-auto p-3">
        <Metric label="Active View" value={views[active].title} />
        <KeyValue label="SHA256" value={meta.sha256} mono />
        <KeyValue label="Entry Point" value={meta.entry_point ?? "unknown"} mono />
        <KeyValue label="Compiler" value={report.file_info?.compiler ?? "unknown"} />
        <KeyValue label="Packer" value={report.file_info?.packer ?? "not detected"} />
        <KeyValue label="Search Index" value={String(deep.search_index?.length ?? 0)} />
        <KeyValue label="Project Symbols" value={String(deep.project?.symbols?.length ?? 0)} />
        <KeyValue label="Fingerprints" value={String(deep.fingerprints?.length ?? 0)} />
        <div>
          <div className="mb-2 text-xs font-semibold uppercase tracking-wider">Capabilities</div>
          <div className="flex flex-wrap gap-1">{(report.capabilities ?? []).slice(0, 16).map((cap) => <Badge key={cap}>{cap}</Badge>)}</div>
        </div>
      </div>
    </div>
  );
}

function BottomDock({ report, searchRows, open, onToggle }: { report: Report; searchRows: any[][]; open: boolean; onToggle: () => void }) {
  return (
    <div className="flex h-full min-h-0 flex-col">
      <button className="flex h-9 items-center gap-2 border-b border-border px-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground" onClick={onToggle}>
        <PanelBottom className="h-4 w-4" />
        Problems, Output, Evidence
      </button>
      {open && (
        <div className="grid min-h-0 flex-1 gap-3 overflow-auto p-3 xl:grid-cols-3">
          <PanelList title="Problems" rows={(report.vulnerabilities ?? []).slice(0, 10).map((v) => [v.severity, v.title])} />
          <PanelList title="Search Results" rows={searchRows.slice(0, 10).map((r) => [r[0], r[1]])} />
          <PanelList title="Detections" rows={(report.deep_analysis?.signatures ?? []).slice(0, 10).map((s: any) => [s.kind, s.name])} />
        </div>
      )}
    </div>
  );
}

function CommandPalette({ report, query, setQuery, openView, onClose, openMarkdown }: { report: Report; query: string; setQuery: (q: string) => void; openView: (id: ViewID) => void; onClose: () => void; openMarkdown: (m: { title: string; body: string }) => void }) {
  const commands = [
    ...Object.entries(views).map(([id, view]) => ({ kind: "view", title: `Open ${view.title}`, detail: view.description, run: () => openView(id as ViewID) })),
    ...reportLinks.map(([path, title]) => ({ kind: "report", title: `Read ${title}`, detail: path, run: () => openMarkdownFile(path, title, openMarkdown) })),
    ...globalRows(report, query).slice(0, 70).map((row) => ({ kind: row[0], title: String(row[1]), detail: String(row[2] ?? ""), run: () => setQuery(String(row[1])) }))
  ].filter((cmd) => !query || `${cmd.title} ${cmd.detail} ${cmd.kind}`.toLowerCase().includes(query.toLowerCase()));
  return (
    <div className="fixed inset-0 z-50 bg-black/70 p-4" onMouseDown={onClose}>
      <Card className="mx-auto mt-[8vh] flex max-h-[76vh] w-full max-w-3xl flex-col overflow-hidden shadow-2xl" onMouseDown={(event) => event.stopPropagation()}>
        <div className="flex items-center gap-2 border-b border-border p-3">
          <Command className="h-4 w-4" />
          <Input autoFocus value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Open view, symbol, address, report" />
        </div>
        <div className="min-h-0 flex-1 overflow-auto p-2">
          {commands.slice(0, 90).map((cmd, index) => (
            <button key={index} className="grid w-full grid-cols-[90px_1fr] gap-2 border border-transparent p-2 text-left text-sm hover:border-border hover:bg-accent" onClick={() => { cmd.run(); onClose(); }}>
              <span className="text-xs text-muted-foreground">{cmd.kind}</span>
              <span>{cmd.title}<small className="block truncate text-xs text-muted-foreground">{cmd.detail}</small></span>
            </button>
          ))}
        </div>
      </Card>
    </div>
  );
}

function ResizeHandle({ side, onDrag }: { side: "right" | "bottom"; onDrag: (delta: number) => void }) {
  const start = (event: React.MouseEvent) => {
    event.preventDefault();
    const origin = side === "bottom" ? event.clientY : event.clientX;
    const move = (moveEvent: MouseEvent) => onDrag((side === "bottom" ? moveEvent.clientY : moveEvent.clientX) - origin);
    const up = () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  };
  return <div className={cn("fixed z-40 bg-transparent hover:bg-primary/40", side === "right" ? "bottom-[26px] top-[44px] w-1 cursor-col-resize" : "inset-x-0 h-1 cursor-row-resize")} style={side === "right" ? { right: "var(--inspector-width, 340px)" } : { bottom: "var(--bottom-height, 256px)" }} onMouseDown={start} />;
}

function Split({ primary, secondary }: { primary: ReactNode; secondary: ReactNode }) {
  return <div className="grid h-full min-h-0 gap-3 xl:grid-cols-[minmax(0,1fr)_360px]">{primary}{secondary}</div>;
}

function GridTables({ tables }: { tables: { headers: string[]; rows: any[][] }[] }) {
  return <div className="grid h-full min-h-0 gap-3 overflow-auto xl:grid-cols-2">{tables.map((t, i) => <DataTable key={i} headers={t.headers} rows={t.rows} />)}</div>;
}

function DataTable({ headers, rows, empty = "No records" }: { headers: string[]; rows: any[][]; empty?: string }) {
  const [filter, setFilter] = useState("");
  const filtered = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter((row) => row.join(" ").toLowerCase().includes(needle));
  }, [filter, rows]);
  return (
    <div className="flex h-full min-h-[220px] flex-col overflow-hidden rounded-lg border border-border bg-card">
      <div className="flex items-center gap-2 border-b border-border bg-card p-2">
        <Search className="h-4 w-4 text-muted-foreground" />
        <Input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder={`Search ${rows.length} rows`} className="h-8" />
        <Badge>{filtered.length}</Badge>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <Table className="min-w-max">
          <thead className="sticky top-0 z-10 bg-secondary">
            <tr>{headers.map((h) => <Th key={h}>{h}</Th>)}</tr>
          </thead>
          <tbody>{filtered.length ? filtered.map((row, i) => <tr key={i} className="hover:bg-accent/60">{row.map((cell, j) => <Td key={j} className={cn(j < 2 && "font-mono text-xs")}>{String(cell ?? "")}</Td>)}</tr>) : <tr><Td colSpan={headers.length}>{empty}</Td></tr>}</tbody>
        </Table>
      </div>
    </div>
  );
}

function CodePane({ title, text, mode }: { title: string; text: string; mode: "asm" | "c" | "plain" }) {
  return (
    <div className="flex h-full min-h-[260px] flex-col overflow-hidden border border-border bg-card">
      <div className="flex h-9 items-center justify-between border-b border-border px-3 text-xs font-semibold"><span>{title}</span><Badge>{mode}</Badge></div>
      <pre className="min-h-0 flex-1 overflow-auto p-3 font-mono text-xs leading-relaxed"><code>{text.split("\n").slice(0, 8000).join("\n")}</code></pre>
    </div>
  );
}

function HexPane({ text }: { text: string }) {
  const rows = text.split("\n").filter(Boolean);
  return (
    <div className="h-full min-h-[260px] overflow-auto border border-border bg-card font-mono text-xs">
      <div className="sticky top-0 grid min-w-[920px] grid-cols-[120px_minmax(520px,1fr)_240px] gap-4 border-b border-border bg-secondary px-3 py-2 text-muted-foreground"><span>Offset</span><span>Bytes</span><span>ASCII</span></div>
      {rows.map((line) => {
        const offset = line.slice(0, 8);
        const ascii = line.includes("|") ? line.slice(line.indexOf("|")) : "";
        const bytes = line.slice(10, line.indexOf("|") > 0 ? line.indexOf("|") : undefined);
        return <div key={line} className="grid min-w-[920px] grid-cols-[120px_minmax(520px,1fr)_240px] gap-4 border-b border-border/70 px-3 py-1 hover:bg-accent"><span>{offset}</span><span>{bytes}</span><span>{ascii}</span></div>;
      })}
    </div>
  );
}

function SideRows({ title, rows }: { title: string; rows: any[][] }) {
  return (
    <Card className="h-full min-h-[260px] overflow-hidden">
      <CardHeader className="border-b border-border p-3"><CardTitle>{title}</CardTitle></CardHeader>
      <CardContent className="h-[calc(100%-48px)] overflow-auto p-2">
        {rows.map((row, i) => <div key={i} className="grid grid-cols-[92px_1fr_70px] gap-2 border-b border-border px-1 py-1.5 text-xs"><span className="truncate font-mono text-muted-foreground">{row[0]}</span><span className="truncate">{row[1]}</span><span className="truncate text-muted-foreground">{row[2]}</span></div>)}
      </CardContent>
    </Card>
  );
}

function PanelList({ title, rows }: { title: string; rows: any[][] }) {
  return <Card className="overflow-hidden"><CardHeader className="border-b border-border p-3"><CardTitle>{title}</CardTitle></CardHeader><CardContent className="space-y-1 p-2">{rows.map((r, i) => <div key={i} className="grid grid-cols-[90px_1fr] gap-2 border-b border-border px-1 py-1 text-xs"><span className="text-muted-foreground">{r[0]}</span><span className="truncate">{r[1]}</span></div>)}</CardContent></Card>;
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">{label}</div><div className="mt-1 text-xl font-semibold">{value}</div></CardContent></Card>;
}

function KeyValue({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return <div className="border-b border-border pb-2"><div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div><div className={cn("mt-1 break-all text-xs", mono && "font-mono")}>{value}</div></div>;
}

function RiskCard({ score, level }: { score: number; level: string }) {
  const pct = Math.max(0, Math.min(100, score));
  return <Card><CardContent className="p-5"><div className="text-xs uppercase tracking-widest text-muted-foreground">Risk Score</div><div className="mt-3 text-4xl font-semibold">{score}</div><div className="mt-1 text-sm text-muted-foreground">{level}</div><div className="mt-4 h-2 border border-border"><div className="h-full bg-primary" style={{ width: `${pct}%` }} /></div></CardContent></Card>;
}

function BarCard({ title, rows, max }: { title: string; rows: [string, number][]; max?: number }) {
  const clean = rows.filter(([, v]) => Number.isFinite(v)).slice(0, 14);
  const top = max ?? Math.max(1, ...clean.map(([, v]) => v));
  return <Card className="overflow-hidden"><CardHeader className="border-b border-border p-3"><CardTitle>{title}</CardTitle></CardHeader><CardContent className="space-y-2 p-3">{clean.map(([k, v]) => <div key={k} className="grid grid-cols-[110px_1fr_48px] items-center gap-2 text-xs"><span className="truncate text-muted-foreground">{k}</span><div className="h-3 border border-border"><div className="h-full bg-primary" style={{ width: `${Math.min(100, (v / top) * 100)}%` }} /></div><span className="text-right font-mono">{Number.isInteger(v) ? v : v.toFixed(2)}</span></div>)}</CardContent></Card>;
}

function MarkdownModal({ title, body, onClose }: { title: string; body: string; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 bg-black/70 p-4">
      <Card className="mx-auto flex h-[calc(100vh-48px)] max-w-5xl flex-col overflow-hidden">
        <div className="flex items-center justify-between border-b border-border p-3"><span className="font-semibold">{title}</span><Button variant="outline" size="sm" onClick={onClose}>Close</Button></div>
        <div className="prose-invert min-h-0 flex-1 overflow-auto p-5 text-sm leading-7" dangerouslySetInnerHTML={{ __html: markdownToHTML(body) }} />
      </Card>
    </div>
  );
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return <div className="grid h-screen place-items-center bg-background text-foreground"><Card className="w-full max-w-md"><CardContent className="p-6 text-center"><Activity className="mx-auto mb-4 h-6 w-6" /><h1 className="text-lg font-semibold">{title}</h1><p className="mt-2 text-sm text-muted-foreground">{detail}</p></CardContent></Card></div>;
}

function usePersistentWorkspace(): [Workspace, React.Dispatch<React.SetStateAction<Workspace>>] {
  const [workspace, setWorkspace] = useState<Workspace>(() => {
    try {
      const saved = JSON.parse(localStorage.getItem("retract-workspace-v2") || "{}");
      return { ...defaultWorkspace, ...saved };
    } catch {
      return defaultWorkspace;
    }
  });
  return [workspace, setWorkspace];
}

async function fetchReport() {
  for (const url of ["/api/report", "../reports/report.json"]) {
    try {
      const res = await fetch(url);
      if (res.ok) return await res.json();
    } catch {
      // fallback
    }
  }
  throw new Error("Unable to fetch report.json");
}

async function fetchText(urls: string[]) {
  for (const url of urls) {
    try {
      const res = await fetch(url);
      if (res.ok) return await res.text();
    } catch {
      // fallback
    }
  }
  return "";
}

async function openMarkdownFile(path: string, title: string, setMarkdown: (m: { title: string; body: string }) => void) {
  const body = await fetchText([`/files/${path}`, `../${path}`]);
  setMarkdown({ title, body: body || "Unable to load report." });
}

function globalRows(report: Report | null, q: string) {
  if (!report) return [];
  const rows: any[][] = [];
  for (const e of report.deep_analysis?.search_index ?? []) rows.push([e.kind, e.name, e.value, e.location]);
  for (const s of report.deep_analysis?.signatures ?? []) rows.push(["signature", s.name, `${s.kind} ${s.confidence}`, (s.evidence ?? []).join("; ")]);
  for (const f of report.deep_analysis?.fingerprints ?? []) rows.push(["fingerprint", f.function, f.simhash, f.start]);
  for (const v of report.vulnerabilities ?? []) rows.push(["vuln", v.id, v.title, v.evidence]);
  if (!q.trim()) return rows;
  const needle = q.toLowerCase();
  return rows.filter((r) => r.join(" ").toLowerCase().includes(needle));
}

function groupViews() {
  const groups: Record<string, ViewID[]> = {};
  for (const id of Object.keys(views) as ViewID[]) {
    groups[views[id].group] = [...(groups[views[id].group] ?? []), id];
  }
  return groups;
}

function importCategoryRows(imports?: any[]): [string, number][] {
  const counts = new Map<string, number>();
  for (const imp of imports ?? []) for (const cat of imp.category ?? ["uncategorized"]) counts.set(cat, (counts.get(cat) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

function markdownToHTML(md: string) {
  const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return md.split(/\r?\n/).map((raw) => {
    const line = esc(raw);
    if (line.startsWith("### ")) return `<h3 class="mt-5 border-b border-border pb-2 text-base font-semibold">${line.slice(4)}</h3>`;
    if (line.startsWith("## ")) return `<h2 class="mt-6 border-b border-border pb-2 text-lg font-semibold">${line.slice(3)}</h2>`;
    if (line.startsWith("# ")) return `<h1 class="mb-4 text-xl font-semibold">${line.slice(2)}</h1>`;
    if (line.startsWith("- ")) return `<p class="ml-4 text-muted-foreground">- ${line.slice(2)}</p>`;
    if (line.includes("|")) return `<pre class="overflow-auto border border-border p-2 text-xs">${line}</pre>`;
    return line ? `<p class="text-muted-foreground">${line.replace(/`([^`]+)`/g, "<code class=\"border border-border px-1\">$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong class=\"text-foreground\">$1</strong>")}</p>` : "<br>";
  }).join("");
}

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}
