package webui

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"retract/internal/utils"
	"retract/pkg/api"
)

func Serve(root, addr string) error {
	if addr == "" {
		addr = "127.0.0.1:8787"
	}
	mux := http.NewServeMux()
	mux.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(root))))
	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(root, "reports", "report.json"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			asset := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
			if strings.HasPrefix(asset, "..") {
				http.NotFound(w, r)
				return
			}
			p := filepath.Join(root, "web", asset)
			if _, err := os.Stat(p); err == nil {
				http.ServeFile(w, r, p)
				return
			}
		}
		p := filepath.Join(root, "web", "index.html")
		if _, err := os.Stat(p); err == nil {
			http.ServeFile(w, r, p)
			return
		}
		http.ServeFile(w, r, filepath.Join(root, "reports", "triage.md"))
	})
	fmt.Printf("serving retract report at http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

func WriteIndex(root string, report api.AnalysisReport) error {
	p, err := utils.SafeJoin(root, "web/index.html")
	if err != nil {
		return err
	}
	if err := utils.EnsureDir(filepath.Dir(p)); err != nil {
		return err
	}
	if dist, ok := frontendDist(); ok {
		if err := copyDir(dist, filepath.Dir(p)); err != nil {
			return err
		}
		return nil
	}
	files, _ := artifactList(root)
	data := struct {
		Report api.AnalysisReport
		Files  []string
		JSON   template.JS
	}{
		Report: report,
		Files:  files,
		JSON:   mustJSON(report),
	}
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	defer f.Close()
	return page.Execute(f, data)
}

func frontendDist() (string, bool) {
	candidates := []string{
		filepath.Join("web", "dist"),
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "web", "dist"))
	}
	for _, candidate := range candidates {
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate, true
		}
	}
	return "", false
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return utils.EnsureDir(target)
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := utils.EnsureDir(filepath.Dir(dst)); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func artifactList(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(rel, "web/") {
			return nil
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out, err
}

func mustJSON(v any) template.JS {
	b, _ := json.Marshal(v)
	return template.JS(b)
}

var page = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>retract · {{.Report.Metadata.Filename}}</title>
<style>
:root{color-scheme:dark;--bg:#000;--panel:#07090c;--panel2:#0d1117;--panel3:#111821;--text:#eef5fb;--muted:#8c9aa8;--line:#1f2a35;--accent:#4cc9f0;--green:#7bdcb5;--bad:#ff5c5c;--warn:#ffbf69;--purple:#c7a6ff}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:#000;color:var(--text);font:13px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}.app{display:grid;grid-template-columns:260px 1fr;min-height:100vh}
aside{position:sticky;top:0;height:100vh;background:#020304;border-right:1px solid var(--line);padding:18px 14px;overflow:auto}.brand{font-size:18px;font-weight:800;margin:0 0 4px}.sha{font:11px ui-monospace,monospace;color:var(--muted);word-break:break-all;margin-bottom:18px}
nav a{display:flex;gap:10px;align-items:center;color:var(--muted);padding:9px 10px;border-radius:8px;margin:2px 0;text-decoration:none}nav a:hover{background:var(--panel2);color:var(--text)}
main{padding:22px;max-width:1600px;width:100%;margin:0 auto}.top{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:18px}.title h1{font-size:24px;margin:0}.subtitle{color:var(--muted);margin-top:4px}.lookup{display:flex;gap:8px;flex-wrap:wrap}
.btn{border:1px solid var(--line);background:var(--panel2);border-radius:8px;padding:8px 10px;color:var(--text)}section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}h2{font-size:16px;margin:0 0 12px}h3{font-size:13px;color:var(--muted);margin:14px 0 8px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}.wide{grid-column:span 2}.metric{background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:12px}.metric span{display:block;color:var(--muted);font-size:12px}.metric b{display:block;font-size:18px;margin-top:3px;word-break:break-word}
.risk-high,.sev-high{color:var(--bad)}.risk-medium,.sev-medium{color:var(--warn)}.risk-low,.sev-info{color:var(--green)}.muted{color:var(--muted)}.pill{display:inline-block;border:1px solid var(--line);background:var(--panel2);border-radius:999px;padding:4px 9px;margin:3px;color:var(--muted)}
table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}th{color:var(--muted);font-size:12px;font-weight:650}tr:hover td{background:#05080b}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}pre{white-space:pre-wrap;background:#020304;border:1px solid var(--line);border-radius:8px;padding:12px;max-height:560px;overflow:auto}.scroll{max-height:460px;overflow:auto;border:1px solid var(--line);border-radius:8px}
.split{display:grid;grid-template-columns:1fr 1fr;gap:12px}.visuals{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}.visuals img{width:100%;border:1px solid var(--line);border-radius:9px;background:#020304}
.toolbar{display:flex;gap:8px;margin:8px 0 12px}.toolbar input{width:100%;background:#020304;border:1px solid var(--line);border-radius:7px;color:var(--text);padding:9px}.files{columns:3}.files a{display:block;break-inside:avoid;padding:2px 0}.kv{display:grid;grid-template-columns:170px 1fr;gap:6px 12px}.kv div:nth-child(odd){color:var(--muted)}
@media(max-width:900px){.app{display:block}aside{position:static;height:auto}.split{grid-template-columns:1fr}.files{columns:1}.top{display:block}}
</style>
</head>
<body>
<div class="app">
<aside>
<div class="brand">retract</div><div class="sha">{{.Report.Metadata.SHA256}}</div>
<nav>
<a href="#overview">⌁ Overview</a><a href="#fileinfo">◫ File Info</a><a href="#hashes"># Hashes</a><a href="#protections">◈ Protections</a><a href="#sections">▤ Sections</a><a href="#imports">⇣ Imports</a><a href="#strings">≋ Strings</a><a href="#disasm">⌘ Disasm / C</a><a href="#vulns">⚠ Vulns</a><a href="#symbols">◇ Symbols</a><a href="#advanced-re">◎ Advanced RE</a><a href="#visuals">◉ Visuals</a><a href="#embedded">▣ Embedded</a><a href="#artifacts">▥ Artifacts</a>
</nav>
</aside>
<main>
<div class="top"><div class="title"><h1>{{.Report.Metadata.Filename}}</h1><div class="subtitle">{{.Report.FileInfo.OperatingSystem}} · {{.Report.Binary.Architecture}} · {{.Report.FileInfo.Compiler}} · {{.Report.FileInfo.Language}}</div></div><div class="lookup"><a class="btn" target="_blank" href="{{.Report.FileInfo.LookupLinks.VirusTotal}}">VirusTotal</a><a class="btn" target="_blank" href="{{.Report.FileInfo.LookupLinks.MalwareBazaar}}">MalwareBazaar</a><a class="btn" href="/files/reports/report.json">JSON</a></div></div>
<section id="overview"><h2>Overview</h2><div class="grid">
<div class="metric"><span class="muted">Risk</span><b class="risk-{{.Report.RiskLevel}}">{{.Report.RiskLevel}} {{.Report.RiskScore}}/100</b></div>
<div class="metric"><span>Format</span><b>{{.Report.FileInfo.Format}}</b></div><div class="metric"><span>MIME</span><b>{{.Report.FileInfo.MIMEType}}</b></div><div class="metric"><span>Packer</span><b>{{.Report.FileInfo.Packer}}</b></div>
<div class="metric"><span class="muted">Strings</span><b>{{len .Report.Strings}}</b></div>
<div class="metric"><span class="muted">Findings</span><b>{{len .Report.Findings}}</b></div>
<div class="metric"><span class="muted">Vulns</span><b>{{len .Report.Vulnerabilities}}</b></div>
<div class="metric"><span class="muted">Functions</span><b>{{len .Report.Functions}}</b></div>
<div class="metric"><span class="muted">Xrefs</span><b>{{len .Report.Xrefs}}</b></div>
<div class="metric"><span class="muted">Embedded</span><b>{{len .Report.EmbeddedArtifacts}}</b></div>
</div></section>
<section id="fileinfo"><h2>File Info</h2><div class="split"><div class="kv"><div>Scan time</div><div>{{.Report.FileInfo.ScanTime}}</div><div>Operating system</div><div>{{.Report.FileInfo.OperatingSystem}}</div><div>Compiler</div><div>{{.Report.FileInfo.Compiler}}</div><div>Language</div><div>{{.Report.FileInfo.Language}}</div><div>Libraries</div><div>{{range .Report.FileInfo.Libraries}}<span class="pill">{{.}}</span>{{end}}</div></div><div class="kv"><div>File type</div><div>{{.Report.Binary.FileType}}</div><div>Architecture</div><div>{{.Report.Binary.Architecture}}</div><div>Mode</div><div>{{.Report.Binary.Mode}}</div><div>Endian</div><div>{{.Report.Binary.Endian}}</div><div>Module address</div><div><code>{{.Report.Binary.ModuleAddress}}</code></div><div>Image size</div><div>{{.Report.Binary.ImageSize}}</div><div>Entry point</div><div><code>{{.Report.Binary.EntryPoint}}</code></div></div></div><h3>All Matches</h3>{{range .Report.FileInfo.Matches}}<div>• {{.}}</div>{{end}}</section>
<section id="hashes"><h2>Hashes</h2><div class="kv"><div>MD5</div><div><code>{{.Report.Metadata.MD5}}</code></div><div>SHA1</div><div><code>{{.Report.Metadata.SHA1}}</code></div><div>SHA256</div><div><code>{{.Report.Metadata.SHA256}}</code></div><div>SHA512</div><div><code>{{.Report.Metadata.SHA512}}</code></div></div></section>
<section id="protections"><h2>Protections & Detections</h2><div>{{range .Report.FileInfo.Protections}}<span class="pill">{{.}}</span>{{end}}</div><h3>Capabilities</h3>{{range .Report.Capabilities}}<span class="pill">{{.}}</span>{{else}}<div class="muted">No high-confidence capabilities inferred.</div>{{end}}</section>
<section id="vulns"><h2>Vulnerability Review</h2><div class="toolbar"><input data-filter="vuln-table" placeholder="Filter vulnerabilities..."></div><div class="scroll"><table id="vuln-table"><tr><th>Severity</th><th>ID</th><th>Category</th><th>Title</th><th>Evidence</th></tr>{{range .Report.Vulnerabilities}}<tr><td class="sev-{{.Severity}}">{{.Severity}}</td><td><code>{{.ID}}</code></td><td>{{.Category}}</td><td>{{.Title}}</td><td>{{.Evidence}}</td></tr>{{end}}</table></div><p><a href="/files/reports/vulnerabilities.md">Full vulnerability report</a></p></section>
<section id="sections"><h2>Sections</h2><table><tr><th>Name</th><th>File Offset</th><th>Address</th><th>Virtual Size</th><th>Raw Size</th><th>Flags</th><th>Entropy</th></tr>{{range .Report.Sections}}<tr><td>{{.Name}}</td><td><code>{{printf "0x%x" .RawOffset}}</code></td><td><code>{{printf "0x%x" .VirtualAddress}}</code></td><td>{{.VirtualSize}}</td><td>{{.RawSize}}</td><td>{{.Flags}}</td><td>{{printf "%.2f" .Entropy}}</td></tr>{{end}}</table></section>
<section id="imports"><h2>Imports</h2><div class="toolbar"><input data-filter="import-table" placeholder="Filter imports..."></div><div class="scroll"><table id="import-table"><tr><th>DLL</th><th>Name</th><th>Ordinal</th><th>Address</th><th>Categories</th></tr>{{range .Report.Imports}}<tr><td>{{.DLL}}</td><td><code>{{.Name}}</code></td><td>{{.Ordinal}}</td><td><code>{{.Address}}</code></td><td>{{range .Category}}<span class="pill">{{.}}</span>{{end}}</td></tr>{{end}}</table></div></section>
<section id="strings"><h2>Strings</h2><div class="grid"><div class="metric"><span>ASCII/UTF-8</span><b>{{index .Report.StringSummary "utf-8"}}</b></div><div class="metric"><span>UTF-16LE</span><b>{{index .Report.StringSummary "utf-16le"}}</b></div><div class="metric"><span>URLs</span><b>{{index .Report.StringSummary "url"}}</b></div><div class="metric"><span>Domains</span><b>{{index .Report.StringSummary "domain"}}</b></div></div><p><a href="/files/strings/all_strings.txt">all strings</a> · <a href="/files/strings/suspicious.txt">suspicious</a> · <a href="/files/strings/urls.txt">urls</a></p></section>
<section id="disasm"><h2>Disassembly, Hex & Recovered C</h2><div class="split"><div><h3>Recovered C</h3><pre id="src"></pre></div><div><h3>Hex Preview</h3><pre id="hex"></pre></div></div><p><a href="/files/disassembly/entry.asm">entry.asm</a> · <a href="/files/source/reconstructed.c">reconstructed.c</a> · <a href="/files/raw/hex_preview.txt">hex preview</a></p></section>
<section id="symbols"><h2>Symbols, Functions, Types & Structs</h2><div class="split"><div class="scroll"><table><tr><th>Name</th><th>Start</th><th>Instr</th><th>Complexity</th><th>Stack</th></tr>{{range .Report.FunctionInsights}}<tr><td>{{.Name}}</td><td><code>{{.Start}}</code></td><td>{{.InstructionCount}}</td><td>{{.Complexity}}</td><td>{{.EstimatedStack}}</td></tr>{{end}}</table></div><div><h3>Types</h3>{{range .Report.InferredTypes}}<div><b>{{.Name}}</b> <span class="muted">{{.Kind}} · {{.Confidence}}</span></div>{{end}}<h3>Struct Candidates</h3>{{range .Report.StructCandidates}}<div><b>{{.Name}}</b> <span class="muted">{{.Confidence}}</span><br>{{range .Fields}}<code>{{.}}</code> {{end}}</div>{{end}}</div></div><p><a href="/files/symbols/xrefs.csv">xrefs</a> · <a href="/files/symbols/inferred_types.json">types</a> · <a href="/files/functions/function_insights.csv">function metrics</a></p></section>
<section id="advanced-re"><h2>Advanced RE Workspace</h2><div class="grid"><div class="metric"><span>Hot paths</span><b>{{len .Report.DeepAnalysis.HotPaths}}</b></div><div class="metric"><span>Patch points</span><b>{{len .Report.DeepAnalysis.PatchPoints}}</b></div><div class="metric"><span>API call sites</span><b>{{len .Report.DeepAnalysis.APICallSites}}</b></div><div class="metric"><span>Type hints</span><b>{{len .Report.DeepAnalysis.TypeHints}}</b></div></div><div class="split"><div class="scroll"><h3>Hot Paths</h3><table><tr><th>Rank</th><th>Function</th><th>Score</th><th>Reasons</th></tr>{{range .Report.DeepAnalysis.HotPaths}}<tr><td>{{.Rank}}</td><td><code>{{.Function}}</code></td><td>{{.Score}}</td><td>{{range .Reasons}}<span class="pill">{{.}}</span>{{end}}</td></tr>{{end}}</table></div><div class="scroll"><h3>Unpacking Hints</h3><table><tr><th>Priority</th><th>Region</th><th>Kind</th><th>Evidence</th></tr>{{range .Report.DeepAnalysis.UnpackingHints}}<tr><td>{{.Priority}}</td><td><code>{{.Region}}</code></td><td>{{.Kind}}</td><td>{{range .Evidence}}<span class="pill">{{.}}</span>{{end}}</td></tr>{{end}}</table></div></div><p><a href="/files/deep/hot_paths.csv">hot paths</a> · <a href="/files/deep/patch_points.csv">patch points</a> · <a href="/files/deep/calling_conventions.csv">calling conventions</a> · <a href="/files/deep/type_hints.csv">type hints</a></p></section>
<section id="visuals"><h2>Visualize</h2><div class="visuals"><img src="/files/visuals/entropy_timeline.png"><img src="/files/visuals/byte_histogram.png"><img src="/files/visuals/section_map.png"></div><p><a href="/files/yara_like/indicators.yaralike">YARA-like rule</a> · <a href="/files/control_flow/cfg.dot">CFG DOT</a></p></section>
<section id="xrefs"><h2>Cross References</h2><div class="toolbar"><input data-filter="xref-table" placeholder="Filter xrefs..."></div><div class="scroll"><table id="xref-table"><tr><th>From</th><th>To</th><th>Kind</th><th>Evidence</th></tr>{{range .Report.Xrefs}}<tr><td><code>{{.From}}</code></td><td>{{.To}}</td><td>{{.Kind}}</td><td>{{.Evidence}}</td></tr>{{end}}</table></div></section>
<section id="embedded"><h2>Embedded Artifacts</h2><table><tr><th>Offset</th><th>Type</th><th>Description</th></tr>{{range .Report.EmbeddedArtifacts}}<tr><td><code>{{printf "0x%x" .Offset}}</code></td><td>{{.Type}}</td><td>{{.Description}}</td></tr>{{else}}<tr><td colspan="3" class="muted">No embedded artifacts found by magic scan.</td></tr>{{end}}</table></section>
<section id="artifacts"><h2>Artifacts</h2><div class="files">{{range .Files}}<a href="/files/{{.}}">{{.}}</a>{{end}}</div></section>
</main>
</div>
<script>
fetch('/files/source/reconstructed.c').then(r=>r.text()).then(t=>document.getElementById('src').textContent=t.slice(0,50000));
fetch('/files/raw/hex_preview.txt').then(r=>r.text()).then(t=>document.getElementById('hex').textContent=t);
document.querySelectorAll('input[data-filter]').forEach(input=>input.addEventListener('input',()=>{
  const q=input.value.toLowerCase(), table=document.getElementById(input.dataset.filter);
  table.querySelectorAll('tr').forEach((tr,i)=>{ if(i===0)return; tr.style.display=tr.textContent.toLowerCase().includes(q)?'':'none'; });
}));
window.RETRACT_REPORT={{.JSON}};
</script>
</body>
</html>`))
