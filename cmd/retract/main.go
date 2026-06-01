package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"retract/internal/analyzer"
	"retract/internal/webui"
	"retract/pkg/api"
)

const version = "0.2.0"

func main() {
	var opts api.Options
	var showVersion bool
	flag.StringVar(&opts.OutputDir, "o", "output", "output directory")
	flag.BoolVar(&opts.JSON, "json", false, "print JSON report to stdout")
	flag.IntVar(&opts.MinString, "min-string", 4, "minimum string length")
	flag.BoolVar(&opts.NoDisasm, "no-disasm", false, "skip disassembly and CFG generation")
	flag.BoolVar(&opts.Full, "full", false, "enable full analysis passes")
	flag.StringVar(&opts.Format, "format", "auto", "force format: auto, pe, elf, macho, raw")
	flag.BoolVar(&opts.Quiet, "quiet", false, "suppress the console summary")
	flag.BoolVar(&opts.Verbose, "verbose", false, "print top findings in the console summary")
	flag.BoolVar(&opts.NoVisuals, "no-visuals", false, "skip PNG visual generation")
	flag.IntVar(&opts.WindowSize, "window", 4096, "entropy sliding window size")
	flag.IntVar(&opts.WindowStep, "step", 2048, "entropy sliding window step")
	flag.IntVar(&opts.DisasmBytes, "disasm-bytes", 8192, "maximum bytes to disassemble from entry point")
	flag.StringVar(&opts.CaseID, "case", "", "case or ticket identifier to embed in reports")
	flag.BoolVar(&opts.Serve, "serve", false, "serve the generated report in a local web UI")
	flag.StringVar(&opts.ServeAddr, "addr", "127.0.0.1:8787", "address for --serve")
	flag.BoolVar(&showVersion, "version", false, "print version")
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), usage())
	}
	args, target, ok := normalizeArgs(os.Args[1:])
	if hasVersionOnly(args) {
		fmt.Printf("retract %s\n", version)
		return
	}
	if !ok {
		flag.Usage()
		os.Exit(2)
	}
	if err := flag.CommandLine.Parse(args); err != nil {
		os.Exit(2)
	}
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	if showVersion {
		fmt.Printf("retract %s\n", version)
		return
	}
	if opts.Full {
		if opts.DisasmBytes < 65536 {
			opts.DisasmBytes = 65536
		}
		if opts.WindowSize > 2048 {
			opts.WindowSize = 2048
		}
		if opts.WindowStep > 1024 {
			opts.WindowStep = 1024
		}
	}
	_, root, err := analyzer.Analyze(target, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "retract: %v\n", err)
		os.Exit(1)
	}
	if opts.Serve {
		if err := webui.Serve(root, opts.ServeAddr); err != nil {
			fmt.Fprintf(os.Stderr, "retract serve: %v\n", err)
			os.Exit(1)
		}
	}
}

func normalizeArgs(args []string) ([]string, string, bool) {
	var flags []string
	target := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) && target == "" {
				target = args[i+1]
				i++
			}
			continue
		}
		if len(arg) > 0 && arg[0] == '-' {
			flags = append(flags, normalizeFlag(arg))
			if needsValue(arg) && !strings.Contains(arg, "=") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		if target != "" {
			return nil, "", false
		}
		target = arg
	}
	return flags, target, target != ""
}

func needsValue(arg string) bool {
	arg = normalizeFlag(arg)
	if strings.Contains(arg, "=") {
		return false
	}
	switch arg {
	case "-o", "-min-string", "-format", "-window", "-step", "-disasm-bytes", "-case", "-addr":
		return true
	default:
		return false
	}
}

func normalizeFlag(arg string) string {
	if len(arg) > 2 && arg[:2] == "--" {
		return "-" + arg[2:]
	}
	return arg
}

func hasVersionOnly(args []string) bool {
	return len(args) == 1 && (args[0] == "-version" || args[0] == "--version")
}

func usage() string {
	return `retract ` + version + `

Usage:
  retract <file> [options]

Examples:
  retract crackme.exe --full --verbose
  retract crackme.exe -o output --min-string 5
  retract crackme.exe --json --no-visuals
  retract crackme.exe --window 2048 --step 512 --disasm-bytes 65536

Core:
  -o <dir>              Output directory (default: output)
  --format <name>       Force format: auto, pe, elf, macho, raw
  --json                Print JSON report to stdout
  --quiet               Suppress console summary
  --verbose             Include top findings in console summary
  --version             Print version
  --case <id>           Case or ticket identifier to embed in reports
  --serve               Serve the generated report in a local web UI
  --addr <host:port>    Address for --serve (default: 127.0.0.1:8787)

Analysis depth:
  --full                Deeper defaults for entropy and disassembly
  --min-string <n>      Minimum string length (default: 4)
  --no-disasm           Skip disassembly, functions, and CFG
  --disasm-bytes <n>    Max bytes to disassemble from entry point
  --window <n>          Entropy sliding window size
  --step <n>            Entropy sliding window step

Artifacts:
  --no-visuals          Skip entropy/section/histogram PNGs

`
}
