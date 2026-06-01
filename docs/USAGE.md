# Usage

## Basic Commands

Build:

```sh
scripts/build.sh
```

Analyze a file:

```sh
bin/retract sample.exe
```

Analyze with deeper defaults:

```sh
bin/retract sample.exe --full
```

Print verbose console findings:

```sh
bin/retract sample.exe --full --verbose
```

Write output to a specific directory:

```sh
bin/retract sample.exe --full -o output
```

Embed a case identifier:

```sh
bin/retract sample.exe --full --case IR-2026-001
```

Serve the local web UI:

```sh
bin/retract sample.exe --full --serve --addr 127.0.0.1:8787
```

Print JSON to stdout:

```sh
bin/retract sample.exe --json
```

Skip visual PNG generation:

```sh
bin/retract sample.exe --full --no-visuals
```

Skip disassembly, function recovery, and CFG:

```sh
bin/retract sample.exe --no-disasm
```

Force a format:

```sh
bin/retract sample.bin --format raw
bin/retract sample.exe --format pe
bin/retract sample.elf --format elf
bin/retract sample.macho --format macho
```

Tune string extraction:

```sh
bin/retract sample.exe --min-string 6
```

Tune entropy windows:

```sh
bin/retract sample.exe --window 2048 --step 512
```

Tune disassembly limit:

```sh
bin/retract sample.exe --disasm-bytes 65536
```

## Helper Scripts

Analyze:

```sh
scripts/analyze.sh sample.exe output
```

Serve:

```sh
scripts/serve.sh sample.exe output 127.0.0.1:8787
```

Test:

```sh
scripts/test.sh
```

Clean generated binary and web build:

```sh
scripts/clean.sh
```

## Command Reference

```text
Usage:
  retract <file> [options]

Core:
  -o <dir>              Output directory (default: output)
  --format <name>       Force format: auto, pe, elf, macho, raw
  --json                Print JSON report to stdout
  --quiet               Suppress the console summary
  --verbose             Include top findings in the console summary
  --version             Print version
  --case <id>           Case or ticket identifier to embed in reports
  --serve               Serve the generated report in a local web UI
  --addr <host:port>    Address for --serve

Analysis depth:
  --full                Deeper defaults for entropy and disassembly
  --min-string <n>      Minimum string length
  --no-disasm           Skip disassembly, functions, and CFG
  --disasm-bytes <n>    Max bytes to disassemble from entry point
  --window <n>          Entropy sliding window size
  --step <n>            Entropy sliding window step

Artifacts:
  --no-visuals          Skip entropy/section/histogram PNGs
```
