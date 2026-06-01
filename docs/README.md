# retract Documentation

This directory contains the project documentation for `retract`.

## Contents

- [Usage](USAGE.md): command line options and examples.
- [Architecture](ARCHITECTURE.md): module layout and analysis pipeline.
- [Output](OUTPUT.md): generated artifact layout.
- [Web UI](WEB_UI.md): local web workbench.
- [Deep Analysis](DEEP_ANALYSIS.md): project database, search index, data flow, graph analysis, and hex metadata.
- [Development](DEVELOPMENT.md): build, test, scripts, and project conventions.

## Build

```sh
scripts/build.sh
```

## Analyze

```sh
bin/retract <file> --full --verbose
```

## Serve

```sh
bin/retract <file> --full --serve --addr 127.0.0.1:8787
```
