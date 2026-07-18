# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

MCP server wrapping Hayabusa for EVTX (Windows Event Log) analysis.

### Goals
- Expose a `scan_evtx` tool that runs Hayabusa against EVTX files
- Return results as structured JSON
- Support filtering by severity level
- Handle errors gracefully

### Stack
- Python, using the `mcp` library
- Hayabusa CLI (installed locally, invoked as subprocess)

## Setup

- `uv sync`
- `python3 scripts/download_hayabusa.py` — downloads latest Hayabusa release for the current platform into `./hayabusa/` and creates a stable `./hayabusa/hayabusa` (or `.exe` on Windows) path pointing at the versioned binary. `./hayabusa/` is gitignored; re-run this script instead of committing the binary.

## Status

No server source code yet (`scripts/download_hayabusa.py` is the only code so far). This file will need commands (run/lint/test) and architecture notes added once the MCP server is scaffolded.
