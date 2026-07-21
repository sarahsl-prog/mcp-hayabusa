# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

MCP server wrapping Hayabusa for EVTX (Windows Event Log) analysis, and expanding into a detection engineering knowledge base.

### Goals
- Expose a `scan_evtx` tool that runs Hayabusa against EVTX files
- Return results as structured JSON
- Support filtering by severity level, rule title, and MITRE ATT&CK tag
- Handle errors gracefully
- Expose Sigma rules as browsable resources
- Expose ATT&CK technique mappings
- Allow Claude to query detection coverage
- Combine with Hayabusa scanning from Module 3

### Structure
- `server.py` — MCP server with resources and tools
- `scanner.py` — Hayabusa scan/rule-listing logic, shared by server entry points
- `hayabusa/` — downloaded Hayabusa binary + bundled Sigma rules (gitignored, see Setup)
- `rules/` — Sigma detection rules (YAML)
- `mappings/` — ATT&CK technique to rule mappings

### Stack
- Python, using the `mcp` library
- Hayabusa CLI (installed locally, invoked as subprocess)

## Setup

- `uv sync`
- `python3 scripts/download_hayabusa.py` — downloads latest Hayabusa release for the current platform into `./hayabusa/` and creates a stable `./hayabusa/hayabusa` (or `.exe` on Windows) path pointing at the versioned binary. `./hayabusa/` is gitignored; re-run this script instead of committing the binary.

## Status

`server.py` exposes two tools: `scan_evtx` (min_severity/rule_filter/tag_filter/output_format/max_results params) and `get_hayabusa_rules` (keyword search over Hayabusa's bundled Sigma rules). `rules/` and `mappings/` for the detection-coverage knowledge base don't exist yet.
