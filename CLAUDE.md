# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

MCP server wrapping Hayabusa for EVTX (Windows Event Log) analysis. In addition to current functionality, also an MCP server providing a detection engineering knowledge base.

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
- `sigma_rules.py` — Sigma rule listing/lookup logic over `rules/`, backs the `detection://rules*` resources
- `attack_techniques.py` — ATT&CK technique/tactic lookup + rule-coverage assessment, backs `detection://attack/techniques/{id}` and the `analyze_coverage`/`suggest_rule` tools
- `hayabusa/` — downloaded Hayabusa binary + bundled Sigma rules (gitignored, see Setup)
- `rules/` — Sigma detection rules (YAML, gitignored, see Setup)
- `mappings/` — ATT&CK technique/tactic to rule mappings (`attack_techniques.json`, `attack_tactics.json`, generated, see Setup)

### Stack
- Python, using the `mcp` library
- Hayabusa CLI (installed locally, invoked as subprocess)

## Setup

- `uv sync`
- `python3 scripts/download_hayabusa.py` — downloads latest Hayabusa release for the current platform into `./hayabusa/` and creates a stable `./hayabusa/hayabusa` (or `.exe` on Windows) path pointing at the versioned binary. `./hayabusa/` is gitignored; re-run this script instead of committing the binary.
- `python3 scripts/download_attack_data.py` — downloads the MITRE ATT&CK Enterprise STIX bundle (~50MB) and extracts compact indexes (technique id/name/description/tactics, tactic shortname/id/name) to `mappings/attack_techniques.json` and `mappings/attack_tactics.json`. Re-run this script instead of committing the raw STIX bundle.
- `rules/` is populated separately from a Sigma rules mirror (e.g. SigmaHQ); it's gitignored, so clone/copy rules into it before using the `detection://rules*` resources.

## Status

`server.py` exposes four tools: `scan_evtx` (min_severity/rule_filter/tag_filter/output_format/max_results params), `get_hayabusa_rules` (keyword search over Hayabusa's bundled Sigma rules), `analyze_coverage` (technique ID or tactic name → coverage report across our Sigma rules), and `suggest_rule` (technique ID → detection-approach suggestion, optionally writing a Sigma rule skeleton to `rules/suggested/`).

It also exposes detection-KB resources backed by `rules/` (2941 Sigma rules from a SigmaHQ mirror) and `mappings/attack_techniques.json` (697 ATT&CK techniques) / `mappings/attack_tactics.json` (15 tactics):
- `detection://rules` — list all Sigma rules
- `detection://rules/{rule_name}` — get a rule's full YAML content by filename stem
- `detection://rules/by-technique/{technique_id}` — list rules tagged with a given ATT&CK technique
- `detection://attack/techniques/{technique_id}` — technique name/description + detecting rules + coverage assessment (`covered` ≥2 rules, `partial` 1 rule, `gap` 0 rules)
