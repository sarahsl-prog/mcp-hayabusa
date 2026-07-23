# mcp-hayabusa

MCP server wrapping [Hayabusa](https://github.com/Yamato-Security/hayabusa) for EVTX (Windows Event Log) analysis.

## Setup

```bash
uv sync
python3 scripts/download_hayabusa.py
```

`download_hayabusa.py` downloads the latest Hayabusa release for your platform into `./hayabusa/` and creates a stable `./hayabusa/hayabusa` (`.exe` on Windows) path. `./hayabusa/` is gitignored — re-run the script instead of committing the binary.

Sigma rules for the detection knowledge base are mirrored from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma.git) into `./rules/`:

```bash
git clone https://github.com/SigmaHQ/sigma.git sigma-rules
cp -r sigma-rules/rules ./rules
```

`./rules/` is gitignored — re-clone/pull and re-copy instead of committing the mirror.

ATT&CK technique metadata for the coverage-assessment resource is generated from the [MITRE ATT&CK STIX bundle](https://github.com/mitre-attack/attack-stix-data):

```bash
python3 scripts/download_attack_data.py
```

`download_attack_data.py` downloads the ~50MB STIX bundle and extracts compact indexes to `mappings/attack_techniques.json` (id/name/description/tactics) and `mappings/attack_tactics.json` (shortname → id/name). Re-run the script instead of committing the raw bundle.

## Running the server

```bash
uv run server.py
```

## Registering with Claude Code

Add to `.claude/settings.json`:

```json
{
  "mcpServers": {
    "hayabusa": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "."
    }
  }
}
```

## Tools

### `scan_evtx`

Scans an EVTX file with Hayabusa and returns structured results.

| Arg | Type | Description |
|-----|------|-------------|
| `file_path` | `str` | Path to the EVTX file to scan. |
| `min_severity` | `str \| None` | Optional minimum severity filter: `informational`, `low`, `medium`, `high`, `critical`. |
| `rule_filter` | `str \| None` | Optional substring to match against rule titles (e.g. `"lateral"` or `"mimikatz"`), case-insensitive. |
| `output_format` | `str` | `"summary"` (default, key fields only) or `"full"` (all fields Hayabusa reports). |
| `max_results` | `int \| None` | Optional cap on the number of findings returned. |
| `tag_filter` | `str \| None` | Optional comma-separated MITRE ATT&CK / rule tags to restrict which rules run (e.g. `"attack.credential-access"` or `"attack.credential-access,attack.lateral-movement"`). Use `get_hayabusa_rules` to discover available tags. |

Returns a dict with `finding_count` (total matches after filtering, before `max_results`), `returned_count` (findings actually returned), and `findings`.

### `get_hayabusa_rules`

Lists available Hayabusa detection rules, optionally filtered by keyword.

| Arg | Type | Description |
|-----|------|-------------|
| `keyword` | `str \| None` | Optional substring to match against a rule's title, description, or tags, case-insensitive. |

Returns a dict with `rule_count` and `rules` (each with `title`, `id`, `level`, `description`, `tags`, `path`).

### `analyze_coverage`

Analyzes detection coverage for an ATT&CK technique ID or tactic name, combining `mappings/attack_techniques.json`/`attack_tactics.json` with the Sigma rules under `./rules/`.

| Arg | Type | Description |
|-----|------|-------------|
| `identifier` | `str` | An ATT&CK technique ID (e.g. `"T1078"`, `"1003.001"`) or a tactic name (e.g. `"Credential Access"`, `"privilege-escalation"`). |

For a technique ID, returns a single-technique report. For a tactic name, returns a report across every technique in that tactic: `query`, `query_type`, `tactic`, `tactic_id`, `technique_count`, `covered_count`, `partial_count`, `gap_count`, `gaps` (technique entries with 0 detecting rules), and `techniques` (full per-technique breakdown, each with `technique_id`, `name`, `rule_count`, `coverage`). Returns an `error` key for an unrecognized ID or tactic name.

## Resources

### `detection://rules`

Lists all Sigma rules under `./rules/`.

Returns a dict with `rule_count` and `rules` (each with `rule_name`, `title`, `id`, `level`, `tags`, `path`).

### `detection://rules/{rule_name}`

Gets a specific Sigma rule's full YAML content by rule name (filename stem, e.g. `lnx_clear_syslog`).

Returns a dict with `rule_name`, `path`, and `rule` (the full parsed YAML). Returns an `error` key if no rule matches.

### `detection://rules/by-technique/{technique_id}`

Lists Sigma rules tagged with a given MITRE ATT&CK technique (e.g. `T1078`, `t1003.001`, or bare `1078`).

Returns a dict with `technique_id`, `rule_count`, and `rules` (same shape as `detection://rules`).

### `detection://attack/techniques/{technique_id}`

Gets an ATT&CK technique's name/description plus our detection coverage for it, cross-referencing `attack.tXXXX` tags on our Sigma rules. Requires `mappings/attack_techniques.json` (see Setup).

Returns a dict with `technique_id`, `name`, `description`, `tactics`, `detecting_rules`, `rule_count`, and `coverage` (`"covered"` at 2+ rules, `"partial"` at 1, `"gap"` at 0). Returns an `error` key for unknown technique IDs.
