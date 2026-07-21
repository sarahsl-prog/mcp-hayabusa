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
