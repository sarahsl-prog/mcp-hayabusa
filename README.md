# mcp-hayabusa

MCP server wrapping [Hayabusa](https://github.com/Yamato-Security/hayabusa) for EVTX (Windows Event Log) analysis.

## Setup

```bash
uv sync
python3 scripts/download_hayabusa.py
```

`download_hayabusa.py` downloads the latest Hayabusa release for your platform into `./hayabusa/` and creates a stable `./hayabusa/hayabusa` (`.exe` on Windows) path. `./hayabusa/` is gitignored — re-run the script instead of committing the binary.

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
