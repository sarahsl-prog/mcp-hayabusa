# MLflow Tool-Call Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every call to one of the four Hayabusa MCP tools (`scan_evtx`, `get_hayabusa_rules`, `analyze_coverage`, `suggest_rule`) is logged as an MLflow run, tagged with the invoking user and tool name, with call params and result metrics recorded.

**Architecture:** A new `mlflow_logging.py` module owns MLflow configuration (tracking URI, experiment) and exposes a single decorator, `log_tool_call`, that wraps a tool function: starts an MLflow run, logs the call's kwargs as params, tags the run with tool name + user + status, invokes the wrapped function, logs numeric/short-string fields from its returned dict as metrics/tags, and closes the run — even on exception. `server.py` applies the decorator to all four `@mcp.tool()` functions. No changes to `scanner.py` / `sigma_rules.py` / `attack_techniques.py` — logging wraps at the MCP boundary only.

**Tech Stack:** `mlflow` (new dependency), Python stdlib (`os`, `time`, `functools`, `getpass`).

## Global Constraints

- Tracking URI: read from `MLFLOW_TRACKING_URI` env var; fall back to local file store `./mlruns` if unset.
- User: read from `MLFLOW_TRACKING_USER` env var; fall back to `getpass.getuser()` (OS user) if unset.
- Applies to all four existing tools: `scan_evtx`, `get_hayabusa_rules`, `analyze_coverage`, `suggest_rule`.
- `./mlruns` must be gitignored — it's a local run store, not committed data.
- Logging must never break tool behavior: if MLflow itself errors (e.g. bad tracking URI), the tool must still run and return its normal result — logging failures are swallowed, not raised.
- Existing tool return shape and `@mcp.tool()` signature (as seen by FastMCP's schema introspection) must be unchanged.

---

### Task 1: Add MLflow dependency and gitignore entry

**Files:**
- Modify: `pyproject.toml`
- Modify: `.gitignore`

- [ ] **Step 1: Add the dependency**

In `pyproject.toml`, add `"mlflow>=2.9.0,<3.0.0"` to the `dependencies` list (alongside `mcp`, `pydantic`, `pyyaml`).

- [ ] **Step 2: Install it**

Run: `uv sync`
Expected: resolves and installs `mlflow` and its transitive deps without conflict.

- [ ] **Step 3: Ignore the local run store**

In `.gitignore`, add a new line: `mlruns/`

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml uv.lock .gitignore
git commit -m "Add mlflow dependency for tool-call logging"
```

---

### Task 2: `mlflow_logging.py` — configuration + decorator

**Files:**
- Create: `mlflow_logging.py`
- Test: `tests/test_mlflow_logging.py`

**Interfaces:**
- Produces: `log_tool_call(func)` — a decorator with no arguments, importable as `from mlflow_logging import log_tool_call`. Wraps a function `f(**kwargs) -> dict` (all four tool functions are called with keyword-compatible signatures) and returns a function with the same signature (via `functools.wraps`, so `inspect.signature` still sees the original params — required for FastMCP's schema generation).
- Produces: `configure()` — idempotent, sets `mlflow.set_tracking_uri(...)` and `mlflow.set_experiment("hayabusa-mcp")` from env vars. Called once at import time by `mlflow_logging.py` itself, and again safely by tests that need a different tracking URI.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_mlflow_logging.py
import os

import mlflow
import pytest

import mlflow_logging


@pytest.fixture
def tracking_dir(tmp_path, monkeypatch):
    uri = f"file://{tmp_path}/mlruns"
    monkeypatch.setenv("MLFLOW_TRACKING_URI", uri)
    monkeypatch.delenv("MLFLOW_TRACKING_USER", raising=False)
    mlflow_logging.configure()
    yield tmp_path
    mlflow.set_tracking_uri(None)


def _latest_run():
    client = mlflow.MlflowClient()
    exp = client.get_experiment_by_name("hayabusa-mcp")
    runs = client.search_runs([exp.experiment_id], order_by=["start_time DESC"])
    return runs[0]


def test_logs_params_and_metrics_on_success(tracking_dir):
    @mlflow_logging.log_tool_call
    def scan_evtx(file_path, min_severity=None):
        return {"file": file_path, "finding_count": 3, "returned_count": 3}

    result = scan_evtx(file_path="/tmp/x.evtx", min_severity="high")

    assert result == {"file": "/tmp/x.evtx", "finding_count": 3, "returned_count": 3}
    run = _latest_run()
    assert run.data.params["file_path"] == "/tmp/x.evtx"
    assert run.data.params["min_severity"] == "high"
    assert run.data.metrics["finding_count"] == 3
    assert run.data.metrics["returned_count"] == 3
    assert run.data.tags["tool_name"] == "scan_evtx"
    assert run.data.tags["status"] == "success"


def test_tags_error_status_on_error_result(tracking_dir):
    @mlflow_logging.log_tool_call
    def get_hayabusa_rules(keyword=None):
        return {"error": "rules dir not found"}

    result = get_hayabusa_rules(keyword="mimikatz")

    assert result == {"error": "rules dir not found"}
    run = _latest_run()
    assert run.data.tags["status"] == "error"
    assert run.data.tags["error"] == "rules dir not found"


def test_reraises_and_still_closes_run_on_exception(tracking_dir):
    @mlflow_logging.log_tool_call
    def broken(x):
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        broken(x=1)

    run = _latest_run()
    assert run.data.tags["status"] == "exception"
    assert mlflow.active_run() is None


def test_user_tag_from_env(tracking_dir, monkeypatch):
    monkeypatch.setenv("MLFLOW_TRACKING_USER", "sarahsl-prog")

    @mlflow_logging.log_tool_call
    def analyze_coverage(identifier):
        return {"identifier": identifier}

    analyze_coverage(identifier="T1078")

    run = _latest_run()
    assert run.data.tags["mlflow.user"] == "sarahsl-prog"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_mlflow_logging.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mlflow_logging'`

- [ ] **Step 3: Write the implementation**

```python
# mlflow_logging.py
"""MLflow tool-call logging for the Hayabusa MCP server.

Wraps MCP tool functions so each call is recorded as an MLflow run:
call params, a user/tool tag, and any numeric/short-string fields from
the tool's returned dict as metrics/tags. Logging failures never break
the wrapped tool.
"""

from __future__ import annotations

import functools
import getpass
import os

import mlflow

EXPERIMENT_NAME = "hayabusa-mcp"

_MAX_TAG_LEN = 250


def configure() -> None:
    """Point MLflow at the configured tracking store and experiment."""
    tracking_uri = os.environ.get("MLFLOW_TRACKING_URI", "./mlruns")
    mlflow.set_tracking_uri(tracking_uri)
    mlflow.set_experiment(EXPERIMENT_NAME)


def _current_user() -> str:
    return os.environ.get("MLFLOW_TRACKING_USER") or getpass.getuser()


def _log_result_fields(result: dict) -> None:
    for key, value in result.items():
        if key == "error":
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            mlflow.log_metric(key, value)
        elif isinstance(value, str) and len(value) <= _MAX_TAG_LEN:
            mlflow.set_tag(key, value)


def log_tool_call(func):
    """Decorator: log a call to an MCP tool function as an MLflow run."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            configure()
            mlflow.start_run(run_name=func.__name__)
            mlflow.set_tag("mlflow.user", _current_user())
            mlflow.set_tag("tool_name", func.__name__)
            for key, value in kwargs.items():
                mlflow.log_param(key, value)
        except Exception:
            # Logging must never block the tool itself.
            if mlflow.active_run() is not None:
                mlflow.end_run()
            return func(*args, **kwargs)

        try:
            result = func(*args, **kwargs)
        except Exception:
            mlflow.set_tag("status", "exception")
            mlflow.end_run()
            raise

        try:
            if isinstance(result, dict) and "error" in result:
                mlflow.set_tag("status", "error")
                mlflow.set_tag("error", str(result["error"])[:_MAX_TAG_LEN])
            else:
                mlflow.set_tag("status", "success")
            if isinstance(result, dict):
                _log_result_fields(result)
        finally:
            mlflow.end_run()

        return result

    return wrapper
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_mlflow_logging.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add mlflow_logging.py tests/test_mlflow_logging.py
git commit -m "Add mlflow_logging module with log_tool_call decorator"
```

---

### Task 3: Wire logging into the four MCP tools

**Files:**
- Modify: `server.py`
- Test: `tests/test_server_logging.py`

**Interfaces:**
- Consumes: `mlflow_logging.log_tool_call` (Task 2), `mlflow_logging.configure` (Task 2).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_server_logging.py
import inspect

import mlflow
import pytest

import server


@pytest.fixture
def tracking_dir(tmp_path, monkeypatch):
    uri = f"file://{tmp_path}/mlruns"
    monkeypatch.setenv("MLFLOW_TRACKING_URI", uri)
    yield tmp_path
    mlflow.set_tracking_uri(None)


TOOL_FUNCS = [
    (server.scan_evtx, {"file_path": "/nonexistent/x.evtx"}),
    (server.get_hayabusa_rules, {"keyword": "mimikatz"}),
    (server.analyze_coverage, {"identifier": "T1078"}),
    (server.suggest_rule, {"technique_id": "T1078"}),
]


@pytest.mark.parametrize("func,kwargs", TOOL_FUNCS, ids=[f.__name__ for f, _ in TOOL_FUNCS])
def test_tool_logs_a_run(tracking_dir, func, kwargs):
    result = func(**kwargs)

    assert isinstance(result, dict)
    client = mlflow.MlflowClient()
    exp = client.get_experiment_by_name(mlflow_logging_experiment_name())
    runs = client.search_runs([exp.experiment_id])
    assert any(r.data.tags.get("tool_name") == func.__name__ for r in runs)


def mlflow_logging_experiment_name():
    import mlflow_logging

    return mlflow_logging.EXPERIMENT_NAME


@pytest.mark.parametrize("func,_", TOOL_FUNCS, ids=[f.__name__ for f, _ in TOOL_FUNCS])
def test_tool_signature_unchanged_for_fastmcp_introspection(func, _):
    sig = inspect.signature(func)
    assert list(sig.parameters) == list(server._ORIGINAL_SIGNATURES[func.__name__])
```

Add, in `server.py`, right after the imports, a small fixture the second test above depends on — a dict of original parameter names captured before wrapping (used only to prove wrapping didn't change what FastMCP sees):

```python
_ORIGINAL_SIGNATURES = {
    "scan_evtx": ["file_path", "min_severity", "rule_filter", "output_format", "max_results", "tag_filter"],
    "get_hayabusa_rules": ["keyword"],
    "analyze_coverage": ["identifier"],
    "suggest_rule": ["technique_id", "create_template"],
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_server_logging.py -v`
Expected: FAIL — `server._ORIGINAL_SIGNATURES` doesn't exist yet, and no runs are tagged since the decorator isn't wired in.

- [ ] **Step 3: Wire the decorator into `server.py`**

Modify `server.py`: add the import and the `_ORIGINAL_SIGNATURES` dict, then decorate each tool function with `@mlflow_logging.log_tool_call`, placed *between* `@mcp.tool()` and the `def`, so FastMCP still sees the original signature via `functools.wraps`:

```python
#!/usr/bin/env python3
"""MCP server wrapping Hayabusa for EVTX analysis."""

from mcp.server.fastmcp import FastMCP

import attack_techniques
import mlflow_logging
import scanner
import sigma_rules

mcp = FastMCP("hayabusa")

_ORIGINAL_SIGNATURES = {
    "scan_evtx": ["file_path", "min_severity", "rule_filter", "output_format", "max_results", "tag_filter"],
    "get_hayabusa_rules": ["keyword"],
    "analyze_coverage": ["identifier"],
    "suggest_rule": ["technique_id", "create_template"],
}


@mcp.tool()
@mlflow_logging.log_tool_call
def scan_evtx(
    file_path: str,
    min_severity: str | None = None,
    rule_filter: str | None = None,
    output_format: str = "summary",
    max_results: int | None = None,
    tag_filter: str | None = None,
) -> dict:
    """Scan an EVTX file with Hayabusa and return structured results.

    Args:
        file_path: Path to the EVTX file to scan.
        min_severity: Optional minimum severity level to filter results
            (informational, low, medium, high, critical).
        rule_filter: Optional substring to match against rule titles
            (e.g. "lateral" or "mimikatz"), case-insensitive.
        output_format: "summary" (default, key fields only) or "full"
            (all fields Hayabusa reports).
        max_results: Optional cap on the number of findings returned.
        tag_filter: Optional comma-separated MITRE ATT&CK / rule tags to
            restrict which rules run (e.g. "attack.credential-access" or
            "attack.credential-access,attack.lateral-movement"). Use
            get_hayabusa_rules to discover available tags.
    """
    return scanner.scan_evtx(
        file_path, min_severity, rule_filter, output_format, max_results, tag_filter
    )


@mcp.tool()
@mlflow_logging.log_tool_call
def get_hayabusa_rules(keyword: str | None = None) -> dict:
    """List available Hayabusa detection rules, optionally filtered by keyword.

    Args:
        keyword: Optional substring to match against a rule's title,
            description, or tags (e.g. "mimikatz" or "lateral"),
            case-insensitive.
    """
    return scanner.list_rules(keyword)


@mcp.tool()
@mlflow_logging.log_tool_call
def analyze_coverage(identifier: str) -> dict:
    """Analyze detection coverage for an ATT&CK technique ID or tactic name.

    Args:
        identifier: An ATT&CK technique ID (e.g. "T1078", "1003.001") or a
            tactic name (e.g. "Credential Access", "privilege-escalation").
            Reports which techniques are covered, partially covered, or
            gaps based on our Sigma rules' `attack.tXXXX` tags.
    """
    return attack_techniques.analyze_coverage(identifier)


@mcp.tool()
@mlflow_logging.log_tool_call
def suggest_rule(technique_id: str, create_template: bool = False) -> dict:
    """Check coverage for an ATT&CK technique and suggest a detection approach.

    If we already have rules covering the technique, reports that coverage
    instead of suggesting anything new. Otherwise returns a suggested
    detection approach and, if requested, writes a Sigma rule skeleton to
    rules/suggested/ for a human to fill in and refine.

    Args:
        technique_id: An ATT&CK technique ID (e.g. "T1078", "1003.001").
        create_template: If True, write a Sigma rule skeleton to
            rules/suggested/ when coverage is missing or partial. Does
            nothing if a template already exists there for this technique.
    """
    return attack_techniques.suggest_rule(technique_id, create_template)


@mcp.resource("detection://rules")
def list_sigma_rules() -> dict:
    """List all Sigma detection rules available under rules/."""
    return sigma_rules.list_rules()


@mcp.resource("detection://rules/{rule_name}")
def get_sigma_rule(rule_name: str) -> dict:
    """Get a specific Sigma rule's full content by rule name (filename stem)."""
    return sigma_rules.get_rule(rule_name)


@mcp.resource("detection://rules/by-technique/{technique_id}")
def get_sigma_rules_by_technique(technique_id: str) -> dict:
    """List Sigma rules tagged with a given MITRE ATT&CK technique ID (e.g. T1078)."""
    return sigma_rules.list_rules_by_technique(technique_id)


@mcp.resource("detection://attack/techniques/{technique_id}")
def get_attack_technique(technique_id: str) -> dict:
    """Get an ATT&CK technique's name/description, detecting rules, and coverage."""
    return attack_techniques.get_technique(technique_id)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_server_logging.py -v`
Expected: 8 passed (4 tools × 2 tests)

- [ ] **Step 5: Run the full existing suite to check for regressions**

Run: `uv run pytest -v`
Expected: all tests pass, including pre-existing `tests/test_scan_evtx.py`.

- [ ] **Step 6: Commit**

```bash
git add server.py tests/test_server_logging.py
git commit -m "Log every MCP tool call to MLflow"
```

---

### Task 4: Document the MLflow env vars

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add a short section to `README.md`**

Add a section (wherever setup/config is documented) covering:

```markdown
## Tool-call logging (MLflow)

Every call to `scan_evtx`, `get_hayabusa_rules`, `analyze_coverage`, and
`suggest_rule` is logged as an MLflow run under the `hayabusa-mcp`
experiment.

- `MLFLOW_TRACKING_URI` — where runs are stored. Defaults to a local
  `./mlruns` directory if unset. Set this to point at a shared MLflow
  tracking server instead.
- `MLFLOW_TRACKING_USER` — the user tagged on each run. Defaults to the
  local OS username (`getpass.getuser()`) if unset.

View logged runs with `uv run mlflow ui --backend-store-uri ./mlruns`.
```

- [ ] **Step 2: Update `CLAUDE.md`**

In the `### Structure` list, add:

```markdown
- `mlflow_logging.py` — MLflow run logging for MCP tool calls (params, result metrics, user/tool tags), wraps all four tools in `server.py`
```

In the `## Status` section, append one sentence noting all four tools now log to MLflow (tracking URI via `MLFLOW_TRACKING_URI`, user via `MLFLOW_TRACKING_USER`).

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "Document MLflow tool-call logging env vars"
```
