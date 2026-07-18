"""Hayabusa EVTX scanning logic, shared by both MCP server implementations."""

import json
import platform
import subprocess
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
HAYABUSA_DIR = REPO_ROOT / "hayabusa"

VALID_SEVERITIES = ["informational", "low", "medium", "high", "critical"]

_SEVERITY_ALIASES = {
    "info": "informational",
    "med": "medium",
    "crit": "critical",
}

SCAN_TIMEOUT_SECONDS = 300


class ScanError(Exception):
    """Raised for expected, user-facing scan failures."""


def _hayabusa_binary() -> Path:
    name = "hayabusa.exe" if platform.system().lower() == "windows" else "hayabusa"
    return HAYABUSA_DIR / name


def _normalize_severity(min_severity: str | None) -> str | None:
    if min_severity is None:
        return None
    key = min_severity.strip().lower()
    normalized = _SEVERITY_ALIASES.get(key, key)
    if normalized not in VALID_SEVERITIES:
        raise ScanError(
            f"Invalid min_severity '{min_severity}'. Must be one of: {', '.join(VALID_SEVERITIES)}"
        )
    return normalized


def scan_evtx(file_path: str, min_severity: str | None = None) -> dict:
    """Run Hayabusa against an EVTX file and return structured findings.

    Always returns a JSON-serializable dict: either findings, or an "error"
    key describing what went wrong. Never raises.
    """
    try:
        evtx_path = Path(file_path).expanduser()
        if not evtx_path.exists():
            raise ScanError(f"EVTX file not found: {evtx_path}")
        if not evtx_path.is_file():
            raise ScanError(f"Not a file: {evtx_path}")

        binary = _hayabusa_binary()
        if not binary.exists():
            raise ScanError(
                f"Hayabusa binary not found at {binary}. "
                "Run scripts/download_hayabusa.py to install it."
            )

        severity = _normalize_severity(min_severity)

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "results.jsonl"
            cmd = [
                str(binary),
                "json-timeline",
                "-f", str(evtx_path),
                "-L",
                "-o", str(output_path),
                "-w",
                "-C",
                "-Q",
            ]
            if severity:
                cmd += ["-m", severity]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=SCAN_TIMEOUT_SECONDS,
                )
            except FileNotFoundError as e:
                raise ScanError(f"Failed to execute Hayabusa binary at {binary}: {e}") from e
            except subprocess.TimeoutExpired as e:
                raise ScanError(
                    f"Hayabusa scan timed out after {SCAN_TIMEOUT_SECONDS}s"
                ) from e

            if result.returncode != 0:
                raise ScanError(
                    f"Hayabusa scan failed (exit {result.returncode}): "
                    f"{result.stderr.strip()[:2000]}"
                )

            findings = []
            if output_path.exists():
                with output_path.open(encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        return {
            "file": str(evtx_path),
            "min_severity": severity,
            "finding_count": len(findings),
            "findings": findings,
        }

    except ScanError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}
