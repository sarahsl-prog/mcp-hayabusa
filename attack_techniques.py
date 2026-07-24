"""MITRE ATT&CK technique/tactic lookups and rule-coverage assessment.

Technique and tactic metadata is read from mappings/attack_techniques.json and
mappings/attack_tactics.json, compact indexes extracted from the ATT&CK STIX
bundle by scripts/download_attack_data.py. Coverage is computed by
cross-referencing technique IDs against the `attack.tXXXX` tags on our Sigma
rules.
"""

import datetime
import json
import re
import uuid
from pathlib import Path

import yaml

import sigma_rules

REPO_ROOT = Path(__file__).resolve().parent
TECHNIQUES_PATH = REPO_ROOT / "mappings" / "attack_techniques.json"
TACTICS_PATH = REPO_ROOT / "mappings" / "attack_tactics.json"
SUGGESTED_RULES_DIR = sigma_rules.RULES_DIR / "suggested"

# Rule-count thresholds for the coverage assessment.
_COVERED_MIN_RULES = 2
_PARTIAL_MIN_RULES = 1

_TECHNIQUE_ID_RE = re.compile(r"^T?\d{4}(\.\d{3})?$", re.IGNORECASE)

# Generic pointers to the log sources most likely to surface each tactic,
# keyed by ATT&CK tactic shortname. Not technique-specific — a starting
# point for a human to refine, not a ready-to-run detection.
_TACTIC_DETECTION_HINTS = {
    "initial-access": "web/email delivery logs and process_creation events for payload execution",
    "execution": "process_creation and command-line logging (e.g. Sysmon EID 1, Security 4688)",
    "persistence": "registry, scheduled task, and service creation events",
    "privilege-escalation": "process access/token manipulation and privilege-use events",
    "defense-evasion": "process/file/registry tampering and log-clearing events",
    "stealth": "anti-forensic and log-tampering events",
    "defense-impairment": "security tool tampering and service-stop events",
    "credential-access": "LSASS access, credential-dumping tool execution, and authentication logs",
    "discovery": "command-line logging for recon utilities (net, whoami, systeminfo, etc.)",
    "lateral-movement": "network logon, WMI, and remote service creation events",
    "collection": "file access and clipboard/screen-capture events",
    "command-and-control": "network connection and DNS logs for C2 beaconing patterns",
    "exfiltration": "network traffic volume/destination anomalies and archive-creation events",
    "impact": "file/service modification and system state-change events",
    "reconnaissance": "external scanning/OSINT indicators, typically outside host telemetry",
    "resource-development": "infrastructure/threat-intel sources, typically outside host telemetry",
}
_DEFAULT_DETECTION_HINT = "process, file, and log activity associated with this technique"


class TechniqueLookupError(Exception):
    """Raised for expected, user-facing technique/tactic lookup failures."""


def _normalize_technique_id(technique_id: str) -> str:
    normalized = technique_id.strip().upper()
    if not normalized:
        raise TechniqueLookupError("technique_id must not be empty")
    if not normalized.startswith("T"):
        normalized = f"T{normalized}"
    return normalized


def _load_json(path: Path) -> dict:
    if not path.exists():
        raise TechniqueLookupError(
            f"ATT&CK data not found at {path}. "
            "Run scripts/download_attack_data.py to fetch it."
        )
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _load_techniques() -> dict:
    return _load_json(TECHNIQUES_PATH)


def _load_tactics() -> dict:
    return _load_json(TACTICS_PATH)


def _assess_coverage(rule_count: int) -> str:
    if rule_count >= _COVERED_MIN_RULES:
        return "covered"
    if rule_count >= _PARTIAL_MIN_RULES:
        return "partial"
    return "gap"


def get_technique(technique_id: str) -> dict:
    """Get an ATT&CK technique's name/description plus our rule coverage for it.

    Always returns a JSON-serializable dict: either the technique details, or
    an "error" key describing what went wrong. Never raises.
    """
    try:
        normalized_id = _normalize_technique_id(technique_id)
        techniques = _load_techniques()

        technique = techniques.get(normalized_id)
        if technique is None:
            raise TechniqueLookupError(
                f"Unknown ATT&CK technique '{technique_id}'. "
                "Check the ID or re-run scripts/download_attack_data.py."
            )

        detecting = sigma_rules.list_rules_by_technique(normalized_id)
        if "error" in detecting:
            raise TechniqueLookupError(detecting["error"])

        rule_count = detecting["rule_count"]

        return {
            "technique_id": normalized_id,
            "name": technique["name"],
            "description": technique["description"],
            "tactics": technique.get("tactics", []),
            "detecting_rules": detecting["rules"],
            "rule_count": rule_count,
            "coverage": _assess_coverage(rule_count),
        }

    except TechniqueLookupError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


def _resolve_tactic_shortname(tactic_name: str, tactics: dict) -> str:
    needle = tactic_name.strip().lower()
    if not needle:
        raise TechniqueLookupError("tactic name must not be empty")

    # Direct shortname match (e.g. "privilege-escalation").
    if needle in tactics:
        return needle

    # Match against the display name, allowing space/dash interchange
    # (e.g. "Privilege Escalation" or "privilege escalation").
    needle_dashed = needle.replace(" ", "-")
    for shortname, info in tactics.items():
        if info["name"].strip().lower() == needle or shortname == needle_dashed:
            return shortname

    raise TechniqueLookupError(
        f"Unknown ATT&CK tactic '{tactic_name}'. "
        f"Known tactics: {', '.join(sorted(t['name'] for t in tactics.values()))}"
    )


def analyze_coverage(identifier: str) -> dict:
    """Analyze detection coverage for an ATT&CK technique ID or tactic name.

    If `identifier` looks like a technique ID (e.g. "T1078", "1003.001"),
    returns a single-technique coverage report. Otherwise treats it as a
    tactic name (e.g. "Credential Access", "privilege-escalation") and
    returns a coverage report across every technique in that tactic.

    Always returns a JSON-serializable dict: either the coverage report, or
    an "error" key describing what went wrong. Never raises.
    """
    try:
        identifier = identifier.strip()
        if not identifier:
            raise TechniqueLookupError("identifier must not be empty")

        if _TECHNIQUE_ID_RE.match(identifier):
            technique = get_technique(identifier)
            if "error" in technique:
                return technique
            return {
                "query": identifier,
                "query_type": "technique",
                "technique_count": 1,
                "covered_count": int(technique["coverage"] == "covered"),
                "partial_count": int(technique["coverage"] == "partial"),
                "gap_count": int(technique["coverage"] == "gap"),
                "techniques": [
                    {
                        "technique_id": technique["technique_id"],
                        "name": technique["name"],
                        "rule_count": technique["rule_count"],
                        "coverage": technique["coverage"],
                    }
                ],
            }

        techniques = _load_techniques()
        tactics = _load_tactics()
        shortname = _resolve_tactic_shortname(identifier, tactics)

        try:
            rule_counts = sigma_rules.count_rules_by_technique()
        except sigma_rules.RuleLookupError as e:
            raise TechniqueLookupError(str(e)) from e

        results = []
        for technique_id, technique in techniques.items():
            if shortname not in technique.get("tactics", []):
                continue
            rule_count = rule_counts.get(technique_id, 0)
            results.append(
                {
                    "technique_id": technique_id,
                    "name": technique["name"],
                    "rule_count": rule_count,
                    "coverage": _assess_coverage(rule_count),
                }
            )

        results.sort(key=lambda r: r["technique_id"])

        covered = [r for r in results if r["coverage"] == "covered"]
        partial = [r for r in results if r["coverage"] == "partial"]
        gaps = [r for r in results if r["coverage"] == "gap"]

        return {
            "query": identifier,
            "query_type": "tactic",
            "tactic": tactics[shortname]["name"],
            "tactic_id": tactics[shortname]["id"],
            "technique_count": len(results),
            "covered_count": len(covered),
            "partial_count": len(partial),
            "gap_count": len(gaps),
            "gaps": gaps,
            "techniques": results,
        }

    except TechniqueLookupError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


def _detection_hint(tactics: list) -> str:
    for tactic in tactics:
        if tactic in _TACTIC_DETECTION_HINTS:
            return _TACTIC_DETECTION_HINTS[tactic]
    return _DEFAULT_DETECTION_HINT


def _mitre_url(technique_id: str) -> str:
    base, _, sub = technique_id.partition(".")
    path = f"{base}/{sub}" if sub else base
    return f"https://attack.mitre.org/techniques/{path}"


def _build_rule_template(technique: dict) -> dict:
    technique_id = technique["technique_id"]
    tactics = technique["tactics"]

    return {
        "title": f"{technique['name']} (Suggested Detection)",
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": (
            f"Suggested detection template for MITRE ATT&CK technique {technique_id} "
            f"({technique['name']}). Generated as a starting point to close a coverage "
            "gap — TODO: replace the selection logic with real telemetry fields before use."
        ),
        "references": [_mitre_url(technique_id)],
        "author": "suggest_rule tool (mcp-hayabusa)",
        "date": datetime.date.today().isoformat(),
        "tags": sorted({f"attack.{t}" for t in tactics} | {f"attack.{technique_id.lower()}"}),
        "logsource": {
            "product": "TODO",
            "category": "TODO",
        },
        "detection": {
            "selection": {
                "TODO_FieldName|contains": "TODO_value",
            },
            "condition": "selection",
        },
        "falsepositives": ["Unknown"],
        "level": "medium",
    }


def _write_rule_template(technique_id: str, rule: dict) -> str:
    filename = f"{technique_id.lower().replace('.', '_')}_suggested.yml"
    dest_path = SUGGESTED_RULES_DIR / filename

    if dest_path.exists():
        raise TechniqueLookupError(
            f"Suggested rule already exists at {dest_path.relative_to(sigma_rules.RULES_DIR)}"
        )

    SUGGESTED_RULES_DIR.mkdir(parents=True, exist_ok=True)
    with dest_path.open("w", encoding="utf-8") as f:
        yaml.dump(rule, f, sort_keys=False, default_flow_style=False, allow_unicode=True)

    return str(dest_path.relative_to(sigma_rules.RULES_DIR))


def suggest_rule(technique_id: str, create_template: bool = False) -> dict:
    """Check coverage for an ATT&CK technique and suggest a detection approach.

    If we already have rules covering the technique, reports that coverage
    instead of suggesting anything new. Otherwise (partial or gap coverage)
    returns a suggested detection approach based on the technique's tactics,
    and — if `create_template` is True — writes a Sigma rule skeleton to
    rules/suggested/ for a human to fill in and refine.

    Always returns a JSON-serializable dict: either the suggestion, or an
    "error" key describing what went wrong. Never raises.
    """
    try:
        technique = get_technique(technique_id)
        if "error" in technique:
            return technique

        result = {
            "technique_id": technique["technique_id"],
            "name": technique["name"],
            "coverage": technique["coverage"],
            "rule_count": technique["rule_count"],
            "detecting_rules": technique["detecting_rules"],
        }

        if technique["coverage"] == "covered":
            result["message"] = (
                f"Already covered by {technique['rule_count']} rule(s); no suggestion needed."
            )
            return result

        result["suggested_approach"] = (
            f"No strong existing coverage for {technique['technique_id']} "
            f"({technique['name']}). Focus on: {_detection_hint(technique['tactics'])}. "
            f"Technique summary: {technique['description'][:300].rstrip()}..."
        )

        if create_template:
            rule = _build_rule_template(technique)
            result["template_path"] = _write_rule_template(technique["technique_id"], rule)
            result["template_rule_id"] = rule["id"]
        else:
            result["template_path"] = None

        return result

    except TechniqueLookupError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}
