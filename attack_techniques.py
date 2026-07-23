"""MITRE ATT&CK technique/tactic lookups and rule-coverage assessment.

Technique and tactic metadata is read from mappings/attack_techniques.json and
mappings/attack_tactics.json, compact indexes extracted from the ATT&CK STIX
bundle by scripts/download_attack_data.py. Coverage is computed by
cross-referencing technique IDs against the `attack.tXXXX` tags on our Sigma
rules.
"""

import json
import re
from pathlib import Path

import sigma_rules

REPO_ROOT = Path(__file__).resolve().parent
TECHNIQUES_PATH = REPO_ROOT / "mappings" / "attack_techniques.json"
TACTICS_PATH = REPO_ROOT / "mappings" / "attack_tactics.json"

# Rule-count thresholds for the coverage assessment.
_COVERED_MIN_RULES = 2
_PARTIAL_MIN_RULES = 1

_TECHNIQUE_ID_RE = re.compile(r"^T?\d{4}(\.\d{3})?$", re.IGNORECASE)


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
