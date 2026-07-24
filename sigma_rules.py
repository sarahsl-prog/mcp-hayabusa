"""Sigma rule knowledge base logic, backed by the rules/ directory."""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent
RULES_DIR = REPO_ROOT / "rules"


class RuleLookupError(Exception):
    """Raised for expected, user-facing rule lookup failures."""


def _load_rule(rule_path: Path) -> dict | None:
    try:
        with rule_path.open(encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict) or "title" not in doc:
        return None
    return doc


def _iter_rule_files():
    for rule_path in RULES_DIR.rglob("*.yml"):
        if ".git" in rule_path.parts:
            continue
        yield rule_path


def _rule_summary(rule_path: Path, doc: dict) -> dict:
    return {
        "rule_name": rule_path.stem,
        "title": doc.get("title", ""),
        "id": doc.get("id"),
        "level": doc.get("level"),
        "tags": doc.get("tags") or [],
        "path": str(rule_path.relative_to(RULES_DIR)),
    }


def list_rules() -> dict:
    """List all Sigma rules available under rules/.

    Always returns a JSON-serializable dict: either rules, or an "error" key
    describing what went wrong. Never raises.
    """
    try:
        if not RULES_DIR.exists():
            raise RuleLookupError(f"Rules directory not found at {RULES_DIR}")

        rules = []
        for rule_path in _iter_rule_files():
            doc = _load_rule(rule_path)
            if doc is None:
                continue
            rules.append(_rule_summary(rule_path, doc))

        rules.sort(key=lambda r: r["title"].lower())

        return {"rule_count": len(rules), "rules": rules}

    except RuleLookupError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


def get_rule(rule_name: str) -> dict:
    """Get a specific Sigma rule's full content by rule name (filename stem).

    Always returns a JSON-serializable dict: either the rule, or an "error"
    key describing what went wrong. Never raises.
    """
    try:
        if not RULES_DIR.exists():
            raise RuleLookupError(f"Rules directory not found at {RULES_DIR}")

        for rule_path in _iter_rule_files():
            if rule_path.stem != rule_name:
                continue
            doc = _load_rule(rule_path)
            if doc is None:
                raise RuleLookupError(f"Rule '{rule_name}' failed to parse as YAML")
            return {
                "rule_name": rule_name,
                "path": str(rule_path.relative_to(RULES_DIR)),
                "rule": doc,
            }

        raise RuleLookupError(f"No rule found with name '{rule_name}'")

    except RuleLookupError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


def count_rules_by_technique() -> dict[str, int]:
    """Count rules per ATT&CK technique tag in a single pass over rules/.

    Returns {technique_id (e.g. "T1078"): rule_count}. Used when checking
    many techniques at once, to avoid re-scanning rules/ per technique.
    Raises RuleLookupError if rules/ doesn't exist.
    """
    if not RULES_DIR.exists():
        raise RuleLookupError(f"Rules directory not found at {RULES_DIR}")

    counts: dict[str, int] = {}
    for rule_path in _iter_rule_files():
        doc = _load_rule(rule_path)
        if doc is None:
            continue
        for tag in doc.get("tags") or []:
            tag = tag.lower()
            if not tag.startswith("attack.t"):
                continue
            technique_id = tag.removeprefix("attack.").upper()
            counts[technique_id] = counts.get(technique_id, 0) + 1

    return counts


def list_rules_by_technique(technique_id: str) -> dict:
    """List rules tagged with a given MITRE ATT&CK technique ID (e.g. "T1078").

    Always returns a JSON-serializable dict: either rules, or an "error" key
    describing what went wrong. Never raises.
    """
    try:
        if not RULES_DIR.exists():
            raise RuleLookupError(f"Rules directory not found at {RULES_DIR}")

        normalized = technique_id.strip().lower()
        if not normalized:
            raise RuleLookupError("technique_id must not be empty")
        if not normalized.startswith("t"):
            normalized = f"t{normalized}"
        target_tag = f"attack.{normalized}"

        rules = []
        for rule_path in _iter_rule_files():
            doc = _load_rule(rule_path)
            if doc is None:
                continue
            tags = [t.lower() for t in (doc.get("tags") or [])]
            if target_tag not in tags:
                continue
            rules.append(_rule_summary(rule_path, doc))

        rules.sort(key=lambda r: r["title"].lower())

        return {
            "technique_id": technique_id,
            "rule_count": len(rules),
            "rules": rules,
        }

    except RuleLookupError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}
