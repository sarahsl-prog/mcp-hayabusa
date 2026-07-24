#!/usr/bin/env python3
"""Validate a Sigma rule against this repo's detection-engineering standards.

Usage: python3 scripts/validate-rule.py <path-to-rule.yml>

Checks (see .claude/skills/detection-engineering/SKILL.md):
1. `tags` includes at least one attack.tXXXX technique tag
2. `level` is one of low/medium/high/critical
3. `falsepositives` is present and not a bare "Unknown"
4. At least one test case is documented (a `# test case` style comment,
   or a `references` entry pointing at a sample/PoC)
"""

import json
import re
import sys
from pathlib import Path

import yaml

ATTACK_TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)
VALID_LEVELS = {"low", "medium", "high", "critical"}
TEST_CASE_COMMENT_RE = re.compile(r"#.*test\s*case", re.IGNORECASE)


def validate_rule(path: Path) -> dict:
    issues = []
    raw_text = path.read_text()

    try:
        rule = yaml.safe_load(raw_text)
    except yaml.YAMLError as e:
        return {
            "file": str(path),
            "valid": False,
            "issues": [f"Failed to parse YAML: {e}"],
        }

    if not isinstance(rule, dict):
        return {
            "file": str(path),
            "valid": False,
            "issues": ["Rule does not parse to a YAML mapping"],
        }

    tags = rule.get("tags") or []
    if not any(ATTACK_TECHNIQUE_RE.match(str(t)) for t in tags):
        issues.append(
            "No ATT&CK technique tag found in `tags` (expected attack.tXXXX format)"
        )

    level = rule.get("level")
    if level not in VALID_LEVELS:
        issues.append(
            f"`level` is {level!r}, must be one of {sorted(VALID_LEVELS)}"
        )

    falsepositives = rule.get("falsepositives")
    if not falsepositives:
        issues.append("`falsepositives` section missing")
    else:
        fp_list = (
            falsepositives if isinstance(falsepositives, list) else [falsepositives]
        )
        if all(str(fp).strip().lower() == "unknown" for fp in fp_list):
            issues.append("`falsepositives` is a bare 'Unknown', not a specific condition")

    references = rule.get("references") or []
    has_test_comment = bool(TEST_CASE_COMMENT_RE.search(raw_text))
    has_test_reference = len(references) > 0
    if not (has_test_comment or has_test_reference):
        issues.append(
            "No test case documented (need a '# test case' comment or a `references` entry)"
        )

    return {
        "file": str(path),
        "valid": len(issues) == 0,
        "issues": issues,
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: validate-rule.py <path-to-rule.yml>"}))
        return 2

    path = Path(sys.argv[1])
    if not path.is_file():
        print(json.dumps({"error": f"file not found: {path}"}))
        return 2

    result = validate_rule(path)
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
