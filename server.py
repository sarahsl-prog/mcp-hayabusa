#!/usr/bin/env python3
"""MCP server wrapping Hayabusa for EVTX analysis."""

from mcp.server.fastmcp import FastMCP

import attack_techniques
import scanner
import sigma_rules

mcp = FastMCP("hayabusa")


@mcp.tool()
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
def get_hayabusa_rules(keyword: str | None = None) -> dict:
    """List available Hayabusa detection rules, optionally filtered by keyword.

    Args:
        keyword: Optional substring to match against a rule's title,
            description, or tags (e.g. "mimikatz" or "lateral"),
            case-insensitive.
    """
    return scanner.list_rules(keyword)


@mcp.tool()
def analyze_coverage(identifier: str) -> dict:
    """Analyze detection coverage for an ATT&CK technique ID or tactic name.

    Args:
        identifier: An ATT&CK technique ID (e.g. "T1078", "1003.001") or a
            tactic name (e.g. "Credential Access", "privilege-escalation").
            Reports which techniques are covered, partially covered, or
            gaps based on our Sigma rules' `attack.tXXXX` tags.
    """
    return attack_techniques.analyze_coverage(identifier)


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
