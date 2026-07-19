#!/usr/bin/env python3
"""MCP server wrapping Hayabusa for EVTX analysis."""

from mcp.server.fastmcp import FastMCP

import scanner

mcp = FastMCP("hayabusa")


@mcp.tool()
def scan_evtx(
    file_path: str,
    min_severity: str | None = None,
    rule_filter: str | None = None,
    output_format: str = "summary",
    max_results: int | None = None,
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
    """
    return scanner.scan_evtx(file_path, min_severity, rule_filter, output_format, max_results)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
