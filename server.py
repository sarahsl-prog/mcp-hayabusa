#!/usr/bin/env python3
"""MCP server wrapping Hayabusa for EVTX analysis."""

from mcp.server.fastmcp import FastMCP

import scanner

mcp = FastMCP("hayabusa")


@mcp.tool()
def scan_evtx(file_path: str, min_severity: str | None = None) -> dict:
    """Scan an EVTX file with Hayabusa and return structured results.

    Args:
        file_path: Path to the EVTX file to scan.
        min_severity: Optional minimum severity level to filter results
            (informational, low, medium, high, critical).
    """
    return scanner.scan_evtx(file_path, min_severity)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
