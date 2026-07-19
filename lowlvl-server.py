#!/usr/bin/env python3
"""MCP server wrapping Hayabusa for EVTX analysis (low-level API)."""

import asyncio
import json

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

import scanner

server = Server("hayabusa")


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="scan_evtx",
            description="Scan an EVTX file with Hayabusa and return structured results.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the EVTX file to scan.",
                    },
                    "min_severity": {
                        "type": "string",
                        "description": "Optional minimum severity level to filter results "
                        "(informational, low, medium, high, critical).",
                    },
                    "rule_filter": {
                        "type": "string",
                        "description": "Optional substring to match against rule titles "
                        "(e.g. 'lateral' or 'mimikatz'), case-insensitive.",
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["summary", "full"],
                        "description": "'summary' (default, key fields only) or 'full' "
                        "(all fields Hayabusa reports).",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Optional cap on the number of findings returned.",
                    },
                },
                "required": ["file_path"],
            },
        )
    ]


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    if name != "scan_evtx":
        raise ValueError(f"Unknown tool: {name}")

    arguments = arguments or {}
    result = scanner.scan_evtx(
        file_path=arguments.get("file_path", ""),
        min_severity=arguments.get("min_severity"),
        rule_filter=arguments.get("rule_filter"),
        output_format=arguments.get("output_format", "summary"),
        max_results=arguments.get("max_results"),
    )
    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]


async def run() -> None:
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="hayabusa",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
