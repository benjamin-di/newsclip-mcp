"""What MCP clients receive from a FastMCP server.

Tests assert on the protocol shapes (tools/list entries with camelCase keys,
tools/call content plus structured result), not on FastMCP's Python objects,
so a framework upgrade cannot silently change what clients see.
"""

from __future__ import annotations

from typing import Any


async def call_tool(
    server: Any, name: str, arguments: dict[str, Any]
) -> tuple[list, Any]:
    """(content blocks, structured result) of one tools/call."""

    result = await server.call_tool(name, arguments)
    return result.content, result.structured_content


async def list_tools(server: Any) -> list[dict[str, Any]]:
    """tools/list entries as sent on the wire (camelCase keys)."""

    return [
        tool.to_mcp_tool().model_dump(by_alias=True, mode="json", exclude_none=True)
        for tool in await server.list_tools()
    ]
