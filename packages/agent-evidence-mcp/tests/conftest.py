"""Shared helpers: an in-process MCP client over the real server."""

from __future__ import annotations

import asyncio
from typing import Any

from mcp.client import Client

from agent_evidence_mcp.server import build_server


def call(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Call one tool through a real MCP client session and return its structured result."""

    async def run() -> dict[str, Any]:
        async with Client(build_server()) as client:
            result = await client.call_tool(name, arguments or {})
            assert result.structured_content is not None, result
            return dict(result.structured_content)

    return asyncio.run(run())
