#!/usr/bin/env python3
"""Start the installed server over stdio and require the contradicted sample decision.

Usage: python scripts/wheel_smoke.py <path to the agent-evidence-mcp executable>
"""

from __future__ import annotations

import asyncio
import sys

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters


async def main(command: str) -> int:
    async with Client(StdioServerParameters(command=command)) as client:
        result = await client.call_tool("verify_sample", {"scenario": "contradicted"})
    decision = (result.structured_content or {}).get("decision")
    print(f"decision: {decision}")
    return 0 if decision == "contradicted" else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(sys.argv[1])))
