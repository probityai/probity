"""MCP server wiring: nine offline, read-only tools over stdio."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import __version__, tools

READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}

# (function, title) in the order they are listed. Names stay under 64 characters.
TOOLS = [
    (tools.verify_claim, "Verify a claim against evidence"),
    (tools.verify_sample, "Run a bundled sample claim"),
    (tools.list_vector_corpora, "List conformance vector corpora"),
    (tools.run_vectors, "Replay a conformance vector corpus"),
    (tools.explain_vector, "Explain one conformance vector"),
    (tools.lookup_term, "Look up a vocabulary term"),
    (tools.check_artifact_digest, "Check an artifact digest against a document"),
    (tools.canonicalize_json, "Canonicalize JSON under RFC 8785"),
    (tools.verify_dsse, "Verify a DSSE envelope"),
]


def build_server() -> MCPServer:
    server = MCPServer(
        "agent-evidence-mcp",
        title="Agent evidence",
        instructions=(
            "Offline, read-only tools that verify a claim about an AI system against supplied evidence "
            "bytes and replay the agent-evidence conformance vectors. Nothing is fetched or written."
        ),
        version=__version__,
    )
    for function, title in TOOLS:
        server.tool(name=function.__name__, title=title, annotations=ToolAnnotations(title=title, **READ_ONLY))(function)
    return server


def main() -> None:
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
