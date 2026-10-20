# Install agent-evidence-mcp

Add this server to your MCP settings. It runs over stdio, needs no API key, makes no network calls and writes nothing.

```json
{
  "mcpServers": {
    "agent-evidence": {
      "command": "uvx",
      "args": ["agent-evidence-mcp@0.2.0"]
    }
  }
}
```

This needs [uv](https://docs.astral.sh/uv/). Without uv, run `pip install agent-evidence-mcp==0.2.0` and use the command `agent-evidence-mcp` with no arguments.

To check the install, call the tool `verify_sample` with `{"scenario": "contradicted"}`. It returns the decision `contradicted` with the reason `selected_span_missing_from_record`.
