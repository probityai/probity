# Install

Every command pins the released version.

| client | command |
| --- | --- |
| Claude Code | `claude mcp add agent-evidence -- uvx agent-evidence-mcp@0.2.5` |
| Claude Code plugin | `/plugin install agent-evidence --marketplace probityai/probity` |
| Gemini CLI | `gemini extensions install https://github.com/probityai/probity` |
| Cursor | put `{"mcpServers": {"agent-evidence": {"command": "uvx", "args": ["agent-evidence-mcp@0.2.5"]}}}` in `.cursor/mcp.json` |
| Any stdio client | command `uvx`, arguments `agent-evidence-mcp@0.2.5` |
| pip | `pip install agent-evidence-mcp==0.2.5`, then run `agent-evidence-mcp` |
| Docker | `docker build -t agent-evidence-mcp .` then `docker run -i --rm agent-evidence-mcp` |

The server speaks MCP over stdio, makes no network calls and needs no credentials.

## Agent frameworks

LangChain and LlamaIndex load the server through their own MCP adapters. Both calls start the pinned stdio server and return its nine tools.

```python
# pip install langchain-mcp-adapters
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient({"agent-evidence": {"transport": "stdio", "command": "uvx", "args": ["agent-evidence-mcp@0.2.5"]}})
tools = await client.get_tools()
```

```python
# pip install llama-index-tools-mcp
from llama_index.tools.mcp import BasicMCPClient, McpToolSpec

tools = await McpToolSpec(client=BasicMCPClient("uvx", args=["agent-evidence-mcp@0.2.5"])).to_tool_list_async()
```
