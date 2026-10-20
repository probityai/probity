# Install

Every command pins the released version.

| client | command |
| --- | --- |
| Claude Code | `claude mcp add agent-evidence -- uvx agent-evidence-mcp@0.2.0` |
| Claude Code plugin | `/plugin install agent-evidence --marketplace probityai/agent-evidence-mcp` |
| Gemini CLI | `gemini extensions install https://github.com/probityai/agent-evidence-mcp` |
| Any stdio client | command `uvx`, arguments `agent-evidence-mcp@0.2.0` |
| pip | `pip install agent-evidence-mcp==0.2.0`, then run `agent-evidence-mcp` |
| Docker | `docker build -t agent-evidence-mcp .` then `docker run -i --rm agent-evidence-mcp` |

The server speaks MCP over stdio, makes no network calls and needs no credentials.
