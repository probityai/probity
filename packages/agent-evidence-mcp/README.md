# agent-evidence-mcp

<!-- mcp-name: io.github.probityai/agent-evidence-mcp -->

An offline, read-only MCP server that decides whether a claim about an AI system holds against evidence bytes you supply, and replays the agent-evidence conformance vectors.

It's for agent builders, auditors and platform engineers who want their assistant to check evidence instead of trusting a report.

Install the released package: `pip install agent-evidence-mcp==0.2.0`. It pins `probity-verify==0.1.1`, `agent-evidence-vectors==0.23.0`, `agent-evidence-vocabulary==0.6.0`, `agent-evidence-admission==0.1.2` and `jcs-admit==0.1.0` exactly. The last one carries the `jcs-admit` and `dsse` Rust crates as wheels.

## Quick start

Add it to Claude Code, then ask the assistant to run the sample claim:

```sh
claude mcp add agent-evidence -- uvx agent-evidence-mcp@0.2.0
```

Or install the Claude Code plugin: `/plugin install agent-evidence --marketplace probityai/agent-evidence-mcp`.

Or call a tool from Python, with no client installed beyond the package:

```sh
uvx --from agent-evidence-mcp==0.2.0 python - <<'PY'
import asyncio
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

async def main():
    async with Client(StdioServerParameters(command="agent-evidence-mcp")) as client:
        result = await client.call_tool("verify_sample", {"scenario": "contradicted"})
        print(result.structured_content["decision"], result.structured_content["reason"])

asyncio.run(main())
PY
```

It prints:

```text
contradicted selected_span_missing_from_record
```

A passage the report quotes is missing from the source capture, so the claim is contradicted. Use `supported` or `not_established` as the scenario for the other two decisions.

## Tools

Nine tools, all read-only, offline and bounded: `verify_claim`, `verify_sample`, `list_vector_corpora`, `run_vectors`, `explain_vector`, `lookup_term` and `check_artifact_digest`, `canonicalize_json` and `verify_dsse`. Nothing is fetched, written or sent.

## Status

Version 0.2.0. The tests run every tool through a real MCP client against the shipped corpus, and a mutation check confirms they fail when a tool's output is broken.

## Documentation

| page | read it for |
| --- | --- |
| [Tools](https://github.com/probityai/agent-evidence-mcp/blob/main/docs/tools.md) | every tool, its arguments and what it returns |
| [Install](https://github.com/probityai/agent-evidence-mcp/blob/main/docs/install.md) | Claude Code, Gemini CLI, Docker and plain stdio |
| [Agent guide](https://github.com/probityai/agent-evidence-mcp/blob/main/llms.txt) | a short index for agents using the server |
| [Changing the repository](https://github.com/probityai/agent-evidence-mcp/blob/main/AGENTS.md) | the commands to run and what never to hand-edit |

## License

Apache-2.0.
