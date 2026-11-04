"""Offline, read-only MCP server over probity-verify and the agent-evidence packages."""

from importlib.metadata import version

# The installed distribution is the one source of the version, so a release bump in
# pyproject.toml reaches the `serverInfo` reply without a second edit.
__version__ = version("agent-evidence-mcp")
