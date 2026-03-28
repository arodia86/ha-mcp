"""
CLI entry points for ha-mcp-sanitize.

Applies the sanitization patches BEFORE starting the ha-mcp server, ensuring
every tool registered by ha-mcp uses the privacy-aware log_tool_usage wrapper.

Usage (configure your AI client to call these instead of ha-mcp):
  stdio mode : ha-mcp-sanitize
  HTTP mode  : ha-mcp-sanitize-web
"""

from __future__ import annotations


def main() -> None:
    """Stdio entry point (replaces ha-mcp for Claude Desktop / MCP clients)."""
    # _patch MUST be imported before ha_mcp.__main__ so that log_tool_usage
    # is replaced before any tools_*.py module binds it as a local name.
    from . import _patch  # noqa: F401 — side-effect: patches ha_mcp

    from ha_mcp.__main__ import main as _ha_mcp_main

    _ha_mcp_main()


def main_web() -> None:
    """HTTP / SSE entry point (replaces ha-mcp-web)."""
    from . import _patch  # noqa: F401

    from ha_mcp.__main__ import main_web as _ha_mcp_main_web

    _ha_mcp_main_web()
