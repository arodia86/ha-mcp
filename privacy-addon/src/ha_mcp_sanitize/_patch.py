"""
Monkey-patches ha_mcp at import time — zero upstream file changes required.

Two patches are applied as side-effects of importing this module:

  Patch 1 — ha_mcp.tools.helpers.log_tool_usage
    Wraps every @log_tool_usage-decorated tool so that:
      • Inbound  (AI → HA): placeholders in kwargs are restored to real values
        before the tool logic runs (so HA / file writes get the real data).
      • Outbound (HA → AI): the tool result is sanitized before being returned,
        replacing sensitive values with stable named placeholders.

  Patch 2 — ToolsRegistry.register_all_tools
    Adds the ha_sanitization_report and ha_sanitization_reset audit tools to
    the MCP server alongside the normal ha-mcp tool set.

This module MUST be imported before any ha_mcp.tools.tools_*.py module is
imported. Since those modules are lazily loaded by the registry, importing
_patch in the entry point (before _main() runs) is sufficient.
"""

from __future__ import annotations

import functools
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Patch 1: log_tool_usage
# ---------------------------------------------------------------------------

import ha_mcp.tools.helpers as _helpers  # noqa: E402

_orig_log_tool_usage = _helpers.log_tool_usage


def _sanitizing_log_tool_usage(func):  # type: ignore[no-untyped-def]
    """
    Replacement for log_tool_usage that sandwiches sanitization around it.

    Execution order for each tool call:
      1. restore(kwargs)        — undo any placeholders the AI echoed back
      2. orig_wrapped(...)      — original timing / logging / tool logic
      3. sanitize(result)       — redact sensitive data before AI sees it
    """
    orig_wrapped = _orig_log_tool_usage(func)

    @functools.wraps(func)
    async def _wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
        from .sanitizer import get_sanitizer

        sanitizer = get_sanitizer()

        # INBOUND: restore placeholders the AI may have echoed in parameters
        if kwargs:
            kwargs = sanitizer.restore(kwargs)

        result = await orig_wrapped(*args, **kwargs)

        # OUTBOUND: redact sensitive data before returning to the AI
        return sanitizer.sanitize(result)

    return _wrapper


_helpers.log_tool_usage = _sanitizing_log_tool_usage
logger.debug("ha-mcp-sanitize: patched log_tool_usage")

# ---------------------------------------------------------------------------
# Patch 2: ToolsRegistry.register_all_tools
# ---------------------------------------------------------------------------

from ha_mcp.tools.registry import ToolsRegistry  # noqa: E402

_orig_register_all = ToolsRegistry.register_all_tools


def _register_all_with_privacy(self):  # type: ignore[no-untyped-def]
    _orig_register_all(self)
    if getattr(self, "_privacy_addon_registered", False):
        return
    try:
        from ._tools import register_privacy_addon_tools

        register_privacy_addon_tools(self.mcp, self.client)
        self._privacy_addon_registered = True
        logger.debug("ha-mcp-sanitize: registered privacy audit tools")
    except Exception as exc:
        logger.warning("ha-mcp-sanitize: could not register privacy tools: %s", exc)


ToolsRegistry.register_all_tools = _register_all_with_privacy
logger.debug("ha-mcp-sanitize: patched ToolsRegistry.register_all_tools")
