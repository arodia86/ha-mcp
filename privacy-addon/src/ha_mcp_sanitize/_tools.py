"""
Privacy audit MCP tools injected into the ha-mcp server by the add-on.

Registered via the ToolsRegistry patch in _patch.py — no changes to
upstream ha-mcp source required.
"""

from __future__ import annotations

import logging
from typing import Any

from .sanitizer import PROTECTED_PATTERNS, get_sanitizer

logger = logging.getLogger(__name__)


def register_privacy_addon_tools(mcp: Any, client: Any) -> None:  # noqa: ARG001
    """Register ha_sanitization_report and ha_sanitization_reset with the MCP server."""

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "idempotentHint": True,
            "tags": ["privacy", "audit"],
            "title": "Sanitization Audit Report",
        }
    )
    async def ha_sanitization_report() -> dict[str, Any]:
        """
        Show the current message sanitization audit log.

        Returns evidence of every sensitive value redacted before being sent to
        the AI (outbound) and every placeholder restored before being written to
        a file or Home Assistant config (inbound).

        Each redaction entry shows:
        - placeholder  — the token the AI sees  (e.g. [HAMCP_REDACTED_EMAIL_3])
        - type         — category (EMAIL, PRIVATE_IP, JWT_TOKEN, …)
        - preview      — first few characters of the original (never the full value)
        - redacted_at  — UTC timestamp

        Each restoration entry shows:
        - placeholder  — the token that was replaced with the real value
        - type         — category
        - restored_at  — UTC timestamp

        Use this to verify that tokens, emails, IPs, GPS coordinates, webhook IDs,
        and passwords are not being leaked to AI systems.
        """
        report = get_sanitizer().get_audit_report()
        report["sanitization_active"] = True
        report["protected_patterns"] = PROTECTED_PATTERNS
        return report

    @mcp.tool(
        annotations={
            "readOnlyHint": False,
            "destructiveHint": False,
            "tags": ["privacy", "audit"],
            "title": "Reset Sanitization Session",
        }
    )
    async def ha_sanitization_reset() -> dict[str, Any]:
        """
        Reset the sanitization session — clear all placeholder mappings and logs.

        Use when starting a fresh conversation context. Returns a final snapshot
        of the previous session before clearing. After reset, any previously
        issued placeholders can no longer be restored, so only call this when
        no outstanding placeholders remain in active use.
        """
        sanitizer = get_sanitizer()
        final_report = sanitizer.get_audit_report()
        final_report["note"] = "Session cleared — placeholder map reset."

        sanitizer._map.clear()
        sanitizer._redaction_log.clear()
        sanitizer._restoration_log.clear()
        sanitizer._counter = 0

        return {"success": True, "previous_session": final_report}
