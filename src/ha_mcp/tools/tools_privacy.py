"""
Privacy and sanitization audit tools for ha-mcp.

Provides tools for inspecting the message sanitization state — what sensitive
data has been redacted from AI-visible messages and what has been restored when
AI-generated content was written back to files or configs.

These tools give the user evidence of what was protected and when.
"""

from __future__ import annotations

import logging
from typing import Any

from ..sanitizer import MessageSanitizer, get_sanitizer, is_sanitization_enabled
from .helpers import log_tool_usage

logger = logging.getLogger(__name__)


def register_privacy_tools(mcp: Any, client: Any, **kwargs: Any) -> None:
    """Register privacy / sanitization audit tools."""

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "idempotentHint": True,
            "tags": ["privacy", "audit"],
            "title": "Sanitization Report",
        }
    )
    @log_tool_usage
    async def ha_sanitization_report() -> dict[str, Any]:
        """
        Show the current message sanitization audit log.

        Returns evidence of every sensitive value that was redacted before being
        sent to the AI (outbound) and every placeholder that was restored before
        being written to a file or Home Assistant config (inbound).

        Each redaction entry shows:
        - placeholder: the token the AI saw (e.g. [HAMCP_REDACTED_EMAIL_3])
        - type: category of sensitive data (EMAIL, PRIVATE_IP, JWT_TOKEN, …)
        - preview: first few characters of the original value (never the full value)
        - redacted_at: UTC timestamp

        Each restoration entry shows:
        - placeholder: the token that was replaced
        - type: category
        - restored_at: UTC timestamp

        Use this tool to verify that sensitive data (tokens, emails, IPs, GPS
        coordinates, webhook IDs, passwords) is not being leaked to AI systems.
        """
        sanitizer = get_sanitizer()
        report = sanitizer.get_audit_report()
        report["sanitization_enabled"] = is_sanitization_enabled()
        report["protected_patterns"] = _list_protected_patterns()
        return report

    @mcp.tool(
        annotations={
            "readOnlyHint": False,
            "destructiveHint": False,
            "tags": ["privacy", "audit"],
            "title": "Reset Sanitization Session",
        }
    )
    @log_tool_usage
    async def ha_sanitization_reset() -> dict[str, Any]:
        """
        Reset the sanitization session — clear all placeholder mappings and audit logs.

        Use this when starting a fresh conversation context. After reset,
        previously issued placeholders can no longer be restored, so only call
        this when you are certain no outstanding placeholders remain in active use.

        Returns a final snapshot of the previous session's audit log before clearing.
        """
        sanitizer = get_sanitizer()
        final_report = sanitizer.get_audit_report()
        final_report["note"] = "Session cleared. Placeholder map reset."

        # Reset the singleton by replacing its internal state
        sanitizer._map.clear()
        sanitizer._redaction_log.clear()
        sanitizer._restoration_log.clear()
        sanitizer._counter = 0

        return {
            "success": True,
            "previous_session": final_report,
        }


def _list_protected_patterns() -> list[dict[str, str]]:
    """Return human-readable descriptions of all active redaction patterns."""
    return [
        {"type": "JWT_TOKEN", "description": "JWT / HA long-lived access tokens (eyJ…)"},
        {"type": "BEARER_TOKEN", "description": "Bearer <token> authorization headers"},
        {"type": "PASSWORD", "description": "Passwords, secrets, API keys in JSON fields"},
        {"type": "WEBHOOK_ID", "description": "Webhook IDs in /api/webhook/<id> paths"},
        {"type": "EMAIL", "description": "Email addresses"},
        {"type": "PRIVATE_IP", "description": "Private/loopback IPv4 addresses (RFC 1918, 127.x)"},
        {"type": "GPS_COORD", "description": "Latitude/longitude coordinates in JSON"},
        {"type": "PUSH_TOKEN", "description": "Mobile push notification tokens"},
        {"type": "API_TOKEN", "description": "Generic long API tokens in JSON token fields"},
    ]
