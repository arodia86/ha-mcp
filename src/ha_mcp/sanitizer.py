"""
Privacy-preserving message sanitizer for ha-mcp.

Automatically redacts sensitive data (tokens, emails, IPs, GPS coords, webhook IDs)
from outbound messages sent to AI systems, and restores the original values in
inbound AI responses before they are written to files or configs.

Flow:
  HA data → [SANITIZE] → AI sees only placeholders → AI responds → [RESTORE] → HA/files get real values

Usage:
    from .sanitizer import get_sanitizer

    sanitizer = get_sanitizer()
    safe_for_ai  = sanitizer.sanitize(tool_result)   # outbound: redact
    real_content = sanitizer.restore(ai_content)     # inbound: un-redact
    report       = sanitizer.get_audit_report()      # evidence log
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Placeholder format: [HAMCP_REDACTED_<TYPE>_<N>]
# Chosen to be visually obvious and unlikely to appear in real data.
# ─────────────────────────────────────────────────────────────────────────────

_PLACEHOLDER_PREFIX = "HAMCP_REDACTED"
PLACEHOLDER_RE = re.compile(r"\[HAMCP_REDACTED_[A-Z_]+_\d+\]")


# ─────────────────────────────────────────────────────────────────────────────
# Sensitive-data patterns
# Each tuple: (label, compiled regex, capture_group_index_or_None)
#
# capture_group_index:
#   None  → redact the entire match
#   1     → redact only group(1); keep surrounding text (e.g. JSON key intact)
# ─────────────────────────────────────────────────────────────────────────────

_PATTERNS: list[tuple[str, re.Pattern[str], int | None]] = [
    # JWT / HA long-lived access tokens (eyJ…)
    (
        "JWT_TOKEN",
        re.compile(r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/]*\b"),
        None,
    ),
    # Bearer <token> in headers or config values
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/]+=*)"),
        1,
    ),
    # Passwords / secrets in JSON ("password": "value")
    (
        "PASSWORD",
        re.compile(
            r'(?i)"(?:password|passwd|secret|api_key|access_token|auth_token|client_secret)"\s*:\s*"([^"]{4,})"'
        ),
        1,
    ),
    # Webhook IDs embedded in paths /api/webhook/<id>
    (
        "WEBHOOK_ID",
        re.compile(r"/api/webhook/([A-Za-z0-9\-_]{20,})"),
        1,
    ),
    # Email addresses
    (
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        None,
    ),
    # Private / loopback IPv4 addresses (RFC 1918 + 127.x)
    (
        "PRIVATE_IP",
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
        ),
        None,
    ),
    # GPS coordinates in JSON ("latitude": 51.5074, "longitude": -0.1278)
    (
        "GPS_COORD",
        re.compile(r'(?i)"(?:latitude|longitude)"\s*:\s*(-?\d{1,3}\.\d{4,})'),
        1,
    ),
    # Notification/push tokens (long opaque strings in notification payloads)
    (
        "PUSH_TOKEN",
        re.compile(
            r'(?i)"(?:push_token|notification_token|device_token|fcm_token|apns_token)"\s*:\s*"([^"]{20,})"'
        ),
        1,
    ),
    # Generic long API tokens in key=value or "key": "value" contexts
    (
        "API_TOKEN",
        re.compile(
            r'(?i)"(?:token|long_lived_access_token|llat)"\s*:\s*"([A-Za-z0-9\-_.]{40,})"'
        ),
        1,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Audit records
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class _RedactionRecord:
    placeholder: str
    pattern_type: str
    preview: str  # First few non-sensitive chars for human confirmation
    timestamp: str


@dataclass
class _RestorationRecord:
    placeholder: str
    pattern_type: str
    timestamp: str


# ─────────────────────────────────────────────────────────────────────────────
# Core sanitizer
# ─────────────────────────────────────────────────────────────────────────────


class MessageSanitizer:
    """
    Session-scoped sanitizer that maintains a stable placeholder ↔ value map.

    A single instance should be used for an entire MCP session so that
    placeholders introduced on the outbound path are correctly resolved
    on the inbound (restore) path.
    """

    def __init__(self) -> None:
        self._map: dict[str, str] = {}  # placeholder → original value
        self._redaction_log: list[_RedactionRecord] = []
        self._restoration_log: list[_RestorationRecord] = []
        self._counter = 0

    # ── public API ────────────────────────────────────────────────────────────

    def sanitize(self, data: Any) -> Any:
        """
        Recursively sanitize *data* before sending to an AI system.

        Strings, dict values, and list items are all processed.
        Numbers, booleans, and None pass through unchanged.
        """
        if isinstance(data, str):
            return self._sanitize_str(data)
        if isinstance(data, dict):
            return {k: self.sanitize(v) for k, v in data.items()}
        if isinstance(data, list):
            return [self.sanitize(item) for item in data]
        return data

    def restore(self, data: Any) -> Any:
        """
        Recursively restore placeholders in *data* received from an AI system.

        Call this before writing AI-generated content to files or HA configs.
        """
        if isinstance(data, str):
            return self._restore_str(data)
        if isinstance(data, dict):
            return {k: self.restore(v) for k, v in data.items()}
        if isinstance(data, list):
            return [self.restore(item) for item in data]
        return data

    def get_audit_report(self) -> dict[str, Any]:
        """Return a structured evidence log of all redactions and restorations."""
        return {
            "summary": {
                "total_redactions": len(self._redaction_log),
                "total_restorations": len(self._restoration_log),
                "active_placeholders": len(self._map),
            },
            "redactions": [
                {
                    "placeholder": r.placeholder,
                    "type": r.pattern_type,
                    "preview": r.preview,
                    "redacted_at": r.timestamp,
                }
                for r in self._redaction_log
            ],
            "restorations": [
                {
                    "placeholder": r.placeholder,
                    "type": r.pattern_type,
                    "restored_at": r.timestamp,
                }
                for r in self._restoration_log
            ],
        }

    @property
    def redaction_count(self) -> int:
        return len(self._redaction_log)

    @property
    def restoration_count(self) -> int:
        return len(self._restoration_log)

    # ── internal helpers ──────────────────────────────────────────────────────

    def _new_placeholder(self, pattern_type: str) -> str:
        self._counter += 1
        return f"[{_PLACEHOLDER_PREFIX}_{pattern_type}_{self._counter}]"

    def _existing_placeholder(self, value: str) -> str | None:
        """Return an already-assigned placeholder for *value*, if any."""
        for ph, orig in self._map.items():
            if orig == value:
                return ph
        return None

    def _register(self, pattern_type: str, value: str) -> str:
        """Register *value* and return its placeholder (creating one if needed)."""
        existing = self._existing_placeholder(value)
        if existing:
            return existing
        ph = self._new_placeholder(pattern_type)
        self._map[ph] = value
        preview = value[:4] + "…" if len(value) > 4 else "****"
        self._redaction_log.append(
            _RedactionRecord(
                placeholder=ph,
                pattern_type=pattern_type,
                preview=preview,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )
        logger.info("Redacted %-20s → %s  (preview: %s)", pattern_type, ph, preview)
        return ph

    def _sanitize_str(self, text: str) -> str:
        for pattern_type, pattern, group_idx in _PATTERNS:
            # We iterate over non-overlapping matches from left to right.
            # Build replacement in a single pass to avoid offset issues.
            new_text_parts: list[str] = []
            last_end = 0
            for m in pattern.finditer(text):
                new_text_parts.append(text[last_end : m.start()])
                if group_idx is not None:
                    # Only the captured group is sensitive; keep surrounding context
                    sensitive_value = m.group(group_idx)
                    ph = self._register(pattern_type, sensitive_value)
                    # Replace only the sensitive group within the full match
                    full = m.group(0)
                    replaced_full = full.replace(sensitive_value, ph, 1)
                    new_text_parts.append(replaced_full)
                else:
                    sensitive_value = m.group(0)
                    ph = self._register(pattern_type, sensitive_value)
                    new_text_parts.append(ph)
                last_end = m.end()
            if new_text_parts:
                new_text_parts.append(text[last_end:])
                text = "".join(new_text_parts)
        return text

    def _restore_str(self, text: str) -> str:
        for ph, original in self._map.items():
            if ph in text:
                text = text.replace(ph, original)
                type_label = ph.replace(f"[{_PLACEHOLDER_PREFIX}_", "").rsplit("_", 1)[0]
                self._restoration_log.append(
                    _RestorationRecord(
                        placeholder=ph,
                        pattern_type=type_label,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    )
                )
                logger.info("Restored %s", ph)
        return text


# ─────────────────────────────────────────────────────────────────────────────
# Global singleton
# ─────────────────────────────────────────────────────────────────────────────

_sanitizer_instance: MessageSanitizer | None = None


def get_sanitizer() -> MessageSanitizer:
    """Return the process-wide sanitizer singleton."""
    global _sanitizer_instance
    if _sanitizer_instance is None:
        _sanitizer_instance = MessageSanitizer()
    return _sanitizer_instance


def is_sanitization_enabled() -> bool:
    """Return True if message sanitization is active (default: True)."""
    try:
        from .config import get_global_settings

        return get_global_settings().enable_sanitization
    except Exception:
        return True  # Fail-safe: sanitize by default
