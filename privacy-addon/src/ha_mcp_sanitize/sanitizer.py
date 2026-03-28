"""
Standalone message sanitizer — no ha-mcp dependency.

Redacts sensitive data (tokens, emails, IPs, GPS, webhook IDs…) from
outbound messages before they reach an AI system, and restores the original
values from inbound AI responses before they are written to files or configs.

Placeholder format:  [HAMCP_REDACTED_<TYPE>_<N>]
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_PLACEHOLDER_PREFIX = "HAMCP_REDACTED"
PLACEHOLDER_RE = re.compile(r"\[HAMCP_REDACTED_[A-Z_]+_\d+\]")

# Keys whose string values should always be redacted when found in a Python dict,
# regardless of surrounding context (no regex match needed).
_SENSITIVE_DICT_KEYS: frozenset[str] = frozenset({
    "password", "passwd", "secret", "api_key", "access_token",
    "auth_token", "client_secret", "push_token", "notification_token",
    "device_token", "fcm_token", "apns_token",
})

# ---------------------------------------------------------------------------
# Sensitive-data patterns
# Each tuple: (label, compiled regex, capture_group_index_or_None)
#
# capture_group_index:
#   None → redact the entire match
#   1    → redact only group(1), keep surrounding JSON key / path context
# ---------------------------------------------------------------------------
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
    # Passwords / secrets in JSON  ("password": "value")
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
    # Private / loopback IPv4 (RFC 1918 + 127.x)
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
    # GPS coordinates in JSON  ("latitude": 51.5074, "longitude": -0.1278)
    (
        "GPS_COORD",
        re.compile(r'(?i)"(?:latitude|longitude)"\s*:\s*(-?\d{1,3}\.\d{4,})'),
        1,
    ),
    # Mobile push notification tokens
    (
        "PUSH_TOKEN",
        re.compile(
            r'(?i)"(?:push_token|notification_token|device_token|fcm_token|apns_token)"\s*:\s*"([^"]{20,})"'
        ),
        1,
    ),
    # Generic long API tokens in JSON token fields
    (
        "API_TOKEN",
        re.compile(
            r'(?i)"(?:token|long_lived_access_token|llat)"\s*:\s*"([A-Za-z0-9\-_.]{40,})"'
        ),
        1,
    ),
]

PROTECTED_PATTERNS: list[dict[str, str]] = [
    {"type": "JWT_TOKEN",     "description": "JWT / HA long-lived access tokens (eyJ…)"},
    {"type": "BEARER_TOKEN",  "description": "Bearer <token> authorization headers"},
    {"type": "PASSWORD",      "description": "Passwords, secrets, API keys in JSON fields"},
    {"type": "WEBHOOK_ID",    "description": "Webhook IDs in /api/webhook/<id> paths"},
    {"type": "EMAIL",         "description": "Email addresses"},
    {"type": "PRIVATE_IP",    "description": "Private / loopback IPv4 addresses (RFC 1918, 127.x)"},
    {"type": "GPS_COORD",     "description": "Latitude / longitude coordinates in JSON"},
    {"type": "PUSH_TOKEN",    "description": "Mobile push notification tokens"},
    {"type": "API_TOKEN",     "description": "Generic long API tokens in JSON token fields"},
]


@dataclass
class _RedactionRecord:
    placeholder: str
    pattern_type: str
    preview: str
    timestamp: str


@dataclass
class _RestorationRecord:
    placeholder: str
    pattern_type: str
    timestamp: str


class MessageSanitizer:
    """
    Session-scoped sanitizer maintaining a stable placeholder ↔ value map.

    Use a single instance per MCP session so that placeholders issued on the
    outbound path are correctly resolved on the inbound (restore) path.
    """

    def __init__(self) -> None:
        self._map: dict[str, str] = {}       # placeholder → original value
        self._redaction_log: list[_RedactionRecord] = []
        self._restoration_log: list[_RestorationRecord] = []
        self._counter = 0

    # ── public API ─────────────────────────────────────────────────────────

    def sanitize(self, data: Any) -> Any:
        """Recursively redact sensitive data before sending to an AI system."""
        if isinstance(data, str):
            return self._sanitize_str(data)
        if isinstance(data, dict):
            result = {}
            for k, v in data.items():
                key_lower = k.lower() if isinstance(k, str) else ""
                if key_lower in _SENSITIVE_DICT_KEYS and isinstance(v, str) and len(v) >= 4:
                    # Redact by key name — no regex needed
                    result[k] = self._register("PASSWORD", v)
                else:
                    result[k] = self.sanitize(v)
            return result
        if isinstance(data, list):
            return [self.sanitize(item) for item in data]
        return data

    def restore(self, data: Any) -> Any:
        """Recursively restore placeholders in data received from an AI system."""
        if isinstance(data, str):
            return self._restore_str(data)
        if isinstance(data, dict):
            return {k: self.restore(v) for k, v in data.items()}
        if isinstance(data, list):
            return [self.restore(item) for item in data]
        return data

    def get_audit_report(self) -> dict[str, Any]:
        """Structured evidence log of every redaction and restoration."""
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

    # ── internal helpers ───────────────────────────────────────────────────

    def _new_placeholder(self, pattern_type: str) -> str:
        self._counter += 1
        return f"[{_PLACEHOLDER_PREFIX}_{pattern_type}_{self._counter}]"

    def _existing_placeholder(self, value: str) -> str | None:
        for ph, orig in self._map.items():
            if orig == value:
                return ph
        return None

    def _register(self, pattern_type: str, value: str) -> str:
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
            parts: list[str] = []
            last_end = 0
            for m in pattern.finditer(text):
                parts.append(text[last_end : m.start()])
                if group_idx is not None:
                    sensitive = m.group(group_idx)
                    ph = self._register(pattern_type, sensitive)
                    parts.append(m.group(0).replace(sensitive, ph, 1))
                else:
                    ph = self._register(pattern_type, m.group(0))
                    parts.append(ph)
                last_end = m.end()
            if parts:
                parts.append(text[last_end:])
                text = "".join(parts)
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


# ── Global singleton ───────────────────────────────────────────────────────

_instance: MessageSanitizer | None = None


def get_sanitizer() -> MessageSanitizer:
    """Return the process-wide sanitizer singleton."""
    global _instance
    if _instance is None:
        _instance = MessageSanitizer()
    return _instance
