"""
ha-mcp-sanitize — privacy add-on for ha-mcp.

Automatically redacts sensitive data (tokens, emails, IPs, GPS coordinates,
webhook IDs, passwords) from messages sent to AI systems, and restores original
values in AI responses before they are written to files or HA configs.

Install alongside ha-mcp, then use ha-mcp-sanitize (or ha-mcp-sanitize-web)
as your MCP server command instead of ha-mcp.

Zero changes to upstream ha-mcp files — merge upstream updates freely.
"""

from .sanitizer import MessageSanitizer, get_sanitizer

__all__ = ["MessageSanitizer", "get_sanitizer"]
