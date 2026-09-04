"""Neutral pure MIME facts shared across business-module boundaries."""

from __future__ import annotations


def is_html_mime_type(mime_type: str) -> bool:
    """Return whether an already-valid media type is one of the HTML types."""
    return mime_type in {"application/xhtml+xml", "text/html"}
