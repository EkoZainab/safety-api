"""Shared sanitization utilities for XML tag injection prevention."""

from __future__ import annotations

import re

_CLOSING_TAG_RE = re.compile(
    r"<\s*/\s*text_to_evaluate\s*>", re.IGNORECASE
)
_OPENING_TAG_RE = re.compile(
    r"<\s*text_to_evaluate", re.IGNORECASE
)


def sanitize_for_xml_tags(text: str) -> str:
    """Escape ``<text_to_evaluate>`` open/close tags injected into user text.

    Handles case variations and whitespace within the tags.
    Other XML tags pass through unchanged.
    """
    # Process closing tags first so partial escapes don't create false matches
    text = _CLOSING_TAG_RE.sub("&lt;/text_to_evaluate&gt;", text)
    text = _OPENING_TAG_RE.sub("&lt;text_to_evaluate", text)
    return text
