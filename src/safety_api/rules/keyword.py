"""Keyword and phrase matching rule implementation."""

from __future__ import annotations

import re

from safety_api.models import Match, RuleConfig
from safety_api.rules.base import BaseRule


class KeywordRule(BaseRule):
    """Matches exact keywords or phrases in text.

    Compiles all keywords into a single regex pattern for efficient
    evaluation. Supports case-sensitive matching and whole-word boundaries.
    """

    def __init__(self, config: RuleConfig) -> None:
        super().__init__(config)
        if not config.keywords:
            raise ValueError(
                f"KeywordRule '{config.id}' requires a non-empty keywords list"
            )

        flags = 0 if config.case_sensitive else re.IGNORECASE
        escaped = [re.escape(kw) for kw in config.keywords]

        if config.match_whole_word:
            pattern_str = r"\b(?:" + "|".join(escaped) + r")\b"
        else:
            pattern_str = "|".join(escaped)

        self._pattern = re.compile(pattern_str, flags)

    def evaluate(self, text: str) -> list[Match]:
        return [
            Match(start=m.start(), end=m.end(), matched_text=m.group())
            for m in self._pattern.finditer(text)
        ]
