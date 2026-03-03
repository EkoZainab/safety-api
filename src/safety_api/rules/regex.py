"""Regex pattern matching rule implementation."""

from __future__ import annotations

import re

from safety_api.models import Match, RuleConfig
from safety_api.rules.base import BaseRule


class RegexRule(BaseRule):
    """Matches regular expression patterns in text.

    Compiles the pattern from the rule config at construction time
    and uses finditer for efficient multi-match scanning.
    """

    def __init__(self, config: RuleConfig) -> None:
        super().__init__(config)
        if not config.pattern:
            raise ValueError(
                f"RegexRule '{config.id}' requires a non-empty pattern"
            )
        self._pattern = re.compile(config.pattern)

    def evaluate(self, text: str) -> list[Match]:
        return [
            Match(start=m.start(), end=m.end(), matched_text=m.group())
            for m in self._pattern.finditer(text)
        ]
