"""Regex pattern matching rule implementation."""

from __future__ import annotations

import logging
import re
import threading

from safety_api.models import Match, RuleConfig
from safety_api.rules.base import BaseRule

logger = logging.getLogger(__name__)

_REGEX_EVAL_TIMEOUT = 5  # seconds


class RegexTimeoutError(RuntimeError):
    """Raised when regex evaluation exceeds the timeout."""


class RegexRule(BaseRule):
    """Matches regular expression patterns in text.

    Compiles the pattern from the rule config at construction time
    and uses finditer for efficient multi-match scanning.
    Includes a timeout guard against catastrophic backtracking (ReDoS).
    """

    def __init__(self, config: RuleConfig) -> None:
        super().__init__(config)
        if not config.pattern:
            raise ValueError(
                f"RegexRule '{config.id}' requires a non-empty pattern"
            )
        try:
            self._pattern = re.compile(config.pattern)
        except re.error as e:
            raise ValueError(
                f"RegexRule '{config.id}' has invalid pattern: {e}"
            ) from e

    def evaluate(self, text: str) -> list[Match]:
        result: list[Match] = []

        def run() -> None:
            result.extend(
                Match(start=m.start(), end=m.end(), matched_text=m.group())
                for m in self._pattern.finditer(text)
            )

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(timeout=_REGEX_EVAL_TIMEOUT)

        if thread.is_alive():
            raise RegexTimeoutError(
                f"Regex evaluation timed out after {_REGEX_EVAL_TIMEOUT}s "
                f"for rule '{self.rule_id}' — pattern may be vulnerable to ReDoS"
            )

        return result
