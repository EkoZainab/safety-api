"""Abstract base class for evaluation rules."""

from __future__ import annotations

import abc

from safety_api.models import Match, RuleConfig


class BaseRule(abc.ABC):
    """Base class that all rule evaluators must implement.

    Each rule takes a RuleConfig at construction time and provides
    an evaluate() method that returns matches found in the input text.
    """

    def __init__(self, config: RuleConfig) -> None:
        self.config = config

    @abc.abstractmethod
    def evaluate(self, text: str) -> list[Match]:
        """Evaluate text and return any matches found.

        Args:
            text: The input text to evaluate against this rule.

        Returns:
            List of Match objects for each occurrence found.
            An empty list means no violations for this rule.
        """
        ...

    @property
    def rule_id(self) -> str:
        return self.config.id
