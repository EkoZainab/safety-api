"""Rule registry and factory for creating rule instances from config."""

from __future__ import annotations

from typing import Any

from safety_api.models import RuleConfig, RuleType
from safety_api.rules.base import BaseRule
from safety_api.rules.keyword import KeywordRule
from safety_api.rules.regex import RegexRule
from safety_api.rules.semantic import SemanticRule

_RULE_REGISTRY: dict[RuleType, type[BaseRule]] = {
    RuleType.KEYWORD: KeywordRule,
    RuleType.REGEX: RegexRule,
    RuleType.SEMANTIC: SemanticRule,
}


def create_rule(config: RuleConfig, **kwargs: Any) -> BaseRule:
    """Instantiate the correct rule class for a given RuleConfig.

    Args:
        config: The rule configuration parsed from YAML.
        **kwargs: Additional arguments passed to the rule constructor
                  (e.g., anthropic_client for semantic rules).

    Returns:
        A concrete BaseRule instance.

    Raises:
        ValueError: If the rule type is not registered.
    """
    cls = _RULE_REGISTRY.get(config.type)
    if cls is None:
        raise ValueError(f"Unknown rule type: {config.type!r}")
    return cls(config, **kwargs)
