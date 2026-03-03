"""Core evaluation engine that runs text through loaded policies."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from safety_api.loader import load_policies
from safety_api.models import (
    DEFAULT_AI_MODEL,
    TEXT_PREVIEW_LENGTH,
    EvaluationResult,
    PolicyFile,
    Severity,
    Violation,
)
from safety_api.rules import create_rule
from safety_api.rules.base import BaseRule

logger = logging.getLogger(__name__)


class _MessagesAPI(Protocol):
    def create(self, **kwargs: Any) -> Any: ...


@runtime_checkable
class AnthropicClientProtocol(Protocol):
    """Structural type for the Anthropic API client."""

    @property
    def messages(self) -> _MessagesAPI: ...


class Evaluator:
    """Runs text against a collection of policies and produces scored results.

    The evaluator pre-builds all rule instances at construction time so
    that repeated evaluate() calls avoid redundant setup work.
    """

    def __init__(
        self,
        policies: list[PolicyFile],
        anthropic_client: AnthropicClientProtocol | Any | None = None,
        ai_model: str = DEFAULT_AI_MODEL,
        severity_threshold: Severity | None = None,
    ) -> None:
        self._policies = policies
        self._anthropic_client = anthropic_client
        self._ai_model = ai_model
        self._severity_threshold = severity_threshold
        self._rule_instances = self._build_rules()

    def _build_rules(self) -> list[tuple[PolicyFile, BaseRule]]:
        """Instantiate all enabled rules from all loaded policies."""
        instances: list[tuple[PolicyFile, BaseRule]] = []

        for policy_file in self._policies:
            for rule_config in policy_file.rules:
                if not rule_config.enabled:
                    continue

                kwargs: dict[str, Any] = {}
                if rule_config.type.value == "semantic":
                    kwargs["anthropic_client"] = self._anthropic_client
                    kwargs["model"] = self._ai_model

                try:
                    rule = create_rule(rule_config, **kwargs)
                    instances.append((policy_file, rule))
                except Exception:
                    logger.exception(
                        "Failed to create rule '%s'", rule_config.id
                    )

        return instances

    def evaluate(self, text: str) -> EvaluationResult:
        """Evaluate a text string against all loaded policies and rules.

        Args:
            text: The input text to evaluate.

        Returns:
            EvaluationResult with all violations, aggregate score,
            and evaluation timing.
        """
        start = time.perf_counter()
        violations: list[Violation] = []
        rules_evaluated = 0

        for policy_file, rule in self._rule_instances:
            matches = rule.evaluate(text)
            rules_evaluated += 1

            if matches:
                source = (
                    "ai" if rule.config.type.value == "semantic" else "rule"
                )
                violation = Violation(
                    rule_id=rule.config.id,
                    rule_name=rule.config.name,
                    policy_id=policy_file.policy.id,
                    policy_name=policy_file.policy.name,
                    severity=rule.config.severity,
                    message=rule.config.message,
                    matches=matches,
                    tags=rule.config.tags,
                    source=source,
                )
                violations.append(violation)

        # Apply severity threshold filter
        if self._severity_threshold is not None:
            threshold_weight = self._severity_threshold.weight
            violations = [
                v for v in violations
                if v.severity.weight >= threshold_weight
            ]

        elapsed_ms = (time.perf_counter() - start) * 1000

        result = EvaluationResult(
            text_preview=text[:TEXT_PREVIEW_LENGTH],
            policies_evaluated=len(self._policies),
            rules_evaluated=rules_evaluated,
            violations=violations,
            evaluation_time_ms=round(elapsed_ms, 2),
        )
        result.compute_score()
        return result

    @classmethod
    def from_policy_dir(
        cls,
        policy_dir: Path,
        **kwargs: Any,
    ) -> Evaluator:
        """Create an Evaluator by loading all policies from a directory.

        Args:
            policy_dir: Directory containing YAML policy files.
            **kwargs: Additional arguments passed to the Evaluator constructor.

        Returns:
            A configured Evaluator instance.
        """
        policies = load_policies(policy_dir)
        return cls(policies=policies, **kwargs)
