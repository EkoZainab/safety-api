"""Core evaluation engine that runs text through loaded policies."""

from __future__ import annotations

import concurrent.futures
import logging
import time
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from safety_api.anthropic_eval import evaluate_with_ai
from safety_api.loader import load_policies, load_policies_with_errors
from safety_api.models import (
    DEFAULT_AI_MODEL,
    TEXT_PREVIEW_LENGTH,
    EvaluationResult,
    Match,
    PolicyFile,
    RuleType,
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
    Semantic (API-based) rules run concurrently to minimize latency.
    """

    def __init__(
        self,
        policies: list[PolicyFile],
        anthropic_client: AnthropicClientProtocol | None = None,
        ai_model: str = DEFAULT_AI_MODEL,
        severity_threshold: Severity | None = None,
        load_errors: list[str] | None = None,
    ) -> None:
        self._policies = policies
        self._anthropic_client = anthropic_client
        self._ai_model = ai_model
        self._severity_threshold = severity_threshold
        self._load_errors: list[str] = load_errors or []
        self._build_warnings: list[str] = []
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
                except Exception as exc:
                    logger.exception(
                        "Failed to create rule '%s'", rule_config.id
                    )
                    self._build_warnings.append(
                        f"Rule '{rule_config.id}' skipped: {exc}"
                    )

        return instances

    @staticmethod
    def _make_violation(
        policy_file: PolicyFile,
        rule: BaseRule,
        matches: list[Match],
    ) -> Violation:
        source = "ai" if rule.config.type == RuleType.SEMANTIC else "rule"
        return Violation(
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

    def evaluate(self, text: str) -> EvaluationResult:
        """Evaluate a text string against all loaded policies and rules.

        Deterministic rules (keyword, regex) run synchronously.
        Semantic rules (API-based) run concurrently via a thread pool.

        Args:
            text: The input text to evaluate.

        Returns:
            EvaluationResult with all violations, aggregate score,
            and evaluation timing.
        """
        start = time.perf_counter()
        violations: list[Violation] = []
        eval_warnings: list[str] = list(self._build_warnings)
        incomplete_reasons: list[str] = list(self._load_errors)
        if self._build_warnings:
            incomplete_reasons.extend(self._build_warnings)
        rules_evaluated = 0

        deterministic: list[tuple[PolicyFile, BaseRule]] = []
        semantic: list[tuple[PolicyFile, BaseRule]] = []

        for policy_file, rule in self._rule_instances:
            if rule.config.type == RuleType.SEMANTIC:
                semantic.append((policy_file, rule))
            else:
                deterministic.append((policy_file, rule))

        # Evaluate deterministic rules synchronously (fast)
        for policy_file, rule in deterministic:
            try:
                matches = rule.evaluate(text)
            except Exception as exc:
                logger.exception(
                    "Rule '%s' failed during evaluation", rule.config.id
                )
                msg = f"Rule '{rule.config.id}' failed: {exc}"
                eval_warnings.append(msg)
                incomplete_reasons.append(msg)
                continue
            rules_evaluated += 1
            if matches:
                violations.append(self._make_violation(policy_file, rule, matches))

        # Evaluate semantic rules concurrently (I/O-bound API calls)
        if semantic:
            max_workers = min(len(semantic), 10)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {
                    pool.submit(rule.evaluate, text): (policy_file, rule)
                    for policy_file, rule in semantic
                }
                for future in concurrent.futures.as_completed(futures):
                    policy_file, rule = futures[future]
                    try:
                        matches = future.result()
                    except Exception as exc:
                        logger.exception(
                            "Rule '%s' failed during evaluation",
                            rule.config.id,
                        )
                        msg = f"Rule '{rule.config.id}' failed: {exc}"
                        eval_warnings.append(msg)
                        incomplete_reasons.append(msg)
                        continue
                    rules_evaluated += 1
                    if matches:
                        violations.append(
                            self._make_violation(policy_file, rule, matches)
                        )

        # Run holistic AI evaluation if client is available
        if self._anthropic_client is not None:
            try:
                ai_violations = evaluate_with_ai(
                    text, self._anthropic_client, model=self._ai_model
                )
                violations.extend(ai_violations)
            except Exception as exc:
                logger.exception("Holistic AI evaluation failed")
                msg = f"Holistic AI evaluation failed: {exc}"
                eval_warnings.append(msg)
                incomplete_reasons.append(msg)

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
            warnings=eval_warnings,
            incomplete=bool(incomplete_reasons),
            incomplete_reasons=incomplete_reasons,
        )
        result.compute_score()
        return result

    def summarize_rules(self) -> dict[str, int]:
        """Return a count of rule instances by type (for dry-run)."""
        counts: dict[str, int] = {}
        for _, rule in self._rule_instances:
            key = rule.config.type.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @classmethod
    def from_policy_dir(
        cls,
        policy_dir: Path,
        *,
        strict: bool = False,
        **kwargs: Any,
    ) -> Evaluator:
        """Create an Evaluator by loading all policies from a directory.

        Args:
            policy_dir: Directory containing YAML policy files.
            strict: If True, raise on any invalid policy file.
            **kwargs: Additional arguments passed to the Evaluator constructor.

        Returns:
            A configured Evaluator instance.
        """
        load_result = load_policies_with_errors(policy_dir, strict=strict)
        return cls(
            policies=load_result.policies,
            load_errors=load_result.errors,
            **kwargs,
        )
