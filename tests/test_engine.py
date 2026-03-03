"""Tests for the evaluation engine."""

from __future__ import annotations

from pathlib import Path

from safety_api.engine import Evaluator
from safety_api.models import PolicyFile, Severity


class TestEvaluator:
    def test_clean_text_no_violations(
        self, pii_policy: PolicyFile, clean_text: str
    ) -> None:
        evaluator = Evaluator(policies=[pii_policy])
        result = evaluator.evaluate(clean_text)
        assert not result.flagged
        assert result.violation_count == 0
        assert result.total_score == 0.0

    def test_pii_text_flags_email(
        self, pii_policy: PolicyFile, pii_text: str
    ) -> None:
        evaluator = Evaluator(policies=[pii_policy])
        result = evaluator.evaluate(pii_text)
        assert result.flagged
        assert result.violation_count >= 1
        assert any("email" in v.rule_id for v in result.violations)

    def test_ssn_text_flags_critical(
        self, pii_policy: PolicyFile, ssn_text: str
    ) -> None:
        evaluator = Evaluator(policies=[pii_policy])
        result = evaluator.evaluate(ssn_text)
        assert result.flagged
        assert result.max_severity == Severity.CRITICAL

    def test_severity_threshold_filters_below(
        self, pii_policy: PolicyFile, pii_text: str
    ) -> None:
        evaluator = Evaluator(
            policies=[pii_policy],
            severity_threshold=Severity.CRITICAL,
        )
        result = evaluator.evaluate(pii_text)
        # Email rule is HIGH, not CRITICAL, so it should be filtered
        for v in result.violations:
            assert v.severity.weight >= Severity.CRITICAL.weight

    def test_severity_threshold_keeps_above(
        self, pii_policy: PolicyFile, ssn_text: str
    ) -> None:
        evaluator = Evaluator(
            policies=[pii_policy],
            severity_threshold=Severity.HIGH,
        )
        result = evaluator.evaluate(ssn_text)
        # SSN is CRITICAL, should pass HIGH threshold
        assert result.violation_count >= 1

    def test_multiple_policies(
        self,
        pii_policy: PolicyFile,
        keyword_policy: PolicyFile,
    ) -> None:
        evaluator = Evaluator(policies=[pii_policy, keyword_policy])
        text = "Email test@x.com and bad word here"
        result = evaluator.evaluate(text)
        assert result.policies_evaluated == 2
        assert result.violation_count >= 2

    def test_evaluation_timing(
        self, pii_policy: PolicyFile, clean_text: str
    ) -> None:
        evaluator = Evaluator(policies=[pii_policy])
        result = evaluator.evaluate(clean_text)
        assert result.evaluation_time_ms >= 0

    def test_text_preview_truncation(self, pii_policy: PolicyFile) -> None:
        long_text = "a" * 500
        evaluator = Evaluator(policies=[pii_policy])
        result = evaluator.evaluate(long_text)
        assert len(result.text_preview) == 200

    def test_rules_evaluated_count(self, pii_policy: PolicyFile) -> None:
        evaluator = Evaluator(policies=[pii_policy])
        result = evaluator.evaluate("some text")
        assert result.rules_evaluated == len(pii_policy.rules)

    def test_from_policy_dir(self, sample_policy_dir: Path) -> None:
        evaluator = Evaluator.from_policy_dir(sample_policy_dir)
        result = evaluator.evaluate("test@example.com")
        assert result.flagged

    def test_disabled_rules_are_skipped(self, pii_policy: PolicyFile) -> None:
        # Disable all rules
        for rule in pii_policy.rules:
            rule.enabled = False
        evaluator = Evaluator(policies=[pii_policy])
        result = evaluator.evaluate("test@example.com 123-45-6789")
        assert result.rules_evaluated == 0
        assert result.violation_count == 0

    def test_score_computation_accuracy(self) -> None:
        from safety_api.models import PolicyConfig, RuleConfig, RuleType

        policy = PolicyFile(
            policy=PolicyConfig(id="p", name="P"),
            rules=[
                RuleConfig(
                    id="low",
                    name="Low",
                    type=RuleType.REGEX,
                    severity=Severity.LOW,
                    pattern=r"aaa",
                    message="low match",
                ),
                RuleConfig(
                    id="high",
                    name="High",
                    type=RuleType.REGEX,
                    severity=Severity.HIGH,
                    pattern=r"bbb",
                    message="high match",
                ),
            ],
        )
        evaluator = Evaluator(policies=[policy])
        result = evaluator.evaluate("aaa bbb")
        expected = Severity.LOW.weight + Severity.HIGH.weight
        assert result.total_score == expected
