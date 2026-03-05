"""Tests for data models."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from safety_api.models import (
    EvaluationResult,
    Match,
    PolicyConfig,
    PolicyFile,
    RuleConfig,
    RuleType,
    Severity,
    Violation,
    redact_result,
)


class TestSeverity:
    def test_weights_are_ordered(self) -> None:
        assert Severity.LOW.weight < Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight < Severity.HIGH.weight
        assert Severity.HIGH.weight < Severity.CRITICAL.weight

    def test_specific_weight_values(self) -> None:
        assert Severity.LOW.weight == 1
        assert Severity.MEDIUM.weight == 3
        assert Severity.HIGH.weight == 7
        assert Severity.CRITICAL.weight == 10

    def test_severity_is_string_enum(self) -> None:
        assert Severity.HIGH.value == "HIGH"
        assert Severity.HIGH == "HIGH"


class TestRuleConfig:
    def test_keyword_type_requires_keywords(self) -> None:
        with pytest.raises(ValidationError, match="keywords"):
            RuleConfig(
                id="test",
                name="Test",
                type=RuleType.KEYWORD,
                severity=Severity.LOW,
                message="test",
                keywords=None,
            )

    def test_keyword_type_with_empty_list_raises(self) -> None:
        with pytest.raises(ValidationError, match="keywords"):
            RuleConfig(
                id="test",
                name="Test",
                type=RuleType.KEYWORD,
                severity=Severity.LOW,
                message="test",
                keywords=[],
            )

    def test_regex_type_requires_pattern(self) -> None:
        with pytest.raises(ValidationError, match="pattern"):
            RuleConfig(
                id="test",
                name="Test",
                type=RuleType.REGEX,
                severity=Severity.LOW,
                message="test",
                pattern=None,
            )

    def test_valid_keyword_config(self, keyword_rule_config: RuleConfig) -> None:
        assert keyword_rule_config.type == RuleType.KEYWORD
        assert keyword_rule_config.keywords is not None
        assert len(keyword_rule_config.keywords) == 2

    def test_valid_regex_config(self, email_rule_config: RuleConfig) -> None:
        assert email_rule_config.type == RuleType.REGEX
        assert email_rule_config.pattern is not None

    def test_semantic_type_allows_no_pattern(self) -> None:
        config = RuleConfig(
            id="test",
            name="Test",
            type=RuleType.SEMANTIC,
            severity=Severity.HIGH,
            message="test",
            prompt="Analyze this text.",
        )
        assert config.type == RuleType.SEMANTIC

    def test_default_values(self) -> None:
        config = RuleConfig(
            id="test",
            name="Test",
            type=RuleType.REGEX,
            severity=Severity.LOW,
            message="test",
            pattern=r"\d+",
        )
        assert config.enabled is True
        assert config.tags == []
        assert config.case_sensitive is False
        assert config.match_whole_word is True


class TestPolicyFile:
    def test_valid_policy_file(self, pii_policy: PolicyFile) -> None:
        assert pii_policy.policy.id == "test-pii"
        assert len(pii_policy.rules) == 2

    def test_policy_file_validation(self) -> None:
        with pytest.raises(ValidationError):
            PolicyFile(
                policy=PolicyConfig(id="test", name="Test"),
                rules="not-a-list",  # type: ignore[arg-type]
            )


class TestMatch:
    def test_match_creation(self) -> None:
        m = Match(start=0, end=5, matched_text="hello")
        assert m.start == 0
        assert m.end == 5
        assert m.matched_text == "hello"

    def test_negative_start_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Match(start=-1, end=5, matched_text="bad")

    def test_negative_end_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Match(start=0, end=-1, matched_text="bad")

    def test_end_before_start_rejected(self) -> None:
        with pytest.raises(ValidationError, match="end"):
            Match(start=5, end=3, matched_text="bad")

    def test_zero_length_match_allowed(self) -> None:
        m = Match(start=3, end=3, matched_text="")
        assert m.start == m.end


class TestViolation:
    def test_violation_defaults(self) -> None:
        v = Violation(
            rule_id="test",
            rule_name="Test",
            policy_id="pol",
            policy_name="Policy",
            severity=Severity.HIGH,
            message="test violation",
        )
        assert v.source == "rule"
        assert v.confidence == 1.0
        assert v.matches == []
        assert v.tags == []


class TestEvaluationResult:
    def test_compute_score_with_no_violations(self) -> None:
        result = EvaluationResult(
            text_preview="test",
            policies_evaluated=1,
            rules_evaluated=5,
        )
        result.compute_score()
        assert result.total_score == 0.0
        assert result.max_severity is None
        assert result.flagged is False

    def test_compute_score_with_violations(self) -> None:
        violations = [
            Violation(
                rule_id="r1",
                rule_name="Rule 1",
                policy_id="p1",
                policy_name="Policy 1",
                severity=Severity.HIGH,
                message="violation 1",
                confidence=1.0,
            ),
            Violation(
                rule_id="r2",
                rule_name="Rule 2",
                policy_id="p1",
                policy_name="Policy 1",
                severity=Severity.CRITICAL,
                message="violation 2",
                confidence=0.8,
            ),
        ]
        result = EvaluationResult(
            text_preview="test",
            policies_evaluated=1,
            rules_evaluated=2,
            violations=violations,
        )
        result.compute_score()

        expected_score = 7 * 1.0 + 10 * 0.8  # HIGH*1.0 + CRITICAL*0.8
        assert result.total_score == expected_score
        assert result.max_severity == Severity.CRITICAL
        assert result.flagged is True

    def test_violation_count_property(self) -> None:
        result = EvaluationResult(
            text_preview="test",
            policies_evaluated=1,
            rules_evaluated=1,
            violations=[
                Violation(
                    rule_id="r1",
                    rule_name="R1",
                    policy_id="p1",
                    policy_name="P1",
                    severity=Severity.LOW,
                    message="v",
                ),
            ],
        )
        assert result.violation_count == 1

    def test_incomplete_defaults_to_false(self) -> None:
        result = EvaluationResult(
            text_preview="test",
            policies_evaluated=1,
            rules_evaluated=1,
        )
        assert result.incomplete is False
        assert result.incomplete_reasons == []

    def test_incomplete_coexists_with_flagged(self) -> None:
        result = EvaluationResult(
            text_preview="test",
            policies_evaluated=1,
            rules_evaluated=1,
            violations=[
                Violation(
                    rule_id="r1",
                    rule_name="R1",
                    policy_id="p1",
                    policy_name="P1",
                    severity=Severity.HIGH,
                    message="v",
                ),
            ],
            incomplete=True,
            incomplete_reasons=["Rule 'x' failed"],
        )
        result.compute_score()
        assert result.flagged is True
        assert result.incomplete is True
        assert result.incomplete_reasons == ["Rule 'x' failed"]

    def test_incomplete_json_serialization(self) -> None:
        result = EvaluationResult(
            text_preview="test",
            policies_evaluated=1,
            rules_evaluated=1,
            incomplete=True,
            incomplete_reasons=["AI evaluation failed"],
        )
        data = json.loads(result.model_dump_json())
        assert data["incomplete"] is True
        assert data["incomplete_reasons"] == ["AI evaluation failed"]

    def test_json_serialization_roundtrip(self) -> None:
        result = EvaluationResult(
            text_preview="test text",
            policies_evaluated=2,
            rules_evaluated=10,
        )
        result.compute_score()
        json_str = result.model_dump_json()
        data = json.loads(json_str)
        assert data["text_preview"] == "test text"
        assert data["policies_evaluated"] == 2
        assert data["flagged"] is False


class TestRedactResult:
    def test_redact_replaces_text_preview(self) -> None:
        result = EvaluationResult(
            text_preview="sensitive text here",
            policies_evaluated=1,
            rules_evaluated=1,
        )
        redacted = redact_result(result)
        assert redacted.text_preview == "[REDACTED]"
        # Original is not mutated
        assert result.text_preview == "sensitive text here"

    def test_redact_replaces_matched_text(self) -> None:
        result = EvaluationResult(
            text_preview="Email test@example.com",
            policies_evaluated=1,
            rules_evaluated=1,
            violations=[
                Violation(
                    rule_id="r1",
                    rule_name="R1",
                    policy_id="p1",
                    policy_name="P1",
                    severity=Severity.HIGH,
                    message="PII found",
                    matches=[
                        Match(start=6, end=22, matched_text="test@example.com"),
                    ],
                ),
            ],
        )
        redacted = redact_result(result)
        assert redacted.violations[0].matches[0].matched_text == "[REDACTED]"
        # Original is not mutated
        assert result.violations[0].matches[0].matched_text == "test@example.com"

    def test_redact_preserves_other_fields(self) -> None:
        result = EvaluationResult(
            text_preview="test",
            policies_evaluated=1,
            rules_evaluated=1,
            violations=[
                Violation(
                    rule_id="r1",
                    rule_name="R1",
                    policy_id="p1",
                    policy_name="P1",
                    severity=Severity.HIGH,
                    message="PII found",
                    matches=[
                        Match(start=0, end=5, matched_text="hello"),
                    ],
                ),
            ],
            incomplete=True,
            incomplete_reasons=["some reason"],
        )
        result.compute_score()
        redacted = redact_result(result)
        assert redacted.flagged is True
        assert redacted.incomplete is True
        assert redacted.violations[0].severity == Severity.HIGH
