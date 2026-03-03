"""Tests for the regex matching rule."""

from __future__ import annotations

from safety_api.models import RuleConfig, RuleType, Severity
from safety_api.rules.regex import RegexRule


class TestRegexRule:
    def test_matches_email_pattern(self, email_rule_config: RuleConfig) -> None:
        rule = RegexRule(email_rule_config)
        matches = rule.evaluate("Email me at test@example.com for details.")
        assert len(matches) == 1
        assert matches[0].matched_text == "test@example.com"

    def test_matches_ssn_pattern(self, ssn_rule_config: RuleConfig) -> None:
        rule = RegexRule(ssn_rule_config)
        matches = rule.evaluate("SSN: 123-45-6789")
        assert len(matches) == 1
        assert matches[0].matched_text == "123-45-6789"

    def test_multiple_matches(self, email_rule_config: RuleConfig) -> None:
        rule = RegexRule(email_rule_config)
        text = "Contact alice@test.com or bob@test.com"
        matches = rule.evaluate(text)
        assert len(matches) == 2

    def test_no_match_returns_empty(self, email_rule_config: RuleConfig) -> None:
        rule = RegexRule(email_rule_config)
        matches = rule.evaluate("No email addresses here.")
        assert matches == []

    def test_empty_text(self, email_rule_config: RuleConfig) -> None:
        rule = RegexRule(email_rule_config)
        assert rule.evaluate("") == []

    def test_match_positions(self, email_rule_config: RuleConfig) -> None:
        rule = RegexRule(email_rule_config)
        matches = rule.evaluate("Hi test@a.com")
        assert len(matches) == 1
        assert matches[0].start == 3
        assert matches[0].end == 13

    def test_phone_number_pattern(self) -> None:
        config = RuleConfig(
            id="phone",
            name="Phone",
            type=RuleType.REGEX,
            severity=Severity.HIGH,
            pattern=r"\b\d{3}-\d{3}-\d{4}\b",
            message="Phone detected",
        )
        rule = RegexRule(config)
        matches = rule.evaluate("Call 555-123-4567 now")
        assert len(matches) == 1
        assert matches[0].matched_text == "555-123-4567"

    def test_complex_pattern(self) -> None:
        config = RuleConfig(
            id="threat",
            name="Threat",
            type=RuleType.REGEX,
            severity=Severity.CRITICAL,
            pattern=r"(?i)\b(i will|i'll)\s+(kill|hurt)\s+(you|them)",
            message="Threat detected",
        )
        rule = RegexRule(config)
        matches = rule.evaluate("I will kill you")
        assert len(matches) == 1

        matches = rule.evaluate("I'll hurt them")
        assert len(matches) == 1

        matches = rule.evaluate("This is fine")
        assert matches == []
