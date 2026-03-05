"""Tests for the regex matching rule."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from safety_api.models import RuleConfig, RuleType, Severity
from safety_api.rules.regex import RegexRule, RegexTimeoutError


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
        assert "123" in matches[0].matched_text

    def test_ssn_broad_pattern_hyphenated(self) -> None:
        config = RuleConfig(
            id="ssn",
            name="SSN",
            type=RuleType.REGEX,
            severity=Severity.CRITICAL,
            pattern=r"\b(?!000|666|9\d{2})(\d{3})[- ]?(?!00)(\d{2})[- ]?(?!0000)(\d{4})\b",
            message="SSN detected",
        )
        rule = RegexRule(config)
        matches = rule.evaluate("SSN: 123-45-6789")
        assert len(matches) == 1

    def test_ssn_broad_pattern_spaced(self) -> None:
        config = RuleConfig(
            id="ssn",
            name="SSN",
            type=RuleType.REGEX,
            severity=Severity.CRITICAL,
            pattern=r"\b(?!000|666|9\d{2})(\d{3})[- ]?(?!00)(\d{2})[- ]?(?!0000)(\d{4})\b",
            message="SSN detected",
        )
        rule = RegexRule(config)
        matches = rule.evaluate("SSN: 123 45 6789")
        assert len(matches) == 1

    def test_ssn_broad_pattern_continuous(self) -> None:
        config = RuleConfig(
            id="ssn",
            name="SSN",
            type=RuleType.REGEX,
            severity=Severity.CRITICAL,
            pattern=r"\b(?!000|666|9\d{2})(\d{3})[- ]?(?!00)(\d{2})[- ]?(?!0000)(\d{4})\b",
            message="SSN detected",
        )
        rule = RegexRule(config)
        matches = rule.evaluate("SSN: 123456789")
        assert len(matches) == 1

    def test_ssn_rejects_invalid_prefixes(self) -> None:
        config = RuleConfig(
            id="ssn",
            name="SSN",
            type=RuleType.REGEX,
            severity=Severity.CRITICAL,
            pattern=r"\b(?!000|666|9\d{2})(\d{3})[- ]?(?!00)(\d{2})[- ]?(?!0000)(\d{4})\b",
            message="SSN detected",
        )
        rule = RegexRule(config)
        # 000 prefix
        assert rule.evaluate("SSN: 000-12-3456") == []
        # 666 prefix
        assert rule.evaluate("SSN: 666-12-3456") == []
        # 9xx prefix
        assert rule.evaluate("SSN: 900-12-3456") == []

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

    def test_invalid_pattern_raises(self) -> None:
        config = RuleConfig(
            id="bad-regex",
            name="Bad Regex",
            type=RuleType.REGEX,
            severity=Severity.LOW,
            pattern=r"(?P<bad",
            message="broken",
        )
        with pytest.raises(ValueError, match="invalid pattern"):
            RegexRule(config)

    def test_empty_pattern_raises(self) -> None:
        config = RuleConfig(
            id="empty-regex",
            name="Empty Regex",
            type=RuleType.REGEX,
            severity=Severity.LOW,
            pattern="valid",  # bypass Pydantic validator
            message="empty",
        )
        config.pattern = ""  # set empty after construction
        with pytest.raises(ValueError, match="non-empty pattern"):
            RegexRule(config)

    def test_luhn_validator_filters_invalid_card(self) -> None:
        config = RuleConfig(
            id="cc",
            name="Credit Card",
            type=RuleType.REGEX,
            severity=Severity.CRITICAL,
            pattern=r"\b(?:\d{4}[- ]?){3}\d{1,4}\b",
            validator="luhn",
            message="CC detected",
        )
        rule = RegexRule(config)
        # 1234567890123456 fails Luhn — should be filtered out
        matches = rule.evaluate("Order #1234567890123456")
        assert matches == []

    def test_luhn_validator_keeps_valid_card(self) -> None:
        config = RuleConfig(
            id="cc",
            name="Credit Card",
            type=RuleType.REGEX,
            severity=Severity.CRITICAL,
            pattern=r"\b(?:\d{4}[- ]?){3}\d{1,4}\b",
            validator="luhn",
            message="CC detected",
        )
        rule = RegexRule(config)
        # 4111111111111111 is a valid Visa test number
        matches = rule.evaluate("Card: 4111111111111111")
        assert len(matches) == 1
        assert matches[0].matched_text == "4111111111111111"

    def test_no_validator_keeps_all_matches(self) -> None:
        config = RuleConfig(
            id="cc",
            name="Credit Card",
            type=RuleType.REGEX,
            severity=Severity.CRITICAL,
            pattern=r"\b(?:\d{4}[- ]?){3}\d{1,4}\b",
            message="CC detected",
        )
        rule = RegexRule(config)
        # Without validator, any matching number is kept
        matches = rule.evaluate("Order #1234567890123456")
        assert len(matches) == 1

    def test_redos_timeout_raises(self) -> None:
        """Verify that a regex exceeding the timeout raises RegexTimeoutError."""
        config = RuleConfig(
            id="redos",
            name="ReDoS Pattern",
            type=RuleType.REGEX,
            severity=Severity.HIGH,
            pattern=r"\d+",
            message="redos test",
        )
        rule = RegexRule(config)

        # Mock Thread so is_alive() returns True (simulates timeout)
        # because Python's re module holds the GIL, making real
        # thread timeouts unreliable.
        with patch("safety_api.rules.regex.threading.Thread") as MockThread:
            mock_thread = MockThread.return_value
            mock_thread.is_alive.return_value = True
            with pytest.raises(RegexTimeoutError):
                rule.evaluate("123")
