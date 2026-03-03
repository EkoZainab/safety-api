"""Tests for the keyword matching rule."""

from __future__ import annotations

import pytest

from safety_api.models import RuleConfig, RuleType, Severity
from safety_api.rules.keyword import KeywordRule


class TestKeywordRule:
    def test_matches_case_insensitive(self, keyword_rule_config: RuleConfig) -> None:
        rule = KeywordRule(keyword_rule_config)
        matches = rule.evaluate("This contains a BAD WORD in it.")
        assert len(matches) == 1
        assert matches[0].matched_text.lower() == "bad word"

    def test_matches_case_sensitive(self) -> None:
        config = RuleConfig(
            id="cs",
            name="Case Sensitive",
            type=RuleType.KEYWORD,
            severity=Severity.LOW,
            keywords=["BadWord"],
            case_sensitive=True,
            match_whole_word=False,
            message="matched",
        )
        rule = KeywordRule(config)

        assert len(rule.evaluate("Contains BadWord here")) == 1
        assert len(rule.evaluate("Contains badword here")) == 0

    def test_whole_word_matching(self) -> None:
        config = RuleConfig(
            id="ww",
            name="Whole Word",
            type=RuleType.KEYWORD,
            severity=Severity.LOW,
            keywords=["bad"],
            case_sensitive=False,
            match_whole_word=True,
            message="matched",
        )
        rule = KeywordRule(config)

        # "bad" as a whole word
        assert len(rule.evaluate("This is bad")) == 1
        # "bad" as part of another word
        assert len(rule.evaluate("This is badly done")) == 0

    def test_substring_matching(self) -> None:
        config = RuleConfig(
            id="sub",
            name="Substring",
            type=RuleType.KEYWORD,
            severity=Severity.LOW,
            keywords=["bad"],
            case_sensitive=False,
            match_whole_word=False,
            message="matched",
        )
        rule = KeywordRule(config)

        matches = rule.evaluate("This is badly done")
        assert len(matches) == 1
        assert matches[0].matched_text.lower() == "bad"

    def test_multiple_keywords(self) -> None:
        config = RuleConfig(
            id="multi",
            name="Multi",
            type=RuleType.KEYWORD,
            severity=Severity.LOW,
            keywords=["alpha", "beta", "gamma"],
            case_sensitive=False,
            match_whole_word=True,
            message="matched",
        )
        rule = KeywordRule(config)

        matches = rule.evaluate("alpha and gamma are here")
        assert len(matches) == 2
        texts = {m.matched_text.lower() for m in matches}
        assert texts == {"alpha", "gamma"}

    def test_no_match_returns_empty_list(
        self, keyword_rule_config: RuleConfig
    ) -> None:
        rule = KeywordRule(keyword_rule_config)
        matches = rule.evaluate("This text contains nothing problematic.")
        assert matches == []

    def test_empty_text(self, keyword_rule_config: RuleConfig) -> None:
        rule = KeywordRule(keyword_rule_config)
        assert rule.evaluate("") == []

    def test_match_positions_are_correct(self) -> None:
        config = RuleConfig(
            id="pos",
            name="Position",
            type=RuleType.KEYWORD,
            severity=Severity.LOW,
            keywords=["hello"],
            case_sensitive=False,
            match_whole_word=True,
            message="matched",
        )
        rule = KeywordRule(config)

        matches = rule.evaluate("say hello world")
        assert len(matches) == 1
        assert matches[0].start == 4
        assert matches[0].end == 9

    def test_special_regex_characters_in_keywords(self) -> None:
        config = RuleConfig(
            id="special",
            name="Special Chars",
            type=RuleType.KEYWORD,
            severity=Severity.LOW,
            keywords=["test.com", "foo+bar"],
            case_sensitive=False,
            match_whole_word=False,
            message="matched",
        )
        rule = KeywordRule(config)

        # Should match literal "test.com", not "testXcom"
        assert len(rule.evaluate("visit test.com")) == 1
        assert len(rule.evaluate("visit testXcom")) == 0

    def test_requires_keywords(self) -> None:
        config = RuleConfig(
            id="empty",
            name="Empty",
            type=RuleType.KEYWORD,
            severity=Severity.LOW,
            keywords=["placeholder"],
            message="matched",
        )
        config.keywords = None  # bypass validator
        with pytest.raises(ValueError, match="requires"):
            KeywordRule(config)

    def test_non_ascii_whole_word(self) -> None:
        config = RuleConfig(
            id="non-ascii",
            name="Non-ASCII",
            type=RuleType.KEYWORD,
            severity=Severity.LOW,
            keywords=["café"],
            case_sensitive=False,
            match_whole_word=True,
            message="matched",
        )
        rule = KeywordRule(config)

        # Should match as a whole word with accented characters
        assert len(rule.evaluate("visit the café today")) == 1
        assert len(rule.evaluate("no match here")) == 0

    def test_cjk_substring_matching(self) -> None:
        config = RuleConfig(
            id="cjk",
            name="CJK",
            type=RuleType.KEYWORD,
            severity=Severity.LOW,
            keywords=["危険"],
            case_sensitive=False,
            match_whole_word=False,
            message="matched",
        )
        rule = KeywordRule(config)
        assert len(rule.evaluate("これは危険です")) == 1
