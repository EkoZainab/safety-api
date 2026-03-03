"""Tests for the semantic (API-based) rule."""

from __future__ import annotations

from unittest.mock import MagicMock

from safety_api.models import RuleConfig
from safety_api.rules.semantic import SemanticRule


def _make_mock_client(response_text: str) -> MagicMock:
    """Create a mock Anthropic client returning the given JSON string."""
    client = MagicMock()
    content_block = MagicMock()
    content_block.text = response_text
    response = MagicMock()
    response.content = [content_block]
    client.messages.create.return_value = response
    return client


class TestSemanticRule:
    def test_no_client_returns_empty(
        self, semantic_rule_config: RuleConfig
    ) -> None:
        rule = SemanticRule(semantic_rule_config, anthropic_client=None)
        matches = rule.evaluate("Some text to evaluate")
        assert matches == []

    def test_flagged_response_with_spans(
        self, semantic_rule_config: RuleConfig
    ) -> None:
        response_json = (
            '{"flagged": true, "confidence": 0.9, '
            '"explanation": "Contains violation", '
            '"spans": [{"start": 0, "end": 4, "text": "Some"}]}'
        )
        client = _make_mock_client(response_json)
        rule = SemanticRule(
            semantic_rule_config, anthropic_client=client
        )

        matches = rule.evaluate("Some text")
        assert len(matches) == 1
        assert matches[0].start == 0
        assert matches[0].end == 4
        assert matches[0].matched_text == "Some"

    def test_flagged_response_without_spans(
        self, semantic_rule_config: RuleConfig
    ) -> None:
        response_json = (
            '{"flagged": true, "confidence": 0.7, '
            '"explanation": "General violation", "spans": []}'
        )
        client = _make_mock_client(response_json)
        rule = SemanticRule(
            semantic_rule_config, anthropic_client=client
        )

        matches = rule.evaluate("Bad content here")
        assert len(matches) == 1
        assert matches[0].matched_text == "[full text]"

    def test_clean_response(
        self, semantic_rule_config: RuleConfig
    ) -> None:
        response_json = (
            '{"flagged": false, "confidence": 0.0, '
            '"explanation": "No issues", "spans": []}'
        )
        client = _make_mock_client(response_json)
        rule = SemanticRule(
            semantic_rule_config, anthropic_client=client
        )

        matches = rule.evaluate("Perfectly fine text")
        assert matches == []

    def test_api_error_returns_empty(
        self, semantic_rule_config: RuleConfig
    ) -> None:
        client = MagicMock()
        client.messages.create.side_effect = RuntimeError("API down")
        rule = SemanticRule(
            semantic_rule_config, anthropic_client=client
        )

        matches = rule.evaluate("Some text")
        assert matches == []

    def test_invalid_json_returns_empty(
        self, semantic_rule_config: RuleConfig
    ) -> None:
        client = _make_mock_client("not valid json {{{")
        rule = SemanticRule(
            semantic_rule_config, anthropic_client=client
        )

        matches = rule.evaluate("Some text")
        assert matches == []

    def test_passes_prompt_to_api(
        self, semantic_rule_config: RuleConfig
    ) -> None:
        response_json = '{"flagged": false, "spans": []}'
        client = _make_mock_client(response_json)
        rule = SemanticRule(
            semantic_rule_config, anthropic_client=client
        )

        rule.evaluate("Test input")

        call_args = client.messages.create.call_args
        user_msg = call_args.kwargs["messages"][0]["content"]
        assert "Analyze this text" in user_msg
        assert "Test input" in user_msg
