"""Tests for the holistic AI evaluation layer."""

from __future__ import annotations

from unittest.mock import MagicMock

from safety_api.anthropic_eval import evaluate_with_ai
from safety_api.models import Severity


def _make_mock_client(response_text: str) -> MagicMock:
    """Create a mock API client returning the given JSON string."""
    client = MagicMock()
    content_block = MagicMock()
    content_block.text = response_text
    response = MagicMock()
    response.content = [content_block]
    client.messages.create.return_value = response
    return client


class TestEvaluateWithAI:
    def test_no_violations_returned(self) -> None:
        client = _make_mock_client('{"violations": []}')
        violations = evaluate_with_ai("Clean text", client)
        assert violations == []

    def test_single_violation(self) -> None:
        response = (
            '{"violations": [{'
            '"category": "Hate Speech",'
            '"severity": "HIGH",'
            '"confidence": 0.85,'
            '"explanation": "Contains hateful language",'
            '"spans": [{"start": 0, "end": 10, "text": "hate words"}]'
            "}]}"
        )
        client = _make_mock_client(response)
        violations = evaluate_with_ai("hate words here", client)

        assert len(violations) == 1
        assert violations[0].severity == Severity.HIGH
        assert violations[0].confidence == 0.85
        assert violations[0].source == "ai"
        assert violations[0].rule_id == "ai-hate-speech"
        assert len(violations[0].matches) == 1

    def test_multiple_violations(self) -> None:
        response = (
            '{"violations": ['
            '{"category": "PII", "severity": "HIGH", "confidence": 0.9, '
            '"explanation": "Email found", '
            '"spans": [{"start": 0, "end": 5, "text": "email"}]},'
            '{"category": "Violence", "severity": "CRITICAL", "confidence": 0.7, '
            '"explanation": "Threat detected", '
            '"spans": [{"start": 10, "end": 15, "text": "threat"}]}'
            "]}"
        )
        client = _make_mock_client(response)
        violations = evaluate_with_ai("some text", client)
        assert len(violations) == 2

    def test_api_error_returns_empty(self) -> None:
        client = MagicMock()
        client.messages.create.side_effect = RuntimeError("Service unavailable")
        violations = evaluate_with_ai("text", client)
        assert violations == []

    def test_invalid_json_returns_empty(self) -> None:
        client = _make_mock_client("not json at all")
        violations = evaluate_with_ai("text", client)
        assert violations == []

    def test_default_confidence(self) -> None:
        response = (
            '{"violations": [{'
            '"category": "Test",'
            '"severity": "LOW",'
            '"explanation": "test",'
            '"spans": []'
            "}]}"
        )
        client = _make_mock_client(response)
        violations = evaluate_with_ai("text", client)
        assert violations[0].confidence == 0.8  # default

    def test_malformed_response_structure(self) -> None:
        # violations should be a list, not a string
        client = _make_mock_client('{"violations": "not a list"}')
        violations = evaluate_with_ai("text", client)
        assert violations == []

    def test_missing_severity_field(self) -> None:
        response = (
            '{"violations": [{'
            '"category": "Test",'
            '"explanation": "test",'
            '"spans": []'
            "}]}"
        )
        client = _make_mock_client(response)
        violations = evaluate_with_ai("text", client)
        assert violations == []

    def test_out_of_bounds_spans_clamped(self) -> None:
        response = (
            '{"violations": [{'
            '"category": "PII",'
            '"severity": "HIGH",'
            '"confidence": 0.9,'
            '"explanation": "found it",'
            '"spans": [{"start": 0, "end": 9999, "text": "overrun"}]'
            "}]}"
        )
        client = _make_mock_client(response)
        text = "short"
        violations = evaluate_with_ai(text, client)
        assert len(violations) == 1
        for m in violations[0].matches:
            assert m.end <= len(text)

    def test_invalid_confidence_range(self) -> None:
        response = (
            '{"violations": [{'
            '"category": "Test",'
            '"severity": "LOW",'
            '"confidence": 5.0,'
            '"explanation": "bad confidence",'
            '"spans": []'
            "}]}"
        )
        client = _make_mock_client(response)
        violations = evaluate_with_ai("text", client)
        assert violations == []

    def test_negative_span_indices(self) -> None:
        response = (
            '{"violations": [{'
            '"category": "Test",'
            '"severity": "LOW",'
            '"confidence": 0.5,'
            '"explanation": "negative",'
            '"spans": [{"start": -1, "end": 5, "text": "bad"}]'
            "}]}"
        )
        client = _make_mock_client(response)
        violations = evaluate_with_ai("text", client)
        assert violations == []
