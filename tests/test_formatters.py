"""Tests for output formatters."""

from __future__ import annotations

import json

from safety_api.formatters.json_fmt import format_json
from safety_api.formatters.text import format_text
from safety_api.models import (
    EvaluationResult,
    Match,
    Severity,
    Violation,
)


def _make_clean_result() -> EvaluationResult:
    result = EvaluationResult(
        text_preview="clean text",
        policies_evaluated=2,
        rules_evaluated=10,
    )
    result.compute_score()
    return result


def _make_flagged_result() -> EvaluationResult:
    violations = [
        Violation(
            rule_id="pii-email",
            rule_name="Email Detection",
            policy_id="pii",
            policy_name="PII Detection",
            severity=Severity.HIGH,
            message="Email address detected",
            matches=[
                Match(start=10, end=26, matched_text="test@example.com")
            ],
            tags=["pii", "contact-info"],
        ),
        Violation(
            rule_id="pii-ssn",
            rule_name="SSN Detection",
            policy_id="pii",
            policy_name="PII Detection",
            severity=Severity.CRITICAL,
            message="SSN detected",
            matches=[
                Match(start=30, end=41, matched_text="123-45-6789")
            ],
            tags=["pii", "government-id"],
        ),
    ]
    result = EvaluationResult(
        text_preview="Contains test@example.com and 123-45-6789",
        policies_evaluated=1,
        rules_evaluated=5,
        violations=violations,
    )
    result.compute_score()
    return result


class TestTextFormatter:
    def test_clean_result(self) -> None:
        output = format_text(_make_clean_result())
        assert "CLEAN" in output
        assert "No violations detected" in output

    def test_flagged_result_contains_violations(self) -> None:
        output = format_text(_make_flagged_result())
        assert "FLAGGED" in output
        assert "Email Detection" in output
        assert "SSN Detection" in output
        assert "test@example.com" in output

    def test_flagged_result_contains_metadata(self) -> None:
        output = format_text(_make_flagged_result())
        assert "Score:" in output
        assert "CRITICAL" in output
        assert "Violations:" in output

    def test_shows_tags(self) -> None:
        output = format_text(_make_flagged_result())
        assert "pii" in output
        assert "contact-info" in output

    def test_shows_match_positions(self) -> None:
        output = format_text(_make_flagged_result())
        assert "pos 10-26" in output


    def test_warnings_section_rendered(self) -> None:
        result = _make_clean_result()
        result.warnings = ["Rule 'x' skipped: bad config", "Something else"]
        output = format_text(result)
        assert "Warnings (2):" in output
        assert "Rule 'x' skipped: bad config" in output
        assert "Something else" in output

    def test_no_warnings_section_when_empty(self) -> None:
        output = format_text(_make_clean_result())
        assert "Warnings" not in output


    def test_incomplete_result_rendering(self) -> None:
        result = _make_clean_result()
        result.incomplete = True
        result.incomplete_reasons = ["Rule 'x' failed: timeout"]
        output = format_text(result)
        assert "INCOMPLETE" in output
        assert "Rule 'x' failed: timeout" in output
        assert "NO VIOLATIONS DETECTED | But evaluation was incomplete" in output

    def test_incomplete_and_flagged_rendering(self) -> None:
        result = _make_flagged_result()
        result.incomplete = True
        result.incomplete_reasons = ["AI evaluation failed"]
        output = format_text(result)
        assert "INCOMPLETE" in output
        assert "FLAGGED" in output
        assert "AI evaluation failed" in output
        # Should NOT show "But evaluation was incomplete" since flagged
        assert "But evaluation was incomplete" not in output


class TestJsonFormatter:
    def test_valid_json_output(self) -> None:
        output = format_json(_make_clean_result())
        data = json.loads(output)
        assert isinstance(data, dict)
        assert "violations" in data
        assert "flagged" in data

    def test_flagged_json_contains_violations(self) -> None:
        output = format_json(_make_flagged_result())
        data = json.loads(output)
        assert data["flagged"] is True
        assert len(data["violations"]) == 2
        assert data["violations"][0]["rule_id"] == "pii-email"

    def test_json_roundtrip(self) -> None:
        result = _make_flagged_result()
        output = format_json(result)
        data = json.loads(output)
        assert data["total_score"] == result.total_score
        assert data["max_severity"] == "CRITICAL"

    def test_json_incomplete_fields(self) -> None:
        result = _make_clean_result()
        result.incomplete = True
        result.incomplete_reasons = ["Load error"]
        output = format_json(result)
        data = json.loads(output)
        assert data["incomplete"] is True
        assert data["incomplete_reasons"] == ["Load error"]
