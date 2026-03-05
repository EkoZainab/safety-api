"""Tests for the evaluation engine."""

from __future__ import annotations

from pathlib import Path

from safety_api.engine import Evaluator
from safety_api.models import Match, PolicyFile, Severity, Violation


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

    def test_large_input_text(self, pii_policy: PolicyFile) -> None:
        large_text = "a" * 10_000 + " test@example.com " + "b" * 10_000
        evaluator = Evaluator(policies=[pii_policy])
        result = evaluator.evaluate(large_text)
        assert result.flagged
        assert any("email" in v.rule_id for v in result.violations)

    def test_concurrent_evaluations(self, pii_policy: PolicyFile) -> None:
        import concurrent.futures

        evaluator = Evaluator(policies=[pii_policy])
        texts = [
            "Contact test@example.com",
            "Clean text here",
            "SSN is 123-45-6789",
            "Another clean text",
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(evaluator.evaluate, texts))

        assert results[0].flagged  # email
        assert not results[1].flagged  # clean
        assert results[2].flagged  # SSN
        assert not results[3].flagged  # clean

    def test_holistic_ai_evaluation_called(self) -> None:
        from unittest.mock import MagicMock, patch

        from safety_api.models import PolicyConfig, RuleConfig, RuleType

        policy = PolicyFile(
            policy=PolicyConfig(id="p", name="P"),
            rules=[
                RuleConfig(
                    id="kw",
                    name="KW",
                    type=RuleType.KEYWORD,
                    severity=Severity.LOW,
                    keywords=["test"],
                    message="match",
                ),
            ],
        )
        mock_client = MagicMock()

        fake_violations = []
        with patch(
            "safety_api.engine.evaluate_with_ai", return_value=fake_violations
        ) as mock_eval:
            evaluator = Evaluator(
                policies=[policy], anthropic_client=mock_client
            )
            evaluator.evaluate("some text")
            mock_eval.assert_called_once_with(
                "some text",
                mock_client,
                model=evaluator._ai_model,
                timeout=evaluator._ai_timeout,
            )

    def test_holistic_ai_violations_merged(self) -> None:
        from unittest.mock import MagicMock, patch

        from safety_api.models import Match, PolicyConfig, RuleConfig, RuleType, Violation

        policy = PolicyFile(
            policy=PolicyConfig(id="p", name="P"),
            rules=[
                RuleConfig(
                    id="kw",
                    name="KW",
                    type=RuleType.KEYWORD,
                    severity=Severity.LOW,
                    keywords=["test"],
                    message="match",
                ),
            ],
        )
        mock_client = MagicMock()
        ai_violation = Violation(
            rule_id="ai-pii",
            rule_name="AI: PII",
            policy_id="ai-holistic",
            policy_name="AI Holistic Evaluation",
            severity=Severity.HIGH,
            message="PII detected",
            source="ai",
            confidence=0.9,
        )

        with patch(
            "safety_api.engine.evaluate_with_ai", return_value=[ai_violation]
        ):
            evaluator = Evaluator(
                policies=[policy], anthropic_client=mock_client
            )
            result = evaluator.evaluate("some text")
            assert any(v.source == "ai" for v in result.violations)
            assert any(v.rule_id == "ai-pii" for v in result.violations)

    def test_holistic_ai_failure_produces_warning(self) -> None:
        from unittest.mock import MagicMock, patch

        from safety_api.models import PolicyConfig, RuleConfig, RuleType

        policy = PolicyFile(
            policy=PolicyConfig(id="p", name="P"),
            rules=[
                RuleConfig(
                    id="kw",
                    name="KW",
                    type=RuleType.KEYWORD,
                    severity=Severity.LOW,
                    keywords=["test"],
                    message="match",
                ),
            ],
        )
        mock_client = MagicMock()

        with patch(
            "safety_api.engine.evaluate_with_ai",
            side_effect=RuntimeError("API down"),
        ):
            evaluator = Evaluator(
                policies=[policy], anthropic_client=mock_client
            )
            result = evaluator.evaluate("some text")
            assert any("Holistic AI evaluation failed" in w for w in result.warnings)

    def test_rule_build_failure_marks_incomplete(self) -> None:
        from safety_api.models import PolicyConfig, RuleConfig, RuleType

        policy = PolicyFile(
            policy=PolicyConfig(id="p", name="P"),
            rules=[
                RuleConfig(
                    id="bad-regex",
                    name="Bad Regex",
                    type=RuleType.REGEX,
                    severity=Severity.HIGH,
                    pattern=r"(?P<bad",  # invalid
                    message="broken",
                ),
            ],
        )
        evaluator = Evaluator(policies=[policy])
        result = evaluator.evaluate("some text")
        assert result.incomplete is True
        assert any("bad-regex" in r for r in result.incomplete_reasons)

    def test_rule_eval_failure_marks_incomplete(self) -> None:
        from unittest.mock import MagicMock

        from safety_api.models import PolicyConfig, RuleConfig, RuleType

        policy = PolicyFile(
            policy=PolicyConfig(id="p", name="P"),
            rules=[
                RuleConfig(
                    id="email",
                    name="Email",
                    type=RuleType.REGEX,
                    severity=Severity.HIGH,
                    pattern=r"\d+",
                    message="test",
                ),
            ],
        )
        evaluator = Evaluator(policies=[policy])

        # Force the rule to fail during evaluation
        evaluator._rule_instances[0][1].evaluate = MagicMock(
            side_effect=RuntimeError("boom")
        )
        result = evaluator.evaluate("123")
        assert result.incomplete is True
        assert any("email" in r and "boom" in r for r in result.incomplete_reasons)

    def test_holistic_ai_failure_marks_incomplete(self) -> None:
        from unittest.mock import MagicMock, patch

        from safety_api.models import PolicyConfig, RuleConfig, RuleType

        policy = PolicyFile(
            policy=PolicyConfig(id="p", name="P"),
            rules=[
                RuleConfig(
                    id="kw",
                    name="KW",
                    type=RuleType.KEYWORD,
                    severity=Severity.LOW,
                    keywords=["test"],
                    message="match",
                ),
            ],
        )
        mock_client = MagicMock()
        with patch(
            "safety_api.engine.evaluate_with_ai",
            side_effect=RuntimeError("API down"),
        ):
            evaluator = Evaluator(
                policies=[policy], anthropic_client=mock_client
            )
            result = evaluator.evaluate("some text")
            assert result.incomplete is True
            assert any(
                "Holistic AI evaluation failed" in r
                for r in result.incomplete_reasons
            )

    def test_load_errors_marks_incomplete(self) -> None:
        from safety_api.models import PolicyConfig, RuleConfig, RuleType

        policy = PolicyFile(
            policy=PolicyConfig(id="p", name="P"),
            rules=[
                RuleConfig(
                    id="kw",
                    name="KW",
                    type=RuleType.KEYWORD,
                    severity=Severity.LOW,
                    keywords=["test"],
                    message="match",
                ),
            ],
        )
        evaluator = Evaluator(
            policies=[policy],
            load_errors=["Failed to load policy from bad.yaml: invalid"],
        )
        result = evaluator.evaluate("hello")
        assert result.incomplete is True
        assert any("bad.yaml" in r for r in result.incomplete_reasons)

    def test_clean_complete_evaluation(
        self, pii_policy: PolicyFile, clean_text: str
    ) -> None:
        evaluator = Evaluator(policies=[pii_policy])
        result = evaluator.evaluate(clean_text)
        assert not result.flagged
        assert not result.incomplete
        assert result.incomplete_reasons == []

    def test_empty_policy_dir_marks_incomplete(self, tmp_path: Path) -> None:
        evaluator = Evaluator.from_policy_dir(tmp_path)
        result = evaluator.evaluate("some text")
        assert result.incomplete is True
        assert any("No YAML policy files found" in r for r in result.incomplete_reasons)

    def test_semantic_without_client_not_incomplete(self) -> None:
        """Semantic rules without a client is intentional config, not incomplete."""
        from safety_api.models import PolicyConfig, RuleConfig, RuleType

        policy = PolicyFile(
            policy=PolicyConfig(id="p", name="P"),
            rules=[
                RuleConfig(
                    id="sem",
                    name="Semantic",
                    type=RuleType.SEMANTIC,
                    severity=Severity.HIGH,
                    prompt="Analyze this text.",
                    message="violation",
                ),
            ],
        )
        evaluator = Evaluator(policies=[policy])  # no client
        result = evaluator.evaluate("some text")
        assert not result.incomplete

    def test_zero_width_chars_stripped_for_matching(self) -> None:
        """Zero-width characters should not prevent keyword matches."""
        from safety_api.models import PolicyConfig, RuleConfig, RuleType

        policy = PolicyFile(
            policy=PolicyConfig(id="p", name="P"),
            rules=[
                RuleConfig(
                    id="kw",
                    name="KW",
                    type=RuleType.KEYWORD,
                    severity=Severity.HIGH,
                    keywords=["kill"],
                    message="violence",
                ),
            ],
        )
        evaluator = Evaluator(policies=[policy])
        result = evaluator.evaluate("k\u200bill")
        assert result.flagged
        assert result.violation_count >= 1

    def test_nfkc_normalization_matches_fullwidth(self) -> None:
        """Fullwidth characters should be normalized and matched."""
        from safety_api.models import PolicyConfig, RuleConfig, RuleType

        policy = PolicyFile(
            policy=PolicyConfig(id="p", name="P"),
            rules=[
                RuleConfig(
                    id="kw",
                    name="KW",
                    type=RuleType.KEYWORD,
                    severity=Severity.HIGH,
                    keywords=["kill"],
                    message="violence",
                ),
            ],
        )
        evaluator = Evaluator(policies=[policy])
        # Fullwidth 'ｋｉｌｌ' (U+FF4B U+FF49 U+FF4C U+FF4C)
        result = evaluator.evaluate("\uff4b\uff49\uff4c\uff4c")
        assert result.flagged

    def test_normalization_preserves_original_in_preview(self) -> None:
        """text_preview should contain the original (un-normalized) text."""
        from safety_api.models import PolicyConfig, RuleConfig, RuleType

        policy = PolicyFile(
            policy=PolicyConfig(id="p", name="P"),
            rules=[
                RuleConfig(
                    id="kw",
                    name="KW",
                    type=RuleType.KEYWORD,
                    severity=Severity.LOW,
                    keywords=["hello"],
                    message="m",
                ),
            ],
        )
        original = "h\u200bello"
        evaluator = Evaluator(policies=[policy])
        result = evaluator.evaluate(original)
        assert result.text_preview == original

    # ------------------------------------------------------------------
    # Deduplication tests
    # ------------------------------------------------------------------

    def test_dedup_overlapping_higher_severity_kept(self) -> None:
        high = Violation(
            rule_id="r1", rule_name="R1", policy_id="p", policy_name="P",
            severity=Severity.HIGH, message="m",
            matches=[Match(start=0, end=10, matched_text="overlap")],
        )
        low = Violation(
            rule_id="r2", rule_name="R2", policy_id="p", policy_name="P",
            severity=Severity.LOW, message="m",
            matches=[Match(start=5, end=15, matched_text="overlap")],
        )
        result = Evaluator._deduplicate_violations([low, high])
        assert len(result) == 1
        assert result[0].rule_id == "r1"

    def test_dedup_non_overlapping_both_kept(self) -> None:
        v1 = Violation(
            rule_id="r1", rule_name="R1", policy_id="p", policy_name="P",
            severity=Severity.HIGH, message="m",
            matches=[Match(start=0, end=5, matched_text="a")],
        )
        v2 = Violation(
            rule_id="r2", rule_name="R2", policy_id="p", policy_name="P",
            severity=Severity.HIGH, message="m",
            matches=[Match(start=10, end=15, matched_text="b")],
        )
        result = Evaluator._deduplicate_violations([v1, v2])
        assert len(result) == 2

    def test_dedup_tiebreak_confidence(self) -> None:
        high_conf = Violation(
            rule_id="r1", rule_name="R1", policy_id="p", policy_name="P",
            severity=Severity.HIGH, message="m", confidence=0.95,
            matches=[Match(start=0, end=10, matched_text="a")],
        )
        low_conf = Violation(
            rule_id="r2", rule_name="R2", policy_id="p", policy_name="P",
            severity=Severity.HIGH, message="m", confidence=0.5,
            matches=[Match(start=0, end=10, matched_text="a")],
        )
        result = Evaluator._deduplicate_violations([low_conf, high_conf])
        assert len(result) == 1
        assert result[0].rule_id == "r1"

    def test_dedup_tiebreak_source(self) -> None:
        rule_v = Violation(
            rule_id="r1", rule_name="R1", policy_id="p", policy_name="P",
            severity=Severity.HIGH, message="m", confidence=0.9, source="rule",
            matches=[Match(start=0, end=10, matched_text="a")],
        )
        ai_v = Violation(
            rule_id="r2", rule_name="R2", policy_id="p", policy_name="P",
            severity=Severity.HIGH, message="m", confidence=0.9, source="ai",
            matches=[Match(start=0, end=10, matched_text="a")],
        )
        result = Evaluator._deduplicate_violations([ai_v, rule_v])
        assert len(result) == 1
        assert result[0].source == "rule"

    def test_dedup_matchless_always_kept(self) -> None:
        with_match = Violation(
            rule_id="r1", rule_name="R1", policy_id="p", policy_name="P",
            severity=Severity.HIGH, message="m",
            matches=[Match(start=0, end=10, matched_text="a")],
        )
        matchless = Violation(
            rule_id="r2", rule_name="R2", policy_id="p", policy_name="P",
            severity=Severity.HIGH, message="m", matches=[],
        )
        result = Evaluator._deduplicate_violations([with_match, matchless])
        assert len(result) == 2

    def test_dedup_empty_list(self) -> None:
        assert Evaluator._deduplicate_violations([]) == []

    def test_dedup_single_violation(self) -> None:
        v = Violation(
            rule_id="r1", rule_name="R1", policy_id="p", policy_name="P",
            severity=Severity.HIGH, message="m",
            matches=[Match(start=0, end=5, matched_text="a")],
        )
        result = Evaluator._deduplicate_violations([v])
        assert len(result) == 1

    def test_dedup_integration_overlapping_rules(self) -> None:
        """Two rules matching overlapping spans → only higher severity survives."""
        from safety_api.models import PolicyConfig, RuleConfig, RuleType

        policy = PolicyFile(
            policy=PolicyConfig(id="p", name="P"),
            rules=[
                RuleConfig(
                    id="broad",
                    name="Broad",
                    type=RuleType.REGEX,
                    severity=Severity.LOW,
                    pattern=r"\d{3}-\d{2}-\d{4}",
                    message="digits",
                ),
                RuleConfig(
                    id="ssn",
                    name="SSN",
                    type=RuleType.REGEX,
                    severity=Severity.CRITICAL,
                    pattern=r"\b\d{3}-\d{2}-\d{4}\b",
                    message="SSN",
                ),
            ],
        )
        evaluator = Evaluator(policies=[policy])
        result = evaluator.evaluate("My SSN is 123-45-6789.")
        # Both rules match the same span; only the CRITICAL one should survive
        assert result.violation_count == 1
        assert result.violations[0].severity == Severity.CRITICAL

    def test_disabled_semantic_rule_no_api_call(self) -> None:
        from unittest.mock import MagicMock, patch

        from safety_api.models import PolicyConfig, RuleConfig, RuleType

        policy = PolicyFile(
            policy=PolicyConfig(id="sem-policy", name="Semantic Policy"),
            rules=[
                RuleConfig(
                    id="disabled-semantic",
                    name="Disabled Semantic",
                    type=RuleType.SEMANTIC,
                    severity=Severity.HIGH,
                    prompt="Analyze this text.",
                    message="AI violation",
                    enabled=False,
                ),
            ],
        )
        mock_client = MagicMock()
        # Patch holistic evaluator so the only possible API call
        # would come from the disabled semantic rule itself.
        with patch("safety_api.engine.evaluate_with_ai", return_value=[]):
            evaluator = Evaluator(
                policies=[policy], anthropic_client=mock_client
            )
            result = evaluator.evaluate("some text")

        mock_client.messages.create.assert_not_called()
        assert result.rules_evaluated == 0

    # ------------------------------------------------------------------
    # Audit logging tests
    # ------------------------------------------------------------------

    def test_audit_log_emitted_with_handler(
        self, pii_policy: PolicyFile
    ) -> None:
        import json
        import logging
        import logging.handlers

        audit = logging.getLogger("safety_api.audit")
        handler = logging.handlers.MemoryHandler(capacity=100)
        handler.setFormatter(logging.Formatter("%(message)s"))
        audit.addHandler(handler)
        audit.setLevel(logging.INFO)

        evaluator = Evaluator(policies=[pii_policy])
        evaluator.evaluate("test@example.com")

        handler.flush()
        assert len(handler.buffer) == 1
        record = json.loads(handler.buffer[0].getMessage())
        assert "text_hash" in record
        assert "timestamp" in record
        assert record["flagged"] is True
        assert record["violation_count"] >= 1
        assert "text_preview" not in record

    def test_audit_log_not_emitted_without_handler(
        self, pii_policy: PolicyFile
    ) -> None:
        import logging

        audit = logging.getLogger("safety_api.audit")
        assert len(audit.handlers) == 0

        evaluator = Evaluator(policies=[pii_policy])
        evaluator.evaluate("test@example.com")
        # No handler means no output — nothing to assert except no crash

    def test_audit_log_excludes_input_text(
        self, pii_policy: PolicyFile
    ) -> None:
        import json
        import logging
        import logging.handlers

        audit = logging.getLogger("safety_api.audit")
        handler = logging.handlers.MemoryHandler(capacity=100)
        handler.setFormatter(logging.Formatter("%(message)s"))
        audit.addHandler(handler)
        audit.setLevel(logging.INFO)

        secret = "super-secret-test@example.com"
        evaluator = Evaluator(policies=[pii_policy])
        evaluator.evaluate(secret)

        handler.flush()
        raw = handler.buffer[0].getMessage()
        assert secret not in raw
        record = json.loads(raw)
        assert all(secret not in str(v) for v in record.values())
