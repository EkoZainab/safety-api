"""Tests for the CLI interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from safety_api.cli import main


class TestCLI:
    def test_clean_text_exits_zero(self, sample_policy_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--text", "Hello world", "--policy-dir", str(sample_policy_dir)],
        )
        assert result.exit_code == 0
        assert "CLEAN" in result.output

    def test_flagged_text_exits_one(self, sample_policy_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--text",
                "Email me at test@example.com",
                "--policy-dir",
                str(sample_policy_dir),
            ],
        )
        assert result.exit_code == 1
        assert "FLAGGED" in result.output

    def test_json_output(self, sample_policy_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--text",
                "Email me at test@example.com",
                "--policy-dir",
                str(sample_policy_dir),
                "--format",
                "json",
            ],
        )
        data = json.loads(result.output)
        assert "violations" in data
        assert data["flagged"] is True

    def test_file_input(self, sample_policy_dir: Path, tmp_path: Path) -> None:
        text_file = tmp_path / "input.txt"
        text_file.write_text("Contact test@example.com", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--file",
                str(text_file),
                "--policy-dir",
                str(sample_policy_dir),
            ],
        )
        assert result.exit_code == 1

    def test_stdin_input(self, sample_policy_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--stdin", "--policy-dir", str(sample_policy_dir)],
            input="Safe text with no issues",
        )
        assert result.exit_code == 0

    def test_severity_threshold(self, sample_policy_dir: Path) -> None:
        runner = CliRunner()
        # Email rule is HIGH — filtering at CRITICAL should suppress it
        result = runner.invoke(
            main,
            [
                "--text",
                "Email me at test@example.com",
                "--policy-dir",
                str(sample_policy_dir),
                "--severity-threshold",
                "CRITICAL",
            ],
        )
        assert result.exit_code == 0
        assert "CLEAN" in result.output

    def test_no_input_shows_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, [])
        assert result.exit_code != 0
        assert "Provide text" in result.output or "Error" in result.output

    def test_help_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Evaluate text" in result.output

    def test_verbose_flag(self, sample_policy_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--text",
                "Hello",
                "--policy-dir",
                str(sample_policy_dir),
                "--verbose",
            ],
        )
        assert result.exit_code == 0

    def test_empty_text_shows_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--text", ""])
        assert result.exit_code != 0

    def test_use_ai_without_api_key(
        self, sample_policy_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--text",
                "Hello",
                "--policy-dir",
                str(sample_policy_dir),
                "--use-ai",
            ],
        )
        assert result.exit_code != 0
        assert "ANTHROPIC_API_KEY" in result.output

    def test_dry_run_shows_rules(self, sample_policy_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--dry-run", "--policy-dir", str(sample_policy_dir)],
        )
        assert result.exit_code == 0
        assert "Loaded" in result.output
        assert "rules from" in result.output
        assert "regex" in result.output

    def test_dry_run_does_not_require_input(self, sample_policy_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--dry-run", "--policy-dir", str(sample_policy_dir)],
        )
        # --dry-run should work without --text/--file/--stdin
        assert result.exit_code == 0

    def test_strict_mode_fails_on_invalid_policy(self, tmp_path: Path) -> None:
        invalid_data = {
            "policy": {"id": "broken", "name": "Broken Policy"},
            "rules": [{"id": "bad-rule", "name": "Bad Rule"}],
        }
        (tmp_path / "invalid.yaml").write_text(
            yaml.dump(invalid_data), encoding="utf-8"
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--text",
                "Hello",
                "--policy-dir",
                str(tmp_path),
                "--strict",
            ],
        )
        assert result.exit_code != 0

    def test_empty_policy_dir_exits_two(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--text", "Hello world", "--policy-dir", str(tmp_path)],
        )
        assert result.exit_code == 2

    def test_flagged_and_incomplete_exits_one(self, tmp_path: Path) -> None:
        """Flagged takes priority over incomplete."""
        valid_data = {
            "policy": {"id": "p", "name": "P", "enabled": True},
            "rules": [
                {
                    "id": "email",
                    "name": "Email",
                    "type": "regex",
                    "severity": "HIGH",
                    "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                    "message": "Email detected",
                    "enabled": True,
                }
            ],
        }
        (tmp_path / "a_valid.yaml").write_text(
            yaml.dump(valid_data), encoding="utf-8"
        )
        (tmp_path / "b_invalid.yaml").write_text(
            "policy:\n  id: broken\nrules:\n  - bad: true\n", encoding="utf-8"
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--text",
                "Email test@example.com",
                "--policy-dir",
                str(tmp_path),
            ],
        )
        # Flagged (exit 1) takes priority over incomplete (exit 2)
        assert result.exit_code == 1

    def test_input_size_limit_rejects_large_input(
        self, sample_policy_dir: Path
    ) -> None:
        runner = CliRunner()
        large_text = "a" * 200
        result = runner.invoke(
            main,
            [
                "--text",
                large_text,
                "--policy-dir",
                str(sample_policy_dir),
                "--max-input-size",
                "100",
            ],
        )
        assert result.exit_code != 0
        assert "exceeds maximum" in result.output

    def test_input_within_size_limit_passes(
        self, sample_policy_dir: Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--text",
                "Hello world",
                "--policy-dir",
                str(sample_policy_dir),
                "--max-input-size",
                "1000",
            ],
        )
        assert result.exit_code == 0

    def test_redact_flag_hides_matched_text(
        self, sample_policy_dir: Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--text",
                "Email me at test@example.com",
                "--policy-dir",
                str(sample_policy_dir),
                "--redact",
            ],
        )
        assert result.exit_code == 1
        assert "test@example.com" not in result.output
        assert "[REDACTED]" in result.output

    def test_redact_flag_json_output(
        self, sample_policy_dir: Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "--text",
                "Email me at test@example.com",
                "--policy-dir",
                str(sample_policy_dir),
                "--redact",
                "--format",
                "json",
            ],
        )
        data = json.loads(result.output)
        assert data["text_preview"] == "[REDACTED]"
        for v in data["violations"]:
            for m in v["matches"]:
                assert m["matched_text"] == "[REDACTED]"

    def test_ai_timeout_flag_accepted(
        self, sample_policy_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        runner = CliRunner()
        # --ai-timeout requires --use-ai, which requires API key — just verify
        # the flag is accepted by the parser (error should be about the key)
        result = runner.invoke(
            main,
            [
                "--text",
                "Hello",
                "--policy-dir",
                str(sample_policy_dir),
                "--use-ai",
                "--ai-timeout",
                "60",
            ],
        )
        assert result.exit_code != 0
        assert "ANTHROPIC_API_KEY" in result.output

    def test_ai_model_flag_accepted(
        self, sample_policy_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        runner = CliRunner()
        # --ai-model requires --use-ai, which requires API key — just verify
        # the flag is accepted by the parser (error should be about the key)
        result = runner.invoke(
            main,
            [
                "--text",
                "Hello",
                "--policy-dir",
                str(sample_policy_dir),
                "--use-ai",
                "--ai-model",
                "claude-haiku-4-5-20251001",
            ],
        )
        assert result.exit_code != 0
        assert "ANTHROPIC_API_KEY" in result.output
