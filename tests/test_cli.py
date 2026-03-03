"""Tests for the CLI interface."""

from __future__ import annotations

import json
from pathlib import Path

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
