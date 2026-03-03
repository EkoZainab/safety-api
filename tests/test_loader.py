"""Tests for the YAML policy loader."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from safety_api.loader import load_policies, load_policy_file


class TestLoadPolicyFile:
    def test_loads_valid_policy(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "sample_policy.yaml"
        policy_file = load_policy_file(fixture)
        assert policy_file.policy.id == "sample-policy"
        assert len(policy_file.rules) == 1
        assert policy_file.rules[0].id == "sample-email"

    def test_raises_on_invalid_policy(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "invalid_policy.yaml"
        with pytest.raises(ValidationError):
            load_policy_file(fixture)

    def test_raises_on_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_policy_file(tmp_path / "nonexistent.yaml")


class TestLoadPolicies:
    def test_loads_from_directory(self, sample_policy_dir: Path) -> None:
        policies = load_policies(sample_policy_dir)
        assert len(policies) == 1
        assert policies[0].policy.id == "test-pii"

    def test_loads_multiple_policies(self, multi_policy_dir: Path) -> None:
        policies = load_policies(multi_policy_dir)
        assert len(policies) == 2
        ids = {p.policy.id for p in policies}
        assert ids == {"pii", "keywords"}

    def test_empty_directory(self, tmp_path: Path) -> None:
        policies = load_policies(tmp_path)
        assert policies == []

    def test_skips_disabled_policies(self, tmp_path: Path) -> None:
        disabled_data = {
            "policy": {
                "id": "disabled",
                "name": "Disabled Policy",
                "enabled": False,
            },
            "rules": [
                {
                    "id": "r1",
                    "name": "R1",
                    "type": "regex",
                    "severity": "LOW",
                    "pattern": r"\d+",
                    "message": "digits",
                    "enabled": True,
                }
            ],
        }
        (tmp_path / "disabled.yaml").write_text(
            yaml.dump(disabled_data), encoding="utf-8"
        )
        policies = load_policies(tmp_path)
        assert len(policies) == 0

    def test_skips_invalid_files_and_continues(self, tmp_path: Path) -> None:
        # One valid, one invalid
        valid_data = {
            "policy": {"id": "valid", "name": "Valid", "enabled": True},
            "rules": [
                {
                    "id": "r1",
                    "name": "R1",
                    "type": "regex",
                    "severity": "LOW",
                    "pattern": r"\d+",
                    "message": "digits",
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

        policies = load_policies(tmp_path)
        assert len(policies) == 1
        assert policies[0].policy.id == "valid"

    def test_loads_yml_extension(self, tmp_path: Path) -> None:
        data = {
            "policy": {"id": "yml-test", "name": "YML", "enabled": True},
            "rules": [
                {
                    "id": "r1",
                    "name": "R1",
                    "type": "regex",
                    "severity": "LOW",
                    "pattern": r"\d+",
                    "message": "digits",
                    "enabled": True,
                }
            ],
        }
        (tmp_path / "test.yml").write_text(
            yaml.dump(data), encoding="utf-8"
        )
        policies = load_policies(tmp_path)
        assert len(policies) == 1
