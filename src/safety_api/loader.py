"""Load and validate YAML policy files from a directory."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from safety_api.models import PolicyFile

logger = logging.getLogger(__name__)


def load_policy_file(path: Path) -> PolicyFile:
    """Load and validate a single YAML policy file.

    Args:
        path: Path to the YAML file.

    Returns:
        Validated PolicyFile model.

    Raises:
        FileNotFoundError: If the file does not exist.
        yaml.YAMLError: If the file is not valid YAML.
        ValidationError: If the YAML does not match the expected schema.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return PolicyFile.model_validate(raw)


def load_policies(policy_dir: Path) -> list[PolicyFile]:
    """Load all YAML policy files from a directory.

    Files that fail validation are logged as errors and skipped,
    allowing partial policy loading when some files are malformed.

    Args:
        policy_dir: Directory containing .yaml/.yml files.

    Returns:
        List of validated PolicyFile models for enabled policies.
    """
    policies: list[PolicyFile] = []
    yaml_files = sorted(
        list(policy_dir.glob("*.yaml")) + list(policy_dir.glob("*.yml"))
    )

    if not yaml_files:
        logger.warning("No YAML policy files found in %s", policy_dir)
        return policies

    for path in yaml_files:
        try:
            policy_file = load_policy_file(path)
            if policy_file.policy.enabled:
                policies.append(policy_file)
                logger.info(
                    "Loaded policy '%s' (%d rules) from %s",
                    policy_file.policy.name,
                    len(policy_file.rules),
                    path.name,
                )
            else:
                logger.info("Skipping disabled policy in %s", path.name)
        except (yaml.YAMLError, ValidationError) as exc:
            logger.error("Failed to load policy from %s: %s", path, exc)

    return policies
