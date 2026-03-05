"""Load and validate YAML policy files from a directory."""

from __future__ import annotations

import dataclasses
import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from safety_api.models import PolicyFile

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class LoadResult:
    """Result of loading policy files, including any errors encountered."""

    policies: list[PolicyFile]
    errors: list[str]
    files_found: int


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


def load_policies(
    policy_dir: Path,
    *,
    strict: bool = False,
) -> list[PolicyFile]:
    """Load all YAML policy files from a directory.

    Args:
        policy_dir: Directory containing .yaml/.yml files.
        strict: If True, raise on the first invalid policy file
            instead of skipping it. Use this in security-critical
            deployments where partial loading is unacceptable.

    Returns:
        List of validated PolicyFile models for enabled policies.

    Raises:
        yaml.YAMLError: In strict mode, if a file is not valid YAML.
        ValidationError: In strict mode, if a file fails schema validation.
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
            if strict:
                raise
            logger.error("Failed to load policy from %s: %s", path, exc)

    return policies


def load_policies_with_errors(
    policy_dir: Path,
    *,
    strict: bool = False,
) -> LoadResult:
    """Load all YAML policy files, capturing errors instead of swallowing them.

    Args:
        policy_dir: Directory containing .yaml/.yml files.
        strict: If True, raise on the first invalid policy file.

    Returns:
        LoadResult with policies, errors, and count of files found.
    """
    policies: list[PolicyFile] = []
    errors: list[str] = []
    yaml_files = sorted(
        list(policy_dir.glob("*.yaml")) + list(policy_dir.glob("*.yml"))
    )

    if not yaml_files:
        errors.append(f"No YAML policy files found in {policy_dir}")
        return LoadResult(policies=policies, errors=errors, files_found=0)

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
            if strict:
                raise
            errors.append(f"Failed to load policy from {path.name}: {exc}")
            logger.error("Failed to load policy from %s: %s", path, exc)

    return LoadResult(
        policies=policies, errors=errors, files_found=len(yaml_files)
    )
