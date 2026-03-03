"""Data models for policies, rules, and evaluation results."""

from __future__ import annotations

import enum
import types
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, computed_field, field_validator

TEXT_PREVIEW_LENGTH = 200
DEFAULT_AI_MODEL = "claude-sonnet-4-20250514"

_SEVERITY_WEIGHTS: types.MappingProxyType[str, int] = types.MappingProxyType({
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 7,
    "CRITICAL": 10,
})


class Severity(enum.StrEnum):
    """Severity levels for policy violations, ordered by impact."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> int:
        """Numeric weight used for aggregate scoring."""
        return _SEVERITY_WEIGHTS[self.value]


class RuleType(enum.StrEnum):
    """Supported rule evaluation strategies."""

    KEYWORD = "keyword"
    REGEX = "regex"
    SEMANTIC = "semantic"


class RuleConfig(BaseModel):
    """Configuration for a single policy rule, parsed from YAML."""

    id: str
    name: str
    description: str = ""
    type: RuleType
    severity: Severity
    message: str
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)

    # Keyword-specific fields
    keywords: list[str] | None = None
    case_sensitive: bool = False
    match_whole_word: bool = True

    # Regex-specific fields
    pattern: str | None = None

    # Semantic-specific fields (API-based evaluation)
    prompt: str | None = None

    @field_validator("keywords")
    @classmethod
    def keywords_required_for_keyword_type(
        cls, v: list[str] | None, info: Any
    ) -> list[str] | None:
        if info.data.get("type") == RuleType.KEYWORD and not v:
            raise ValueError("'keywords' is required for keyword-type rules")
        return v

    @field_validator("pattern")
    @classmethod
    def pattern_required_for_regex_type(
        cls, v: str | None, info: Any
    ) -> str | None:
        if info.data.get("type") == RuleType.REGEX and not v:
            raise ValueError("'pattern' is required for regex-type rules")
        return v


class PolicyConfig(BaseModel):
    """Top-level policy metadata from a YAML file."""

    id: str
    name: str
    description: str = ""
    version: str = "1.0.0"
    enabled: bool = True


class PolicyFile(BaseModel):
    """Complete parsed YAML policy file containing metadata and rules."""

    policy: PolicyConfig
    rules: list[RuleConfig]


class Match(BaseModel):
    """A single match location within the evaluated text."""

    start: int = Field(ge=0)
    end: int = Field(ge=0)
    matched_text: str

    @field_validator("end")
    @classmethod
    def end_not_before_start(cls, v: int, info: Any) -> int:
        start = info.data.get("start", 0)
        if v < start:
            raise ValueError(f"end ({v}) must be >= start ({start})")
        return v


class Violation(BaseModel):
    """A rule violation found during evaluation."""

    rule_id: str
    rule_name: str
    policy_id: str
    policy_name: str
    severity: Severity
    message: str
    matches: list[Match] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    source: str = "rule"  # "rule" for deterministic, "ai" for API-based
    confidence: float = 1.0  # 1.0 for deterministic rules, 0.0-1.0 for AI


class EvaluationResult(BaseModel):
    """Complete result of evaluating text against all loaded policies."""

    text_preview: str = Field(
        description=f"First {TEXT_PREVIEW_LENGTH} chars of input text"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )
    policies_evaluated: int
    rules_evaluated: int
    violations: list[Violation] = Field(default_factory=list)
    total_score: float = 0.0
    max_severity: Severity | None = None
    flagged: bool = False
    evaluation_time_ms: float = 0.0
    warnings: list[str] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def violation_count(self) -> int:
        """Total number of violations."""
        return len(self.violations)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def violations_by_severity(self) -> dict[Severity, int]:
        """Count of violations grouped by severity level."""
        counts: dict[Severity, int] = {}
        for v in self.violations:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts

    def compute_score(self) -> None:
        """Compute aggregate score and severity from collected violations."""
        if not self.violations:
            self.total_score = 0.0
            self.max_severity = None
            self.flagged = False
            return

        self.total_score = sum(
            v.severity.weight * v.confidence for v in self.violations
        )
        self.max_severity = max(
            self.violations, key=lambda v: v.severity.weight
        ).severity
        self.flagged = self.total_score > 0
