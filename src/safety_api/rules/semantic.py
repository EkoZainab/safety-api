"""Anthropic API-based semantic rule implementation."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from pydantic import BaseModel, Field, ValidationError

from safety_api.models import DEFAULT_AI_MODEL, DEFAULT_AI_TIMEOUT, Match, RuleConfig
from safety_api.rules.base import BaseRule

logger = logging.getLogger(__name__)


class _SpanResponse(BaseModel):
    """Validated span from semantic API response."""

    start: int = Field(ge=0)
    end: int = Field(ge=0)
    text: str = ""


class _SemanticResponse(BaseModel):
    """Validated API response for semantic evaluation."""

    flagged: bool
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    explanation: str = ""
    spans: list[_SpanResponse] = Field(default_factory=list)


class SemanticRule(BaseRule):
    """Uses the Anthropic API for semantic content evaluation.

    This rule sends text to an LLM for nuanced analysis that cannot be
    captured by keyword or regex matching alone — such as detecting coded
    language, implicit bias, or context-dependent threats.

    The rule is a no-op when no API client is provided, making it safe
    to include in policy files without requiring API credentials.
    """

    def __init__(
        self,
        config: RuleConfig,
        anthropic_client: Any | None = None,
        model: str = DEFAULT_AI_MODEL,
        timeout: float = DEFAULT_AI_TIMEOUT,
    ) -> None:
        super().__init__(config)
        self._client = anthropic_client
        self._model = model
        self._timeout = timeout

    def evaluate(self, text: str) -> list[Match]:
        """Evaluate text using the Anthropic API.

        Returns an empty list if no client is configured, allowing
        semantic rules to be defined in YAML without requiring
        API access for basic rule-based evaluation.
        """
        if self._client is None:
            logger.debug(
                "Skipping semantic rule '%s': no API client configured",
                self.rule_id,
            )
            return []
        return self._call_api(text)

    def _call_api(self, text: str) -> list[Match]:
        """Make the API call and parse the structured JSON response."""
        evaluation_prompt = (
            self.config.prompt
            or "Analyze this text for policy violations."
        )

        system_msg = (
            "You are a content policy evaluator. Respond ONLY with valid JSON.\n"
            "Schema: {\"flagged\": bool, \"confidence\": float 0-1, "
            "\"explanation\": str, \"spans\": [{\"start\": int, \"end\": int, "
            "\"text\": str}]}\n"
            "If no violation is found, set flagged=false and spans to an empty list."
        )
        sanitized_text = text.replace("</text_to_evaluate>", "&lt;/text_to_evaluate&gt;")
        user_msg = (
            f"{evaluation_prompt}\n\n"
            f"<text_to_evaluate>\n{sanitized_text}\n</text_to_evaluate>"
        )

        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=1024,
                system=system_msg,
                messages=[{"role": "user", "content": user_msg}],
                timeout=httpx.Timeout(self._timeout, connect=10.0),
            )
            content = response.content[0].text
            result = _SemanticResponse.model_validate(json.loads(content))

            if not result.flagged:
                return []

            text_len = len(text)
            if result.spans:
                matches: list[Match] = []
                for s in result.spans:
                    clamped_start = min(s.start, text_len)
                    clamped_end = min(s.end, text_len)
                    if clamped_start >= clamped_end:
                        continue
                    matches.append(Match(
                        start=clamped_start,
                        end=clamped_end,
                        matched_text=s.text or text[clamped_start:clamped_end],
                    ))
                if matches:
                    return matches

            # Flagged but no valid spans — flag the entire text
            return [Match(start=0, end=text_len, matched_text="[full text]")]

        except (ValidationError, json.JSONDecodeError) as e:
            raise RuntimeError(
                f"Invalid API response for rule '{self.rule_id}': {e}"
            ) from e
