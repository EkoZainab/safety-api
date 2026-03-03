"""JSON output formatter."""

from __future__ import annotations

from safety_api.models import EvaluationResult


def format_json(result: EvaluationResult, indent: int = 2) -> str:
    """Format an evaluation result as pretty-printed JSON.

    Delegates to Pydantic's model_dump_json for correct serialization
    of enums, datetimes, and nested models.
    """
    return result.model_dump_json(indent=indent)
