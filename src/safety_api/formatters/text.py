"""Human-readable text output formatter."""

from __future__ import annotations

from safety_api.models import EvaluationResult, Violation

_SEPARATOR = "=" * 60
_THIN_SEP = "-" * 60
_MAX_MATCHES_SHOWN = 5


def _format_violation(index: int, violation: Violation) -> list[str]:
    """Format a single violation for display."""
    lines: list[str] = []
    lines.append(f"\n  [{index}] {violation.severity.value} — {violation.rule_name}")
    lines.append(f"      Policy  : {violation.policy_name}")
    lines.append(f"      Message : {violation.message}")
    lines.append(f"      Source  : {violation.source}")

    if violation.matches:
        for match in violation.matches[:_MAX_MATCHES_SHOWN]:
            lines.append(
                f'      Match   : "{match.matched_text}" '
                f"(pos {match.start}-{match.end})"
            )
        remaining = len(violation.matches) - _MAX_MATCHES_SHOWN
        if remaining > 0:
            lines.append(f"      ... and {remaining} more matches")

    if violation.tags:
        lines.append(f"      Tags    : {', '.join(violation.tags)}")

    return lines


def format_text(result: EvaluationResult) -> str:
    """Format an evaluation result as a human-readable report."""
    lines: list[str] = [
        _SEPARATOR,
        "Content Policy Evaluation Report",
        _SEPARATOR,
        f"Timestamp : {result.timestamp.isoformat()}",
        f"Text      : {result.text_preview!r}",
        f"Policies  : {result.policies_evaluated}",
        f"Rules     : {result.rules_evaluated}",
        f"Time      : {result.evaluation_time_ms:.1f}ms",
        _THIN_SEP,
    ]

    if result.incomplete:
        lines.append("RESULT: INCOMPLETE")
        for reason in result.incomplete_reasons:
            lines.append(f"  - {reason}")
        lines.append(_THIN_SEP)

    if result.flagged:
        max_sev = result.max_severity.value if result.max_severity else "N/A"
        lines.append(
            f"RESULT: FLAGGED  |  Score: {result.total_score:.1f}  "
            f"|  Max Severity: {max_sev}"
        )
        by_sev = result.violations_by_severity
        breakdown = ", ".join(
            f"{count} {sev.value}" for sev, count in sorted(
                by_sev.items(), key=lambda x: x[0].weight, reverse=True
            )
        )
        lines.append(f"Violations: {result.violation_count} ({breakdown})")
        lines.append(_THIN_SEP)

        for i, violation in enumerate(result.violations, 1):
            lines.extend(_format_violation(i, violation))
    elif result.incomplete:
        lines.append(
            "NO VIOLATIONS DETECTED | But evaluation was incomplete"
        )
    else:
        lines.append("RESULT: CLEAN  |  No violations detected")

    if result.warnings:
        lines.append(_THIN_SEP)
        lines.append(f"Warnings ({len(result.warnings)}):")
        for warning in result.warnings:
            lines.append(f"  - {warning}")

    lines.append(f"\n{_SEPARATOR}")
    return "\n".join(lines)
