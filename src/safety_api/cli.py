"""CLI interface for the content policy evaluator."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import click

from safety_api.engine import Evaluator
from safety_api.formatters.json_fmt import format_json
from safety_api.formatters.text import format_text
from safety_api.models import DEFAULT_AI_MODEL, Severity

# Default policy directory is the policies/ dir at the project root
DEFAULT_POLICY_DIR = Path(__file__).resolve().parent.parent.parent / "policies"


def _resolve_input(
    text: str | None,
    input_file: Path | None,
    use_stdin: bool,
) -> str | None:
    """Resolve text input from one of three sources."""
    if text:
        return text
    if input_file:
        return input_file.read_text(encoding="utf-8")
    if use_stdin:
        return click.get_text_stream("stdin").read()
    return None


def _get_anthropic_client() -> Any:
    """Lazily import and initialize the Anthropic client.

    Validates that the API key is present before constructing the
    client so failures surface immediately rather than mid-evaluation.
    """
    import os

    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise click.UsageError(
            "ANTHROPIC_API_KEY environment variable is required for --use-ai. "
            "Set it with: export ANTHROPIC_API_KEY=your-key-here"
        )

    try:
        import anthropic

        return anthropic.Anthropic()
    except ImportError as err:
        raise click.UsageError(
            "The 'anthropic' package is required for --use-ai. "
            "Install with: pip3 install 'safety-api[ai]'"
        ) from err
    except Exception as exc:
        raise click.UsageError(
            f"Failed to initialize Anthropic client: {exc}"
        ) from exc


@click.command()
@click.option(
    "--text",
    "-t",
    type=str,
    default=None,
    help="Text string to evaluate.",
)
@click.option(
    "--file",
    "-f",
    "input_file",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to a text file to evaluate.",
)
@click.option(
    "--stdin",
    "use_stdin",
    is_flag=True,
    default=False,
    help="Read text from stdin.",
)
@click.option(
    "--policy-dir",
    "-p",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Directory containing YAML policy files.",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format (default: text).",
)
@click.option(
    "--severity-threshold",
    "-s",
    type=click.Choice(
        ["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False
    ),
    default=None,
    help="Only report violations at or above this severity level.",
)
@click.option(
    "--use-ai",
    is_flag=True,
    default=False,
    help="Enable AI-based semantic evaluation (requires ANTHROPIC_API_KEY).",
)
@click.option(
    "--ai-model",
    type=str,
    default=DEFAULT_AI_MODEL,
    help="Model to use for AI evaluation.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show loaded rules and exit without evaluating.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable verbose logging output.",
)
@click.version_option(package_name="safety-api")
def main(
    text: str | None,
    input_file: Path | None,
    use_stdin: bool,
    policy_dir: Path | None,
    output_format: str,
    severity_threshold: str | None,
    use_ai: bool,
    ai_model: str,
    dry_run: bool,
    verbose: bool,
) -> None:
    """Evaluate text against configurable content safety policies.

    Provide input via --text, --file, or --stdin. The tool exits with
    code 0 for clean text and code 1 when violations are found, making
    it suitable for CI/CD pipeline integration.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    # Resolve policy directory
    resolved_policy_dir = policy_dir or DEFAULT_POLICY_DIR
    if not resolved_policy_dir.is_dir():
        raise click.UsageError(
            f"Policy directory not found: {resolved_policy_dir}"
        )

    # Optionally initialize AI client
    anthropic_client = _get_anthropic_client() if use_ai else None

    severity = Severity(severity_threshold) if severity_threshold else None

    evaluator = Evaluator.from_policy_dir(
        policy_dir=resolved_policy_dir,
        anthropic_client=anthropic_client,
        ai_model=ai_model,
        severity_threshold=severity,
    )

    if dry_run:
        summary = evaluator.summarize_rules()
        total = sum(summary.values())
        click.echo(f"Loaded {total} rules from {resolved_policy_dir}:")
        for rule_type, count in sorted(summary.items()):
            label = "  (API call)" if rule_type == "semantic" else ""
            click.echo(f"  {rule_type}: {count}{label}")
        return

    # Resolve input text
    input_text = _resolve_input(text, input_file, use_stdin)
    if not input_text:
        raise click.UsageError(
            "Provide text via --text, --file, or --stdin."
        )

    result = evaluator.evaluate(input_text)

    # Format and output
    if output_format == "json":
        click.echo(format_json(result))
    else:
        click.echo(format_text(result))

    # Exit code: 1 if flagged, 0 if clean
    sys.exit(1 if result.flagged else 0)
