# safety-api

A text content policy evaluator that flags violations with severity scores and explanations. Evaluates text against configurable YAML-based policy rules covering PII detection, hate speech, prompt injection, and violence/threats.

## Architecture

```
src/safety_api/
├── models.py          # Pydantic data models (Severity, RuleConfig, Violation, EvaluationResult)
├── engine.py          # Core evaluation engine — runs text through all loaded policies
├── cli.py             # Click CLI with multiple input methods and output formats
├── loader.py          # YAML policy file loader with validation
├── anthropic_eval.py  # Optional AI-based holistic evaluation layer
├── rules/
│   ├── base.py        # Abstract base class for rules
│   ├── keyword.py     # Keyword/phrase matching (compiled to single regex)
│   ├── regex.py       # Regex pattern matching
│   └── semantic.py    # API-based semantic evaluation
└── formatters/
    ├── text.py        # Human-readable report output
    └── json_fmt.py    # JSON output via Pydantic serialization
```

The evaluator uses a **factory pattern** for rules — adding a new rule type requires implementing `BaseRule.evaluate()` and registering it in the rule registry. No engine changes needed.

## Installation

```bash
pip3 install -e .
```

With AI evaluation support:

```bash
pip3 install -e ".[ai]"
```

With development tools (pytest, ruff, mypy):

```bash
pip3 install -e ".[dev]"
```

## Usage

### Basic evaluation

```bash
# Evaluate a text string
safety-api --text "Contact me at john@example.com"

# Evaluate from a file
safety-api --file input.txt

# Read from stdin
echo "some text to check" | safety-api --stdin
```

### Output formats

```bash
# Human-readable report (default)
safety-api --text "test@example.com" --format text

# JSON output for programmatic use
safety-api --text "test@example.com" --format json
```

### Severity filtering

Only report violations at or above a threshold:

```bash
safety-api --text "some text" --severity-threshold HIGH
```

Severity levels and their weights:

| Level    | Weight | Description                            |
|----------|--------|----------------------------------------|
| LOW      | 1      | Minor concern, informational           |
| MEDIUM   | 3      | Moderate concern, should be reviewed   |
| HIGH     | 7      | Serious concern, likely requires action |
| CRITICAL | 10     | Severe violation, immediate action      |

### AI-powered evaluation

Enable semantic analysis using the Anthropic API for detecting nuanced violations like coded language and implicit bias:

```bash
export ANTHROPIC_API_KEY=your-key-here
safety-api --text "some text" --use-ai
```

### Exit codes

- `0` — no violations found (clean)
- `1` — violations detected (flagged)

This makes the tool suitable for CI/CD pipeline integration:

```bash
safety-api --text "$USER_INPUT" --severity-threshold HIGH || echo "Content flagged"
```

## Policy Configuration

Policies are defined in YAML files in the `policies/` directory. Each file contains a policy with one or more rules.

### Included policies

- **pii_detection.yaml** — email addresses, SSNs, phone numbers, credit card numbers
- **hate_speech.yaml** — dehumanizing language, supremacist rhetoric, calls for group violence
- **prompt_injection.yaml** — instruction overrides, role assumption, system prompt extraction, encoding evasion
- **violence_threats.yaml** — direct threats, weapons in threatening context, self-harm, mass violence

### Writing custom policies

```yaml
policy:
  id: custom-policy
  name: Custom Policy
  description: Your policy description
  version: "1.0.0"
  enabled: true

rules:
  - id: custom-regex-rule
    name: Pattern Match
    type: regex                    # regex, keyword, or semantic
    severity: HIGH                 # LOW, MEDIUM, HIGH, or CRITICAL
    pattern: "your-regex-here"
    message: Description of what was detected
    enabled: true
    tags: [custom, category]

  - id: custom-keyword-rule
    name: Keyword Match
    type: keyword
    severity: MEDIUM
    keywords:
      - "phrase one"
      - "phrase two"
    case_sensitive: false
    match_whole_word: true
    message: Keyword detected
    enabled: true
    tags: [custom]
```

Use a custom policy directory:

```bash
safety-api --text "some text" --policy-dir /path/to/policies/
```

## Development

### Running tests

```bash
pytest
```

### Linting and type checking

```bash
ruff check src/ tests/
mypy src/
```

## Design Decisions

- **Pydantic v2** for YAML validation at the boundary and JSON serialization. Field validators enforce cross-field constraints (e.g., keyword rules must have keywords).
- **Click** over argparse for decorator-based CLI definition and built-in test runner.
- **Rule factory pattern** for extensibility — new rule types are a single class + registry entry.
- **Graceful degradation** — invalid policy files are logged and skipped, semantic rules no-op without an API client.
- **Deterministic scoring** — aggregate score is the sum of `severity_weight * confidence` across all violations, giving consistent, explainable results.
