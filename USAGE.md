# Usage Guide

## Quick Start

```bash
# Install
pip3 install -e .

# Evaluate text
safety-api --text "Contact me at john@example.com"

# Check exit code: 0 = clean, 1 = flagged, 2 = incomplete
echo $?
```

## Input Methods

### Inline text

```bash
safety-api --text "My SSN is 123-45-6789"
```

### From a file

```bash
safety-api --file document.txt
```

### From stdin (piping)

```bash
cat document.txt | safety-api --stdin
echo "check this text" | safety-api --stdin
```

## Output Formats

### Human-readable (default)

```bash
safety-api --text "test@example.com"
```

```
============================================================
Content Policy Evaluation Report
============================================================
Timestamp : 2026-03-05T12:00:00+00:00
Text      : 'test@example.com'
Policies  : 4
Rules     : 12
Time      : 3.2ms
------------------------------------------------------------
RESULT: FLAGGED  |  Score: 7.0  |  Max Severity: HIGH
Violations: 1 (1 HIGH)
------------------------------------------------------------

  [1] HIGH — Email Detection
      Policy  : PII Detection
      Message : Email address detected in text
      Source  : rule
      Match   : "test@example.com" (pos 0-16)
      Tags    : pii, contact-info

============================================================
```

### JSON output

```bash
safety-api --text "test@example.com" --format json
```

Useful for piping into `jq` or consuming programmatically:

```bash
safety-api --text "test@example.com" --format json | jq '.violations[].rule_name'
```

## Severity Filtering

Only report violations at or above a threshold:

```bash
# Only HIGH and CRITICAL
safety-api --text "some text" --severity-threshold HIGH

# Only CRITICAL
safety-api --text "some text" --severity-threshold CRITICAL
```

| Level    | Weight | Use case                               |
|----------|--------|----------------------------------------|
| LOW      | 1      | Informational, minor concerns          |
| MEDIUM   | 3      | Should be reviewed                     |
| HIGH     | 7      | Likely requires action                 |
| CRITICAL | 10     | Immediate action required              |

## AI-Powered Evaluation

Enable semantic analysis for detecting nuanced violations like coded language, implicit bias, and context-dependent threats:

```bash
export ANTHROPIC_API_KEY=your-key-here

# Enable AI evaluation
safety-api --text "some text" --use-ai

# Use a specific model
safety-api --text "some text" --use-ai --ai-model claude-haiku-4-5-20251001
```

When `--use-ai` is enabled, two things happen:

1. **Per-rule semantic evaluation** — any `semantic` type rules in your policies call the API individually
2. **Holistic evaluation** — a broad multi-category analysis runs across all text in a single API call, detecting violations that rule-based checks might miss

AI violations appear alongside rule-based ones, with a `confidence` score (0.0-1.0) instead of the deterministic 1.0.

## Previewing Loaded Rules

Use `--dry-run` to see what rules are loaded without evaluating any text:

```bash
safety-api --dry-run
safety-api --dry-run --policy-dir ./my-policies
```

```
Loaded 12 rules from policies:
  keyword: 3
  regex: 8
  semantic: 1  (API call)
```

## Input Size Limit

Input is limited to 100KB by default to prevent resource exhaustion. The limit is a hard reject (not truncation) to avoid hiding violations at the end of the input:

```bash
# Override the default 100KB limit
safety-api --text "..." --max-input-size 204800  # 200KB
```

## Output Redaction

Use `--redact` to mask matched text and the text preview in output. This prevents the tool from leaking the PII it detects:

```bash
safety-api --text "My SSN is 123-45-6789" --redact
# Matched text shows as [REDACTED] instead of the actual SSN

safety-api --text "test@example.com" --redact --format json
# JSON output has matched_text: "[REDACTED]" and text_preview: "[REDACTED]"
```

## Strict Mode

By default, invalid policy files are skipped with a warning. Use `--strict` to fail immediately:

```bash
safety-api --text "test" --strict
```

This is useful in CI to catch policy configuration errors early.

## Custom Policies

### Policy directory

Point to a custom directory of YAML policy files:

```bash
safety-api --text "check this" --policy-dir /path/to/policies/
```

### Writing a policy file

```yaml
policy:
  id: my-policy
  name: My Custom Policy
  description: Detects custom patterns
  version: "1.0.0"
  enabled: true

rules:
  - id: api-key-detection
    name: API Key Detection
    type: regex
    severity: CRITICAL
    pattern: "(sk-[a-zA-Z0-9]{32,})"
    message: "API key detected in text"
    enabled: true
    tags: [secrets, credentials]

  - id: profanity-filter
    name: Profanity Filter
    type: keyword
    severity: MEDIUM
    keywords:
      - "badword1"
      - "badword2"
    case_sensitive: false
    match_whole_word: true
    message: "Profanity detected"
    enabled: true
    tags: [content, profanity]

  - id: tone-check
    name: Aggressive Tone Detection
    type: semantic
    severity: HIGH
    prompt: "Check if the text contains aggressive or hostile tone."
    message: "Aggressive tone detected"
    enabled: true
    tags: [tone, ai]
```

### Rule types

| Type       | Fields                                          | Requires API |
|------------|-------------------------------------------------|-------------|
| `keyword`  | `keywords`, `case_sensitive`, `match_whole_word` | No          |
| `regex`    | `pattern`                                        | No          |
| `semantic` | `prompt`                                         | Yes         |

### Disabling rules or policies

Set `enabled: false` on any rule or the policy itself to skip it:

```yaml
policy:
  id: my-policy
  name: My Policy
  enabled: false  # entire policy skipped
```

## CI/CD Integration

### Exit codes

The tool uses a **fail-closed** architecture:

| Code | Meaning    | Description                                          |
|------|------------|------------------------------------------------------|
| `0`  | Clean      | No violations found, evaluation complete             |
| `1`  | Flagged    | Violations detected (takes priority over incomplete) |
| `2`  | Incomplete | Evaluation degraded but no violations found          |

Exit code 2 is triggered when rules crash, regex times out, AI evaluation fails, or policy files are invalid. This ensures degraded evaluations are never silently treated as clean.

### Basic gate

```bash
safety-api --file user_input.txt --severity-threshold HIGH
EXIT_CODE=$?
if [ $EXIT_CODE -eq 1 ]; then
  echo "Content policy violation detected"
  exit 1
elif [ $EXIT_CODE -eq 2 ]; then
  echo "Evaluation incomplete — treating as failure"
  exit 1
fi
```

### JSON parsing in CI

```bash
RESULT=$(safety-api --file input.txt --format json)
FLAGGED=$(echo "$RESULT" | jq -r '.flagged')
SCORE=$(echo "$RESULT" | jq -r '.total_score')

if [ "$FLAGGED" = "true" ]; then
  echo "Flagged with score: $SCORE"
  exit 1
fi
```

### Strict mode for policy validation

```bash
# Fail the build if any policy file is malformed
safety-api --text "test" --policy-dir ./policies --strict
```

### With AI in CI

```bash
# Use AI evaluation in CI (requires ANTHROPIC_API_KEY secret)
safety-api --file submission.txt --use-ai --severity-threshold MEDIUM
```

## Verbose Logging

Enable debug logging to see rule evaluation details:

```bash
safety-api --text "test" --verbose
```

## All CLI Options

| Flag                    | Short | Description                                    |
|-------------------------|-------|------------------------------------------------|
| `--text`                | `-t`  | Text string to evaluate                        |
| `--file`                | `-f`  | Path to a text file to evaluate                |
| `--stdin`               |       | Read text from stdin                           |
| `--policy-dir`          | `-p`  | Directory containing YAML policy files         |
| `--format`              | `-o`  | Output format: `text` or `json`                |
| `--severity-threshold`  | `-s`  | Minimum severity to report                     |
| `--use-ai`              |       | Enable AI-based evaluation                     |
| `--ai-model`            |       | Model for AI evaluation                        |
| `--max-input-size`      |       | Max input size in bytes (default: 102400)      |
| `--redact`              |       | Mask matched text and preview in output        |
| `--strict`              |       | Fail on invalid policy files                   |
| `--dry-run`             |       | Show loaded rules without evaluating           |
| `--verbose`             | `-v`  | Enable debug logging                           |
| `--version`             |       | Show version                                   |
| `--help`                |       | Show help                                      |
