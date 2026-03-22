"""Stage 5 — Fix Validator."""

from __future__ import annotations

import re

from pipeline.models import Finding, FixResult, ValidationResult
from pipeline.stages.base import run_stage


def validate(
    finding: Finding,
    fix: FixResult,
    *,
    sandbox_root: str,
    output_dir: str,
) -> ValidationResult:
    """Validate the applied fix mechanically — syntax, lint, structural checks."""
    prompt = f"""\
Validate the fix that has been applied to disk.

STAGE 4 FIX OUTPUT:
CHANGE_SUMMARY: {fix.change_summary}

FILE: {finding.file_path}
REPO_PATH: .

The fixed file has already been written to disk. Run your validation checks.
"""

    output = run_stage(
        "fix_validator",
        prompt,
        sandbox_root=sandbox_root,
        output_dir=output_dir,
    )

    return _parse_validation(output)


def _parse_validation(output: str) -> ValidationResult:
    """Parse the delimited validation output from model output."""
    result = ValidationResult(raw_output=output)

    match = re.search(
        r"VALIDATION_COMPLETE\s*\n(.*?)VALIDATION_END",
        output,
        re.DOTALL,
    )
    body = match.group(1) if match else output

    def extract_field(key: str) -> str:
        m = re.search(rf"^{key}:\s*(.+)", body, re.MULTILINE)
        return m.group(1).strip() if m else ""

    result.syntax_check = extract_field("SYNTAX_CHECK")
    result.flake8_output = extract_field("FLAKE8_OUTPUT")
    result.pylint_output = extract_field("PYLINT_OUTPUT")
    result.structural_notes = extract_field("STRUCTURAL_NOTES")

    # Extract errors block
    errors_match = re.search(
        r"^ERRORS:\s*\n(.*?)(?=\nVALIDATION_END|\Z)",
        body,
        re.MULTILINE | re.DOTALL,
    )
    if errors_match:
        result.errors = errors_match.group(1).strip()

    # Determine pass/fail
    validation_field = extract_field("VALIDATION")
    result.passed = validation_field.upper() == "PASS"

    return result
