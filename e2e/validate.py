"""Output validation for E2E pipeline runs."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass
class StageCheck:
    stage: str
    file_expected: str
    found: bool
    non_empty: bool
    optional: bool = False


@dataclass
class FindingResult:
    finding_id: str
    finding: dict
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    output_dir: str = ""
    error: str = ""


@dataclass
class ValidatedResult:
    finding_result: FindingResult
    checks: list[StageCheck] = field(default_factory=list)
    verdict: str = ""
    all_required_passed: bool = False


# Files the pipeline always writes (regardless of verdict)
_REQUIRED_FILES = [
    ("Stage 0", "normalizer_raw.json"),
    ("Stage 1", "vulnerability_researcher.txt"),
    ("Stage 2", "exploitability_assessor.txt"),
    ("Stage 2b", "assessment_verifier.txt"),
    ("Stage 6", "pr_author.txt"),
    ("Summary", "summary.json"),
]

# Files only written for PATCH / SUPPRESS+CODE_CHANGE verdicts
_CONDITIONAL_FILES = [
    ("Stage 3", "codebase_explorer.txt"),
    ("Stage 4", "fix_writer.txt"),
    ("Stage 5", "fix_validator.txt"),
]

# Dry-run output files
_DRY_RUN_FILES = [
    ("Dry Run JSON", "dry_run_output.json"),
    ("Dry Run Body", "dry_run_body.md"),
]


def _check_file(
    output_dir: str, filename: str, stage: str, optional: bool = False
) -> StageCheck:
    path = os.path.join(output_dir, filename)
    found = os.path.isfile(path)
    non_empty = found and os.path.getsize(path) > 0
    return StageCheck(
        stage=stage,
        file_expected=filename,
        found=found,
        non_empty=non_empty,
        optional=optional,
    )


def _parse_verdict(output_dir: str) -> str:
    summary_path = os.path.join(output_dir, "summary.json")
    if not os.path.isfile(summary_path):
        return ""
    try:
        with open(summary_path) as f:
            data = json.load(f)
        return data.get("verdict", data.get("outcome", ""))
    except (json.JSONDecodeError, OSError):
        return ""


def check_outputs(result: FindingResult, dry_run: bool = True) -> ValidatedResult:
    """Smoke-test that a pipeline run produced expected output files."""
    checks: list[StageCheck] = []
    output_dir = result.output_dir

    # Required stage outputs
    for stage, filename in _REQUIRED_FILES:
        checks.append(_check_file(output_dir, filename, stage))

    # Conditional stage outputs (optional — depend on verdict)
    for stage, filename in _CONDITIONAL_FILES:
        checks.append(_check_file(output_dir, filename, stage, optional=True))

    # Dry-run outputs
    if dry_run and result.exit_code == 0:
        for stage, filename in _DRY_RUN_FILES:
            checks.append(_check_file(output_dir, filename, stage))

    verdict = _parse_verdict(output_dir)

    all_required = all(c.found and c.non_empty for c in checks if not c.optional)

    return ValidatedResult(
        finding_result=result,
        checks=checks,
        verdict=verdict,
        all_required_passed=all_required,
    )
