"""Stage 4 — Fix Writer."""

from __future__ import annotations

import re

from pipeline.models import (
    CodebaseExploration,
    ExploitabilityAssessment,
    Finding,
    FixResult,
    ResearchReport,
)
from pipeline.stages.base import run_stage


def write_fix(
    finding: Finding,
    research: ResearchReport,
    assessment: ExploitabilityAssessment,
    exploration: CodebaseExploration,
    *,
    sandbox_root: str,
    output_dir: str,
    previous_errors: str | None = None,
) -> FixResult:
    """Write a minimal fix for the vulnerability as a unified diff patch."""
    retry_context = ""
    if previous_errors:
        retry_context = f"""
PREVIOUS_FIX_FAILED: true
VALIDATION_ERRORS:
{previous_errors}

Review the errors above carefully. Do not repeat the same mistake.

"""

    prompt = f"""\
Write a fix for the following vulnerability.

{retry_context}--- STAGE 1: VULNERABILITY RESEARCH ---
{research.raw_output}
--- END STAGE 1 ---

--- STAGE 2: EXPLOITABILITY ASSESSMENT ---
{assessment.raw_output}
--- END STAGE 2 ---

--- STAGE 3: CODEBASE EXPLORATION ---
{exploration.raw_output}
--- END STAGE 3 ---

FINDING DETAILS:
FILE: {finding.file_path}
LINE: {finding.line_number}
REPO_PATH: .
"""

    output = run_stage(
        "fix_writer",
        prompt,
        sandbox_root=sandbox_root,
        output_dir=output_dir,
    )

    return _parse_fix(output)


def _parse_fix(output: str) -> FixResult:
    """Parse the delimited fix output from model output."""
    result = FixResult(raw_output=output)

    # Extract patch between PATCH: and PATCH_END markers
    patch_match = re.search(
        r"^PATCH:\s*\n(.*?)^PATCH_END",
        output,
        re.MULTILINE | re.DOTALL,
    )
    if patch_match:
        result.patch = patch_match.group(1).strip()

    # Extract change summary
    summary_match = re.search(
        r"^CHANGE_SUMMARY:\s*\n(.*?)(?=\nFIX_END|\Z)",
        output,
        re.MULTILINE | re.DOTALL,
    )
    if summary_match:
        result.change_summary = summary_match.group(1).strip()

    return result
