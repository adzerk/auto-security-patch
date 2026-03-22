"""Stage 3 — Codebase Explorer."""

from __future__ import annotations

import re

from pipeline.models import (
    CodebaseExploration,
    ExploitabilityAssessment,
    Finding,
    ResearchReport,
)
from pipeline.stages.base import run_stage


def explore(
    finding: Finding,
    research: ResearchReport,
    assessment: ExploitabilityAssessment,
    *,
    sandbox_root: str,
    output_dir: str,
) -> CodebaseExploration:
    """Explore the codebase to gather context for the fix writer."""
    prompt = f"""\
Explore the codebase to gather everything the Fix Writer needs.

--- STAGE 1: VULNERABILITY RESEARCH ---
{research.raw_output}
--- END STAGE 1 ---

--- STAGE 2: EXPLOITABILITY ASSESSMENT ---
{assessment.raw_output}
--- END STAGE 2 ---

FINDING DETAILS:
FILE: {finding.file_path}
LINE: {finding.line_number}
REPO_PATH: .
"""

    output = run_stage(
        "codebase_explorer",
        prompt,
        sandbox_root=sandbox_root,
        output_dir=output_dir,
    )

    return _parse_exploration(output)


def _parse_exploration(output: str) -> CodebaseExploration:
    """Parse the delimited exploration report from model output."""
    result = CodebaseExploration(raw_output=output)

    match = re.search(
        r"CODEBASE_EXPLORATION_COMPLETE\s*\n(.*?)CODEBASE_EXPLORATION_END",
        output,
        re.DOTALL,
    )
    body = match.group(1) if match else output

    def extract(key: str) -> str:
        pattern = rf"^{key}:\s*\n(.*?)(?=\n[A-Z_]+:|\Z)"
        m = re.search(pattern, body, re.MULTILINE | re.DOTALL)
        return m.group(1).strip() if m else ""

    result.affected_file_content = extract("AFFECTED_FILE_CONTENT")
    result.related_files = extract("RELATED_FILES")
    result.existing_safe_patterns = extract("EXISTING_SAFE_PATTERNS")
    result.test_coverage = extract("TEST_COVERAGE")
    result.recommended_fix_pattern = extract("RECOMMENDED_FIX_PATTERN")

    return result
