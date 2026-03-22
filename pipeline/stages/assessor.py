"""Stage 2 — Exploitability Assessor."""

from __future__ import annotations

import re

from pipeline.models import (
    Confidence,
    ExploitabilityAssessment,
    Finding,
    ResearchReport,
    Verdict,
)
from pipeline.stages.base import run_stage


def assess(
    finding: Finding,
    research: ResearchReport,
    *,
    sandbox_root: str,
    output_dir: str,
) -> ExploitabilityAssessment:
    """Assess whether this specific instance is exploitable."""
    prompt = f"""\
Assess the exploitability of the following finding.

--- STAGE 1: VULNERABILITY RESEARCH ---
{research.raw_output}
--- END STAGE 1 ---

FINDING DETAILS:
FILE: {finding.file_path}
LINE: {finding.line_number}
SEVERITY: {finding.severity}
CODE: (see raw finding data below)
REPO_PATH: .

DESCRIPTION: {finding.description}

RAW FINDING DATA:
{finding.raw_blob}
"""

    output = run_stage(
        "exploitability_assessor",
        prompt,
        sandbox_root=sandbox_root,
        output_dir=output_dir,
    )

    return _parse_assessment(output)


def _parse_assessment(output: str) -> ExploitabilityAssessment:
    """Parse the delimited assessment from model output."""
    result = ExploitabilityAssessment(raw_output=output)

    match = re.search(
        r"EXPLOITABILITY_ASSESSMENT_COMPLETE\s*\n(.*?)EXPLOITABILITY_ASSESSMENT_END",
        output,
        re.DOTALL,
    )
    body = match.group(1) if match else output

    # Extract verdict
    verdict_match = re.search(r"^VERDICT:\s*(\S+)", body, re.MULTILINE)
    if verdict_match:
        raw_verdict = verdict_match.group(1).strip()
        try:
            result.verdict = Verdict(raw_verdict)
        except ValueError:
            result.verdict = Verdict.NEEDS_INVESTIGATION

    # Extract confidence
    conf_match = re.search(r"^CONFIDENCE:\s*(\S+)", body, re.MULTILINE)
    if conf_match:
        try:
            result.confidence = Confidence(conf_match.group(1).strip())
        except ValueError:
            pass

    # Extract reasoning
    reasoning_match = re.search(
        r"^REASONING:\s*\n(.*?)(?=\n(?:SUPPRESSION_INSTRUCTIONS|OPEN_QUESTIONS|EXPLOITABILITY_ASSESSMENT_END)|\Z)",
        body,
        re.MULTILINE | re.DOTALL,
    )
    if reasoning_match:
        result.reasoning = reasoning_match.group(1).strip()

    # Extract suppression instructions (if SUPPRESS)
    supp_match = re.search(
        r"^SUPPRESSION_INSTRUCTIONS:\s*\n(.*?)(?=\n(?:OPEN_QUESTIONS|EXPLOITABILITY_ASSESSMENT_END)|\Z)",
        body,
        re.MULTILINE | re.DOTALL,
    )
    if supp_match:
        result.suppression_instructions = supp_match.group(1).strip()

    # Extract open questions (if NEEDS_INVESTIGATION)
    oq_match = re.search(
        r"^OPEN_QUESTIONS:\s*\n(.*?)(?=\nEXPLOITABILITY_ASSESSMENT_END|\Z)",
        body,
        re.MULTILINE | re.DOTALL,
    )
    if oq_match:
        result.open_questions = oq_match.group(1).strip()

    return result
