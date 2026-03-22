"""Stage 2b — Assessment Verifier."""

from __future__ import annotations

import re

from pipeline.models import (
    AssessmentVerification,
    ExploitabilityAssessment,
    Finding,
    ReferenceCheck,
    VerificationVerdict,
)
from pipeline.stages.base import run_stage


def verify_assessment(
    finding: Finding,
    assessment: ExploitabilityAssessment,
    *,
    sandbox_root: str,
    output_dir: str,
) -> AssessmentVerification:
    """Verify that file:line references in the assessor's REASONING are accurate."""
    refs = _extract_refs(assessment.reasoning)

    if not refs:
        return AssessmentVerification(
            verdict=VerificationVerdict.VERIFIED,
            references_checked=0,
            contradiction_notes="No file:line references found in assessor reasoning.",
            raw_output="(skipped — no file:line references to verify)",
        )

    prompt = f"""\
Verify the following exploitability assessment by checking each file:line reference.

--- STAGE 2: EXPLOITABILITY ASSESSMENT ---
{assessment.raw_output}
--- END STAGE 2 ---

FILE:LINE REFERENCES TO VERIFY:
{chr(10).join(refs)}

For each reference above, use read_file to read the file and confirm whether the code
at that location matches what the assessor claimed.
"""

    output = run_stage(
        "assessment_verifier",
        prompt,
        sandbox_root=sandbox_root,
        output_dir=output_dir,
    )

    return _parse_verification(output)


def _extract_refs(reasoning: str) -> list[str]:
    """Extract unique `path/to/file.py:LINE` references from REASONING text."""
    pattern = r"`([^`\s]+\.[a-zA-Z0-9]+:\d+)`"
    matches = re.findall(pattern, reasoning)
    seen: set[str] = set()
    unique: list[str] = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            unique.append(m)
    return unique


def _parse_verification(output: str) -> AssessmentVerification:
    """Parse the delimited verification output from model output."""
    result = AssessmentVerification(raw_output=output)

    match = re.search(
        r"ASSESSMENT_VERIFICATION_COMPLETE\s*\n(.*?)ASSESSMENT_VERIFICATION_END",
        output,
        re.DOTALL,
    )
    body = match.group(1) if match else output

    def extract_int(key: str) -> int:
        m = re.search(rf"^{key}:\s*(\d+)", body, re.MULTILINE)
        return int(m.group(1)) if m else 0

    result.references_checked = extract_int("REFERENCES_CHECKED")
    result.confirmed_count = extract_int("CONFIRMED")
    result.contradicted_count = extract_int("CONTRADICTED")
    result.not_found_count = extract_int("NOT_FOUND")

    verdict_match = re.search(r"^VERDICT:\s*(\S+)", body, re.MULTILINE)
    if verdict_match:
        try:
            result.verdict = VerificationVerdict(verdict_match.group(1).strip())
        except ValueError:
            result.verdict = VerificationVerdict.PARTIALLY_VERIFIED

    details_match = re.search(
        r"^REFERENCE_DETAILS:\s*\n(.*?)(?=\nCONTRADICTION_NOTES:|\nASSESSMENT_VERIFICATION_END|\Z)",
        body,
        re.MULTILINE | re.DOTALL,
    )
    if details_match:
        details_text = details_match.group(1)
        for block in re.finditer(
            r"-\s*REF:\s*(.+?)\n\s*STATUS:\s*(.+?)\n\s*NOTE:\s*(.+?)(?=\n\s*-\s*REF:|\Z)",
            details_text,
            re.DOTALL,
        ):
            result.reference_details.append(
                ReferenceCheck(
                    ref=block.group(1).strip(),
                    status=block.group(2).strip(),
                    note=block.group(3).strip(),
                )
            )

    contradiction_match = re.search(
        r"^CONTRADICTION_NOTES:\s*\n(.*?)(?=\nASSESSMENT_VERIFICATION_END|\Z)",
        body,
        re.MULTILINE | re.DOTALL,
    )
    if contradiction_match:
        notes = contradiction_match.group(1).strip()
        if notes.lower() != "none.":
            result.contradiction_notes = notes

    return result
