"""Tests for the Exploitability Assessor (Stage 2) parsing."""

from pipeline.models import Confidence, Verdict
from pipeline.stages.assessor import _parse_assessment


def _make_output(
    verdict: str = "SUPPRESS",
    confidence: str = "HIGH",
    reasoning: str = "Not exploitable because the endpoint is internal-only.",
    suppression_instructions: str = "Add `# nosec B303` to line 42.",
    suppression_action: str = "CODE_CHANGE",
    open_questions: str = "",
) -> str:
    sections = [
        "EXPLOITABILITY_ASSESSMENT_COMPLETE",
        f"TEST_ID: Test Finding",
        f"FILE: app.py",
        f"LINE: 42",
        f"VERDICT: {verdict}",
        f"CONFIDENCE: {confidence}",
        "",
        "REASONING:",
        reasoning,
    ]
    if suppression_instructions:
        sections.append("")
        sections.append("SUPPRESSION_INSTRUCTIONS:")
        sections.append(suppression_instructions)
    if suppression_action:
        sections.append("")
        sections.append(f"SUPPRESSION_ACTION: {suppression_action}")
    if open_questions:
        sections.append("")
        sections.append("OPEN_QUESTIONS:")
        sections.append(open_questions)
    sections.append("")
    sections.append("EXPLOITABILITY_ASSESSMENT_END")
    return "\n".join(sections)


def test_suppress_with_code_change():
    output = _make_output(suppression_action="CODE_CHANGE")
    result = _parse_assessment(output)
    assert result.verdict == Verdict.SUPPRESS
    assert result.confidence == Confidence.HIGH
    assert result.suppression_action == "CODE_CHANGE"
    assert "nosec" in result.suppression_instructions


def test_suppress_with_informational():
    output = _make_output(
        suppression_action="INFORMATIONAL",
        suppression_instructions="Dead code — no action required.",
    )
    result = _parse_assessment(output)
    assert result.verdict == Verdict.SUPPRESS
    assert result.suppression_action == "INFORMATIONAL"


def test_suppress_without_action_field():
    """Backward compat: missing SUPPRESSION_ACTION defaults to empty string."""
    output = _make_output(suppression_action="")
    result = _parse_assessment(output)
    assert result.verdict == Verdict.SUPPRESS
    assert result.suppression_action == ""


def test_patch_verdict_no_suppression_action():
    output = _make_output(
        verdict="PATCH",
        suppression_instructions="",
        suppression_action="",
    )
    result = _parse_assessment(output)
    assert result.verdict == Verdict.PATCH
    assert result.suppression_action == ""


def test_needs_investigation_with_open_questions():
    output = _make_output(
        verdict="NEEDS_INVESTIGATION",
        confidence="LOW",
        suppression_instructions="",
        suppression_action="",
        open_questions="1. Is this endpoint public?\n2. Is there auth middleware?",
    )
    result = _parse_assessment(output)
    assert result.verdict == Verdict.NEEDS_INVESTIGATION
    assert result.suppression_action == ""
    assert "auth middleware" in result.open_questions
