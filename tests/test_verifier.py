"""Tests for the Assessment Verifier (Stage 2b)."""

from unittest.mock import patch

from pipeline.models import (
    AssessmentVerification,
    ExploitabilityAssessment,
    Finding,
    ReferenceCheck,
    Severity,
    VerificationVerdict,
)
from pipeline.stages.verifier import (
    _extract_refs,
    _parse_verification,
    verify_assessment,
)

# ---------------------------------------------------------------------------
# _extract_refs
# ---------------------------------------------------------------------------


def test_extract_refs_finds_backtick_refs():
    reasoning = (
        "The vulnerability is at `app/db.py:42` where user input is passed "
        "directly. Also see `utils/helpers.py:17` for the callsite."
    )
    refs = _extract_refs(reasoning)
    assert refs == ["app/db.py:42", "utils/helpers.py:17"]


def test_extract_refs_deduplicates():
    reasoning = (
        "See `app/db.py:42` for the issue. As noted above, `app/db.py:42` "
        "is also problematic."
    )
    refs = _extract_refs(reasoning)
    assert refs == ["app/db.py:42"]


def test_extract_refs_empty_when_no_refs():
    reasoning = "The vulnerability is in app/db.py at line 42 (no backticks)."
    refs = _extract_refs(reasoning)
    assert refs == []


# ---------------------------------------------------------------------------
# _parse_verification
# ---------------------------------------------------------------------------

_VERIFIED_OUTPUT = """\
ASSESSMENT_VERIFICATION_COMPLETE
REFERENCES_CHECKED: 2
CONFIRMED: 2
CONTRADICTED: 0
NOT_FOUND: 0
VERDICT: VERIFIED

REFERENCE_DETAILS:
- REF: app/db.py:42
  STATUS: CONFIRMED
  NOTE: Line 42 contains an unsanitized string interpolation into a SQL query.

- REF: utils/helpers.py:17
  STATUS: CONFIRMED
  NOTE: Line 17 calls db.execute with raw user input as expected.

CONTRADICTION_NOTES:
None.

ASSESSMENT_VERIFICATION_END
"""

_CONTRADICTED_OUTPUT = """\
ASSESSMENT_VERIFICATION_COMPLETE
REFERENCES_CHECKED: 1
CONFIRMED: 0
CONTRADICTED: 1
NOT_FOUND: 0
VERDICT: CONTRADICTED

REFERENCE_DETAILS:
- REF: app/db.py:42
  STATUS: CONTRADICTED
  NOTE: Line 42 is a parameterized query using db.execute with placeholders, not string interpolation.

CONTRADICTION_NOTES:
The assessor claimed there was no sanitization at app/db.py:42, but the code at that
line uses parameterized queries which are the standard protection against SQL injection.
The PATCH verdict is not supported by the evidence.

ASSESSMENT_VERIFICATION_END
"""

_NOT_FOUND_OUTPUT = """\
ASSESSMENT_VERIFICATION_COMPLETE
REFERENCES_CHECKED: 1
CONFIRMED: 0
CONTRADICTED: 0
NOT_FOUND: 1
VERDICT: PARTIALLY_VERIFIED

REFERENCE_DETAILS:
- REF: app/missing.py:10
  STATUS: NOT_FOUND
  NOTE: File app/missing.py does not exist in the repository.

CONTRADICTION_NOTES:
One reference could not be verified because the cited file does not exist.

ASSESSMENT_VERIFICATION_END
"""


def test_parse_verification_verified():
    result = _parse_verification(_VERIFIED_OUTPUT, )

    assert result.verdict == VerificationVerdict.VERIFIED
    assert result.references_checked == 2
    assert result.confirmed_count == 2
    assert result.contradicted_count == 0
    assert result.not_found_count == 0
    assert result.contradiction_notes == ""
    assert len(result.reference_details) == 2
    assert result.reference_details[0].ref == "app/db.py:42"
    assert result.reference_details[0].status == "CONFIRMED"
    assert result.reference_details[1].ref == "utils/helpers.py:17"
    assert result.reference_details[1].status == "CONFIRMED"


def test_parse_verification_contradicted():
    result = _parse_verification(_CONTRADICTED_OUTPUT, )

    assert result.verdict == VerificationVerdict.CONTRADICTED
    assert result.references_checked == 1
    assert result.confirmed_count == 0
    assert result.contradicted_count == 1
    assert result.not_found_count == 0
    assert "parameterized" in result.contradiction_notes
    assert len(result.reference_details) == 1
    assert result.reference_details[0].ref == "app/db.py:42"
    assert result.reference_details[0].status == "CONTRADICTED"


def test_parse_verification_not_found():
    result = _parse_verification(_NOT_FOUND_OUTPUT, )

    assert result.verdict == VerificationVerdict.PARTIALLY_VERIFIED
    assert result.references_checked == 1
    assert result.not_found_count == 1
    assert len(result.reference_details) == 1
    assert result.reference_details[0].ref == "app/missing.py:10"
    assert result.reference_details[0].status == "NOT_FOUND"


# ---------------------------------------------------------------------------
# verify_assessment (integration-level with mocked run_stage)
# ---------------------------------------------------------------------------

_FINDING = Finding(
    file_path="app/db.py",
    line_number=42,
    title="SQL Injection",
    description="Unsanitized query construction.",
    severity=Severity.HIGH,
)


def test_verify_assessment_skips_when_no_refs():
    assessment = ExploitabilityAssessment(
        reasoning="The vulnerability exists in the query at line 42.",  # no backtick refs
        raw_output="EXPLOITABILITY_ASSESSMENT_COMPLETE\nVERDICT: PATCH\nEXPLOITABILITY_ASSESSMENT_END",
    )

    with patch("pipeline.stages.verifier.run_stage") as mock_run_stage:
        result = verify_assessment(
            _FINDING,
            assessment,
            sandbox_root="/tmp/repo",
            output_dir="/tmp/output",
        )

    mock_run_stage.assert_not_called()
    assert result.verdict == VerificationVerdict.VERIFIED
    assert result.references_checked == 0
    assert "No file:line references" in result.contradiction_notes


def test_verify_assessment_calls_run_stage():
    assessment = ExploitabilityAssessment(
        reasoning="The issue is at `app/db.py:42` where no sanitization occurs.",
        raw_output="EXPLOITABILITY_ASSESSMENT_COMPLETE\nVERDICT: PATCH\nEXPLOITABILITY_ASSESSMENT_END",
    )

    minimal_output = (
        "ASSESSMENT_VERIFICATION_COMPLETE\n"
        "REFERENCES_CHECKED: 1\n"
        "CONFIRMED: 1\n"
        "CONTRADICTED: 0\n"
        "NOT_FOUND: 0\n"
        "VERDICT: VERIFIED\n\n"
        "REFERENCE_DETAILS:\n"
        "- REF: app/db.py:42\n"
        "  STATUS: CONFIRMED\n"
        "  NOTE: Line 42 has unsanitized input.\n\n"
        "CONTRADICTION_NOTES:\n"
        "None.\n\n"
        "ASSESSMENT_VERIFICATION_END\n"
    )

    with patch(
        "pipeline.stages.verifier.run_stage", return_value=minimal_output
    ) as mock_run_stage:
        result = verify_assessment(
            _FINDING,
            assessment,
            sandbox_root="/tmp/repo",
            output_dir="/tmp/output",
        )

    mock_run_stage.assert_called_once()
    call_args = mock_run_stage.call_args
    assert call_args.args[0] == "assessment_verifier"
    assert result.verdict == VerificationVerdict.VERIFIED
    assert result.references_checked == 1


def test_parse_verification_missing_delimiter_falls_back():
    """When the delimiter block is absent, the parser falls back to treating the
    entire output as the body and still extracts whatever fields are present."""
    malformed = (
        "VERDICT: CONTRADICTED\n"
        "REFERENCES_CHECKED: 1\n"
        "CONFIRMED: 0\n"
        "CONTRADICTED: 1\n"
        "NOT_FOUND: 0\n"
    )
    result = _parse_verification(malformed)
    assert result.verdict == VerificationVerdict.CONTRADICTED
    assert result.references_checked == 1
    assert result.contradicted_count == 1


def test_parse_verification_invalid_verdict_falls_back_to_partially_verified():
    """An unrecognised VERDICT string should default to PARTIALLY_VERIFIED."""
    output = (
        "ASSESSMENT_VERIFICATION_COMPLETE\n"
        "REFERENCES_CHECKED: 1\n"
        "CONFIRMED: 0\n"
        "CONTRADICTED: 0\n"
        "NOT_FOUND: 1\n"
        "VERDICT: UNKNOWN_VALUE\n\n"
        "REFERENCE_DETAILS:\n"
        "- REF: app/db.py:42\n"
        "  STATUS: NOT_FOUND\n"
        "  NOTE: File not found.\n\n"
        "CONTRADICTION_NOTES:\n"
        "None.\n\n"
        "ASSESSMENT_VERIFICATION_END\n"
    )
    result = _parse_verification(output)
    assert result.verdict == VerificationVerdict.PARTIALLY_VERIFIED
