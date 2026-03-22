"""Tests for pipeline data models."""

from pipeline.models import (
    AssessmentVerification,
    Confidence,
    ExploitabilityAssessment,
    Finding,
    PipelineContext,
    Severity,
    Verdict,
    VerificationVerdict,
)


def test_finding_creation():
    f = Finding(
        file_path="app.py",
        line_number=42,
        title="SQL Injection",
        description="String-based query construction",
        severity="HIGH",
        cwe_id="CWE-89",
    )
    assert f.file_path == "app.py"
    assert f.line_number == 42
    assert f.cwe_id == "CWE-89"


def test_finding_optional_fields():
    f = Finding(
        file_path="app.py",
        line_number=1,
        title="Test",
        description="Test desc",
        severity="LOW",
    )
    assert f.cwe_id is None
    assert f.raw_blob == ""


def test_verdict_enum():
    assert Verdict.PATCH.value == "PATCH"
    assert Verdict.SUPPRESS.value == "SUPPRESS"
    assert Verdict.NEEDS_INVESTIGATION.value == "NEEDS_INVESTIGATION"
    assert Verdict("PATCH") == Verdict.PATCH


def test_severity_enum():
    assert Severity.CRITICAL.value == "CRITICAL"
    assert Severity("HIGH") == Severity.HIGH


def test_pipeline_context_defaults():
    ctx = PipelineContext()
    assert ctx.finding is None
    assert ctx.pipeline_failed is False


def test_assessment_defaults():
    a = ExploitabilityAssessment()
    assert a.verdict == Verdict.NEEDS_INVESTIGATION
    assert a.confidence == Confidence.LOW


def test_verification_verdict_enum():
    assert VerificationVerdict("VERIFIED") == VerificationVerdict.VERIFIED
    assert (
        VerificationVerdict("PARTIALLY_VERIFIED")
        == VerificationVerdict.PARTIALLY_VERIFIED
    )
    assert VerificationVerdict("CONTRADICTED") == VerificationVerdict.CONTRADICTED


def test_assessment_verification_defaults():
    v = AssessmentVerification()
    assert v.verdict == VerificationVerdict.VERIFIED
    assert v.references_checked == 0
    assert v.reference_details == []


def test_pipeline_context_has_verification_field():
    ctx = PipelineContext()
    assert ctx.verification is None
