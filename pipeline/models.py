"""Data models for the security patch pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    PATCH = "PATCH"
    SUPPRESS = "SUPPRESS"
    NEEDS_INVESTIGATION = "NEEDS_INVESTIGATION"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VerificationVerdict(str, Enum):
    VERIFIED = "VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    CONTRADICTED = "CONTRADICTED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    """Canonical vulnerability finding extracted by the normalizer (Stage 0)."""

    file_path: str
    line_number: int
    title: str
    description: str
    severity: Severity
    cwe_id: str | None = None
    raw_blob: str = ""

    def __post_init__(self) -> None:
        # Coerce a plain string to the Severity enum for backward compatibility
        if not isinstance(self.severity, Severity):
            self.severity = Severity(self.severity)


@dataclass
class ResearchReport:
    """Output of the Vulnerability Researcher (Stage 1)."""

    raw_output: str = ""
    what_it_is: str = ""
    how_exploited: str = ""
    real_world_impact: str = ""
    standard_remediations: str = ""
    references: str = ""


@dataclass
class ExploitabilityAssessment:
    """Output of the Exploitability Assessor (Stage 2)."""

    verdict: Verdict = Verdict.NEEDS_INVESTIGATION
    confidence: Confidence = Confidence.LOW
    reasoning: str = ""
    suppression_instructions: str = ""
    open_questions: str = ""
    raw_output: str = ""


@dataclass
class ReferenceCheck:
    """Result for a single file:line citation in the assessor's REASONING."""

    ref: str
    status: str  # CONFIRMED | CONTRADICTED | NOT_FOUND
    note: str = ""


@dataclass
class AssessmentVerification:
    """Output of the Assessment Verifier (Stage 2b)."""

    verdict: VerificationVerdict = VerificationVerdict.VERIFIED
    references_checked: int = 0
    confirmed_count: int = 0
    contradicted_count: int = 0
    not_found_count: int = 0
    contradiction_notes: str = ""
    reference_details: list = field(default_factory=list)  # list[ReferenceCheck]
    raw_output: str = ""


@dataclass
class CodebaseExploration:
    """Output of the Codebase Explorer (Stage 3)."""

    affected_file_content: str = ""
    related_files: str = ""
    existing_safe_patterns: str = ""
    test_coverage: str = ""
    recommended_fix_pattern: str = ""
    raw_output: str = ""


@dataclass
class FixResult:
    """Output of the Fix Writer (Stage 4)."""

    patch: str = ""
    change_summary: str = ""
    changed_files: list = field(default_factory=list)
    raw_output: str = ""


@dataclass
class ValidationResult:
    """Output of the Fix Validator (Stage 5)."""

    passed: bool = False
    syntax_check: str = ""
    flake8_output: str = ""
    pylint_output: str = ""
    structural_notes: str = ""
    errors: str = ""
    raw_output: str = ""


@dataclass
class PRResult:
    """Output of the PR Author (Stage 6)."""

    action: str = ""  # PR_CREATED | ISSUE_CREATED | DRY_RUN | FAILED
    url: str = ""
    branch: str = ""
    title: str = ""
    body: str = ""
    raw_output: str = ""


@dataclass
class PipelineContext:
    """Accumulates results across all pipeline stages."""

    finding: Finding | None = None
    research: ResearchReport | None = None
    assessment: ExploitabilityAssessment | None = None
    verification: AssessmentVerification | None = None
    exploration: CodebaseExploration | None = None
    fix: FixResult | None = None
    validation: ValidationResult | None = None
    pr_result: PRResult | None = None
    pipeline_failed: bool = False
    failure_reason: str = ""
