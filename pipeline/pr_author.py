"""Stage 6 — PR/Issue Author.

Hybrid stage: LLM writes the PR/issue body, orchestrator handles git/GitHub ops.
"""

from __future__ import annotations

import logging
import re

from pipeline.models import PipelineContext, PRResult, Verdict
from pipeline.stages.base import run_stage

logger = logging.getLogger(__name__)


def generate_body(ctx: PipelineContext, *, output_dir: str) -> str:
    """Use the LLM to generate a well-written PR or issue body."""
    finding = ctx.finding
    verdict = ctx.assessment.verdict if ctx.assessment else Verdict.NEEDS_INVESTIGATION

    # Build context from all stages
    sections = [
        f"FINDING: {finding.title} in {finding.file_path}:{finding.line_number}"
    ]
    sections.append(f"SEVERITY: {finding.severity}")
    sections.append(f"CWE: {finding.cwe_id or 'N/A'}")
    sections.append(f"VERDICT: {verdict.value}")

    if ctx.research:
        sections.append(
            f"\n--- STAGE 1: VULNERABILITY RESEARCH ---\n{ctx.research.raw_output}"
        )

    if ctx.assessment:
        sections.append(
            f"\n--- STAGE 2: EXPLOITABILITY ASSESSMENT ---\n{ctx.assessment.raw_output}"
        )

    if ctx.exploration:
        sections.append(
            f"\n--- STAGE 3: CODEBASE EXPLORATION ---\n{ctx.exploration.raw_output}"
        )

    if ctx.fix:
        sections.append(
            f"\n--- STAGE 4: FIX ---\nCHANGE_SUMMARY: {ctx.fix.change_summary}"
        )
        sections.append(f"PATCH:\n{ctx.fix.patch}")

    if ctx.validation:
        sections.append(f"\n--- STAGE 5: VALIDATION ---\n{ctx.validation.raw_output}")

    if ctx.pipeline_failed:
        sections.append(f"\n--- PIPELINE FAILURE ---\n{ctx.failure_reason}")

    context_text = "\n".join(sections)

    # Determine what kind of body to write
    if verdict == Verdict.PATCH and not ctx.pipeline_failed:
        body_type = "pull request"
    elif verdict == Verdict.SUPPRESS and ctx.fix:
        body_type = "suppression pull request"
    elif verdict == Verdict.SUPPRESS:
        body_type = "suppression issue"
    elif verdict == Verdict.NEEDS_INVESTIGATION:
        body_type = "investigation issue"
    else:
        body_type = "pipeline failure issue"

    prompt = f"""\
Write a {body_type} body for the following security finding.

{context_text}

Write a clear, well-structured GitHub {body_type} body in Markdown. \
Include all relevant details from the stage outputs. \
If this is a PR, include the diff in a collapsible <details> block. \
End with a "Caveats" section noting this was AI-generated and should be reviewed.
"""

    body = run_stage(
        "pr_author",
        prompt,
        output_dir=output_dir,
    )

    return body


def build_title(ctx: PipelineContext) -> str:
    """Build the PR/issue title based on verdict and context."""
    finding = ctx.finding
    verdict = ctx.assessment.verdict if ctx.assessment else None
    short_file = finding.file_path.split("/")[-1] if finding else "unknown"

    if ctx.pipeline_failed:
        return f"[Security] Pipeline failed for {finding.title} in {short_file}"
    elif verdict == Verdict.PATCH:
        return f"[Auto-Fix] {finding.title} in {short_file}"
    elif verdict == Verdict.SUPPRESS and ctx.fix:
        return f"[Suppress] {finding.title} in {short_file} — not exploitable"
    elif verdict == Verdict.SUPPRESS:
        return f"[Security] Suppress {finding.title} in {short_file} — not exploitable"
    elif verdict == Verdict.NEEDS_INVESTIGATION:
        return f"[Security] {finding.title} in {short_file} — investigation required"
    else:
        return f"[Security] {finding.title} in {short_file}"


def build_labels(ctx: PipelineContext) -> list[str]:
    """Build appropriate labels for the PR/issue."""
    labels = ["security"]
    severity = ctx.finding.severity.lower() if ctx.finding else "unknown"
    labels.append(f"severity:{severity}")

    verdict = ctx.assessment.verdict if ctx.assessment else None
    if ctx.pipeline_failed:
        labels.append("pipeline-failure")
    elif verdict == Verdict.PATCH:
        labels.append("automated-fix")
    elif verdict == Verdict.SUPPRESS:
        labels.append("suppression" if ctx.fix else "wontfix")
    elif verdict == Verdict.NEEDS_INVESTIGATION:
        labels.append("needs-triage")

    return labels


def build_branch_name(ctx: PipelineContext) -> str:
    """Build a git branch name for the fix."""
    finding = ctx.finding

    def _sanitize(s: str) -> str:
        """Replace unsafe characters and collapse consecutive hyphens."""
        s = re.sub(r"[^a-zA-Z0-9._-]", "-", s)
        s = re.sub(r"-{2,}", "-", s)
        return s.strip("-")

    title_part = _sanitize(finding.title.lower().replace(" ", "-"))
    file_part = _sanitize(finding.file_path.replace("/", "_"))
    prefix = (
        "auto-suppress"
        if ctx.assessment and ctx.assessment.verdict == Verdict.SUPPRESS
        else "auto-fix"
    )
    branch = f"{prefix}/{title_part}-{file_part}-{finding.line_number}"
    return branch[:200]
