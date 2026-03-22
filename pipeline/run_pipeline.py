"""Main pipeline orchestrator.

Reads env vars, runs all stages in sequence, handles the retry loop,
and creates PRs/issues via the GitHub API.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from pipeline.github_client import GitHubClient
from pipeline.models import PipelineContext, PRResult, Verdict
from pipeline.normalizer import normalize
from pipeline.pr_author import build_branch_name, build_labels, build_title, generate_body
from pipeline.sandbox import RepoSandbox
from pipeline.stages.assessor import assess
from pipeline.stages.explorer import explore
from pipeline.stages.fix_writer import write_fix
from pipeline.stages.researcher import research
from pipeline.stages.validator import validate

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

OUTPUT_DIR = "pipeline-output"
MAX_FIX_ATTEMPTS = 2


def main() -> None:
    # Read configuration from environment
    vuln_data = os.environ.get("VULNERABILITY_DATA", "")
    target_repo = os.environ.get("TARGET_REPO", "")
    dry_run = os.environ.get("DRY_RUN", "false").lower() in ("true", "1", "yes")
    gh_token = os.environ.get("GITHUB_TOKEN", "")

    if not vuln_data:
        logger.error("VULNERABILITY_DATA is required")
        sys.exit(1)
    if not target_repo:
        logger.error("TARGET_REPO is required")
        sys.exit(1)

    MAX_INPUT_BYTES = 1_000_000  # 1 MB — reject oversized blobs early
    if len(vuln_data.encode()) > MAX_INPUT_BYTES:
        logger.error(
            "VULNERABILITY_DATA is too large (%d bytes, max %d)",
            len(vuln_data.encode()),
            MAX_INPUT_BYTES,
        )
        sys.exit(1)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ctx = PipelineContext()

    # ------------------------------------------------------------------
    # Stage 0: Normalize
    # ------------------------------------------------------------------
    logger.info("=== Stage 0: Normalizer ===")
    try:
        ctx.finding = normalize(vuln_data, output_dir=OUTPUT_DIR)
    except Exception as e:
        logger.error("Normalizer failed: %s", e)
        sys.exit(1)

    logger.info(
        "Finding: %s in %s:%d (%s)",
        ctx.finding.title,
        ctx.finding.file_path,
        ctx.finding.line_number,
        ctx.finding.severity,
    )

    # ------------------------------------------------------------------
    # Clone target repo into sandbox
    # ------------------------------------------------------------------
    repo_url = f"https://github.com/{target_repo}.git"
    with RepoSandbox(repo_url, token=gh_token) as sandbox:
        sandbox_root = sandbox.path

        # --------------------------------------------------------------
        # Stage 1: Research
        # --------------------------------------------------------------
        logger.info("=== Stage 1: Vulnerability Researcher ===")
        try:
            ctx.research = research(
                ctx.finding,
                sandbox_root=sandbox_root,
                output_dir=OUTPUT_DIR,
            )
        except Exception as e:
            logger.error("Researcher failed: %s", e)
            ctx.pipeline_failed = True
            ctx.failure_reason = f"Stage 1 (Researcher) failed: {e}"

        # --------------------------------------------------------------
        # Stage 2: Assess
        # --------------------------------------------------------------
        if not ctx.pipeline_failed:
            logger.info("=== Stage 2: Exploitability Assessor ===")
            try:
                ctx.assessment = assess(
                    ctx.finding,
                    ctx.research,
                    sandbox_root=sandbox_root,
                    output_dir=OUTPUT_DIR,
                )
                logger.info(
                    "Verdict: %s (confidence: %s)",
                    ctx.assessment.verdict.value,
                    ctx.assessment.confidence.value,
                )
            except Exception as e:
                logger.error("Assessor failed: %s", e)
                ctx.pipeline_failed = True
                ctx.failure_reason = f"Stage 2 (Assessor) failed: {e}"

        # --------------------------------------------------------------
        # Stages 3–5: Only if verdict is PATCH
        # --------------------------------------------------------------
        if (
            not ctx.pipeline_failed
            and ctx.assessment
            and ctx.assessment.verdict == Verdict.PATCH
        ):
            # Stage 3: Explore
            logger.info("=== Stage 3: Codebase Explorer ===")
            try:
                ctx.exploration = explore(
                    ctx.finding,
                    ctx.research,
                    ctx.assessment,
                    sandbox_root=sandbox_root,
                    output_dir=OUTPUT_DIR,
                )
            except Exception as e:
                logger.error("Explorer failed: %s", e)
                ctx.pipeline_failed = True
                ctx.failure_reason = f"Stage 3 (Explorer) failed: {e}"

            # Stage 4→5 retry loop
            if not ctx.pipeline_failed:
                previous_errors: str | None = None
                fix_succeeded = False

                for attempt in range(1, MAX_FIX_ATTEMPTS + 1):
                    logger.info(
                        "=== Stage 4: Fix Writer (attempt %d/%d) ===",
                        attempt,
                        MAX_FIX_ATTEMPTS,
                    )
                    try:
                        ctx.fix = write_fix(
                            ctx.finding,
                            ctx.research,
                            ctx.assessment,
                            ctx.exploration,
                            sandbox_root=sandbox_root,
                            output_dir=OUTPUT_DIR,
                            previous_errors=previous_errors,
                        )
                    except Exception as e:
                        logger.error("Fix Writer failed: %s", e)
                        previous_errors = str(e)
                        continue

                    if not ctx.fix.patch:
                        previous_errors = "Stage 4 output contained no PATCH block."
                        logger.warning(previous_errors)
                        continue

                    # Apply the patch
                    logger.info("Applying patch via git apply...")
                    success, apply_err = sandbox.apply_patch(ctx.fix.patch)
                    if not success:
                        previous_errors = f"git apply failed: {apply_err}"
                        logger.warning(previous_errors)
                        continue

                    # Stage 5: Validate
                    logger.info("=== Stage 5: Fix Validator ===")
                    try:
                        ctx.validation = validate(
                            ctx.finding,
                            ctx.fix,
                            sandbox_root=sandbox_root,
                            output_dir=OUTPUT_DIR,
                        )
                    except Exception as e:
                        logger.error("Validator failed: %s", e)
                        previous_errors = str(e)
                        continue

                    if ctx.validation.passed:
                        logger.info("Validation PASSED")
                        fix_succeeded = True
                        break
                    else:
                        previous_errors = ctx.validation.errors or ctx.validation.raw_output
                        logger.warning("Validation FAILED: %s", previous_errors)

                if not fix_succeeded:
                    ctx.pipeline_failed = True
                    ctx.failure_reason = (
                        f"Fix failed after {MAX_FIX_ATTEMPTS} attempts. "
                        f"Last error: {previous_errors}"
                    )

        # --------------------------------------------------------------
        # Stage 6: PR/Issue Author
        # --------------------------------------------------------------
        logger.info("=== Stage 6: PR/Issue Author ===")
        verdict = ctx.assessment.verdict if ctx.assessment else None

        # Generate body via LLM
        try:
            body = generate_body(ctx, output_dir=OUTPUT_DIR)
        except Exception as e:
            logger.error("PR Author LLM call failed: %s", e)
            body = _fallback_body(ctx)

        title = build_title(ctx)
        labels = build_labels(ctx)

        if dry_run:
            logger.info("DRY RUN — not creating PR/issue")
            ctx.pr_result = PRResult(
                action="DRY_RUN",
                url="N/A",
                title=title,
                body=body,
            )
            _write_dry_run_output(title, body, labels, verdict, ctx)
        elif ctx.pipeline_failed or verdict != Verdict.PATCH:
            # Create issue
            if gh_token:
                try:
                    gh = GitHubClient(gh_token, target_repo)
                    url = gh.create_issue(title=title, body=body, labels=labels)
                    ctx.pr_result = PRResult(
                        action="ISSUE_CREATED", url=url, title=title, body=body,
                    )
                except Exception as e:
                    logger.error("Failed to create issue: %s", e)
                    ctx.pr_result = PRResult(action="FAILED", title=title, body=body)
            else:
                logger.warning("No GITHUB_TOKEN — cannot create issue")
                ctx.pr_result = PRResult(action="FAILED", title=title, body=body)
        else:
            # Create PR
            branch = build_branch_name(ctx)
            try:
                sandbox.create_branch(branch)
                sandbox.commit(
                    f"fix: remediate {ctx.finding.title} in {ctx.finding.file_path}",
                    files=[ctx.finding.file_path],
                )
                push_ok, push_err = sandbox.push(branch)
                if not push_ok:
                    raise RuntimeError(f"git push failed: {push_err}")

                gh = GitHubClient(gh_token, target_repo)
                base = gh.get_default_branch()
                url = gh.create_pr(
                    title=title, body=body, head=branch, base=base, labels=labels,
                )
                ctx.pr_result = PRResult(
                    action="PR_CREATED", url=url, branch=branch, title=title, body=body,
                )
            except Exception as e:
                logger.error("Failed to create PR: %s", e)
                ctx.pr_result = PRResult(action="FAILED", title=title, body=body)

    # ------------------------------------------------------------------
    # Final summary
    # ------------------------------------------------------------------
    _write_summary(ctx)

    if ctx.pr_result:
        logger.info("Result: %s — %s", ctx.pr_result.action, ctx.pr_result.url or "N/A")

    if ctx.pipeline_failed:
        logger.error("Pipeline finished with failures: %s", ctx.failure_reason)
        sys.exit(1)


def _fallback_body(ctx: PipelineContext) -> str:
    """Generate a minimal body if the LLM call fails."""
    finding = ctx.finding
    lines = [
        f"## Security Finding: {finding.title}",
        f"**File:** `{finding.file_path}` line {finding.line_number}",
        f"**Severity:** {finding.severity}",
        f"**CWE:** {finding.cwe_id or 'N/A'}",
        "",
        f"{finding.description}",
        "",
        "> Generated by auto-security-patch pipeline (LLM body generation failed)",
    ]
    if ctx.failure_reason:
        lines.insert(-1, f"\n**Pipeline failure:** {ctx.failure_reason}")
    return "\n".join(lines)


def _write_dry_run_output(
    title: str,
    body: str,
    labels: list[str],
    verdict: Verdict | None,
    ctx: PipelineContext,
) -> None:
    """Write dry-run output to pipeline-output/ for review."""
    output = {
        "action": "DRY_RUN",
        "verdict": verdict.value if verdict else None,
        "title": title,
        "labels": labels,
        "body": body,
        "pipeline_failed": ctx.pipeline_failed,
        "failure_reason": ctx.failure_reason or None,
    }
    path = os.path.join(OUTPUT_DIR, "dry_run_output.json")
    Path(path).write_text(json.dumps(output, indent=2))
    logger.info("Dry-run output written to %s", path)

    # Also write the body as markdown for easy preview
    md_path = os.path.join(OUTPUT_DIR, "dry_run_body.md")
    Path(md_path).write_text(f"# {title}\n\n{body}")


def _write_summary(ctx: PipelineContext) -> None:
    """Write a final pipeline summary."""
    summary = {
        "finding": {
            "title": ctx.finding.title if ctx.finding else None,
            "file": ctx.finding.file_path if ctx.finding else None,
            "line": ctx.finding.line_number if ctx.finding else None,
            "severity": ctx.finding.severity if ctx.finding else None,
        },
        "verdict": ctx.assessment.verdict.value if ctx.assessment else None,
        "confidence": ctx.assessment.confidence.value if ctx.assessment else None,
        "pipeline_failed": ctx.pipeline_failed,
        "failure_reason": ctx.failure_reason or None,
        "result": {
            "action": ctx.pr_result.action if ctx.pr_result else None,
            "url": ctx.pr_result.url if ctx.pr_result else None,
        },
    }
    path = os.path.join(OUTPUT_DIR, "summary.json")
    Path(path).write_text(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
