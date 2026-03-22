"""Stage 1 — Vulnerability Researcher."""

from __future__ import annotations

import re

from pipeline.models import Finding, ResearchReport
from pipeline.stages.base import run_stage


def research(finding: Finding, *, sandbox_root: str, output_dir: str) -> ResearchReport:
    """Research the vulnerability class and produce a structured report."""
    prompt = f"""\
Research the following security vulnerability finding.

FINDING DETAILS:
TEST_ID: {finding.title}
TEST_NAME: {finding.title}
SEVERITY: {finding.severity}
CWE: {finding.cwe_id or "NULL"}
CWE_LINK: {"https://cwe.mitre.org/data/definitions/" + finding.cwe_id.split("-")[1] + ".html" if finding.cwe_id else "NULL"}
DESCRIPTION: {finding.description}
FILE: {finding.file_path}
LINE: {finding.line_number}
RULE_LINK: NULL

RAW FINDING DATA:
{finding.raw_blob}
"""

    output = run_stage(
        "vulnerability_researcher",
        prompt,
        sandbox_root=sandbox_root,
        output_dir=output_dir,
    )

    return _parse_research(output)


def _parse_research(output: str) -> ResearchReport:
    """Parse the delimited research report from model output."""
    report = ResearchReport(raw_output=output)

    # Extract sections between markers
    match = re.search(
        r"VULNERABILITY_RESEARCH_COMPLETE\s*\n(.*?)VULNERABILITY_RESEARCH_END",
        output,
        re.DOTALL,
    )
    if not match:
        report.what_it_is = output  # fallback: use entire output
        return report

    body = match.group(1)

    def extract(key: str) -> str:
        pattern = rf"^{key}:\s*\n(.*?)(?=\n[A-Z_]+:|$)"
        m = re.search(pattern, body, re.MULTILINE | re.DOTALL)
        return m.group(1).strip() if m else ""

    report.what_it_is = extract("WHAT_IT_IS")
    report.how_exploited = extract("HOW_EXPLOITED")
    report.real_world_impact = extract("REAL_WORLD_IMPACT")
    report.standard_remediations = extract("STANDARD_REMEDIATIONS")
    report.references = extract("REFERENCES")

    return report
