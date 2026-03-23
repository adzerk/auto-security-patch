"""Summary report generation for E2E runs."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from e2e.validate import ValidatedResult


def write_report(
    results: list[ValidatedResult],
    output_dir: str,
    *,
    scan_path: str = "",
    target_repo: str = "",
    dry_run: bool = True,
) -> None:
    """Write JSON and Markdown reports summarising the E2E run."""
    os.makedirs(output_dir, exist_ok=True)

    findings_data = []
    for vr in results:
        fr = vr.finding_result
        stages_completed = [c.stage for c in vr.checks if c.found and c.non_empty]
        findings_data.append(
            {
                "id": fr.finding_id,
                "test_id": fr.finding.get("test_id", ""),
                "file": fr.finding.get("filename", ""),
                "line": fr.finding.get("line_number", 0),
                "severity": fr.finding.get("issue_severity", ""),
                "exit_code": fr.exit_code,
                "verdict": vr.verdict,
                "stages_completed": stages_completed,
                "validation_passed": vr.all_required_passed,
                "error": fr.error,
            }
        )

    verdicts: dict[str, int] = {}
    for fd in findings_data:
        v = fd["verdict"] or "UNKNOWN"
        verdicts[v] = verdicts.get(v, 0) + 1

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_path": scan_path,
        "target_repo": target_repo,
        "dry_run": dry_run,
        "total_findings": len(results),
        "succeeded": sum(1 for fd in findings_data if fd["exit_code"] == 0),
        "failed": sum(1 for fd in findings_data if fd["exit_code"] != 0),
        "verdicts": verdicts,
        "findings": findings_data,
    }

    # JSON report
    json_path = os.path.join(output_dir, "e2e_report.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    # Markdown report
    md_path = os.path.join(output_dir, "e2e_report.md")
    with open(md_path, "w") as f:
        f.write("# E2E Pipeline Report\n\n")
        f.write(f"- **Date:** {report['timestamp']}\n")
        f.write(f"- **Scan path:** {scan_path}\n")
        f.write(f"- **Target repo:** {target_repo}\n")
        f.write(f"- **Dry run:** {dry_run}\n")
        f.write(f"- **Total:** {report['total_findings']}  |  ")
        f.write(f"Succeeded: {report['succeeded']}  |  ")
        f.write(f"Failed: {report['failed']}\n")
        f.write(f"- **Verdicts:** {verdicts}\n\n")

        f.write(
            "| # | ID | File | Line | Severity | Verdict | Stages | Valid | Exit |\n"
        )
        f.write("|---|---|---|---|---|---|---|---|---|\n")
        for i, fd in enumerate(findings_data, 1):
            stages_str = (
                ", ".join(fd["stages_completed"]) if fd["stages_completed"] else "-"
            )
            valid = "pass" if fd["validation_passed"] else "FAIL"
            f.write(
                f"| {i} | {fd['test_id']} | {fd['file']} | {fd['line']} "
                f"| {fd['severity']} | {fd['verdict'] or '-'} | {stages_str} "
                f"| {valid} | {fd['exit_code']} |\n"
            )

        if any(fd["error"] for fd in findings_data):
            f.write("\n## Errors\n\n")
            for fd in findings_data:
                if fd["error"]:
                    f.write(f"### {fd['id']}\n\n```\n{fd['error']}\n```\n\n")
