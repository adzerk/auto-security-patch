"""E2E test runner — scan vulnerable-app and process findings through the pipeline."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed

from e2e.report import write_report
from e2e.scan import finding_id, finding_to_vulnerability_data, run_bandit
from e2e.validate import FindingResult, ValidatedResult, check_outputs


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run the auto-security-patch pipeline E2E against a scanned codebase.",
    )
    p.add_argument(
        "--scan-path",
        default=os.path.join(os.path.dirname(__file__), "..", "..", "vulnerable-app"),
        help="Path to code to scan with Bandit (default: ../vulnerable-app)",
    )
    p.add_argument(
        "--target-repo",
        default="adzerk/purposefully-vulnerable-repo",
        help="GitHub org/repo for the sandbox clone",
    )
    p.add_argument(
        "--live",
        action="store_true",
        help="Run pipeline in live mode (creates real PRs/issues); default is dry-run",
    )
    p.add_argument(
        "--max-parallel", type=int, default=1, help="Max concurrent pipeline runs"
    )
    p.add_argument(
        "--max-findings", type=int, default=5, help="Cap on findings to process"
    )
    p.add_argument(
        "--severity", default="HIGH,MEDIUM", help="Comma-separated severity filter"
    )
    p.add_argument(
        "--output-dir", default="e2e-output", help="Root directory for E2E outputs"
    )
    p.add_argument(
        "--skip-scan", action="store_true", help="Skip Bandit; use --findings-file"
    )
    p.add_argument("--findings-file", help="Pre-scanned Bandit JSON array file")
    p.add_argument(
        "--timeout", type=int, default=600, help="Per-finding timeout in seconds"
    )
    return p.parse_args()


def validate_env() -> None:
    missing = []
    if not os.environ.get("ANTHROPIC_API_KEY"):
        missing.append("ANTHROPIC_API_KEY")
    if not os.environ.get("GITHUB_TOKEN"):
        missing.append("GITHUB_TOKEN")
    if missing:
        print(
            f"ERROR: Missing required env vars: {', '.join(missing)}", file=sys.stderr
        )
        sys.exit(1)


def run_single_finding(
    finding: dict,
    *,
    target_repo: str,
    dry_run: bool,
    output_dir: str,
    timeout: int,
) -> FindingResult:
    """Invoke the pipeline as a subprocess for one finding."""
    fid = finding_id(finding)
    work_dir = os.path.join(output_dir, fid)
    os.makedirs(work_dir, exist_ok=True)

    env = {
        **os.environ,
        "VULNERABILITY_DATA": finding_to_vulnerability_data(finding),
        "TARGET_REPO": target_repo,
        "DRY_RUN": "true" if dry_run else "false",
    }

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pipeline.run_pipeline"],
            env=env,
            cwd=work_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return FindingResult(
            finding_id=fid,
            finding=finding,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            output_dir=os.path.join(work_dir, "pipeline-output"),
        )
    except subprocess.TimeoutExpired as exc:
        return FindingResult(
            finding_id=fid,
            finding=finding,
            exit_code=1,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            output_dir=os.path.join(work_dir, "pipeline-output"),
            error=f"Timed out after {timeout}s",
        )
    except Exception as exc:
        return FindingResult(
            finding_id=fid,
            finding=finding,
            exit_code=1,
            output_dir=os.path.join(work_dir, "pipeline-output"),
            error=str(exc),
        )


def main() -> None:
    args = parse_args()
    dry_run = not args.live
    validate_env()

    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    # --- Step 1: Get findings ---
    if args.skip_scan:
        if not args.findings_file:
            print("ERROR: --skip-scan requires --findings-file", file=sys.stderr)
            sys.exit(1)
        with open(args.findings_file) as f:
            findings = json.load(f)
        print(f"Loaded {len(findings)} finding(s) from {args.findings_file}")
    else:
        scan_path = os.path.abspath(args.scan_path)
        severity_list = [s.strip() for s in args.severity.split(",")]
        print(f"Scanning {scan_path} with Bandit (severity={severity_list})...")
        findings = run_bandit(scan_path, severity_list, args.max_findings)
        print(f"Found {len(findings)} finding(s)")

        # Save findings for reproducibility
        findings_path = os.path.join(output_dir, "bandit_findings.json")
        with open(findings_path, "w") as f:
            json.dump(findings, f, indent=2)

    if not findings:
        print("No findings to process.")
        return

    # --- Step 2: Process each finding ---
    print(
        f"\nProcessing {len(findings)} finding(s) (parallel={args.max_parallel}, dry_run={dry_run})...\n"
    )

    results: list[FindingResult] = []

    if args.max_parallel <= 1:
        for i, finding in enumerate(findings, 1):
            fid = finding_id(finding)
            test_id = finding.get("test_id", "?")
            filename = finding.get("filename", "?")
            line = finding.get("line_number", "?")
            print(f"[{i}/{len(findings)}] {test_id} {filename}:{line} ({fid})")

            result = run_single_finding(
                finding,
                target_repo=args.target_repo,
                dry_run=dry_run,
                output_dir=output_dir,
                timeout=args.timeout,
            )
            status = (
                "OK" if result.exit_code == 0 else f"FAIL (exit {result.exit_code})"
            )
            if result.error:
                status += f" — {result.error}"
            print(f"  -> {status}")
            results.append(result)
    else:
        with ProcessPoolExecutor(max_workers=args.max_parallel) as pool:
            future_to_finding = {}
            for finding in findings:
                fut = pool.submit(
                    run_single_finding,
                    finding,
                    target_repo=args.target_repo,
                    dry_run=dry_run,
                    output_dir=output_dir,
                    timeout=args.timeout,
                )
                future_to_finding[fut] = finding

            for fut in as_completed(future_to_finding):
                finding = future_to_finding[fut]
                fid = finding_id(finding)
                try:
                    result = fut.result()
                except Exception as exc:
                    work_dir = os.path.join(output_dir, fid)
                    result = FindingResult(
                        finding_id=fid,
                        finding=finding,
                        exit_code=1,
                        output_dir=os.path.join(work_dir, "pipeline-output"),
                        error=str(exc),
                    )
                status = (
                    "OK" if result.exit_code == 0 else f"FAIL (exit {result.exit_code})"
                )
                print(f"  {fid}: {status}")
                results.append(result)

    # --- Step 3: Validate outputs ---
    validated: list[ValidatedResult] = [
        check_outputs(r, dry_run=dry_run) for r in results
    ]

    # --- Step 4: Write report ---
    write_report(
        validated,
        output_dir,
        scan_path=args.scan_path,
        target_repo=args.target_repo,
        dry_run=dry_run,
    )

    # --- Summary ---
    passed = sum(1 for v in validated if v.all_required_passed)
    failed = len(validated) - passed
    verdicts = {}
    for v in validated:
        vname = v.verdict or "UNKNOWN"
        verdicts[vname] = verdicts.get(vname, 0) + 1

    print(f"\n{'=' * 60}")
    print(f" E2E Run Complete")
    print(f" Total: {len(validated)}  |  Passed: {passed}  |  Failed: {failed}")
    print(f" Verdicts: {verdicts}")
    print(f" Reports: {output_dir}/e2e_report.{{json,md}}")
    print(f"{'=' * 60}")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
