"""Bandit scanning and finding extraction for E2E tests."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys


def run_bandit(
    scan_path: str,
    severity_filter: list[str] | None = None,
    max_findings: int = 10,
) -> list[dict]:
    """Run Bandit against *scan_path* and return individual finding dicts.

    Each dict is a single Bandit result suitable for use as
    ``VULNERABILITY_DATA``.
    """
    if severity_filter is None:
        severity_filter = ["HIGH", "MEDIUM"]

    scan_path = os.path.abspath(scan_path)
    if not os.path.isdir(scan_path):
        raise FileNotFoundError(f"Scan path does not exist: {scan_path}")

    if not shutil.which("bandit"):
        print(
            "ERROR: bandit not found. Install with: poetry install --with e2e",
            file=sys.stderr,
        )
        raise RuntimeError("bandit not found in PATH")

    # Bandit exits 1 when findings exist — that's expected.
    proc = subprocess.run(
        ["bandit", "-r", scan_path, "-f", "json", "-q"],
        capture_output=True,
        text=True,
    )

    if proc.returncode not in (0, 1):
        raise RuntimeError(f"Bandit failed (exit {proc.returncode}): {proc.stderr}")

    if not proc.stdout.strip():
        return []

    data = json.loads(proc.stdout)
    results: list[dict] = data.get("results", [])

    # Filter by severity
    allowed = {s.upper() for s in severity_filter}
    filtered = [r for r in results if r.get("issue_severity", "").upper() in allowed]

    return filtered[:max_findings]


def finding_to_vulnerability_data(finding: dict) -> str:
    """Serialize a single Bandit finding dict to a JSON string."""
    return json.dumps(finding)


def finding_id(finding: dict) -> str:
    """Generate a stable directory-safe identifier for a finding."""
    test_id = finding.get("test_id", "unknown")
    filename = finding.get("filename", "unknown")
    # Use just the basename, replace dots/slashes with underscores
    basename = os.path.basename(filename).replace(".", "_")
    line = finding.get("line_number", 0)
    return f"{test_id}_{basename}_{line}"
