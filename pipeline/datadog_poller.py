"""Poll Datadog for critical code-security findings and dispatch the pipeline.

Usage:
    DD_API_KEY=... DD_APP_KEY=... ANTHROPIC_API_KEY=... GITHUB_TOKEN=... \
        python -m pipeline.datadog_poller
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from pipeline.datadog_client import DatadogClient
from pipeline.run_pipeline import main as run_pipeline_main

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

_REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _derive_target_repo(finding: dict) -> str | None:
    """Extract an org/repo slug from a Datadog finding's metadata.

    Tries these strategies in order:
      1. ``repo:org/name`` tag
      2. ``git_repository:https://github.com/org/name`` tag → extract slug
      3. ``resource`` field if it looks like an org/repo slug
    Returns *None* when no repo can be derived.
    """
    for tag in finding.get("tags", []):
        if tag.startswith("repo:"):
            slug = tag.removeprefix("repo:")
            if _REPO_SLUG_RE.match(slug):
                return slug
        if tag.startswith("git_repository:"):
            url = tag.removeprefix("git_repository:")
            parsed = urlparse(url)
            path = parsed.path.strip("/").removesuffix(".git")
            if _REPO_SLUG_RE.match(path):
                return path

    resource = finding.get("resource")
    if resource and _REPO_SLUG_RE.match(resource):
        return resource

    return None


def _load_state(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        logger.warning("Corrupt state file %s — starting fresh", path)
        return {}


def _save_state(path: str, state: dict) -> None:
    tmp = Path(path).with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    os.replace(tmp, path)


def main() -> None:
    api_key = os.environ.get("DD_API_KEY", "")
    app_key = os.environ.get("DD_APP_KEY", "")
    site = os.environ.get("DD_SITE", "datadoghq.com")
    state_file = os.environ.get("DD_STATE_FILE", "datadog_processed.json")
    repos_env = os.environ.get("DD_REPOS", "")

    if not api_key or not app_key:
        logger.error("DD_API_KEY and DD_APP_KEY are required")
        sys.exit(1)

    repo_allowlist: set[str] | None = None
    if repos_env:
        repo_allowlist = {r.strip() for r in repos_env.split(",") if r.strip()}
        logger.info("Repo allowlist: %s", repo_allowlist)

    client = DatadogClient(api_key=api_key, app_key=app_key, site=site)
    findings = client.fetch_critical_code_findings()

    state = _load_state(state_file)
    processed = 0
    skipped = 0
    failed = 0

    for finding in findings:
        fid = finding.get("id", "")
        if not fid:
            logger.warning("Finding has no id, skipping: %s", finding)
            continue
        if fid in state:
            skipped += 1
            continue

        repo = _derive_target_repo(finding)
        if not repo:
            logger.warning(
                "Cannot derive target repo for finding %s — tags: %s, resource: %s",
                fid,
                finding.get("tags"),
                finding.get("resource"),
            )
            continue

        if repo_allowlist and repo not in repo_allowlist:
            logger.info("Finding %s repo %s not in allowlist, skipping", fid, repo)
            skipped += 1
            continue

        logger.info("Processing finding %s for repo %s", fid, repo)
        prev_vuln = os.environ.get("VULNERABILITY_DATA")
        prev_repo = os.environ.get("TARGET_REPO")
        os.environ["VULNERABILITY_DATA"] = json.dumps(finding)
        os.environ["TARGET_REPO"] = repo

        now = datetime.now(timezone.utc).isoformat()
        try:
            run_pipeline_main()
            state[fid] = {"processed_at": now, "result": "OK"}
            processed += 1
        except SystemExit:
            state[fid] = {"processed_at": now, "result": "FAILED"}
            failed += 1
            logger.error("Pipeline failed for finding %s", fid)
        except Exception:
            state[fid] = {"processed_at": now, "result": "FAILED"}
            failed += 1
            logger.exception("Pipeline error for finding %s", fid)
        finally:
            # Restore env vars to prevent leaking between iterations
            if prev_vuln is None:
                os.environ.pop("VULNERABILITY_DATA", None)
            else:
                os.environ["VULNERABILITY_DATA"] = prev_vuln
            if prev_repo is None:
                os.environ.pop("TARGET_REPO", None)
            else:
                os.environ["TARGET_REPO"] = prev_repo

        _save_state(state_file, state)
    logger.info(
        "Datadog poller complete: %d processed, %d skipped, %d failed",
        processed,
        skipped,
        failed,
    )


if __name__ == "__main__":
    main()
