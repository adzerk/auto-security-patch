"""Sandbox for repository operations.

Clones the target repo into a temporary directory and provides a context
manager for safe lifecycle management.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class RepoSandbox:
    """Context manager that clones a repo into a temp dir and cleans up on exit.

    Usage::

        with RepoSandbox("https://github.com/org/repo.git", token="ghp_...") as sb:
            content = (Path(sb.path) / "app.py").read_text()
            sb.apply_patch(diff_text)
            sb.create_branch("auto-fix/cwe-89")
    """

    def __init__(self, repo_url: str, *, token: str | None = None) -> None:
        self.repo_url = repo_url
        self.token = token
        self._tmpdir: str | None = None

    @property
    def path(self) -> str:
        if self._tmpdir is None:
            raise RuntimeError(
                "Sandbox not entered — use 'with RepoSandbox(...) as sb:'"
            )
        return self._tmpdir

    def __enter__(self) -> RepoSandbox:
        self._tmpdir = tempfile.mkdtemp(prefix="secpatch_")
        logger.info("Cloning %s into %s", self.repo_url, self._tmpdir)
        clone_url = self._auth_url()
        self._run(["git", "clone", "--depth=1", clone_url, self._tmpdir])
        # Configure a git identity so commits don't fail in CI environments
        self._run(
            [
                "git",
                "config",
                "user.email",
                "auto-security-patch[bot]@users.noreply.github.com",
            ]
        )
        self._run(["git", "config", "user.name", "auto-security-patch[bot]"])
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._tmpdir and os.path.isdir(self._tmpdir):
            logger.info("Cleaning up sandbox: %s", self._tmpdir)
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None

    def _auth_url(self) -> str:
        """Inject token into HTTPS clone URL if provided."""
        if self.token and self.repo_url.startswith("https://"):
            return self.repo_url.replace(
                "https://", f"https://x-access-token:{self.token}@"
            )
        return self.repo_url

    def _run(
        self,
        cmd: list[str],
        *,
        cwd: str | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run a subprocess with no shell=True. Uses list args only."""
        try:
            return subprocess.run(
                cmd,
                cwd=cwd or self._tmpdir,
                capture_output=True,
                text=True,
                timeout=120,
                check=check,
            )
        except subprocess.CalledProcessError as e:
            # Redact the token from error output before surfacing
            token = self.token or ""

            def _redact(s: str) -> str:
                return s.replace(token, "***") if token else s

            safe_cmd = [_redact(arg) for arg in (e.cmd or [])]
            safe_stderr = _redact(e.stderr or "")
            safe_stdout = _redact(e.stdout or "")
            raise RuntimeError(
                f"Command {safe_cmd} failed (exit {e.returncode}):\n{safe_stderr or safe_stdout}"
            ) from None

    def apply_patch(self, diff_text: str) -> tuple[bool, str]:
        """Apply a unified diff patch via git apply.

        Returns (success, error_message).
        """
        with tempfile.NamedTemporaryFile(
            suffix=".diff", dir=self._tmpdir, delete=False, mode="w"
        ) as tmp:
            patch_file = tmp.name
            tmp.write(diff_text)

        try:
            result = self._run(
                ["git", "apply", "--check", patch_file],
                check=False,
            )
            if result.returncode != 0:
                return False, result.stderr.strip()
            # Patch checks out — apply for real
            self._run(["git", "apply", patch_file])
            return True, ""
        finally:
            if os.path.exists(patch_file):
                os.unlink(patch_file)

    def get_changed_files(self) -> list[str]:
        """Return list of files modified since HEAD (staged or unstaged)."""
        result = self._run(["git", "diff", "--name-only", "HEAD"], check=False)
        return [f.strip() for f in result.stdout.splitlines() if f.strip()]

    def create_branch(self, branch_name: str) -> None:
        self._run(["git", "checkout", "-b", branch_name])

    def commit(self, message: str, files: list[str] | None = None) -> None:
        if files:
            self._run(["git", "add"] + files)
        else:
            self._run(["git", "add", "-A"])
        self._run(["git", "commit", "-m", message])

    def push(self, branch_name: str) -> tuple[bool, str]:
        """Push the branch. Returns (success, error_message)."""
        result = self._run(
            ["git", "push", "origin", branch_name],
            check=False,
        )
        if result.returncode != 0:
            # Redact token from git stderr (may contain authenticated remote URL)
            token = self.token or ""
            stderr = result.stderr.strip()
            if token:
                stderr = stderr.replace(token, "***")
            return False, stderr
        return True, ""
