"""Thin wrapper around PyGithub for creating branches, PRs, and issues."""

from __future__ import annotations

import logging

from github import Auth, Github

logger = logging.getLogger(__name__)


class GitHubClient:
    """Minimal GitHub API client for the pipeline's needs."""

    def __init__(self, token: str, target_repo: str) -> None:
        self._gh = Github(auth=Auth.Token(token))
        self._repo = self._gh.get_repo(target_repo)

    def create_pr(
        self,
        *,
        title: str,
        body: str,
        head: str,
        base: str = "main",
        labels: list[str] | None = None,
    ) -> str:
        """Create a pull request. Returns the PR URL."""
        pr = self._repo.create_pull(
            title=title,
            body=body,
            head=head,
            base=base,
        )
        if labels:
            self._ensure_labels(labels)
            pr.set_labels(*labels)
        logger.info("Created PR: %s", pr.html_url)
        return pr.html_url

    def create_issue(
        self,
        *,
        title: str,
        body: str,
        labels: list[str] | None = None,
    ) -> str:
        """Create an issue. Returns the issue URL."""
        if labels:
            self._ensure_labels(labels)
        issue = self._repo.create_issue(
            title=title,
            body=body,
            labels=labels or [],
        )
        logger.info("Created issue: %s", issue.html_url)
        return issue.html_url

    def get_default_branch(self) -> str:
        return self._repo.default_branch

    def _ensure_labels(self, labels: list[str]) -> None:
        """Create labels if they don't exist (idempotent)."""
        existing = {lbl.name for lbl in self._repo.get_labels()}
        for label in labels:
            if label not in existing:
                try:
                    self._repo.create_label(name=label, color="ededed")
                except Exception as e:
                    logger.warning("Could not create label %r: %s", label, e)
