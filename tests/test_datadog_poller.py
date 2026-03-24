"""Tests for the Datadog poller that dispatches findings to the pipeline."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pipeline.datadog_poller import (
    _derive_target_repo,
    _load_state,
    _save_state,
    main,
)

_SENTINEL = object()


def _finding(
    fid: str = "abc123",
    tags: list[str] | object = _SENTINEL,
    resource: str | None | object = _SENTINEL,
) -> dict:
    base: dict = {
        "id": fid,
        "message": "SQL Injection in app.py",
        "severity": "critical",
        "status": "open",
        "tags": tags if tags is not _SENTINEL else ["repo:acme/webapp"],
        "resource": resource if resource is not _SENTINEL else "acme/webapp",
        "type": "code_security",
    }
    return base


class TestDeriveTargetRepo:
    def test_from_repo_tag(self) -> None:
        finding = _finding(tags=["repo:acme/webapp", "env:prod"])
        assert _derive_target_repo(finding) == "acme/webapp"

    def test_from_git_repository_tag(self) -> None:
        finding = _finding(
            tags=["git_repository:https://github.com/acme/api-server", "env:prod"],
            resource=None,
        )
        assert _derive_target_repo(finding) == "acme/api-server"

    def test_from_resource_field(self) -> None:
        finding = _finding(tags=["env:prod"], resource="acme/backend")
        assert _derive_target_repo(finding) == "acme/backend"

    def test_returns_none_when_no_repo(self) -> None:
        finding = _finding(tags=["env:prod"], resource=None)
        finding.pop("resource", None)
        assert _derive_target_repo(finding) is None

    def test_returns_none_for_non_slug_resource(self) -> None:
        finding = _finding(tags=[], resource="some-service")
        assert _derive_target_repo(finding) is None

    def test_git_repository_tag_with_dot_git_suffix(self) -> None:
        finding = _finding(
            tags=["git_repository:https://github.com/acme/api-server.git"],
            resource=None,
        )
        assert _derive_target_repo(finding) == "acme/api-server"


class TestStateFile:
    def test_load_missing_file(self, tmp_path: Path) -> None:
        state = _load_state(str(tmp_path / "nonexistent.json"))
        assert state == {}

    def test_round_trip(self, tmp_path: Path) -> None:
        path = str(tmp_path / "state.json")
        data = {"f1": {"processed_at": "2026-03-24T10:00:00Z", "result": "DRY_RUN"}}
        _save_state(path, data)
        assert _load_state(path) == data


class TestMain:
    @patch.dict(
        os.environ,
        {
            "DD_API_KEY": "ak",
            "DD_APP_KEY": "appk",
            "GITHUB_TOKEN": "gh",
            "ANTHROPIC_API_KEY": "ant",
            "DRY_RUN": "true",
        },
        clear=False,
    )
    @patch("pipeline.datadog_poller.run_pipeline_main")
    @patch("pipeline.datadog_poller.DatadogClient")
    def test_processes_new_findings(
        self,
        mock_dd_cls: MagicMock,
        mock_pipeline: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_dd = MagicMock()
        mock_dd_cls.return_value = mock_dd
        mock_dd.fetch_critical_code_findings.return_value = [
            _finding("f1"),
            _finding("f2"),
        ]

        state_file = str(tmp_path / "state.json")
        with patch.dict(os.environ, {"DD_STATE_FILE": state_file}):
            main()

        assert mock_pipeline.call_count == 2

    @patch.dict(
        os.environ,
        {
            "DD_API_KEY": "ak",
            "DD_APP_KEY": "appk",
            "GITHUB_TOKEN": "gh",
            "ANTHROPIC_API_KEY": "ant",
            "DRY_RUN": "true",
        },
        clear=False,
    )
    @patch("pipeline.datadog_poller.run_pipeline_main")
    @patch("pipeline.datadog_poller.DatadogClient")
    def test_skips_processed(
        self,
        mock_dd_cls: MagicMock,
        mock_pipeline: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_dd = MagicMock()
        mock_dd_cls.return_value = mock_dd
        mock_dd.fetch_critical_code_findings.return_value = [
            _finding("f1"),
            _finding("f2"),
        ]

        state_file = str(tmp_path / "state.json")
        Path(state_file).write_text(
            json.dumps(
                {
                    "f1": {"processed_at": "2026-03-24T10:00:00Z", "result": "DRY_RUN"},
                }
            )
        )

        with patch.dict(os.environ, {"DD_STATE_FILE": state_file}):
            main()

        assert mock_pipeline.call_count == 1

    @patch.dict(
        os.environ,
        {
            "DD_API_KEY": "ak",
            "DD_APP_KEY": "appk",
            "GITHUB_TOKEN": "gh",
            "ANTHROPIC_API_KEY": "ant",
            "DRY_RUN": "true",
        },
        clear=False,
    )
    @patch("pipeline.datadog_poller.run_pipeline_main")
    @patch("pipeline.datadog_poller.DatadogClient")
    def test_handles_pipeline_failure(
        self,
        mock_dd_cls: MagicMock,
        mock_pipeline: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_dd = MagicMock()
        mock_dd_cls.return_value = mock_dd
        mock_dd.fetch_critical_code_findings.return_value = [
            _finding("f1"),
            _finding("f2"),
        ]

        mock_pipeline.side_effect = [SystemExit(1), None]

        state_file = str(tmp_path / "state.json")
        with patch.dict(os.environ, {"DD_STATE_FILE": state_file}):
            main()

        # Both findings attempted despite first failure
        assert mock_pipeline.call_count == 2

        state = json.loads(Path(state_file).read_text())
        assert state["f1"]["result"] == "FAILED"
        assert state["f2"]["result"] == "OK"

    def test_missing_env_vars(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(SystemExit):
                main()

    @patch.dict(
        os.environ,
        {
            "DD_API_KEY": "ak",
            "DD_APP_KEY": "appk",
            "GITHUB_TOKEN": "gh",
            "ANTHROPIC_API_KEY": "ant",
            "DRY_RUN": "true",
        },
        clear=False,
    )
    @patch("pipeline.datadog_poller.run_pipeline_main")
    @patch("pipeline.datadog_poller.DatadogClient")
    def test_skips_finding_without_repo(
        self,
        mock_dd_cls: MagicMock,
        mock_pipeline: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_dd = MagicMock()
        mock_dd_cls.return_value = mock_dd
        no_repo = _finding("f1", tags=["env:prod"], resource=None)
        no_repo.pop("resource", None)
        mock_dd.fetch_critical_code_findings.return_value = [no_repo]

        state_file = str(tmp_path / "state.json")
        with patch.dict(os.environ, {"DD_STATE_FILE": state_file}):
            main()

        mock_pipeline.assert_not_called()

    @patch.dict(
        os.environ,
        {
            "DD_API_KEY": "ak",
            "DD_APP_KEY": "appk",
            "GITHUB_TOKEN": "gh",
            "ANTHROPIC_API_KEY": "ant",
            "DRY_RUN": "true",
            "DD_REPOS": "acme/webapp,acme/api",
        },
        clear=False,
    )
    @patch("pipeline.datadog_poller.run_pipeline_main")
    @patch("pipeline.datadog_poller.DatadogClient")
    def test_filters_by_repo_allowlist(
        self,
        mock_dd_cls: MagicMock,
        mock_pipeline: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_dd = MagicMock()
        mock_dd_cls.return_value = mock_dd
        mock_dd.fetch_critical_code_findings.return_value = [
            _finding("f1", tags=["repo:acme/webapp"]),
            _finding("f2", tags=["repo:acme/other"]),
            _finding("f3", tags=["repo:acme/api"]),
        ]

        state_file = str(tmp_path / "state.json")
        with patch.dict(os.environ, {"DD_STATE_FILE": state_file}):
            main()

        # Only f1 (acme/webapp) and f3 (acme/api) should be processed
        assert mock_pipeline.call_count == 2
