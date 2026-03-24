"""Tests for the Datadog security findings API client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from pipeline.datadog_client import MAX_PAGES, DatadogClient, DatadogClientError


def _make_response(
    findings: list[dict],
    cursor: str | None = None,
    status_code: int = 200,
) -> httpx.Response:
    """Build a mock httpx.Response with Datadog findings payload."""
    body: dict = {
        "data": [{"id": f["id"], "type": "finding", "attributes": f} for f in findings],
        "meta": {},
    }
    if cursor:
        body["meta"]["page"] = {"cursor": cursor}
    resp = httpx.Response(status_code=status_code, json=body)
    return resp


def _finding(fid: str = "abc123", **overrides: object) -> dict:
    """Return a minimal Datadog finding dict."""
    base: dict = {
        "id": fid,
        "message": "SQL Injection in app.py",
        "severity": "critical",
        "status": "open",
        "tags": ["repo:acme/webapp", "env:prod"],
        "resource": "acme/webapp",
        "type": "code_security",
    }
    base.update(overrides)
    return base


class TestFetchCriticalCodeFindings:
    """Tests for DatadogClient.fetch_critical_code_findings."""

    @patch("pipeline.datadog_client.httpx.Client")
    def test_fetch_single_page(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

        findings = [_finding("f1"), _finding("f2")]
        mock_client.get.return_value = _make_response(findings)

        client = DatadogClient(api_key="ak", app_key="appk")
        result = client.fetch_critical_code_findings()

        assert len(result) == 2
        assert result[0]["id"] == "f1"
        assert result[1]["id"] == "f2"
        mock_client.get.assert_called_once()

    @patch("pipeline.datadog_client.httpx.Client")
    def test_fetch_paginated(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

        page1 = _make_response([_finding("f1")], cursor="cursor_abc")
        page2 = _make_response([_finding("f2")])
        mock_client.get.side_effect = [page1, page2]

        client = DatadogClient(api_key="ak", app_key="appk")
        result = client.fetch_critical_code_findings()

        assert len(result) == 2
        assert result[0]["id"] == "f1"
        assert result[1]["id"] == "f2"
        assert mock_client.get.call_count == 2

        # Second call should include cursor param
        second_call_kwargs = mock_client.get.call_args_list[1]
        params = second_call_kwargs.kwargs.get("params") or second_call_kwargs[1].get(
            "params", {}
        )
        assert params.get("page[cursor]") == "cursor_abc"

    @patch("pipeline.datadog_client.httpx.Client")
    def test_fetch_empty(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

        mock_client.get.return_value = _make_response([])

        client = DatadogClient(api_key="ak", app_key="appk")
        result = client.fetch_critical_code_findings()

        assert result == []

    @patch("pipeline.datadog_client.httpx.Client")
    def test_api_error_raises(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

        error_resp = httpx.Response(403, json={"errors": ["Forbidden"]})
        mock_client.get.return_value = error_resp

        client = DatadogClient(api_key="ak", app_key="appk")
        with pytest.raises(DatadogClientError, match="403"):
            client.fetch_critical_code_findings()

    @patch("pipeline.datadog_client.httpx.Client")
    def test_filter_query(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

        mock_client.get.return_value = _make_response([])

        client = DatadogClient(api_key="ak", app_key="appk")
        client.fetch_critical_code_findings()

        call_kwargs = mock_client.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        query = params.get("filter[query]", "")
        assert "@severity:critical" in query
        assert "@status:open" in query

    @patch("pipeline.datadog_client.httpx.Client")
    def test_custom_site(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

        mock_client.get.return_value = _make_response([])

        client = DatadogClient(api_key="ak", app_key="appk", site="datadoghq.eu")
        client.fetch_critical_code_findings()

        call_args = mock_client_cls.call_args
        base_url = call_args.kwargs.get("base_url") or call_args[1].get("base_url", "")
        assert "datadoghq.eu" in base_url

    def test_invalid_site_rejected(self) -> None:
        with pytest.raises(ValueError, match="Unknown Datadog site"):
            DatadogClient(api_key="ak", app_key="appk", site="evil.com")

    @patch("pipeline.datadog_client.httpx.Client")
    def test_max_pages_stops_pagination(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

        # Every page returns a cursor, simulating infinite pagination
        mock_client.get.return_value = _make_response(
            [_finding("f1")], cursor="always_more"
        )

        client = DatadogClient(api_key="ak", app_key="appk")
        result = client.fetch_critical_code_findings()

        assert mock_client.get.call_count == MAX_PAGES
        assert len(result) == MAX_PAGES
