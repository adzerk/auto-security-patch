"""Thin wrapper around the Datadog Security Monitoring Findings API."""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

FINDINGS_PATH = "/api/v2/security_monitoring/findings"
DEFAULT_FILTER = "@severity:critical @type:(code_security OR sca) @status:open"
MAX_PAGES = 50  # safety limit to prevent infinite pagination


class DatadogClientError(Exception):
    """Raised when a Datadog API call fails."""


_VALID_SITES = frozenset(
    {
        "datadoghq.com",
        "datadoghq.eu",
        "ddog-gov.com",
        "ap1.datadoghq.com",
        "us3.datadoghq.com",
        "us5.datadoghq.com",
    }
)


class DatadogClient:
    """Read-only client for querying Datadog security findings."""

    def __init__(
        self,
        api_key: str,
        app_key: str,
        site: str = "datadoghq.com",
    ) -> None:
        if site not in _VALID_SITES:
            raise ValueError(
                f"Unknown Datadog site {site!r}; expected one of {sorted(_VALID_SITES)}"
            )
        self._api_key = api_key
        self._app_key = app_key
        self._base_url = f"https://api.{site}"

    def fetch_critical_code_findings(self) -> list[dict]:
        """Fetch all critical code-security findings (paginated).

        Returns a list of finding attribute dicts.
        """
        findings: list[dict] = []
        cursor: str | None = None

        with httpx.Client(
            base_url=self._base_url,
            headers={
                "DD-API-KEY": self._api_key,
                "DD-APPLICATION-KEY": self._app_key,
            },
            timeout=30.0,
        ) as client:
            for page in range(MAX_PAGES):
                params: dict[str, str] = {"filter[query]": DEFAULT_FILTER}
                if cursor:
                    params["page[cursor]"] = cursor

                resp = client.get(FINDINGS_PATH, params=params)
                if not resp.is_success:
                    raise DatadogClientError(
                        f"Datadog API returned {resp.status_code}: "
                        f"{resp.text[:500]}"
                    )

                body = resp.json()
                for item in body.get("data", []):
                    findings.append(item.get("attributes", item))

                cursor = body.get("meta", {}).get("page", {}).get("cursor")
                if not cursor:
                    break

        logger.info(
            "Fetched %d critical code-security findings from Datadog", len(findings)
        )
        return findings
