"""Tests for the normalizer — uses fixtures to verify parsing of various formats.

Note: These tests require ANTHROPIC_API_KEY to be set since the normalizer
calls the Claude API. They are integration tests, not unit tests.
To run without API calls, mock anthropic.Anthropic.
"""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pipeline.normalizer import normalize

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _mock_tool_response(data: dict):
    """Create a mock API response that returns a tool_use block."""
    mock_block = MagicMock()
    mock_block.type = "tool_use"
    mock_block.input = data

    mock_response = MagicMock()
    mock_response.id = "test-id"
    mock_response.model = "test-model"
    mock_response.content = [mock_block]
    return mock_response


class TestNormalizerParsing:
    """Test normalizer with mocked API calls."""

    @patch("pipeline.normalizer.get_client")
    def test_bandit_json(self, mock_get_client, tmp_path):
        raw = (FIXTURES_DIR / "bandit_finding.json").read_text()

        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_client.messages.create.return_value = _mock_tool_response({
            "file_path": "app.py",
            "line_number": 42,
            "cwe_id": "CWE-89",
            "severity": "MEDIUM",
            "title": "SQL Injection",
            "description": "Possible SQL injection via string-based query construction.",
            "confidence": "high",
        })

        finding = normalize(raw, output_dir=str(tmp_path))
        assert finding.file_path == "app.py"
        assert finding.line_number == 42
        assert finding.cwe_id == "CWE-89"
        assert finding.severity == "MEDIUM"

    @patch("pipeline.normalizer.get_client")
    def test_sarif_json(self, mock_get_client, tmp_path):
        raw = (FIXTURES_DIR / "sarif_finding.json").read_text()

        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_client.messages.create.return_value = _mock_tool_response({
            "file_path": "app.py",
            "line_number": 134,
            "cwe_id": "CWE-78",
            "severity": "HIGH",
            "title": "OS Command Injection",
            "description": "OS command injection via user-controlled input.",
            "confidence": "high",
        })

        finding = normalize(raw, output_dir=str(tmp_path))
        assert finding.file_path == "app.py"
        assert finding.line_number == 134
        assert finding.cwe_id == "CWE-78"

    @patch("pipeline.normalizer.get_client")
    def test_freeform_text(self, mock_get_client, tmp_path):
        raw = (FIXTURES_DIR / "freeform_finding.txt").read_text()

        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_client.messages.create.return_value = _mock_tool_response({
            "file_path": "db.py",
            "line_number": 15,
            "cwe_id": "CWE-798",
            "severity": "HIGH",
            "title": "Hardcoded Credentials",
            "description": "Hardcoded database password found.",
            "confidence": "high",
        })

        finding = normalize(raw, output_dir=str(tmp_path))
        assert finding.file_path == "db.py"
        assert finding.line_number == 15

    @patch("pipeline.normalizer.get_client")
    def test_low_confidence_raises(self, mock_get_client, tmp_path):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_client.messages.create.return_value = _mock_tool_response({
            "file_path": "unknown",
            "line_number": 0,
            "severity": "LOW",
            "title": "Unknown",
            "description": "Could not parse",
            "confidence": "low",
        })

        with pytest.raises(ValueError, match="low confidence"):
            normalize("some garbage data", output_dir=str(tmp_path))

    @patch("pipeline.normalizer.get_client")
    def test_no_tool_block_raises(self, mock_get_client, tmp_path):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        mock_text = MagicMock()
        mock_text.type = "text"
        mock_text.text = "I could not parse this."

        mock_response = MagicMock()
        mock_response.id = "test-id"
        mock_response.model = "test-model"
        mock_response.content = [mock_text]
        mock_client.messages.create.return_value = mock_response

        with pytest.raises(ValueError, match="tool_use"):
            normalize("junk", output_dir=str(tmp_path))

    @patch("pipeline.normalizer.get_client")
    def test_raw_blob_preserved(self, mock_get_client, tmp_path):
        raw = "the original vulnerability data"

        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_client.messages.create.return_value = _mock_tool_response({
            "file_path": "x.py",
            "line_number": 1,
            "severity": "LOW",
            "title": "Test",
            "description": "Test",
            "confidence": "high",
        })

        finding = normalize(raw, output_dir=str(tmp_path))
        assert finding.raw_blob == raw
