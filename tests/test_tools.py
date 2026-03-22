"""Tests for tool implementations — especially sandboxing and allowlists."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline.tools import (
    _is_safe_url,
    execute_tool,
    list_files,
    read_file,
    run_command,
    search_content,
    web_fetch,
)


@pytest.fixture
def sandbox(tmp_path):
    """Create a temporary sandbox with some test files."""
    (tmp_path / "app.py").write_text("def hello():\n    print('hello')\n")
    (tmp_path / "db.py").write_text("import sqlite3\n\ndef query(sql):\n    pass\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "util.py").write_text("# utility\n")
    return str(tmp_path)


class TestReadFile:
    def test_read_existing_file(self, sandbox):
        result = read_file("app.py", sandbox_root=sandbox)
        assert "def hello" in result

    def test_read_missing_file(self, sandbox):
        result = read_file("missing.py", sandbox_root=sandbox)
        assert "Error: file not found" in result

    def test_read_subdirectory_file(self, sandbox):
        result = read_file("sub/util.py", sandbox_root=sandbox)
        assert "utility" in result

    def test_path_traversal_rejected(self, sandbox):
        with pytest.raises(PermissionError, match="escapes sandbox"):
            read_file("../../etc/passwd", sandbox_root=sandbox)

    def test_absolute_path_traversal_rejected(self, sandbox):
        with pytest.raises(PermissionError, match="escapes sandbox"):
            read_file("/etc/passwd", sandbox_root=sandbox)


class TestListFiles:
    def test_list_python_files(self, sandbox):
        result = list_files("*.py", sandbox_root=sandbox)
        assert "app.py" in result
        assert "db.py" in result

    def test_list_with_glob(self, sandbox):
        result = list_files("sub/*.py", sandbox_root=sandbox)
        assert "util.py" in result

    def test_no_matches(self, sandbox):
        result = list_files("*.java", sandbox_root=sandbox)
        assert "No files matching" in result


class TestSearchContent:
    def test_search_finds_match(self, sandbox):
        result = search_content("def hello", sandbox_root=sandbox)
        assert "app.py:1" in result

    def test_search_with_glob_filter(self, sandbox):
        result = search_content("import", sandbox_root=sandbox, glob="db.py")
        assert "db.py" in result
        assert "app.py" not in result

    def test_search_no_match(self, sandbox):
        result = search_content("nonexistent_pattern_xyz", sandbox_root=sandbox)
        assert "No matches" in result

    def test_invalid_regex(self, sandbox):
        result = search_content("[invalid", sandbox_root=sandbox)
        assert "Invalid regex" in result


class TestRunCommand:
    def test_allowed_py_compile(self, sandbox):
        result = run_command("py_compile", "app.py", sandbox_root=sandbox)
        # Valid Python file: py_compile succeeds silently → "(no output)" or empty
        # If python is not on PATH this returns "Error: command not found"
        import shutil

        if shutil.which("python"):
            assert result in ("(no output)", "") or "error" not in result.lower()
        else:
            pytest.skip("python not on PATH")

    def test_disallowed_check_rejected(self, sandbox):
        result = run_command("rm", "/", sandbox_root=sandbox)
        assert "not allowed" in result

    def test_disallowed_curl_rejected(self, sandbox):
        result = run_command("curl", "https://example.com", sandbox_root=sandbox)
        assert "not allowed" in result

    def test_disallowed_bash_rejected(self, sandbox):
        result = run_command("bash", "app.py", sandbox_root=sandbox)
        assert "not allowed" in result

    def test_path_traversal_rejected(self, sandbox):
        result = run_command("py_compile", "../../etc/passwd", sandbox_root=sandbox)
        assert "Error" in result

    def test_empty_check_rejected(self, sandbox):
        result = run_command("", "app.py", sandbox_root=sandbox)
        assert "Error" in result


class TestWebFetchSSRF:
    def test_http_scheme_rejected(self):
        """Non-HTTPS URLs must be rejected."""
        safe, reason = _is_safe_url("http://169.254.169.254/latest/meta-data/")
        assert not safe
        assert "Non-HTTPS" in reason

    def test_link_local_ip_rejected(self):
        """Link-local addresses (169.254.x.x) must be rejected even over HTTPS."""
        # Patch socket.getaddrinfo to simulate resolving to 169.254.169.254
        import socket

        fake_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0))
        ]
        with patch("pipeline.tools.socket.getaddrinfo", return_value=fake_addrinfo):
            safe, reason = _is_safe_url("https://metadata.internal/")
        assert not safe
        assert "169.254.169.254" in reason

    def test_private_ip_rejected(self):
        """RFC 1918 addresses must be rejected."""
        import socket

        fake_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.1.1", 0))
        ]
        with patch("pipeline.tools.socket.getaddrinfo", return_value=fake_addrinfo):
            safe, reason = _is_safe_url("https://internal.corp/")
        assert not safe
        assert "192.168.1.1" in reason

    def test_loopback_ip_rejected(self):
        """Loopback addresses must be rejected."""
        import socket

        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0))]
        with patch("pipeline.tools.socket.getaddrinfo", return_value=fake_addrinfo):
            safe, reason = _is_safe_url("https://localhost/")
        assert not safe
        assert "127.0.0.1" in reason

    def test_web_fetch_rejects_http(self):
        """web_fetch must return an error string for non-HTTPS URLs."""
        result = web_fetch("http://169.254.169.254/latest/meta-data/")
        assert "Error" in result
        assert "Non-HTTPS" in result

    def test_web_fetch_rejects_private_ip(self):
        """web_fetch must return an error string when hostname resolves to private IP."""
        import socket

        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0))]
        with patch("pipeline.tools.socket.getaddrinfo", return_value=fake_addrinfo):
            result = web_fetch("https://internal.example.com/page")
        assert "Error" in result
        assert "10.0.0.1" in result


class TestExecuteTool:
    def test_dispatch_read_file(self, sandbox):
        result = execute_tool("read_file", {"path": "app.py"}, sandbox_root=sandbox)
        assert "def hello" in result

    def test_dispatch_unknown_tool(self, sandbox):
        result = execute_tool("delete_everything", {}, sandbox_root=sandbox)
        assert "unknown tool" in result

    def test_dispatch_invalid_args(self, sandbox):
        result = execute_tool("read_file", {"wrong_arg": "x"}, sandbox_root=sandbox)
        assert "Error" in result
