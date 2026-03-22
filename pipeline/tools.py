"""Custom tool implementations for the Claude API.

Each tool is a Python function that the orchestrator executes when the model
requests it via tool_use. All filesystem tools are sandboxed to a root directory.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup
from duckduckgo_search import DDGS

# Maximum bytes returned by read_file / web_fetch
MAX_READ_BYTES = 256_000
MAX_FETCH_BYTES = 512_000
FETCH_TIMEOUT = 15

# Allowlisted checks for run_command (Stage 5 only).
# Each entry maps a check name to a callable that builds the full argv list.
ALLOWED_COMMANDS: dict[str, callable] = {
    "py_compile": lambda path: ["python", "-m", "py_compile", path],
    "flake8": lambda path: ["flake8", path, "--max-line-length=120"],
    "pylint": lambda path: ["pylint", path, "--errors-only"],
}


# ---------------------------------------------------------------------------
# Path sandboxing
# ---------------------------------------------------------------------------


def _resolve_sandboxed(path: str, sandbox_root: str) -> str:
    """Resolve *path* relative to *sandbox_root* and reject traversal."""
    resolved = os.path.realpath(os.path.join(sandbox_root, path))
    root = os.path.realpath(sandbox_root)
    if not resolved.startswith(root + os.sep) and resolved != root:
        raise PermissionError(f"Path escapes sandbox: {path}")
    return resolved


# ---------------------------------------------------------------------------
# URL safety check (SSRF prevention)
# ---------------------------------------------------------------------------


def _is_safe_url(url: str) -> tuple[bool, str]:
    """Return (True, "") if *url* is safe to fetch, else (False, reason).

    Rejects:
    - Non-HTTPS schemes
    - Hostnames that resolve to RFC 1918, link-local, or loopback addresses

    Note: DNS rebinding (public IP at check-time, private IP at connect-time)
    is a known residual risk. Full mitigation requires a custom httpx transport
    that validates the peer IP at connect time. This check is defense-in-depth.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False, f"Non-HTTPS scheme rejected: {parsed.scheme!r}"

    hostname = parsed.hostname
    if not hostname:
        return False, "Could not parse hostname from URL"

    try:
        addrinfos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        return False, f"Could not resolve hostname {hostname!r}: {e}"

    for _family, _type, _proto, _canonname, sockaddr in addrinfos:
        addr_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(addr_str)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return (
                False,
                f"Hostname {hostname!r} resolves to blocked address: {addr_str}",
            )

    return True, ""


# ---------------------------------------------------------------------------
# Filesystem tools
# ---------------------------------------------------------------------------


def read_file(path: str, *, sandbox_root: str) -> str:
    """Read a file inside the sandbox. Returns the file content as a string."""
    resolved = _resolve_sandboxed(path, sandbox_root)
    try:
        content = Path(resolved).read_text(errors="replace")
    except FileNotFoundError:
        return f"Error: file not found: {path}"
    except IsADirectoryError:
        return f"Error: {path} is a directory, not a file"
    if len(content) > MAX_READ_BYTES:
        content = (
            content[:MAX_READ_BYTES] + f"\n... (truncated at {MAX_READ_BYTES} bytes)"
        )
    return content


def write_file(path: str, content: str, *, sandbox_root: str) -> str:
    """Write content to a file inside the sandbox. Creates parent dirs if needed."""
    if len(content.encode()) > MAX_READ_BYTES:
        return f"Error: content too large (max {MAX_READ_BYTES} bytes)"
    resolved = _resolve_sandboxed(path, sandbox_root)
    os.makedirs(os.path.dirname(resolved), exist_ok=True)
    Path(resolved).write_text(content)
    return f"OK: wrote {path}"


def list_files(pattern: str, *, sandbox_root: str) -> str:
    """Glob for files inside the sandbox. Returns newline-separated paths."""
    root = os.path.realpath(sandbox_root)
    matches: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            # Skip files whose realpath escapes the sandbox (e.g. symlinks)
            if not os.path.realpath(full).startswith(root + os.sep):
                continue
            rel = os.path.relpath(full, root)
            if fnmatch.fnmatch(rel, pattern):
                matches.append(rel)
    matches.sort()
    if not matches:
        return f"No files matching pattern: {pattern}"
    return "\n".join(matches[:500])


def search_content(
    pattern: str,
    *,
    sandbox_root: str,
    glob: str | None = None,
) -> str:
    """Search file contents in the sandbox. Returns matching lines with context."""
    root = os.path.realpath(sandbox_root)
    try:
        regex = re.compile(pattern)
    except re.error as e:
        return f"Invalid regex: {e}"

    results: list[str] = []
    limit = 200  # max result lines
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            # Skip files whose realpath escapes the sandbox (e.g. symlinks)
            if not os.path.realpath(full).startswith(root + os.sep):
                continue
            rel = os.path.relpath(full, root)
            if glob and not fnmatch.fnmatch(rel, glob):
                continue
            # skip binary files
            try:
                with open(full, errors="replace") as f:
                    for lineno, line in enumerate(f, 1):
                        if regex.search(line):
                            results.append(f"{rel}:{lineno}: {line.rstrip()}")
                            if len(results) >= limit:
                                results.append(f"... (truncated at {limit} matches)")
                                return "\n".join(results)
            except (OSError, UnicodeDecodeError):
                continue
    if not results:
        return f"No matches for pattern: {pattern}"
    return "\n".join(results)


# ---------------------------------------------------------------------------
# Web tools (Stage 1 only)
# ---------------------------------------------------------------------------


def web_search(query: str) -> str:
    """Search the web using DuckDuckGo. Returns a summary of results."""
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=8))
    except Exception as e:
        return f"Search error: {e}"
    if not results:
        return "No results found."
    lines: list[str] = []
    for r in results:
        lines.append(f"**{r.get('title', '')}**")
        lines.append(r.get("href", ""))
        lines.append(r.get("body", ""))
        lines.append("")
    return "\n".join(lines)


def web_fetch(url: str) -> str:
    """Fetch a URL and return its text content (HTML stripped)."""
    safe, reason = _is_safe_url(url)
    if not safe:
        return f"Error: {reason}"

    try:
        resp = httpx.get(
            url,
            timeout=FETCH_TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": "auto-security-patch/0.1"},
        )
        resp.raise_for_status()
    except httpx.HTTPError as e:
        return f"Fetch error: {e}"

    content_type = resp.headers.get("content-type", "")
    body = resp.text[:MAX_FETCH_BYTES]

    if "html" in content_type:
        soup = BeautifulSoup(body, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        text = soup.get_text(separator="\n", strip=True)
        if len(text) > MAX_FETCH_BYTES:
            text = text[:MAX_FETCH_BYTES] + "\n... (truncated)"
        return text
    return body


# ---------------------------------------------------------------------------
# Command execution (Stage 5 only)
# ---------------------------------------------------------------------------


def run_command(check: str, path: str, *, sandbox_root: str) -> str:
    """Run an allowlisted check on a sandboxed file.

    Args:
        check: One of 'py_compile', 'flake8', 'pylint'.
        path: Path to the file to check, relative to the sandbox root.
    """
    if check not in ALLOWED_COMMANDS:
        return (
            f"Error: check '{check}' is not allowed. "
            f"Allowed: {', '.join(ALLOWED_COMMANDS)}"
        )

    try:
        resolved = _resolve_sandboxed(path, sandbox_root)
    except PermissionError as e:
        return f"Error: {e}"

    cmd = ALLOWED_COMMANDS[check](resolved)

    try:
        result = subprocess.run(
            cmd,
            cwd=sandbox_root,
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr
        if result.returncode != 0:
            output += f"\n(exit code: {result.returncode})"
        return output.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return "Error: command timed out after 60 seconds"
    except FileNotFoundError:
        return f"Error: command not found: {cmd[0]}"


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

# Maps tool name → callable. The orchestrator passes sandbox_root as a kwarg.
TOOL_REGISTRY: dict[str, callable] = {
    "read_file": read_file,
    "write_file": write_file,
    "list_files": list_files,
    "search_content": search_content,
    "web_search": web_search,
    "web_fetch": web_fetch,
    "run_command": run_command,
}


def execute_tool(name: str, arguments: dict, *, sandbox_root: str) -> str:
    """Execute a tool by name with the given arguments.

    Injects sandbox_root for tools that require it.
    """
    fn = TOOL_REGISTRY.get(name)
    if fn is None:
        return f"Error: unknown tool '{name}'"

    # Inject sandbox_root for tools that accept it
    needs_sandbox = name in (
        "read_file",
        "write_file",
        "list_files",
        "search_content",
        "run_command",
    )
    if needs_sandbox:
        arguments = {**arguments, "sandbox_root": sandbox_root}

    try:
        return fn(**arguments)
    except TypeError as e:
        return f"Error: invalid arguments for tool '{name}': {e}"
    except PermissionError as e:
        return f"Error: {e}"
