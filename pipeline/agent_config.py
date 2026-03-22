"""Per-stage tool restrictions and JSON schema definitions for the Claude API.

Each stage's Claude API call includes ONLY the tool definitions listed here.
The model physically cannot request a tool not in its list.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Tool JSON schemas (Anthropic API format)
# ---------------------------------------------------------------------------

TOOL_SCHEMAS: dict[str, dict] = {
    "read_file": {
        "name": "read_file",
        "description": "Read a file from the repository. Path is relative to repo root.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the file (e.g. 'app.py' or 'src/db.py')",
                },
            },
            "required": ["path"],
        },
    },
    "list_files": {
        "name": "list_files",
        "description": "List files matching a glob pattern in the repository.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern (e.g. '*.py', 'src/**/*.py', 'test_*.py')",
                },
            },
            "required": ["pattern"],
        },
    },
    "search_content": {
        "name": "search_content",
        "description": "Search file contents using a regex pattern. Returns matching lines with file paths and line numbers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for",
                },
                "glob": {
                    "type": "string",
                    "description": "Optional glob to filter which files to search (e.g. '*.py')",
                },
            },
            "required": ["pattern"],
        },
    },
    "web_search": {
        "name": "web_search",
        "description": "Search the web for information. Returns titles, URLs, and snippets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query",
                },
            },
            "required": ["query"],
        },
    },
    "web_fetch": {
        "name": "web_fetch",
        "description": "Fetch a web page and return its text content (HTML tags stripped).",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to fetch",
                },
            },
            "required": ["url"],
        },
    },
    "run_command": {
        "name": "run_command",
        "description": (
            "Run an allowlisted check on a file in the repository. "
            "Allowed checks: py_compile (Python syntax), flake8 (style/errors), pylint (errors only). "
            "Use for syntax checking and linting only."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "check": {
                    "type": "string",
                    "enum": ["py_compile", "flake8", "pylint"],
                    "description": "Check to run: 'py_compile', 'flake8', or 'pylint'",
                },
                "path": {
                    "type": "string",
                    "description": "Relative path to the file to check (e.g. 'app.py' or 'src/db.py')",
                },
            },
            "required": ["check", "path"],
        },
    },
    "write_file": {
        "name": "write_file",
        "description": "Write content to a file in the repository. Overwrites the file if it exists. Path is relative to repo root.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the file to write (e.g. 'app.py' or 'src/db.py')",
                },
                "content": {
                    "type": "string",
                    "description": "The full content to write to the file",
                },
            },
            "required": ["path", "content"],
        },
    },
}

# ---------------------------------------------------------------------------
# Per-stage tool allow-lists
# ---------------------------------------------------------------------------

STAGE_TOOLS: dict[str, list[str]] = {
    "normalizer": [],
    "vulnerability_researcher": ["web_search", "web_fetch"],
    "exploitability_assessor": ["read_file", "list_files", "search_content"],
    "assessment_verifier": ["read_file", "search_content"],
    "codebase_explorer": ["read_file", "list_files", "search_content"],
    "fix_writer": ["read_file", "write_file"],
    "fix_validator": ["read_file", "run_command"],
    "pr_author": [],  # no tools — LLM writes body text only
}

# Per-stage model overrides. Stages not listed use the default MODEL from base.py.
STAGE_MODELS: dict[str, str] = {
    "exploitability_assessor": "claude-opus-4-6",
}


def get_tools_for_stage(stage_name: str) -> list[dict]:
    """Return the list of tool schema dicts for a given pipeline stage."""
    tool_names = STAGE_TOOLS.get(stage_name, [])
    return [TOOL_SCHEMAS[name] for name in tool_names]


def get_model_for_stage(stage_name: str) -> str | None:
    """Return a model override for the given stage, or None to use the default."""
    return STAGE_MODELS.get(stage_name)
