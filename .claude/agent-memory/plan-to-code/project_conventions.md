---
name: auto-security-patch project conventions
description: Code conventions, architecture, and patterns for the auto-security-patch pipeline project
type: project
---

## Architecture

Multi-stage AI pipeline for automated security vulnerability remediation. Stages:
- Stage 0: Normalizer (`pipeline/normalizer.py`) — parses raw vuln blobs into `Finding` objects
- Stage 1–6: Researcher, Assessor, Explorer, Fix Writer, Validator, PR Author (all in `pipeline/stages/`)
- Base runner: `pipeline/stages/base.py` — shared API call loop and tool dispatch
- Tools: `pipeline/tools.py` — sandboxed filesystem/web/command tools
- GitHub integration: `pipeline/github_client.py`, `pipeline/sandbox.py`
- Data models: `pipeline/models.py`
- Agent prompts: `agents/*.md`

## Key Patterns

- All tool functions accept `sandbox_root` as a keyword-only arg; injected by `execute_tool()`
- Anthropic client is a module-level singleton via `get_client()` in `pipeline/stages/base.py`
- `pipeline/normalizer.py` imports `get_client` from `pipeline.stages.base` (not `anthropic` directly)
- `Finding.severity` is `Severity` enum (str subclass) with `__post_init__` coercion from str
- `PipelineContext` has no `stage_logs` field (removed in security fixes)
- `run_command` tool uses `{check: str, path: str}` interface (not freeform `command: str`)
- Allowed checks: `py_compile`, `flake8`, `pylint` — defined in `ALLOWED_COMMANDS` dict

## Test Conventions

- Tests in `tests/` directory, plain pytest (no asyncio)
- Normalizer tests patch `pipeline.stages.base.get_client` (not `pipeline.normalizer.anthropic.Anthropic`)
- Sandbox fixture at `tmp_path` used in tool tests
- Dataclass defaults tested via direct instantiation

## Security Constraints Applied

- `web_fetch` validates URLs via `_is_safe_url()` (HTTPS only, blocks RFC 1918/loopback/link-local)
- `run_command` uses allowlist of built command arrays, path validated via `_resolve_sandboxed`
- `list_files`/`search_content` use `followlinks=False` and skip realpath-escaping files
- `RepoSandbox._run()` catches `CalledProcessError` and redacts token before re-raising as `RuntimeError`
- Branch names sanitized with `re.sub(r'[^a-zA-Z0-9._-]', '-', ...)`, max 200 chars

**Why:** Security audit of the pipeline identified injection/SSRF/token-leak vulnerabilities in March 2026.
**How to apply:** Any future tool additions should follow the same sandbox/allowlist/SSRF patterns.
