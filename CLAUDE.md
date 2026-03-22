# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install (includes linting tools needed by Stage 5)
pip install -e ".[dev]"
pip install flake8 pylint

# Run all tests
python -m pytest tests/

# Run a single test
python -m pytest tests/test_tools.py::TestRunCommand::test_disallowed_bash_rejected -v

# Run pipeline locally (dry run)
DRY_RUN=true ANTHROPIC_API_KEY=... GITHUB_TOKEN=... VULNERABILITY_DATA='...' TARGET_REPO=org/repo python -m pipeline.run_pipeline
```

## Architecture

The pipeline is a 7-stage agentic loop triggered by GitHub Actions (`workflow_dispatch` or `workflow_call`). Each stage is a Claude API call with a scoped set of tools; the orchestrator (`pipeline/run_pipeline.py`) sequences them, handles the retry loop, and performs mechanical operations (git, GitHub API) that agents must not do themselves.

### Stage flow

```
VULNERABILITY_DATA (env var, any format)
  │
  ▼
Stage 0 — Normalizer          pipeline/normalizer.py
  │  forced tool_use → Finding dataclass
  ▼
Stage 1 — Researcher          pipeline/stages/researcher.py
  │  web_search + web_fetch → research report
  ▼
Stage 2 — Assessor            pipeline/stages/assessor.py
  │  read_file + search → PATCH / SUPPRESS / NEEDS_INVESTIGATION
  │
  ├─ if PATCH ──────────────────────────────────────────────────┐
  │                                                              │
  │  Stage 3 — Explorer        pipeline/stages/explorer.py      │
  │  Stage 4 — Fix Writer      pipeline/stages/fix_writer.py    │
  │    └─ orchestrator: git apply patch                         │
  │  Stage 5 — Validator       pipeline/stages/validator.py     │
  │    └─ FAIL → retry Stage 4 (max 2 attempts)                │
  │                                                              │
  └──────────────────────────────────────────────────────────────┘
  ▼
Stage 6 — PR Author           pipeline/pr_author.py
  LLM writes body text, orchestrator calls GitHubClient
  PATCH → PR | SUPPRESS/NEEDS_INVESTIGATION/FAILED → issue
```

### Key design constraints

**Tool restrictions** (`pipeline/agent_config.py`): Each stage's Claude API call only receives the tool schemas it needs. The model cannot call a tool outside its allowlist — this is enforced at the API level, not the prompt level. The `STAGE_TOOLS` dict maps stage name → allowed tool names.

**Custom tools** (`pipeline/tools.py`): All tools are Python functions we implement and dispatch ourselves. `run_command` takes `(check, path)` — not a freeform shell string — and only runs `py_compile`, `flake8`, or `pylint`. `read_file`/`list_files`/`search_content` validate paths against the sandbox root via `_resolve_sandboxed`. `web_fetch` has SSRF protection via `_is_safe_url`.

**Sandbox** (`pipeline/sandbox.py`): `RepoSandbox` clones the target repo into a `tempfile.mkdtemp()` dir and is used as a context manager. The orchestrator applies patches via `git apply` between Stage 4 and 5 — agents never write files directly.

**Output parsing**: Stages 1–5 use the POC's proven delimiter format (`VULNERABILITY_RESEARCH_COMPLETE ... VULNERABILITY_RESEARCH_END`, etc.) rather than JSON. Stage 0 uses forced `tool_use` for structured output since it's a single-turn call.

**Stage 6 split**: `pipeline/pr_author.py` has an LLM call (body generation, `agents/pr_author.md` prompt) plus pure-Python decision logic (`build_title`, `build_labels`, `build_branch_name`). The `GitHubClient` (`pipeline/github_client.py`) only does the API calls.

### Agent prompts

`agents/*.md` — loaded at runtime by `pipeline/stages/base.py:load_prompt()`. The path resolution goes up 3 levels from `pipeline/stages/base.py` to the repo root, then into `agents/`. If running from an installed wheel rather than source, ensure `agents/` is on the Python path or copy it alongside the package.

### Secrets required

| Secret | Purpose |
|--------|---------|
| `ANTHROPIC_API_KEY` | Claude API calls |
| `GH_PAT` | Push branches + create PRs/issues on target repo (needs `contents:write`, `pull-requests:write`, `issues:write`) |
