# Plan: Production-Ready Alpha — Auto Security Patch Pipeline (GitHub Actions)

## Context

The POC (`ai-code-security-resolver-poc/`) demonstrated a working 6-stage agent pipeline that resolves code security vulnerabilities via Claude agents, producing GitHub PRs/issues. The POC was orchestrated via shell scripts calling `claude` CLI subprocesses with agent markdown prompts. This plan produces a **production-ready alpha** in `auto-security-patch/`, replacing the shell orchestration with a **Python pipeline triggered by GitHub Actions** (`workflow_dispatch` + `workflow_call`).

Key constraints:
- No Datadog Security API access yet → input is a flexible, opaque blob (any format)
- Sandboxing is critical — the pipeline clones and patches foreign repos
- Human oversight always — output is PRs/issues, never auto-merge
- Locally-runnable for development; GitHub-hosted for production

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  GitHub Actions (workflow_dispatch / workflow_call)          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Docker container (python:3.12-slim + git + gh)       │  │
│  │                                                       │  │
│  │  run_pipeline.py (orchestrator)                       │  │
│  │    │                                                  │  │
│  │    ├─ Stage 0: Normalizer  (text in/out, no tools)    │  │
│  │    ├─ Stage 1: Researcher  (tools: web_search, fetch) │  │
│  │    ├─ Stage 2: Assessor    (tools: read, glob, grep)  │  │
│  │    │   └─ verdict: PATCH / SUPPRESS / NEEDS_INVEST.   │  │
│  │    │                                                  │  │
│  │    │  ┌─ if PATCH ────────────────────────────────┐   │  │
│  │    ├──│ Stage 3: Explorer  (tools: read, glob, grep)│  │  │
│  │    │  │ Stage 4: Fix Writer (tools: read)           │  │  │
│  │    │  │   └─ orchestrator: git apply patch          │  │  │
│  │    │  │ Stage 5: Validator  (tools: read, bash*)     │  │  │
│  │    │  │   └─ FAIL? → retry Stage 4 (max 2 attempts) │  │  │
│  │    │  └─────────────────────────────────────────────┘│  │  │
│  │    │                                                  │  │
│  │    └─ Stage 6: PR/Issue Author (LLM body + git ops)   │  │
│  │         PATCH → PR  |  SUPPRESS → issue               │  │
│  │         NEEDS_INVESTIGATION → issue                    │  │
│  │         PIPELINE_FAILED → issue                        │  │
│  │                                                       │  │
│  │  Sandbox: target repo cloned to tmpdir, cleaned up    │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Trigger
- `workflow_dispatch`: manual trigger with UI inputs including dry_run checkbox
- `workflow_call`: callable from other workflows with identical inputs + explicit secrets

Inputs:
- `vulnerability_data` (required, string): raw blob — any format
- `target_repo` (required, string): `org/repo` to patch
- `dry_run` (optional, boolean, default false): log output without creating PRs/issues

### Stage 0 — Normalizer (new)
A single Claude API call (no tools) that takes the raw `vulnerability_data` blob and extracts a canonical `Finding`. Uses the API's tool_use feature to force structured JSON output into the Finding schema. If the model returns low confidence or cannot extract required fields, the pipeline fails fast with a clear error.

```python
class Finding(BaseModel):
    file_path: str
    line_number: int
    cwe_id: str | None      # e.g. "CWE-89"
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW
    title: str               # short label
    description: str         # longer context
    raw_blob: str            # original input preserved for downstream agents
```

### Stages 1–6 — Agent Pipeline

Each stage is a Python function that:
1. Loads its agent prompt from `agents/<name>.md`
2. Renders context from previous stages into the prompt
3. Calls the Claude API with **only its allowed tools** (enforced by `agent_config.py`)
4. Parses the response (delimited text blocks, same format as POC)
5. Returns a typed result dataclass
6. Writes full reasoning + raw response to `pipeline-output/stage_N.log`

| Stage | Agent | Tools (custom implementations) | Output |
|-------|-------|-------------------------------|--------|
| 0 | Normalizer | _(none — forced tool_use for structured output)_ | `Finding` |
| 1 | Researcher | `web_search`, `web_fetch` | Research report (text) |
| 2 | Assessor | `read_file`, `list_files`, `search_content` | Verdict + reasoning |
| 3 | Explorer | `read_file`, `list_files`, `search_content` | Fix pattern recommendation |
| 4 | Fix Writer | `read_file` | Unified diff patch |
| 5 | Validator | `read_file`, `run_command` (restricted) | PASS / FAIL + errors |
| 6 | PR Author | _(no tools — LLM writes body, orchestrator does git/GitHub)_ | PR/Issue body + URL |

**Flow control:**
- If verdict ≠ PATCH → skip Stages 3–5, go to Stage 6 (issue creation)
- Stage 4→5 retry loop: max 2 attempts. On validation FAIL, errors fed back to Stage 4 prompt
- If pipeline fails at any stage → Stage 6 creates a failure issue

### Custom Tool Implementations (`pipeline/tools.py`)

The Anthropic SDK requires us to define tools as JSON schemas and handle tool calls ourselves. Each tool is a Python function the orchestrator executes when the model requests it:

| Tool Name | Schema | Implementation |
|-----------|--------|----------------|
| `web_search` | `{query: str}` | Calls a search API (or `duckduckgo-search` library) |
| `web_fetch` | `{url: str}` | `httpx.get()` with timeout, size limit, HTML→text |
| `read_file` | `{path: str}` | Read from sandbox tmpdir; path validated to stay within sandbox |
| `list_files` | `{pattern: str}` | `glob.glob()` within sandbox tmpdir |
| `search_content` | `{pattern: str, glob: str?}` | `grep -rn` equivalent within sandbox tmpdir |
| `run_command` | `{command: str}` | **Stage 5 only.** Allowlisted commands: `python -m py_compile`, `flake8`, `pylint`. Rejects anything else. Runs in sandbox tmpdir via `subprocess.run(args_list)` (no shell=True) |

**Path sandboxing**: `read_file`, `list_files`, `search_content` all resolve paths relative to the sandbox tmpdir and reject traversal (e.g., `../../etc/passwd`).

### Stage 6: PR/Issue Author (LLM for body, orchestrator for git)

Stage 6 is a hybrid — the LLM writes the PR/issue body (synthesizing all prior stage outputs into a coherent, reviewer-friendly narrative) while the orchestrator handles the mechanical git/GitHub operations.

**LLM call (no tools):** receives all stage outputs and produces a well-written PR or issue body with:
- Vulnerability summary (from Stage 1 research)
- Exploitability reasoning (from Stage 2)
- What the fix does and why (from Stages 3–4)
- Diff in collapsible `<details>` block
- Caveats, confidence level, things for the reviewer to verify

**Orchestrator decision tree (after LLM generates body):**
| Condition | Action | Title Pattern |
|-----------|--------|---------------|
| verdict=PATCH, fix valid | Create branch, commit, push, open PR | `[Auto-Fix] {title} in {file}` |
| verdict=SUPPRESS | Open issue | `[Security] Suppress {title} in {file} — not exploitable` |
| verdict=NEEDS_INVESTIGATION | Open issue | `[Security] {title} in {file} — investigation required` |
| pipeline failed | Open issue | `[Security] Pipeline failed for {title} in {file}` |
| dry_run=true | Log body + metadata to artifact | _(no GitHub API calls)_ |

---

## File Structure

```
auto-security-patch/
├── .github/
│   └── workflows/
│       └── security-patch.yml       # workflow_dispatch + workflow_call
├── Dockerfile                       # python:3.12-slim + git + gh CLI
├── pipeline/
│   ├── __init__.py
│   ├── models.py                    # Finding, StageResult, Verdict enum, PipelineContext
│   ├── agent_config.py             # STAGE_TOOLS dict — per-stage tool allow-lists
│   ├── tools.py                    # Custom tool implementations (read_file, web_search, etc.)
│   ├── normalizer.py               # Stage 0: parse raw blob → Finding (forced tool_use)
│   ├── stages/
│   │   ├── __init__.py
│   │   ├── base.py                 # Base stage runner: load prompt, call API, handle tools, log
│   │   ├── researcher.py           # Stage 1
│   │   ├── assessor.py             # Stage 2
│   │   ├── explorer.py             # Stage 3
│   │   ├── fix_writer.py           # Stage 4
│   │   └── validator.py            # Stage 5
│   ├── sandbox.py                  # Context manager: clone repo to tmpdir, cleanup
│   ├── github_client.py            # create_branch, commit, push, create_pr, create_issue
│   ├── pr_author.py                # Stage 6: LLM writes body, orchestrator does git/GitHub
│   └── run_pipeline.py             # CLI entrypoint: orchestrator logic, retry loop, logging
├── agents/                         # Agent prompt templates (ported from POC)
│   ├── normalizer.md
│   ├── vulnerability_researcher.md
│   ├── exploitability_assessor.md
│   ├── codebase_explorer.md
│   ├── fix_writer.md
│   ├── fix_validator.md
│   └── pr_author.md
├── tests/
│   ├── fixtures/                   # Sample blobs: Bandit JSON, SARIF, freeform text
│   ├── test_normalizer.py
│   ├── test_models.py
│   ├── test_tools.py               # Tool sandboxing tests (path traversal, allowlist)
│   └── test_pipeline_integration.py
├── pyproject.toml                  # deps: anthropic, pydantic, pygithub, gitpython, httpx, duckduckgo-search
├── PLAN.md
└── README.md
```

Note: `pr_author.md` is an agent prompt for the LLM to write PR/issue bodies; the orchestrator handles git/GitHub operations mechanically.

---

## Sandboxing Design

Five layers of isolation:

### Layer 1 — Docker Container
- Custom `Dockerfile` based on `python:3.12-slim`, adding `git` and `gh` CLI
- Ephemeral: destroyed after the job, no persistent state
- GitHub Actions `container:` directive — filesystem isolated from runner host

### Layer 2 — Repo Operations in Temp Dir (`sandbox.py`)
- `RepoSandbox` context manager: clones target repo to `tempfile.mkdtemp()`, yields path, cleans up on `__exit__`
- All tool implementations receive the sandbox path and resolve relative to it
- Path traversal protection: `os.path.realpath()` checked against sandbox root
- No `shell=True` anywhere — all subprocess calls use list args

### Layer 3 — Least-Privilege GitHub Token
- Action's `GITHUB_TOKEN` has `contents: read` only (checkout this repo)
- Target repo operations use `GH_PAT` secret scoped to `contents: write` + `pull-requests: write` + `issues: write`

### Layer 4 — Per-Agent Tool Restrictions (`agent_config.py`)
Each stage's Claude API call includes **only** the tool definitions for that stage. The model physically cannot request a tool not in its list.

```python
STAGE_TOOLS: dict[str, list[str]] = {
    "normalizer": [],                                    # text only
    "researcher": ["web_search", "web_fetch"],
    "assessor": ["read_file", "list_files", "search_content"],
    "explorer": ["read_file", "list_files", "search_content"],
    "fix_writer": ["read_file"],
    "validator": ["read_file", "run_command"],           # run_command allowlisted
}
```

### Layer 5 — Command Allowlist (Stage 5 only)
`run_command` tool validates the command against an allowlist before execution:
```python
ALLOWED_COMMANDS = ["python", "flake8", "pylint"]
```
Rejects any command not starting with an allowed prefix. No shell=True. Runs in sandbox tmpdir.

---

## GitHub Actions Workflow (`security-patch.yml`)

```yaml
on:
  workflow_dispatch:
    inputs:
      vulnerability_data:
        description: 'Raw vulnerability blob (any format)'
        required: true
        type: string
      target_repo:
        description: 'Target repo to patch (org/repo)'
        required: true
        type: string
      dry_run:
        description: 'Dry run — log output without creating PRs/issues'
        required: false
        type: boolean
        default: false

  workflow_call:
    inputs:
      vulnerability_data:
        required: true
        type: string
      target_repo:
        required: true
        type: string
      dry_run:
        required: false
        type: boolean
        default: false
    secrets:
      ANTHROPIC_API_KEY:
        required: true
      GH_PAT:
        required: true

jobs:
  patch:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    container:
      image: ghcr.io/${{ github.repository }}/pipeline:latest  # or build inline
    steps:
      - uses: actions/checkout@v4
      - run: pip install -e .
      - name: Run pipeline
        run: python -m pipeline.run_pipeline
        env:
          VULNERABILITY_DATA: ${{ inputs.vulnerability_data }}
          TARGET_REPO: ${{ inputs.target_repo }}
          DRY_RUN: ${{ inputs.dry_run }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GH_PAT }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: pipeline-logs
          path: pipeline-output/
```

---

## Orchestrator Logic (`run_pipeline.py`)

```
1. Read env vars: VULNERABILITY_DATA, TARGET_REPO, DRY_RUN, ANTHROPIC_API_KEY, GITHUB_TOKEN
2. Stage 0: Normalize → Finding
3. Clone target repo into sandbox
4. Stage 1: Research (in sandbox context for web tools)
5. Stage 2: Assess → verdict
6. If verdict == PATCH:
   a. Stage 3: Explore codebase
   b. attempt = 0
   c. while attempt < 2:
      - Stage 4: Write fix → unified diff
      - Orchestrator: git apply diff in sandbox
      - If apply fails: capture error, increment attempt, continue
      - Stage 5: Validate applied fix
      - If PASS: break
      - If FAIL: capture errors, increment attempt, continue
   d. If all attempts failed: set pipeline_failed = True
7. Stage 6:
   a. LLM call (no tools) → generates PR/issue body from all stage outputs
   b. Orchestrator decision tree:
      - PATCH + valid fix → create branch, commit, push, open PR with LLM body
      - SUPPRESS → open issue with LLM body (suppression reasoning)
      - NEEDS_INVESTIGATION → open issue with LLM body (open questions)
      - pipeline_failed → open issue with failure details
      - dry_run → write body + metadata to pipeline-output/ only
8. Cleanup sandbox
```

**Error handling:**
- Each stage wrapped in try/except. On Claude API failure (rate limit, timeout): retry once with exponential backoff, then fail the stage
- Stage failure → set `pipeline_failed = True`, skip remaining stages, proceed to Stage 6
- All stage outputs (success or failure) written to `pipeline-output/`

---

## Output Parsing Strategy

Keep the POC's proven approach: **delimited text blocks with key:value headers**.

Each agent prompt instructs the model to output its result between markers (e.g., `VULNERABILITY_RESEARCH_COMPLETE` / `VULNERABILITY_RESEARCH_END`). The orchestrator extracts:
- Verdict: `grep -m1 "^VERDICT:" | split`
- Patch: text between `PATCH:` and `PATCH_END` markers
- Validation: `grep -m1 "^VALIDATION:" | split`

This is simpler and more reliable than trying to force full JSON from multi-turn tool-using conversations. The POC proved it works.

Exception: Stage 0 (Normalizer) uses forced `tool_use` for structured JSON output since it's a single-turn, no-tool call where we need a clean Pydantic model.

---

## Agent Prompts (Port from POC)

Port the 6 agent `.md` files from `ai-code-security-resolver-poc/agents/` with these changes:
- Replace `$VARIABLE` shell interpolation with Python `{variable}` template placeholders
- Keep the same delimited output format (proven to work)
- Add `normalizer.md` for Stage 0
- Keep `pr_author.md` — LLM writes the PR/issue body (no tools, text synthesis only)
- Add explicit notes about which tools are available in each prompt

---

## Critical Files (ordered by implementation dependency)

1. **`pipeline/models.py`** — Finding, Verdict enum, StageResult, PipelineContext
2. **`pipeline/tools.py`** — Custom tool implementations with path sandboxing
3. **`pipeline/agent_config.py`** — STAGE_TOOLS dict, tool JSON schema definitions
4. **`pipeline/sandbox.py`** — RepoSandbox context manager (clone, cleanup)
5. **`pipeline/stages/base.py`** — Base stage runner (load prompt, call API, handle tool loop, log)
6. **`pipeline/normalizer.py`** — Stage 0 (forced tool_use structured output)
7. **`pipeline/stages/researcher.py`** — Stage 1
8. **`pipeline/stages/assessor.py`** — Stage 2
9. **`pipeline/stages/explorer.py`** — Stage 3
10. **`pipeline/stages/fix_writer.py`** — Stage 4
11. **`pipeline/stages/validator.py`** — Stage 5
12. **`pipeline/github_client.py`** — Git/GitHub operations (branch, commit, push, PR, issue)
13. **`pipeline/pr_author.py`** — Stage 6: LLM call for body text + orchestrator decision tree for git/GitHub
14. **`pipeline/run_pipeline.py`** — Orchestrator: wires stages, retry loop, error handling
15. **`agents/*.md`** — Ported + adapted prompt templates
16. **`.github/workflows/security-patch.yml`** — Dual-trigger workflow
17. **`Dockerfile`** — python:3.12-slim + git + gh
18. **`pyproject.toml`** — Dependencies
19. **`tests/`** — Normalizer tests, tool sandboxing tests, integration test

---

## Verification

1. **Unit tests**: `pytest tests/test_normalizer.py` — fixtures for Bandit JSON, SARIF, freeform text
2. **Tool sandboxing tests**: `pytest tests/test_tools.py` — path traversal rejected, command allowlist enforced
3. **Dry-run local**: `DRY_RUN=true VULNERABILITY_DATA='...' TARGET_REPO=org/repo python -m pipeline.run_pipeline` — verify all stages complete, output written to `pipeline-output/`
4. **Dry-run in Actions**: Trigger `workflow_dispatch` with Bandit JSON fixture, `dry_run=true` — verify artifact uploaded
5. **Live run**: Trigger against `vulnerable-app` repo with known SQL injection finding — verify PR created with correct diff
