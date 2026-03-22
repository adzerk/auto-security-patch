# auto-security-patch

An AI-powered pipeline that takes a raw security vulnerability report — in any format — and automatically produces a GitHub pull request with a fix, or an issue with a suppression/investigation recommendation. All output requires human review before merging.

## How it works

A vulnerability blob (Bandit JSON, SARIF, plain text, or anything else) is passed to a 7-stage Claude agent pipeline. Each stage has a narrowly scoped set of tools and produces structured output for the next stage. The orchestrator handles all git/GitHub operations — agents never write files or call APIs directly.

```mermaid
flowchart TD
    Input([VULNERABILITY_DATA\nany format]) --> S0

    S0["Stage 0 — Normalizer\nExtracts canonical Finding\nfile · line · CWE · severity"]
    S1["Stage 1 — Researcher\nFetches CWE page, OWASP docs,\nreal-world CVEs"]
    S2["Stage 2 — Assessor\nReads actual code, checks auth\nmiddleware, call paths"]
    S2b["Stage 2b — Assessment Verifier\nReads every cited file:line ref\nand checks code matches claims"]

    S0 --> S1 --> S2 --> S2b

    S2b -->|SUPPRESS| S6
    S2b -->|NEEDS_INVESTIGATION| S6
    S2b -->|CONTRADICTED → override| S6
    S2b -->|PATCH| S3

    subgraph fix ["Fix loop (max 2 attempts)"]
        S3["Stage 3 — Explorer\nDiscovers related files,\nexisting safe patterns"] --> S4
        S4["Stage 4 — Fix Writer\nOutputs unified diff\n(read-only tools)"] --> Apply
        Apply["Orchestrator\ngit apply patch"] --> S5
        S5["Stage 5 — Validator\nRuns py_compile + flake8\nChecks struct integrity"]
        S5 -->|FAIL| S4
    end

    S3 -.-> fix
    fix --> S6

    S6["Stage 6 — PR Author\nLLM writes body text\nOrchestrator calls GitHub API"]

    S6 -->|PATCH| PR([Pull Request])
    S6 -->|SUPPRESS| Issue1([Issue: suppress])
    S6 -->|NEEDS_INVESTIGATION| Issue2([Issue: investigate])
    S6 -->|Pipeline failed| Issue3([Issue: failure report])
```

## Security model

The pipeline is designed for minimal blast radius:

- **Tool restrictions**: each stage's Claude API call only receives the tool schemas it needs — the model cannot call a tool outside its allowlist (enforced at the API level)
- **Sandboxed filesystem access**: all file reads/writes operate on a temp-dir clone of the target repo; path traversal is rejected by resolving against the sandbox root
- **No shell=True anywhere**: subprocess calls use list args throughout
- **SSRF protection**: `web_fetch` validates URLs against RFC 1918/link-local/loopback ranges before connecting
- **Token redaction**: GitHub tokens are stripped from error messages before logging
- **Human oversight always**: output is PRs and issues — nothing is auto-merged

## Usage

### GitHub Actions (recommended)

Trigger manually from the **Actions** tab, or call from another workflow:

```yaml
# In another workflow:
jobs:
  patch:
    uses: adzerk/auto-security-patch/.github/workflows/security-patch.yml@main
    with:
      vulnerability_data: ${{ toJson(steps.scan.outputs.finding) }}
      target_repo: adzerk/my-service
      dry_run: false
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      REPO_WRITE_TOKEN: ${{ secrets.REPO_WRITE_TOKEN }}
```

**Required secrets:**

| Secret | Scopes needed |
|--------|--------------|
| `ANTHROPIC_API_KEY` | Claude API |
| `REPO_WRITE_TOKEN` | `contents:write`, `pull-requests:write`, `issues:write` on the target repo |

### Local dry run

```bash
pyenv local 3.14.2
poetry env use $(pyenv which python)
poetry install --with dev

export ANTHROPIC_API_KEY=...
export GITHUB_TOKEN=...          # needs write access to target repo
export TARGET_REPO=org/repo
export DRY_RUN=true
export VULNERABILITY_DATA='{"test_id":"B608","filename":"app.py","line_number":42,...}'

poetry run python -m pipeline.run_pipeline
# Outputs to pipeline-output/ — no PRs or issues created
```

## Input format

`VULNERABILITY_DATA` accepts any format. The normalizer (Stage 0) uses Claude to extract the key fields. Supported out of the box:

- **Bandit JSON** — single finding object from `bandit -f json`
- **SARIF** — GitHub Advanced Security, Semgrep, CodeQL output
- **Plain text** — any human-readable vulnerability description

The pipeline fails fast with a clear error if it cannot extract `file_path` and `line_number` with high confidence.

## Output

| Verdict | GitHub output |
|---------|--------------|
| `PATCH` | Pull request with diff, research summary, exploitability reasoning, reviewer checklist |
| `SUPPRESS` | Issue with exact suppression comment to add and justification |
| `NEEDS_INVESTIGATION` | Issue with specific open questions for a human reviewer |
| Pipeline failure | Issue with available context and failure details |

All output is logged to a `pipeline-logs` artifact on the Actions run regardless of outcome.
