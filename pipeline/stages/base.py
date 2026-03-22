"""Base stage runner: loads prompt, calls Claude API, handles tool loop, logs."""

from __future__ import annotations

import json
import logging
import os
import random
import time
from pathlib import Path

import anthropic

from pipeline.agent_config import get_tools_for_stage
from pipeline.tools import execute_tool

logger = logging.getLogger(__name__)

MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-20250514")
MAX_TOKENS = 16_384
MAX_TOOL_ROUNDS = 30  # safety cap on agentic loops
API_RETRY_DELAY = 5  # seconds before retrying on transient errors

AGENTS_DIR = Path(__file__).resolve().parent.parent.parent / "agents"

# Module-level Anthropic client singleton
_client: anthropic.Anthropic | None = None


def get_client() -> anthropic.Anthropic:
    """Return the module-level Anthropic client, initializing it on first call."""
    global _client
    if _client is None:
        _client = anthropic.Anthropic()
    return _client


def load_prompt(agent_name: str) -> str:
    """Load an agent prompt markdown file from the agents/ directory."""
    path = AGENTS_DIR / f"{agent_name}.md"
    if not path.exists():
        raise FileNotFoundError(f"Agent prompt not found: {path}")
    return path.read_text()


def run_stage(
    stage_name: str,
    user_message: str,
    *,
    sandbox_root: str = "",
    output_dir: str = "pipeline-output",
    model: str | None = None,
) -> str:
    """Run a single pipeline stage.

    1. Loads the agent prompt from agents/<stage_name>.md
    2. Calls the Claude API with the stage's allowed tools
    3. Handles the tool-use loop (model requests tool → we execute → feed result back)
    4. Returns the model's final text output
    5. Logs everything to pipeline-output/

    Args:
        stage_name: Name matching both the agent .md file and the STAGE_TOOLS key.
        user_message: The rendered prompt with context from previous stages.
        sandbox_root: Path to the cloned repo (for filesystem tools).
        output_dir: Directory to write stage logs.
        model: Override the Claude model to use.

    Returns:
        The model's final text response (all text blocks concatenated).
    """
    client = get_client()
    system_prompt = load_prompt(stage_name)
    tools = get_tools_for_stage(stage_name)
    used_model = model or MODEL

    messages = [{"role": "user", "content": user_message}]
    all_text: list[str] = []
    all_raw: list[dict] = []

    for round_num in range(MAX_TOOL_ROUNDS):
        logger.info("Stage %s — API call round %d", stage_name, round_num + 1)

        response = _call_api(
            client,
            model=used_model,
            system=system_prompt,
            messages=messages,
            tools=tools,
        )
        all_raw.append(
            {"round": round_num + 1, "response": _serialize_response(response)}
        )

        # Collect text blocks
        text_parts = [block.text for block in response.content if block.type == "text"]
        all_text.extend(text_parts)

        # Check for tool use
        tool_blocks = [block for block in response.content if block.type == "tool_use"]

        if response.stop_reason == "end_turn" or not tool_blocks:
            break

        # Execute tools and build tool_result messages
        tool_results = []
        for tool_block in tool_blocks:
            logger.info(
                "Stage %s — tool call: %s(%s)",
                stage_name,
                tool_block.name,
                json.dumps(tool_block.input, default=str)[:200],
            )
            result = execute_tool(
                tool_block.name,
                tool_block.input,
                sandbox_root=sandbox_root,
            )
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tool_block.id,
                    "content": result,
                }
            )

        # Continue the conversation
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

    # Write logs
    _write_log(output_dir, stage_name, "\n".join(all_text), all_raw)

    return "\n".join(all_text)


def _call_api(
    client: anthropic.Anthropic,
    *,
    model: str,
    system: str,
    messages: list[dict],
    tools: list[dict],
    max_tokens: int = MAX_TOKENS,
    extra_kwargs: dict | None = None,
) -> anthropic.types.Message:
    """Call the Claude API with one retry on transient errors."""
    kwargs = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": messages,
    }
    if tools:
        kwargs["tools"] = tools
    if extra_kwargs:
        kwargs.update(extra_kwargs)

    for attempt in range(2):
        try:
            return client.messages.create(**kwargs)
        except anthropic.BadRequestError as e:
            raise RuntimeError(
                f"API rejected the request (context overflow or malformed input): {e}"
            ) from e
        except anthropic.APIStatusError as e:
            if e.status_code in (429, 529):
                if attempt == 0:
                    logger.warning("API overloaded/rate-limited (will retry): %s", e)
                    time.sleep(API_RETRY_DELAY + random.uniform(0, 3))
                else:
                    raise
            else:
                raise
        except (anthropic.RateLimitError, anthropic.APIConnectionError) as e:
            if attempt == 0:
                logger.warning("API error (will retry): %s", e)
                time.sleep(API_RETRY_DELAY + random.uniform(0, 3))
            else:
                raise


def _serialize_response(response: anthropic.types.Message) -> dict:
    """Serialize an API response to a JSON-safe dict for logging."""
    return {
        "id": response.id,
        "model": response.model,
        "stop_reason": response.stop_reason,
        "usage": {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
        },
        "content": [_serialize_block(b) for b in response.content],
    }


def _serialize_block(block) -> dict:
    if block.type == "text":
        return {"type": "text", "text": block.text}
    if block.type == "tool_use":
        return {
            "type": "tool_use",
            "id": block.id,
            "name": block.name,
            "input": block.input,
        }
    return {"type": block.type}


def _write_log(
    output_dir: str,
    stage_name: str,
    text_output: str,
    raw_rounds: list[dict],
) -> None:
    """Write stage output and raw API logs to the output directory."""
    os.makedirs(output_dir, exist_ok=True)

    # Human-readable output
    text_path = os.path.join(output_dir, f"{stage_name}.txt")
    Path(text_path).write_text(text_output)

    # Full API log (JSON)
    raw_path = os.path.join(output_dir, f"{stage_name}_raw.json")
    Path(raw_path).write_text(json.dumps(raw_rounds, indent=2, default=str))

    logger.info("Stage %s logs written to %s", stage_name, output_dir)
