"""Stage 0 — Normalizer: parse a raw vulnerability blob into a Finding.

Uses forced tool_use to extract structured JSON from arbitrary input formats.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from pipeline.models import Finding
from pipeline.stages.base import MODEL, _call_api, get_client

logger = logging.getLogger(__name__)

NORMALIZER_PROMPT = """\
You are a vulnerability data normalizer. You receive a raw vulnerability \
report in an unknown format (could be JSON, SARIF, plain text, CSV, or \
anything else). Your job is to extract the key fields into a structured \
Finding object.

Extract these fields:
- file_path: the path to the affected source file
- line_number: the line number of the finding (integer)
- cwe_id: CWE identifier like "CWE-89" (null if not present)
- severity: one of CRITICAL, HIGH, MEDIUM, LOW (infer from context if needed)
- title: a short label for the vulnerability (e.g. "SQL Injection", "Hardcoded Secret")
- description: a longer description of the finding

If you cannot confidently extract file_path and line_number, set confidence \
to "low". Otherwise set confidence to "high".

Always preserve the original input verbatim in the raw_blob field.
"""

EXTRACT_TOOL = {
    "name": "extract_finding",
    "description": "Extract a normalized vulnerability finding from raw data.",
    "input_schema": {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Path to the affected source file",
            },
            "line_number": {
                "type": "integer",
                "description": "Line number of the finding",
            },
            "cwe_id": {
                "type": ["string", "null"],
                "description": "CWE identifier (e.g. CWE-89) or null",
            },
            "severity": {
                "type": "string",
                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                "description": "Severity level",
            },
            "title": {
                "type": "string",
                "description": "Short label for the vulnerability",
            },
            "description": {
                "type": "string",
                "description": "Longer description of the finding",
            },
            "confidence": {
                "type": "string",
                "enum": ["high", "low"],
                "description": "Confidence in extraction accuracy",
            },
        },
        "required": [
            "file_path",
            "line_number",
            "severity",
            "title",
            "description",
            "confidence",
        ],
    },
}


def normalize(raw_blob: str, *, output_dir: str = "pipeline-output") -> Finding:
    """Parse a raw vulnerability blob into a canonical Finding.

    Raises ValueError if extraction fails or confidence is low.
    """
    client = get_client()
    model = os.environ.get("CLAUDE_MODEL", MODEL)

    response = _call_api(
        client,
        model=model,
        system=NORMALIZER_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Extract the vulnerability finding from this data:\n\n{raw_blob}",
            }
        ],
        tools=[EXTRACT_TOOL],
        max_tokens=2048,
        extra_kwargs={"tool_choice": {"type": "tool", "name": "extract_finding"}},
    )

    # Log raw response
    os.makedirs(output_dir, exist_ok=True)
    Path(os.path.join(output_dir, "normalizer_raw.json")).write_text(
        json.dumps(
            {
                "id": response.id,
                "model": response.model,
                "content": [
                    {"type": b.type, **({"input": b.input} if b.type == "tool_use" else {})}
                    for b in response.content
                ],
            },
            indent=2,
            default=str,
        )
    )

    # Extract the tool_use block
    tool_block = next(
        (b for b in response.content if b.type == "tool_use"),
        None,
    )
    if tool_block is None:
        raise ValueError("Normalizer did not return a tool_use block")

    data = tool_block.input
    confidence = data.get("confidence", "low")
    if confidence == "low":
        raise ValueError(
            f"Normalizer has low confidence in extraction: {json.dumps(data, indent=2)}"
        )

    finding = Finding(
        file_path=data["file_path"],
        line_number=data["line_number"],
        cwe_id=data.get("cwe_id"),
        severity=data["severity"],
        title=data["title"],
        description=data["description"],
        raw_blob=raw_blob,
    )

    logger.info(
        "Normalized finding: %s in %s:%d (severity=%s)",
        finding.title,
        finding.file_path,
        finding.line_number,
        finding.severity,
    )
    return finding
