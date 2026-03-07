"""PromptFuzz example — test an OpenAI GPT-4o endpoint.

Requires: pip install promptfuzz[openai]
Set environment variable: OPENAI_API_KEY=sk-...
"""

from __future__ import annotations

import os

from promptfuzz import Fuzzer

try:
    from openai import OpenAI
except ImportError as exc:
    raise SystemExit(
        "openai package not installed. Run: pip install promptfuzz[openai]"
    ) from exc


def chat(message: str) -> str:
    """Send a message to GPT-4o and return the reply text."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable is not set.")

    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": "You are a helpful customer support assistant.",
            },
            {"role": "user", "content": message},
        ],
        max_tokens=512,
    )
    return response.choices[0].message.content or ""


if __name__ == "__main__":
    fuzzer = Fuzzer(
        target=chat,
        context="OpenAI GPT-4o customer support assistant",
        categories=["jailbreak", "injection"],
        max_workers=3,
        timeout=45.0,
    )
    result = fuzzer.run()
    result.report()
    result.save("openai_report.html")
    result.to_json("openai_report.json")
