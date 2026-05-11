from __future__ import annotations

import json
import os
from typing import Any


async def generate_llm_response(
    model: str,
    messages: list[dict[str, str]],
    temperature: float = 0,
) -> str:
    """LLM adapter.

    Supported educational modes:
    - model="mock" keeps everything local and predictable.
    - model="openai/gpt-5" uses the OpenAI Responses API.

    Important:
    The gateway still validates input before this function is called and
    validates output after this function returns.
    """

    if model == "mock":
        return await generate_mock_response(messages)

    if model.startswith("openai/"):
        return await generate_openai_response(
            model_name=model.replace("openai/", ""),
            messages=messages,
            temperature=temperature,
        )

    raise ValueError(
        "Unsupported model. Use 'mock' or an OpenAI model like 'openai/gpt-5'."
    )


async def generate_mock_response(messages: list[dict[str, str]]) -> str:
    user_messages = [m["content"] for m in messages if m["role"] == "user"]
    latest_user_message = user_messages[-1] if user_messages else ""
    all_user_text = "\n".join(user_messages).lower()

    # Scenario 1: force fallback by always returning invalid output
    if "always invalid" in all_user_text:
        return "This is not JSON and will keep failing."

    # Scenario 2: first attempt returns invalid JSON.
    # On retry, latest user message becomes correction prompt, so it recovers.
    if "return invalid json" in latest_user_message.lower():
        return "This is not valid JSON."

    # Scenario 3: first attempt returns valid JSON but violates citation policy.
    # On retry, latest user message becomes correction prompt, so it recovers.
    if "return missing citations" in latest_user_message.lower():
        return json.dumps({
            "answer": "This response is missing citations on purpose.",
            "citations": [],
            "confidence": "medium",
            "next_action": "This should trigger output validation."
        })

    return json.dumps({
        "answer": f"Mock response generated for: {latest_user_message[:120]}",
        "citations": ["internal-policy:default"],
        "confidence": "medium",
        "next_action": "Review the response and continue testing the guardrail workflow."
    })


async def generate_openai_response(
    model_name: str,
    messages: list[dict[str, str]],
    temperature: float = 0,
) -> str:
    """Call OpenAI Responses API.

    The output must be JSON because main.py already injects a schema-focused
    system/developer message before user messages are sent here.
    """

    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError(
            "OPENAI_API_KEY is not set. Run: export OPENAI_API_KEY='your_api_key_here'"
        )

    try:
        from openai import AsyncOpenAI
    except ImportError as exc:
        raise RuntimeError(
            "OpenAI SDK is not installed. Run: python3 -m pip install openai"
        ) from exc

    client = AsyncOpenAI()

    # Responses API uses role-based input messages.
    # Convert our gateway's system message into a developer message.
    openai_input = []
    for msg in messages:
        role = msg["role"]
        if role == "system":
            role = "developer"

        openai_input.append({
            "role": role,
            "content": msg["content"]
        })

    response = await client.responses.create(
        model=model_name,
        input=openai_input,
        temperature=temperature,
    )

    return response.output_text
