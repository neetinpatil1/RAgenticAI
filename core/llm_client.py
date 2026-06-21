"""
core/llm_client.py
==================
Unified LLM client. Routes calls to Ollama, Claude (Anthropic), or Gemini
based on the LLM_PROVIDER env var.

Switch providers without touching any workflow code:
  LLM_PROVIDER=ollama   → local Ollama REST API (default, no API key)
  LLM_PROVIDER=claude   → Anthropic API via anthropic SDK
  LLM_PROVIDER=gemini   → Google Generative AI via google-generativeai SDK

Tier mapping:
  Tier 1 (complex):  Ollama=qwen2.5-coder:14b  Claude=claude-sonnet-4-6       Gemini=gemini-2.5-pro
  Tier 2 (fast):     Ollama=llama3.2:3b         Claude=claude-haiku-4-5-*      Gemini=gemini-2.0-flash
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


async def call_llm(
    system_prompt: str,
    user_prompt: str,
    use_tier1: bool = True,
    timeout: Optional[int] = None,
    json_mode: bool = False,
    max_tokens: int = 1024,
    temperature: float = 0.1,
) -> str:
    """
    Call the configured LLM provider and return the text response.

    Args:
        system_prompt: System/role instructions for the model.
        user_prompt:   The user turn content.
        use_tier1:     True = high-capability model; False = fast/cheap model.
        timeout:       Request timeout in seconds (Ollama only; ignored for cloud).
        json_mode:     Request JSON-formatted output where the provider supports it.
        max_tokens:    Maximum output tokens.
        temperature:   Sampling temperature.
    """
    from core.config import settings
    provider = settings.llm.provider.lower()
    if provider == "claude":
        return await _call_claude(system_prompt, user_prompt, use_tier1, max_tokens, temperature)
    elif provider == "gemini":
        return await _call_gemini(system_prompt, user_prompt, use_tier1, json_mode, max_tokens, temperature)
    else:
        return await _call_ollama(system_prompt, user_prompt, use_tier1, timeout, json_mode, max_tokens, temperature)


async def _call_ollama(
    system_prompt: str,
    user_prompt: str,
    use_tier1: bool,
    timeout: Optional[int],
    json_mode: bool,
    max_tokens: int,
    temperature: float,
) -> str:
    import httpx
    from core.config import settings

    if timeout is None:
        timeout = settings.ollama.request_timeout
    model = settings.ollama.tier1_model if use_tier1 else settings.ollama.tier2_model

    payload: dict = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens,
            "num_ctx":     4096,
            "num_gpu":     99,
            "num_thread":  8,
        },
    }
    # json format: safe for small models; qwen2.5-coder:14b hangs on strict JSON mode
    if json_mode and not use_tier1:
        payload["format"] = "json"

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(f"{settings.ollama.base_url}/api/chat", json=payload)
        r.raise_for_status()
        return r.json()["message"]["content"]


async def _call_claude(
    system_prompt: str,
    user_prompt: str,
    use_tier1: bool,
    max_tokens: int,
    temperature: float,
) -> str:
    import anthropic
    from core.config import settings

    model = settings.llm.claude_tier1 if use_tier1 else settings.llm.claude_tier2
    client = anthropic.AsyncAnthropic(api_key=settings.llm.anthropic_api_key)
    msg = await client.messages.create(
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        system=system_prompt or "You are a security analysis assistant.",
        messages=[{"role": "user", "content": user_prompt}],
    )
    return msg.content[0].text


async def _call_gemini(
    system_prompt: str,
    user_prompt: str,
    use_tier1: bool,
    json_mode: bool,
    max_tokens: int,
    temperature: float,
) -> str:
    from google import genai
    from google.genai import types
    from core.config import settings

    model_name = settings.llm.gemini_tier1 if use_tier1 else settings.llm.gemini_tier2

    # ADC (Application Default Credentials): no API key, use gcloud credentials.
    # Run: gcloud auth application-default login
    if settings.llm.google_api_key:
        client = genai.Client(api_key=settings.llm.google_api_key)
    elif settings.llm.google_cloud_project:
        client = genai.Client(
            vertexai=True,
            project=settings.llm.google_cloud_project,
            location=settings.llm.google_cloud_location,
        )
    else:
        # ADC without Vertex AI — credentials picked up from gcloud default login
        import google.auth
        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/generative-language"]
        )
        client = genai.Client(credentials=credentials)

    contents = []
    if system_prompt:
        contents.append(types.Content(role="user", parts=[types.Part(text=system_prompt)]))
        contents.append(types.Content(role="model", parts=[types.Part(text="Understood.")]))
    contents.append(types.Content(role="user", parts=[types.Part(text=user_prompt)]))

    config = types.GenerateContentConfig(
        max_output_tokens=max_tokens,
        temperature=temperature,
        response_mime_type="application/json" if json_mode else "text/plain",
    )
    response = await client.aio.models.generate_content(
        model=model_name,
        contents=contents,
        config=config,
    )
    return response.text
