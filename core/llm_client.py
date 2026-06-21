"""
core/llm_client.py
==================
Unified async LLM client — routes to Ollama or Google Gemini API based on
the LLM_PROVIDER environment variable (controlled by `settings.llm_provider`).

Provider selection (set in .env):
    LLM_PROVIDER=ollama   → calls Ollama /api/chat (local, Metal GPU)
    LLM_PROVIDER=gemini   → calls Google Gemini REST API (cloud)

Gemini rate limiting:
    Free tier: tier1 (gemini-2.5-flash) = 10 RPM, tier2 (gemini-2.5-flash-lite) = 30 RPM.
    A shared token bucket serialises all concurrent calls and spaces them to fit the quota.
    The Lock is lazily initialised on first use to avoid event-loop binding issues in Python 3.9.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Literal

import httpx

from core.config import settings

logger = logging.getLogger(__name__)

_GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


# ---------------------------------------------------------------------------
# Token bucket — lazy Lock init (safe in Python 3.9)
# ---------------------------------------------------------------------------

class _TokenBucket:
    """
    Async token bucket. All callers queue through a shared lock and are
    dispatched one-per-interval, staying within the RPM quota.

    The asyncio.Lock is created on first use (not at import time) so it
    binds to the running event loop correctly on Python 3.9.
    """
    def __init__(self, rpm: int):
        self._interval = 60.0 / rpm
        self._next_allowed: float = 0.0        # monotonic clock — 0 means "fire immediately"
        self._lock: asyncio.Lock | None = None  # lazy init

    async def acquire(self) -> None:
        # Lazy-init the Lock inside the running event loop
        if self._lock is None:
            self._lock = asyncio.Lock()

        async with self._lock:
            now = time.monotonic()
            if self._next_allowed <= now:
                # Slot is free — take it, schedule next slot from now
                self._next_allowed = now + self._interval
                return          # fire immediately, no sleep needed
            else:
                # Queue this request: reserve the next available slot
                wait = self._next_allowed - now
                self._next_allowed += self._interval

        # Sleep OUTSIDE the lock so other callers can queue their slots
        logger.debug("llm_client | Gemini rate-limit tier slot in %.1fs", wait)
        await asyncio.sleep(wait)


# Rate limiting — controlled by GEMINI_RPM env var.
# Set to 0 (or unset) to disable (recommended for billing tier 1: 1000 RPM).
# Set to a positive integer to cap requests/min (e.g. 8 for free tier).
_GEMINI_RPM = int(os.getenv("GEMINI_RPM", "0"))
_BUCKET_GEMINI: _TokenBucket | None = _TokenBucket(rpm=_GEMINI_RPM) if _GEMINI_RPM > 0 else None


async def _gemini_bucket_acquire() -> None:
    if _BUCKET_GEMINI is not None:
        await _BUCKET_GEMINI.acquire()


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

async def llm_chat(
    tier: Literal["tier1", "tier2"],
    messages: list[dict],
    json_mode: bool = False,
    max_tokens: int = 1024,
    temperature: float | None = None,
    timeout: int | None = None,
    ollama_options: dict | None = None,
) -> str:
    """
    Call the active LLM provider and return the response text.

    Args:
        tier:           "tier1" (high-accuracy) or "tier2" (fast).
        messages:       [{"role": "system"|"user"|"assistant", "content": str}].
                        System messages are extracted for Gemini's systemInstruction field.
        json_mode:      Request JSON output. Ollama: format=json (tier2 only). Gemini: responseMimeType.
        max_tokens:     Maximum output tokens.
        temperature:    Sampling temperature. None = provider default.
        timeout:        Request timeout override (seconds).
        ollama_options: Ollama-specific options dict (num_ctx, num_gpu…). Ignored for Gemini.
    """
    if settings.llm_provider == "gemini":
        return await _call_gemini(tier, messages, json_mode, max_tokens, temperature, timeout)
    else:
        return await _call_ollama(tier, messages, json_mode, max_tokens, temperature, timeout, ollama_options)


# ---------------------------------------------------------------------------
# Ollama backend
# ---------------------------------------------------------------------------

async def _call_ollama(
    tier: str,
    messages: list[dict],
    json_mode: bool,
    max_tokens: int,
    temperature: float | None,
    timeout: int | None,
    extra_options: dict | None,
) -> str:
    model = settings.ollama.tier1_model if tier == "tier1" else settings.ollama.tier2_model
    if timeout is None:
        timeout = settings.ollama.request_timeout

    options: dict = {"num_predict": max_tokens}
    if temperature is not None:
        options["temperature"] = temperature
    if extra_options:
        options.update(extra_options)

    payload: dict = {
        "model":    model,
        "messages": messages,
        "stream":   False,
        "options":  options,
    }
    # format=json only for tier2 — qwen2.5-coder hangs with it enabled
    if json_mode and tier == "tier2":
        payload["format"] = "json"

    logger.debug("llm_chat | provider=ollama tier=%s model=%s", tier, model)

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(f"{settings.ollama.base_url}/api/chat", json=payload)
        response.raise_for_status()

    return response.json()["message"]["content"]


# ---------------------------------------------------------------------------
# Gemini REST API backend  (rate-limited via token bucket)
# ---------------------------------------------------------------------------

async def _call_gemini(
    tier: str,
    messages: list[dict],
    json_mode: bool,
    max_tokens: int,
    temperature: float | None,
    timeout: int | None,
) -> str:
    """
    Call Google Gemini generateContent REST API.

    All concurrent callers acquire a slot from the per-tier token bucket before
    sending — they are automatically serialised and spaced to stay within the
    RPM quota. No 429s.
    """
    model = settings.gemini.tier1_model if tier == "tier1" else settings.gemini.tier2_model
    if timeout is None:
        timeout = settings.gemini.request_timeout

    # Build request body
    system_parts: list[str] = []
    contents: list[dict] = []
    for msg in messages:
        if msg["role"] == "system":
            system_parts.append(msg["content"])
        elif msg["role"] == "assistant":
            contents.append({"role": "model", "parts": [{"text": msg["content"]}]})
        else:
            contents.append({"role": "user",  "parts": [{"text": msg["content"]}]})

    if not contents:
        raise ValueError("llm_chat: at least one non-system message required")

    body: dict = {"contents": contents, "generationConfig": {"maxOutputTokens": max_tokens}}
    if system_parts:
        body["systemInstruction"] = {"parts": [{"text": "\n\n".join(system_parts)}]}
    if temperature is not None:
        body["generationConfig"]["temperature"] = temperature
    if json_mode:
        body["generationConfig"]["responseMimeType"] = "application/json"

    url = _GEMINI_URL.format(model=model)
    max_retries = 6
    backoff = 5  # seconds — base for exponential backoff on transient errors

    for attempt in range(max_retries):
        # Wait for a rate-limit slot (no-op when GEMINI_RPM=0)
        await _gemini_bucket_acquire()

        logger.debug("llm_chat | tier=%s attempt=%d", tier, attempt + 1)

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    url,
                    params={"key": settings.gemini.api_key},
                    json=body,
                )
        except httpx.RequestError as exc:
            wait = backoff * (2 ** attempt)
            logger.warning("llm_chat | tier=%s attempt=%d/%d — request error, retrying in %ds", tier, attempt + 1, max_retries, wait)
            await asyncio.sleep(wait)
            continue

        if response.status_code in (429, 503):
            wait = backoff * (2 ** attempt)   # 5, 10, 20, 40, 80, 160s
            logger.warning(
                "llm_chat | tier=%s attempt=%d/%d — service unavailable (status=%d), retrying in %ds",
                tier, attempt + 1, max_retries, response.status_code, wait,
            )
            await asyncio.sleep(wait)
            continue

        if not response.is_success:
            # Log status code only — no URL, no model, no key
            logger.error("llm_chat | tier=%s attempt=%d/%d — unexpected status=%d", tier, attempt + 1, max_retries, response.status_code)
            response.raise_for_status()

        data = response.json()
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError) as exc:
            raise ValueError(f"LLM response structure unexpected: {list(data.keys())}") from exc

    raise RuntimeError(f"LLM call failed after {max_retries} attempts (tier={tier})")
