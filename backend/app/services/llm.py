"""LLM client — a thin, provider-neutral wrapper over any OpenAI-compatible
chat completions endpoint (Groq, Together, Fireworks, vLLM, Ollama, DashScope…).

SentinelForge is tuned for **open-source models on Groq** (Llama 3.x). Compared
to frontier hosted models, OSS models need a client that is defensive about the
things they get wrong, so this wrapper adds:

- retry with exponential backoff + jitter (thundering-herd safe)
- per-call token accounting persisted to the audit log
- **robust JSON extraction** (code-fence stripping + brace-balancing) plus one
  automatic *repair* round-trip — OSS models frequently wrap or truncate JSON
- structured output that works on providers *without* strict ``json_schema``
  (Groq) by falling back to ``json_object`` mode + Pydantic validation
- provider-aware params: ``parallel_tool_calls`` / ``enable_thinking`` are only
  sent to DashScope, which is the only backend that accepts them (sending them
  to Groq returns HTTP 500)
- streaming that surfaces ``reasoning_content`` (reasoning models) separately
- a graceful mock fallback when no API key is set (zero-key demo runs)
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from app.config import settings

logger = logging.getLogger("sentinelforge.llm")


@dataclass
class TokenUsage:
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    thinking_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens + self.thinking_tokens


_client = None


def _get_client():
    global _client
    if _client is None:
        from openai import OpenAI

        _client = OpenAI(
            api_key=settings.llm_api_key or "missing",
            base_url=settings.llm_base_url,
            timeout=settings.llm_request_timeout_seconds,
        )
    return _client


def _retryable(exc: BaseException) -> bool:
    try:
        from openai import APIConnectionError, APITimeoutError, RateLimitError

        return isinstance(exc, (RateLimitError, APITimeoutError, APIConnectionError))
    except Exception:
        return False


async def _with_retry(fn, *args, **kwargs):
    max_attempts = 3
    base_delay = 1.0
    max_delay = 30.0
    attempt = 0
    while True:
        attempt += 1
        try:
            return await asyncio.to_thread(fn, *args, **kwargs)
        except Exception as exc:
            if not _retryable(exc) or attempt >= max_attempts:
                raise
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay = random.uniform(0, delay)
            logger.warning(
                "llm call attempt %d failed (%s); retrying in %.2fs", attempt, exc, delay
            )
            await asyncio.sleep(delay)


# --------------------------------------------------------------------------- #
# Robust JSON extraction — the single most important OSS-model hardening.
# Small/mid open models routinely wrap JSON in prose, ```json fences, or emit a
# trailing token that truncates the object. This recovers the object best-effort.
# --------------------------------------------------------------------------- #

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def extract_json(content: str) -> Any:
    """Best-effort parse of a JSON value out of a raw model response.

    Tries, in order: direct parse → fenced block → the first balanced
    ``{...}``/``[...]`` span. Raises ``json.JSONDecodeError`` if nothing parses.
    """
    if content is None:
        raise json.JSONDecodeError("empty content", "", 0)
    text = content.strip()
    # 1) straight parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # 2) fenced ```json ... ``` block
    m = _FENCE_RE.search(text)
    if m:
        try:
            return json.loads(m.group(1).strip())
        except json.JSONDecodeError:
            text = m.group(1).strip()
    # 3) first balanced object/array span
    span = _first_json_span(text)
    if span is not None:
        return json.loads(span)
    raise json.JSONDecodeError("no JSON value found", text[:200], 0)


def _first_json_span(text: str) -> str | None:
    """Return the first brace/bracket-balanced JSON span, honoring strings."""
    start = None
    opener = None
    closer = None
    for i, ch in enumerate(text):
        if ch in "{[":
            start, opener = i, ch
            closer = "}" if ch == "{" else "]"
            break
    if start is None:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _usage_from(resp, model: str) -> TokenUsage:
    try:
        u = resp.usage
        thinking = getattr(u, "reasoning_tokens", 0) or 0
        if not thinking:
            ctd = getattr(u, "completion_tokens_details", None)
            thinking = getattr(ctd, "reasoning_tokens", 0) or 0 if ctd else 0
        return TokenUsage(
            model=model,
            input_tokens=getattr(u, "prompt_tokens", 0) or getattr(u, "input_tokens", 0) or 0,
            output_tokens=getattr(u, "completion_tokens", 0) or getattr(u, "output_tokens", 0) or 0,
            thinking_tokens=thinking,
        )
    except Exception:
        return TokenUsage(model=model)


async def _record(incident_id: str | None, usage: TokenUsage) -> None:
    from app.services.metrics import record_llm_tokens

    for kind, count in (
        ("input", usage.input_tokens),
        ("output", usage.output_tokens),
        ("thinking", usage.thinking_tokens),
    ):
        if count:
            record_llm_tokens(usage.model, kind, count)
    try:
        from app.db.audit import write_audit

        await write_audit(
            incident_id=incident_id,
            actor=f"system:llm:{usage.model}",
            action="llm.api_call",
            details={"model": usage.model, "tokens": usage.total},
            qwen_model=usage.model,
            qwen_input_tokens=usage.input_tokens or None,
            qwen_output_tokens=usage.output_tokens or None,
            qwen_thinking_tokens=usage.thinking_tokens or None,
        )
    except Exception as exc:
        logger.debug("token record skipped: %s", exc)


class LLMClient:
    """Async wrapper over an OpenAI-compatible chat completions endpoint."""

    @property
    def enabled(self) -> bool:
        return settings.llm_enabled

    async def complete(
        self,
        *,
        model: str,
        messages: list[dict],
        incident_id: str | None = None,
        tools: list[dict] | None = None,
        parallel_tool_calls: bool = True,
        response_format: dict | None = None,
        enable_thinking: bool = False,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> dict[str, Any]:
        """Non-streaming completion. Returns dict with content, tool_calls, usage."""
        from app.services.metrics import record_llm_latency

        if not self.enabled:
            return await self._mock_complete(model, messages, enable_thinking)

        kwargs = self._build_kwargs(
            model=model,
            messages=messages,
            tools=tools,
            parallel_tool_calls=parallel_tool_calls,
            response_format=response_format,
            enable_thinking=enable_thinking,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        client = _get_client()
        t0 = time.monotonic()
        resp = await _with_retry(client.chat.completions.create, **kwargs)
        record_llm_latency(model, time.monotonic() - t0)
        usage = _usage_from(resp, model)
        await _record(incident_id, usage)
        msg = resp.choices[0].message
        return {
            "content": msg.content or "",
            "tool_calls": [tc.to_dict() for tc in (msg.tool_calls or [])],
            "reasoning": getattr(msg, "reasoning_content", None),
            "usage": usage.__dict__,
            "model": model,
        }

    def _build_kwargs(
        self,
        *,
        model: str,
        messages: list[dict],
        tools: list[dict] | None,
        parallel_tool_calls: bool,
        response_format: dict | None,
        enable_thinking: bool,
        temperature: float,
        max_tokens: int | None,
        stream: bool = False,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if tools:
            kwargs["tools"] = tools
            # Only DashScope (Qwen Cloud) accepts parallel_tool_calls; sending it
            # to Groq / NVIDIA NIM / most OSS endpoints returns HTTP 500.
            if settings.is_dashscope:
                kwargs["parallel_tool_calls"] = parallel_tool_calls
        if response_format:
            kwargs["response_format"] = response_format
        if max_tokens:
            kwargs["max_tokens"] = max_tokens
        if enable_thinking and settings.is_dashscope:
            kwargs["extra_body"] = {"enable_thinking": True}
        if stream:
            kwargs["stream"] = True
            kwargs["stream_options"] = {"include_usage": True}
        return kwargs

    async def stream(
        self,
        *,
        model: str,
        messages: list[dict],
        incident_id: str | None = None,
        tools: list[dict] | None = None,
        parallel_tool_calls: bool = True,
        enable_thinking: bool = False,
        temperature: float = 0.2,
    ) -> AsyncIterator[dict[str, Any]]:
        """Streaming completion. Yields chunk dicts:
        {"kind": "thinking"|"content", "content": "..."} or
        {"kind": "tool_call", "tool_call": {...}}.
        """
        if not self.enabled:
            async for chunk in self._mock_stream(model, messages, enable_thinking):
                yield chunk
            return

        kwargs = self._build_kwargs(
            model=model,
            messages=messages,
            tools=tools,
            parallel_tool_calls=parallel_tool_calls,
            response_format=None,
            enable_thinking=enable_thinking,
            temperature=temperature,
            max_tokens=None,
            stream=True,
        )
        client = _get_client()
        usage = TokenUsage(model=model)
        stream = await asyncio.to_thread(client.chat.completions.create, **kwargs)

        # Bridge the SDK's sync iterator onto the event loop without blocking it.
        queue: asyncio.Queue = asyncio.Queue()
        SENTINEL = object()

        async def _producer():
            def _push_all():
                try:
                    for chunk in stream:
                        queue.put_nowait(chunk)
                except Exception as exc:
                    queue.put_nowait(exc)
                finally:
                    queue.put_nowait(SENTINEL)

            await asyncio.to_thread(_push_all)

        task = asyncio.create_task(_producer())
        try:
            while True:
                item = await queue.get()
                if item is SENTINEL:
                    break
                if isinstance(item, Exception):
                    raise item
                chunk = item
                if getattr(chunk, "usage", None):
                    u = chunk.usage
                    usage.input_tokens = getattr(u, "prompt_tokens", 0) or usage.input_tokens
                    usage.output_tokens = getattr(u, "completion_tokens", 0) or usage.output_tokens
                    continue
                try:
                    delta = chunk.choices[0].delta
                except (IndexError, AttributeError):
                    continue
                reasoning = getattr(delta, "reasoning_content", None)
                if reasoning:
                    yield {"kind": "thinking", "content": reasoning}
                if getattr(delta, "content", None):
                    yield {"kind": "content", "content": delta.content}
                if getattr(delta, "tool_calls", None):
                    for tc in delta.tool_calls:
                        yield {"kind": "tool_call", "tool_call": tc.to_dict()}
        finally:
            await task
            await _record(incident_id, usage)

    async def structured(
        self,
        *,
        model: str,
        messages: list[dict],
        schema_model: type,
        incident_id: str | None = None,
        temperature: float = 0.1,
    ):
        """Strict structured output with an OSS-friendly fallback chain.

        1. Try native strict ``json_schema`` (DashScope). If the provider rejects
           it (Groq), fall back to ``json_object`` mode with the schema in-prompt.
        2. Extract JSON robustly from whatever comes back.
        3. Validate with Pydantic. On failure, do ONE *repair* round-trip that
           feeds the validation error back to the model — this recovers the vast
           majority of OSS malformed-output cases without a human in the loop.
        """
        if not self.enabled:
            return self._mock_structured(schema_model, messages)

        schema = schema_model.model_json_schema()
        schema_name = schema_model.__name__

        content = await self._structured_raw(
            model=model,
            messages=messages,
            schema=schema,
            schema_name=schema_name,
            incident_id=incident_id,
            temperature=temperature,
        )
        try:
            return schema_model.model_validate(extract_json(content))
        except Exception as first_err:
            logger.info("structured(%s) invalid; attempting one repair pass", schema_name)
            repair_msgs = list(messages) + [
                {"role": "assistant", "content": content[:2000]},
                {
                    "role": "user",
                    "content": (
                        "That response did not match the required schema "
                        f"({type(first_err).__name__}: {str(first_err)[:300]}). "
                        "Reply with ONLY the corrected JSON object — no prose, no code fences."
                    ),
                },
            ]
            content2 = await self._structured_raw(
                model=model,
                messages=repair_msgs,
                schema=schema,
                schema_name=schema_name,
                incident_id=incident_id,
                temperature=0.0,
            )
            return schema_model.model_validate(extract_json(content2))

    async def _structured_raw(
        self,
        *,
        model: str,
        messages: list[dict],
        schema: dict,
        schema_name: str,
        incident_id: str | None,
        temperature: float,
    ) -> str:
        # DashScope supports strict json_schema; try it first.
        if settings.is_dashscope:
            try:
                resp = await self.complete(
                    model=model,
                    messages=messages,
                    incident_id=incident_id,
                    temperature=temperature,
                    response_format={
                        "type": "json_schema",
                        "json_schema": {"name": schema_name, "schema": schema, "strict": True},
                    },
                )
                return resp["content"]
            except Exception:
                pass
        # OSS path: json_object mode + schema hint in a trailing system message.
        schema_hint = json.dumps({"name": schema_name, "schema": schema}, indent=1)
        fallback_msgs = list(messages) + [
            {
                "role": "system",
                "content": (
                    "Respond ONLY with a single valid JSON object matching this schema. "
                    "Do NOT include any text, explanation, or code fences outside the JSON.\n\n"
                    f"{schema_hint}"
                ),
            },
        ]
        resp = await self.complete(
            model=model,
            messages=fallback_msgs,
            incident_id=incident_id,
            temperature=temperature,
            response_format={"type": "json_object"},
        )
        return resp["content"]

    # ----- mock fallback (zero-key demo) -----

    async def _mock_complete(
        self, model: str, messages: list[dict], thinking: bool
    ) -> dict[str, Any]:
        await asyncio.sleep(0.15)
        last = messages[-1]["content"] if messages else ""
        reasoning = (
            "Analyzing the security finding. Assessing whether this is a true positive. "
            "The affected asset is production-facing, so blast radius could be high. "
            "Checking entity overlap and severity signals to justify the verdict."
            if thinking
            else None
        )
        content = json.dumps(
            {"note": "mock-response", "echo": last[:200], "model": model}, indent=2
        )
        return {
            "content": content,
            "tool_calls": [],
            "reasoning": reasoning,
            "usage": {
                "model": model,
                "input_tokens": len(last) // 4,
                "output_tokens": 40,
                "thinking_tokens": 80 if thinking else 0,
            },
            "model": model,
        }

    async def _mock_stream(self, model: str, messages: list[dict], thinking: bool):
        if thinking:
            for w in ["Let", "me", "analyze", "this", "finding", "carefully."] + [
                "The",
                "signal",
                "is",
                "elevated;",
            ]:
                await asyncio.sleep(0.03)
                yield {"kind": "thinking", "content": w + " "}
        for w in ("Mock", "streaming", "response", "from", model):
            await asyncio.sleep(0.05)
            yield {"kind": "content", "content": w + " "}

    def _mock_structured(self, schema_model: type, messages: list[dict]):
        try:
            return schema_model.model_construct()
        except Exception:
            return schema_model()


# Canonical singleton.
llm = LLMClient()
