"""Backwards-compatibility shim.

The LLM client moved to :mod:`app.services.llm` and is now provider-neutral
(SentinelForge runs on open-source models via Groq by default). This module
re-exports the new names under the legacy ``qwen`` / ``QwenClient`` symbols so
older imports keep working. Prefer importing from ``app.services.llm``.
"""
from __future__ import annotations

from app.services.llm import LLMClient, TokenUsage, extract_json, llm

# Legacy aliases.
QwenClient = LLMClient
qwen = llm

__all__ = ["LLMClient", "QwenClient", "TokenUsage", "extract_json", "llm", "qwen"]
