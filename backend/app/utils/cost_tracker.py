from __future__ import annotations

import logging

logger = logging.getLogger("sentinelforge.cost")


async def record_token_usage(
    incident_id: str | None,
    model: str,
    input_tokens: int,
    output_tokens: int,
    thinking_tokens: int = 0,
) -> None:
    """Persist token usage so the analytics endpoint can show cost per incident.

    Writes to the audit_log via the incidents repo (imported lazily to avoid
    a circular import at module load)."""
    try:
        from app.db.audit import write_audit

        await write_audit(
            incident_id=incident_id,
            actor=f"system:qwen:{model}",
            action="qwen.token_usage",
            details={
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "thinking_tokens": thinking_tokens,
                "total": input_tokens + output_tokens + thinking_tokens,
            },
        )
    except Exception as exc:  # never let cost tracking break a call
        logger.warning("token usage recording failed: %s", exc)


def estimate_tokens(text: str) -> int:
    """Rough token estimate when the API doesn't return usage."""
    return max(1, len(text) // 4)


__all__ = ["record_token_usage", "estimate_tokens"]
