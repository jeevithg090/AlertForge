"""Model router — picks the cheapest capable model tier for each task.

SentinelForge runs on **open-source models** (Llama 3.x on Groq by default), so
routing is about matching the task to one of two tiers rather than burning the
biggest model on everything:

    * smart — 70B-class. Judgment, tool selection, structured planning, synthesis.
    * fast  — 8B-class.  Cheap classification, normalization, status checks.

Small OSS models are excellent at the second group and unreliable at the first
(multi-tool loops, schema-faithful JSON, nuanced severity calls), so we spend
the 70B budget only where it changes the outcome. An optional dedicated
*reasoning* model (e.g. deepseek-r1-distill on Groq) is used for the hardest
triage calls when configured.
"""

from __future__ import annotations

from app.config import settings
from app.schemas.incident import Severity

# Tasks that never need 70B-class judgment — keep them on the fast tier.
_FAST_TASKS = frozenset({"execution", "status_check", "normalization", "semantic_check", "dedup"})
_CRITICAL = frozenset({Severity.P1_CRITICAL.value, Severity.P2_HIGH.value})


def _sev(severity: str | Severity) -> str:
    return severity.value if isinstance(severity, Severity) else str(severity)


def select_model(severity: str | Severity, task: str) -> str:
    """Return a concrete model id for ``task`` at the given incident ``severity``."""
    sev = _sev(severity)

    if task in _FAST_TASKS:
        return settings.llm_model_fast

    if task == "triage":
        if sev in _CRITICAL:
            # Hardest, highest-stakes call — use the reasoning model if provided.
            return settings.llm_model_reasoning or settings.llm_model_smart
        # P3/P4 triage is largely pattern-matching; the fast tier is enough.
        return settings.llm_model_fast

    # investigation (tool loops), remediation (strict plan), pir, hunt → smart.
    return settings.llm_model_smart


def use_thinking(severity: str | Severity, task: str = "triage") -> bool:
    """Whether to ask for an explicit reasoning trace on this call.

    Only worthwhile for high-stakes triage. On providers without native
    reasoning output, the agent emulates it with a streamed rationale, so this
    stays meaningful regardless of backend.
    """
    return task == "triage" and _sev(severity) in _CRITICAL
