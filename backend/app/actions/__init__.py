"""Action safety layer — where the LLM proposes and deterministic code disposes.

A production SOC tool is trusted with containment only if a fully compromised /
prompt-injected model still cannot cause a prohibited or out-of-budget action.
This package enforces that: every mutating action flows
`propose → guardrails → dry-run → execute → verify → rollback`, and the
guardrail decision is a pure, deterministic function of a policy + the request.
"""
from app.actions.executor import ActionExecutor, get_executor
from app.actions.models import (
    ActionRequest,
    ActionResult,
    ActionStatus,
    Decision,
    GuardrailContext,
    GuardrailDecision,
    TargetKind,
)
from app.actions.policy import GuardrailPolicy

__all__ = [
    "ActionExecutor",
    "get_executor",
    "ActionRequest",
    "ActionResult",
    "ActionStatus",
    "Decision",
    "GuardrailContext",
    "GuardrailDecision",
    "TargetKind",
    "GuardrailPolicy",
]
