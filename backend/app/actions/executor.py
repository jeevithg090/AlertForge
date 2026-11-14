"""Action executor — runs a proposed action through the safety lifecycle.

    propose → guardrails → (approval check) → preflight → dry-run → execute →
    verify → (rollback on failure)

The guardrail decision is authoritative: a DENY is terminal and no approval can
override it. Execution is idempotent (by ``idempotency_key``) and every state
transition is auditable via an injected callback (so the executor has no hard DB
dependency and is unit-testable in isolation).
"""

from __future__ import annotations

import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Any

from app.actions.base import ActionAdapter
from app.actions.models import (
    ActionRequest,
    ActionResult,
    ActionStatus,
    GuardrailContext,
    GuardrailDecision,
)
from app.actions.policy import GuardrailPolicy, evaluate

logger = logging.getLogger("sentinelforge.actions")

AuditFn = Callable[[str, ActionRequest, ActionResult], Awaitable[None]]


class ActionExecutor:
    def __init__(
        self,
        policy: GuardrailPolicy,
        adapters: list[ActionAdapter],
        *,
        audit: AuditFn | None = None,
        window_seconds: int = 300,
    ) -> None:
        self.policy = policy
        self._adapters: dict[str, ActionAdapter] = {a.action_type: a for a in adapters}
        self._audit = audit
        self._window_seconds = window_seconds
        self._window: deque[float] = deque()  # timestamps of executed mutating actions
        self._incident_counts: dict[str, int] = {}  # incident_id -> executed mutating count
        self._executed_keys: set[str] = set()  # idempotency keys already executed

    # ---- authorization (pure decision + live counters) ---- #

    def build_context(self, request: ActionRequest, approvers: tuple[str, ...]) -> GuardrailContext:
        self._expire_window()
        return GuardrailContext(
            incident_action_count=self._incident_counts.get(request.incident_id, 0),
            window_action_count=len(self._window),
            approvers=tuple(dict.fromkeys(a for a in approvers if a)),  # distinct, order-preserving
        )

    def authorize(
        self, request: ActionRequest, approvers: tuple[str, ...] = ()
    ) -> GuardrailDecision:
        return evaluate(self.policy, request, self.build_context(request, approvers))

    # ---- full lifecycle ---- #

    async def run(self, request: ActionRequest, *, approvers: tuple[str, ...] = ()) -> ActionResult:
        ctx = self.build_context(request, approvers)
        decision = evaluate(self.policy, request, ctx)

        # 1. Hard denial — terminal, un-overridable.
        if decision.blocked:
            return await self._finish(
                ActionResult(ActionStatus.DENIED, request, decision), "action.denied"
            )

        # 2. Approval sufficiency (a DENY above already short-circuited).
        if decision.needs_human and len(ctx.approvers) < decision.approvers_required:
            return await self._finish(
                ActionResult(ActionStatus.AWAITING_APPROVAL, request, decision),
                "action.awaiting_approval",
            )

        # 3. Idempotency.
        if request.idempotency_key in self._executed_keys:
            return await self._finish(
                ActionResult(ActionStatus.SKIPPED_DUPLICATE, request, decision),
                "action.skipped_duplicate",
            )

        adapter = self._adapters.get(request.action_type)
        if adapter is None:
            return await self._finish(
                ActionResult(ActionStatus.FAILED, request, decision, error="no adapter registered"),
                "action.failed",
            )

        # 4. Preflight + dry-run (always, even in live mode).
        try:
            blast = await adapter.preflight(request)
            planned = await adapter.dry_run(request)
        except Exception as exc:  # noqa: BLE001
            return await self._finish(
                ActionResult(
                    ActionStatus.FAILED, request, decision, error=f"preflight/dry-run: {exc}"
                ),
                "action.failed",
            )

        evidence: dict[str, Any] = {
            "blast_radius": blast.summary,
            "reversible": blast.reversible,
            "planned_effect": planned.summary,
            "simulated_adapter": adapter.simulated,
        }

        # 5. Dry-run-only mode: stop here (the safe default for production).
        if self.policy.dry_run_only:
            self._record(request)
            return await self._finish(
                ActionResult(
                    ActionStatus.DRY_RUN_OK,
                    request,
                    decision,
                    effect=planned.details,
                    evidence=evidence,
                ),
                "action.dry_run_ok",
            )

        # 6. Live execution → verify → rollback-on-failure.
        try:
            effect = await adapter.execute(request)
            ok = await adapter.verify(request, effect)
        except Exception as exc:  # noqa: BLE001
            return await self._finish(
                ActionResult(
                    ActionStatus.FAILED, request, decision, evidence=evidence, error=str(exc)
                ),
                "action.failed",
            )

        if ok:
            self._record(request)
            return await self._finish(
                ActionResult(
                    ActionStatus.VERIFIED, request, decision, effect=effect, evidence=evidence
                ),
                "action.verified",
            )

        rolled_back = False
        try:
            rolled_back = await adapter.rollback(request, effect)
        except Exception as exc:  # noqa: BLE001
            evidence["rollback_error"] = str(exc)
        return await self._finish(
            ActionResult(
                ActionStatus.ROLLED_BACK if rolled_back else ActionStatus.FAILED,
                request,
                decision,
                effect=effect,
                evidence=evidence,
                rolled_back=rolled_back,
                error="verification failed",
            ),
            "action.rolled_back" if rolled_back else "action.failed",
        )

    # ---- internals ---- #

    def _record(self, request: ActionRequest) -> None:
        self._executed_keys.add(request.idempotency_key)
        self._incident_counts[request.incident_id] = (
            self._incident_counts.get(request.incident_id, 0) + 1
        )
        self._window.append(time.monotonic())

    def _expire_window(self) -> None:
        cutoff = time.monotonic() - self._window_seconds
        while self._window and self._window[0] < cutoff:
            self._window.popleft()

    async def _finish(self, result: ActionResult, action: str) -> ActionResult:
        from app.services.metrics import record_action

        record_action(result.request.action_type, result.status.value)
        logger.info(
            "action %s %s target=%s decision=%s",
            result.request.action_type,
            result.status.value,
            result.request.target,
            result.decision.decision.value if result.decision else "?",
        )
        if self._audit is not None:
            try:
                await self._audit(action, result.request, result)
            except Exception as exc:  # noqa: BLE001
                logger.debug("action audit skipped: %s", exc)
        return result


# ---- process-wide singleton wired from settings + default adapters ---- #

_executor: ActionExecutor | None = None


def get_executor() -> ActionExecutor:
    global _executor
    if _executor is None:
        from app.actions.adapters import default_adapters
        from app.config import settings

        async def _audit(action: str, req: ActionRequest, res: ActionResult) -> None:
            from app.db.audit import write_audit

            await write_audit(
                incident_id=req.incident_id,
                actor="system:action_executor",
                action=action,
                details={
                    "action_type": req.action_type,
                    "target": req.target,
                    "status": res.status.value,
                    "decision": res.decision.decision.value if res.decision else None,
                    "reasons": list(res.decision.reasons) if res.decision else [],
                    "evidence": res.evidence,
                    "error": res.error,
                },
            )

        _executor = ActionExecutor(
            GuardrailPolicy.from_settings(settings),
            default_adapters(),
            audit=_audit,
            window_seconds=settings.action_window_seconds,
        )
    return _executor
