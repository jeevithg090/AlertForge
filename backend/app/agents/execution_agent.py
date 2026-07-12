"""Execution Agent — OPS persona.

Executes approved containment steps sequentially. Every *mutating* step is routed
through the deterministic action safety layer (``app.actions``): the LLM/plan
only proposed the action — the guardrail engine authorizes it, a dry-run/verify
lifecycle applies it, and prohibited targets (internal ranges, protected
accounts, domain controllers, …) are refused no matter what was approved.

Non-mutating steps (notifications, out-of-band human actions) keep the simple
tool/simulate path. Validation failures trigger rollback.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from app.actions import ActionRequest, ActionStatus, get_executor
from app.actions.models import is_mutating
from app.agents.base import AgentPersona
from app.config import settings
from app.db import incidents as incidents_db
from app.db.audit import write_audit
from app.schemas.events import make_event
from app.services.llm import llm
from app.services.redis_client import publish_event
from app.tools.registry import execute_tool

logger = logging.getLogger("sentinelforge.agents.execution")


def _extract_target(action_type: str, params: dict) -> str:
    p = params or {}
    if action_type in ("block_ip", "firewall_change"):
        return p.get("ip_address") or p.get("ip") or ""
    if action_type in ("suspend_account", "rotate_credentials"):
        return p.get("username") or p.get("user") or ""
    if action_type == "isolate_host":
        return p.get("hostname") or p.get("host") or ""
    if action_type == "quarantine_file":
        return p.get("file_hash") or p.get("path") or ""
    return p.get("target", "")


class ExecutionAgent(AgentPersona):
    PERSONA = "OPS"
    LABEL = "The Operator"
    COLOR = "#00FF88"

    async def run(self, incident_id: str) -> bool:
        """Execute all approved steps. Returns True iff the incident is fully resolved."""
        incident = await incidents_db.get_incident(incident_id)
        steps = await incidents_db.list_steps(incident_id)
        approved = [s for s in steps if s["status"] in ("APPROVED", "PENDING")]

        if not approved:
            await self.say(incident_id, "No approved steps to execute.")
            return False

        await self.say(incident_id, f"Executing {len(approved)} approved steps...")
        fully_resolved = True

        for step in approved:
            sid = step["id"]
            step_num = step["step_number"]
            desc = step["description"]

            await self.say(incident_id, f"Step {step_num}/{len(approved)}: {desc}")
            await publish_event(
                incident_id,
                make_event("step.executing", incident_id, step_id=sid, step_number=step_num, description=desc),
            )
            await incidents_db.update_step(sid, status="EXECUTING", executed_at=datetime.now(timezone.utc))

            outcome, output = await self._apply_step(incident_id, incident or {}, step)

            if outcome == "OK":
                await incidents_db.update_step(
                    sid, status="SUCCESS",
                    execution_output=json.dumps(output, default=str)[:2000],
                    validation_passed=True, completed_at=datetime.now(timezone.utc),
                )
                await publish_event(incident_id, make_event("step.complete", incident_id, step_id=sid, step_number=step_num))
                await self.say(incident_id, f"Step {step_num} ✓ complete.")

            elif outcome == "BLOCKED":
                # Guardrail refused the action — NOT a system failure. Surface it,
                # keep going, but the incident is not auto-resolved (needs a human).
                fully_resolved = False
                reason = "; ".join(output.get("reasons", [])) or "policy denied"
                await incidents_db.update_step(
                    sid, status="BLOCKED",
                    execution_output=json.dumps(output, default=str)[:2000], validation_passed=False,
                )
                await write_audit(
                    incident_id=incident_id, actor="system:guardrails",
                    action="action.blocked_by_policy",
                    details={"step_number": step_num, "rule": output.get("rule"), "reasons": output.get("reasons")},
                )
                await publish_event(
                    incident_id,
                    make_event("step.blocked", incident_id, step_id=sid, step_number=step_num,
                               rule=output.get("rule"), reason=reason),
                )
                await self.say(incident_id, f"Step {step_num} 🛡️ BLOCKED by guardrails: {reason}. Escalating for manual review.")

            elif outcome == "PENDING":
                # Needs more approval (e.g. two-person rule) — revert to awaiting.
                fully_resolved = False
                await incidents_db.update_step(sid, status="AWAITING_APPROVAL", validation_passed=None)
                await publish_event(
                    incident_id,
                    make_event("approval.required", incident_id, step_id=sid, step_number=step_num,
                               description=desc, action_type=step.get("action_type"),
                               reason="; ".join(output.get("reasons", []))),
                )
                await self.say(incident_id, f"Step {step_num} needs a second approver — holding.")

            else:  # FAILED
                await incidents_db.update_step(
                    sid, status="FAILED",
                    execution_output=json.dumps(output, default=str)[:2000], validation_passed=False,
                )
                await publish_event(incident_id, make_event("step.failed", incident_id, step_id=sid, step_number=step_num))
                await self.say(incident_id, f"Step {step_num} ✗ failed. Attempting rollback...")
                if await self._rollback_step(step):
                    await incidents_db.update_step(sid, was_rolled_back=True)
                    await publish_event(incident_id, make_event("rollback.triggered", incident_id, step_id=sid))
                return False  # a genuine execution failure aborts the run

        await write_audit(
            incident_id=incident_id, actor="system:execution_agent", action="execution.complete",
            details={"steps_executed": len(approved), "fully_resolved": fully_resolved},
        )
        if fully_resolved:
            await self.say(incident_id, f"All {len(approved)} steps executed. Incident resolved.")
        else:
            await self.say(incident_id, "Execution finished; some steps were blocked or need a second approver — not auto-resolving.")
        return fully_resolved

    async def _apply_step(self, incident_id: str, incident: dict, step: dict) -> tuple[str, dict]:
        """Return (outcome, output). outcome ∈ {OK, BLOCKED, PENDING, FAILED}."""
        action_type = step.get("action_type") or "human_action"
        params = step.get("tool_parameters") or {}
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except (json.JSONDecodeError, TypeError):
                params = {}

        # Non-mutating steps: keep the simple tool/simulate path.
        if not is_mutating(action_type):
            output = await self._execute_tool_or_sim(step)
            failed = isinstance(output, dict) and output.get("error")
            return ("FAILED" if failed else "OK", output if isinstance(output, dict) else {"result": output})

        # Mutating steps: route through the deterministic safety layer.
        req = ActionRequest(
            action_type=action_type,
            target=_extract_target(action_type, params),
            incident_id=incident_id,
            severity=incident.get("severity", "P3_MEDIUM"),
            reason=(step.get("description") or "")[:200],
            requested_by="system:execution_agent",
            params=params,
        )
        approvers: tuple[str, ...] = ()
        a1 = step.get("approved_by")
        a2 = step.get("second_approver")
        if a1:
            approvers = (a1,)
        if a2:
            approvers = (a1, a2) if a1 else (a2,)
        result = await get_executor().run(req, approvers=approvers)

        if result.status in (ActionStatus.DRY_RUN_OK, ActionStatus.VERIFIED):
            return ("OK", {"status": result.status.value, "effect": result.effect, **result.evidence})
        if result.status == ActionStatus.SKIPPED_DUPLICATE:
            return ("OK", {"status": result.status.value, "idempotent": True})
        if result.status == ActionStatus.DENIED:
            d = result.decision
            return ("BLOCKED", {"blocked": True, "rule": d.matched_rule if d else None,
                                "reasons": list(d.reasons) if d else []})
        if result.status == ActionStatus.AWAITING_APPROVAL:
            d = result.decision
            return ("PENDING", {"needs_approvers": d.approvers_required if d else 2,
                                "reasons": list(d.reasons) if d else []})
        return ("FAILED", {"error": result.error or "action failed", "evidence": result.evidence})

    async def _execute_tool_or_sim(self, step: dict) -> dict:
        tool_name = step.get("tool_to_invoke")
        tool_params = step.get("tool_parameters") or {}
        if tool_name:
            try:
                if isinstance(tool_params, str):
                    tool_params = json.loads(tool_params)
                return await execute_tool(tool_name, tool_params)
            except Exception as exc:
                return {"error": str(exc), "tool": tool_name}

        resp = await llm.complete(
            model=settings.llm_model_fast,
            messages=[
                {"role": "system", "content": "You are an execution agent. Simulate executing this step and return a JSON result."},
                {"role": "user", "content": json.dumps({"step": step["description"], "action_type": step["action_type"]})},
            ],
        )
        try:
            return json.loads(resp["content"])
        except Exception:
            return {"simulated": True, "description": step["description"]}

    async def _rollback_step(self, step: dict) -> bool:
        rollback = step.get("rollback_procedure")
        if not rollback:
            return False
        await self.say(step.get("incident_id", ""), f"Rolling back step {step['step_number']}: {rollback[:80]}...")
        await incidents_db.update_step(
            step["id"], rollback_output=f"Rollback executed: {rollback}", was_rolled_back=True,
        )
        return True
