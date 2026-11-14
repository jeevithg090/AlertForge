"""Human-in-the-loop approval gate — SOC version.

Auto-approve LOW risk; pure notifications; MEDIUM risk on P3/P4.
ALWAYS require human for: REQUIRES_APPROVAL risk, plus any containment action
that mutates production state (block_ip, suspend_account, isolate_host,
firewall_change, rotate_credentials, quarantine_file, configuration_change,
shell_command) — regardless of severity.
All P1 steps require human.
Timeout auto-approve for low severity if no human response (scheduled by the
background sweeper in ``scheduled_auto_approve``).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from app.config import settings
from app.schemas.incident import Severity
from app.schemas.remediation import ALWAYS_MANUAL_ACTION_TYPES, RemediationRisk, RemediationStep

logger = logging.getLogger("sentinelforge.hitl")


def requires_approval(step: RemediationStep | dict, incident_severity: str) -> bool:
    s = step if isinstance(step, RemediationStep) else RemediationStep.model_validate(step)
    sev = incident_severity

    # All steps on a P1 require human review.
    if sev == Severity.P1_CRITICAL.value:
        return True
    # Containment actions that mutate production state — ALWAYS require human,
    # regardless of severity. This is the fix for the previous P1-only clause.
    if s.action_type in ALWAYS_MANUAL_ACTION_TYPES:
        return True
    # REQUIRES_APPROVAL risk always requires human.
    if s.risk_level == RemediationRisk.REQUIRES_APPROVAL:
        return True
    # HIGH risk on P2 still requires human; auto-approve only for P3/P4 + notification.
    return bool(
        s.risk_level == RemediationRisk.HIGH
        and sev in (Severity.P1_CRITICAL.value, Severity.P2_HIGH.value)
    )


def auto_approvable(step: RemediationStep | dict, incident_severity: str) -> bool:
    """True if the gate can auto-approve without a human."""
    s = step if isinstance(step, RemediationStep) else RemediationStep.model_validate(step)
    sev = incident_severity

    if requires_approval(s, sev):
        return False
    if s.risk_level == RemediationRisk.LOW:
        return True
    if s.action_type == "notification":
        return True
    return bool(
        s.risk_level == RemediationRisk.MEDIUM
        and sev in (Severity.P3_MEDIUM.value, Severity.P4_LOW.value)
    )


def timeout_auto_approve_minutes(severity: str) -> int | None:
    if severity == Severity.P4_LOW.value:
        return settings.auto_approve_timeout_p4
    if severity == Severity.P3_MEDIUM.value:
        return settings.auto_approve_timeout_p3
    return None  # P1/P2 never auto-approve by timeout


async def apply_gate(
    incident_id: str,
    incident_severity: str,
    steps: list[dict[str, Any]],
) -> list[str]:
    """Persist steps, mark auto-approved ones, and return step ids awaiting human."""
    from app.db import incidents as incidents_db
    from app.db.audit import write_audit
    from app.schemas.events import make_event
    from app.services.redis_client import publish_event, publish_to_stream

    await incidents_db.create_steps(incident_id, steps)
    pending_human: list[str] = []

    stored = await incidents_db.list_steps(incident_id)
    for stored_step, plan_step in zip(stored, steps):
        sid = stored_step["id"]
        rs = RemediationStep.model_validate(plan_step)
        if requires_approval(rs, incident_severity):
            await incidents_db.update_step(sid, status="AWAITING_APPROVAL")
            pending_human.append(sid)
            await publish_event(
                incident_id,
                make_event(
                    "approval.required",
                    incident_id,
                    step_id=sid,
                    step_number=rs.step_number,
                    description=rs.description,
                    risk_level=rs.risk_level.value,
                    action_type=rs.action_type,
                    rollback=rs.rollback_procedure,
                ),
            )
        elif auto_approvable(rs, incident_severity):
            await incidents_db.update_step(sid, status="APPROVED", approved_by="system:hitl_auto")
            await write_audit(
                incident_id=incident_id,
                actor="system:hitl_auto",
                action="remediation_step.auto_approved",
                details={"step_number": rs.step_number, "risk_level": rs.risk_level.value},
            )
        else:
            await incidents_db.update_step(sid, status="AWAITING_APPROVAL")
            pending_human.append(sid)

    if pending_human:
        await incidents_db.update_incident(incident_id, status="AWAITING_APPROVAL")
    else:
        # nothing needs a human — straight to execution
        await incidents_db.update_incident(incident_id, status="EXECUTING")
        await publish_to_stream("planned", {"incident_id": incident_id, "resume": True})

    return pending_human


# ---------- Timeout auto-approve sweeper ----------

_SWEEPER_RUNNING = False


async def scheduled_auto_approve(interval_seconds: int = 30) -> None:
    """Background coroutine: periodically scans AWAITING_APPROVAL rows whose
    severity's timeout has elapsed, auto-approves them, and nudges execution.

    Intended to be launched by the orchestrator's `run()`. Idempotent +
    singleton-protected so it can run inside the worker process.
    """
    global _SWEEPER_RUNNING
    if _SWEEPER_RUNNING:
        return
    _SWEEPER_RUNNING = True
    try:
        from app.db import incidents as incidents_db
        from app.db.audit import write_audit
        from app.schemas.events import make_event
        from app.services.redis_client import publish_event, publish_to_stream

        while True:
            await asyncio.sleep(interval_seconds)
            try:
                pending = await incidents_db.list_pending_steps()
            except Exception as exc:
                logger.debug("auto-approve sweeper read failed: %s", exc)
                continue
            for step in pending:
                incident = await incidents_db.get_incident(step["incident_id"])
                if not incident:
                    continue
                sev = incident.get("severity")
                timeout = timeout_auto_approve_minutes(sev)
                if not timeout:
                    continue  # P1/P2 never auto-approve
                # ``created_at`` columns exist on remediation_steps
                created_raw = step.get("created_at") or step.get("approved_at")
                try:
                    created = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                except Exception:
                    continue
                if datetime.now(timezone.utc) < created + timedelta(minutes=timeout):
                    continue
                # Atomic concurrency guard: claim the step via CAS-style update.
                claimed = await incidents_db.cas_update_step(
                    step_id=step["id"],
                    from_status="AWAITING_APPROVAL",
                    to_status="APPROVED",
                    approved_by=f"system:hitl_timeout({timeout}m)",
                )
                if not claimed:
                    continue
                await write_audit(
                    incident_id=step["incident_id"],
                    actor=f"system:hitl_timeout({timeout}m)",
                    action="remediation_step.auto_approved_by_timeout",
                    details={"step_number": step["step_number"], "timeout_minutes": timeout},
                )
                await publish_event(
                    step["incident_id"],
                    make_event(
                        "approval.received",
                        step["incident_id"],
                        step_id=step["id"],
                        decision="auto_approved_timeout",
                        timeout_minutes=timeout,
                    ),
                )
                await publish_to_stream(
                    "planned", {"incident_id": step["incident_id"], "resume": True}
                )
    finally:
        _SWEEPER_RUNNING = False
