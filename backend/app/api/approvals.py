from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.db import incidents as incidents_db
from app.db.audit import write_audit
from app.services.auth import require_role
from app.services.redis_client import publish_event

router = APIRouter()


class ApprovalDecision(BaseModel):
    rationale: str | None = None


@router.get("/pending")
async def list_pending() -> dict:
    rows = await incidents_db.list_pending_steps()
    return {"pending": rows, "count": len(rows)}


@router.post("/{step_id}/approve")
async def approve_step(
    step_id: str,
    decision: ApprovalDecision,
    operator: dict = Depends(require_role("approver", "admin")),
) -> dict:
    approver = operator["sub"]
    step = await incidents_db.get_step(step_id)
    if not step:
        raise HTTPException(status_code=404, detail="step not found")
    if step["status"] != "AWAITING_APPROVAL":
        raise HTTPException(status_code=409, detail=f"step is {step['status']}, not awaiting approval")

    # Atomic compare-and-set to prevent the two-operators-approve-same-step race.
    claimed = await incidents_db.cas_update_step(
        step_id=step_id,
        from_status="AWAITING_APPROVAL",
        to_status="APPROVED",
        approved_by=approver,
    )
    if not claimed:
        raise HTTPException(status_code=410, detail="step was already acted on by another approver")

    await write_audit(
        incident_id=step["incident_id"],
        actor=approver,
        action="remediation_step.approved",
        details={
            "step_number": step["step_number"],
            "risk_level": step["risk_level"],
            "action_description": step["description"],
            "approval_rationale": decision.rationale,
        },
    )
    await publish_event(
        step["incident_id"],
        {"type": "approval.received", "step_id": step_id, "decision": "approved",
         "approver": approver},
    )
    # Nudge the execution agent to resume
    from app.services.redis_client import publish_to_stream

    await publish_to_stream("planned", {"incident_id": step["incident_id"], "resume": True})
    return {"step_id": step_id, "status": "APPROVED"}


@router.post("/{step_id}/reject")
async def reject_step(
    step_id: str,
    decision: ApprovalDecision,
    operator: dict = Depends(require_role("approver", "admin")),
) -> dict:
    approver = operator["sub"]
    step = await incidents_db.get_step(step_id)
    if not step:
        raise HTTPException(status_code=404, detail="step not found")

    claimed = await incidents_db.cas_update_step(
        step_id=step_id,
        from_status="AWAITING_APPROVAL",
        to_status="REJECTED",
        approved_by=approver,
    )
    if not claimed:
        raise HTTPException(status_code=410, detail="step was already acted on by another approver")

    await write_audit(
        incident_id=step["incident_id"],
        actor=approver,
        action="remediation_step.rejected",
        details={"step_number": step["step_number"], "reason": decision.rationale},
    )
    await publish_event(
        step["incident_id"],
        {"type": "approval.received", "step_id": step_id, "decision": "rejected",
         "approver": approver},
    )
    return {"step_id": step_id, "status": "REJECTED"}


@router.post("/{step_id}/escalate")
async def escalate_step(
    step_id: str,
    decision: ApprovalDecision,
    operator: dict = Depends(require_role("approver", "admin")),
) -> dict:
    approver = operator["sub"]
    step = await incidents_db.get_step(step_id)
    if not step:
        raise HTTPException(status_code=404, detail="step not found")

    claimed = await incidents_db.cas_update_step(
        step_id=step_id,
        from_status="AWAITING_APPROVAL",
        to_status="ESCALATED",
        approved_by=approver,
    )
    if not claimed:
        raise HTTPException(status_code=410, detail="step was already acted on by another approver")

    await write_audit(
        incident_id=step["incident_id"],
        actor=approver,
        action="remediation_step.escalated",
        details={"step_number": step["step_number"], "reason": decision.rationale},
    )
    await publish_event(
        step["incident_id"],
        {"type": "approval.received", "step_id": step_id, "decision": "escalated",
         "approver": approver},
    )
    return {"step_id": step_id, "status": "ESCALATED"}


@router.post("/{step_id}/second-approve")
async def second_approve(
    step_id: str,
    decision: ApprovalDecision,
    operator: dict = Depends(require_role("approver", "admin")),
) -> dict:
    approver = operator["sub"]
    step = await incidents_db.get_step(step_id)
    if not step:
        raise HTTPException(status_code=404, detail="step not found")
    if step["status"] != "AWAITING_APPROVAL":
        raise HTTPException(status_code=409, detail=f"step is {step['status']}, not awaiting approval")
    if step.get("approved_by") == approver:
        raise HTTPException(status_code=409, detail="cannot second-approve your own approval")
    if step.get("second_approver"):
        raise HTTPException(status_code=409, detail="step already has a second approver")

    from app.db.connection import execute as db_execute

    rowcount = await db_execute(
        """
        UPDATE remediation_steps
        SET second_approver = $1, status = 'APPROVED'
        WHERE id = $2::uuid
          AND status = 'AWAITING_APPROVAL'
          AND second_approver IS NULL
          AND approved_by IS DISTINCT FROM $1
        """,
        approver,
        step_id,
    )
    if not rowcount or int(rowcount.split()[-1]) == 0:
        raise HTTPException(status_code=410, detail="step was already acted on or conflict")

    await write_audit(
        incident_id=step["incident_id"],
        actor=approver,
        action="remediation_step.second_approved",
        details={"step_number": step["step_number"], "rationale": decision.rationale},
    )
    await publish_event(
        step["incident_id"],
        {"type": "approval.received", "step_id": step_id, "decision": "approved",
         "approver": approver, "second_approver": True},
    )
    from app.services.redis_client import publish_to_stream

    await publish_to_stream("planned", {"incident_id": step["incident_id"], "resume": True})
    return {"step_id": step_id, "status": "APPROVED", "second_approver": approver}