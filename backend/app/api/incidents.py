from __future__ import annotations

import json
import os
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.config import settings
from app.db import incidents as incidents_db
from app.services.auth import ANALYST_ROLES, operator_id, require_role

router = APIRouter()

_analyst = Depends(require_role(*ANALYST_ROLES))


def _as_dict(value: Any) -> dict:
    """Coerce a JSONB column (asyncpg hands these back as strings) to a dict."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return {}
    return value or {}


@router.get("")
async def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    service: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
) -> dict:
    rows = await incidents_db.list_incidents(
        status=status, severity=severity, service=service, limit=limit, offset=offset
    )
    return {"incidents": rows, "count": len(rows), "limit": limit, "offset": offset}


@router.get("/pending")
async def pending_approvals_view() -> dict:
    """Convenience: incidents awaiting approval."""
    rows = await incidents_db.list_incidents(status="AWAITING_APPROVAL")
    return {"incidents": rows, "count": len(rows)}


@router.get("/{incident_id}")
async def get_incident(incident_id: str) -> dict[str, Any]:
    row = await incidents_db.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="incident not found")
    return row


@router.get("/{incident_id}/timeline")
async def get_timeline(incident_id: str) -> dict:
    from app.db.audit import fetch_audit_for_incident

    return {"incident_id": incident_id, "events": await fetch_audit_for_incident(incident_id)}


@router.get("/{incident_id}/thinking")
async def get_thinking(incident_id: str) -> dict:
    row = await incidents_db.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="incident not found")
    triage = row.get("triage_result") or {}
    return {"incident_id": incident_id, "thinking_trace": triage.get("thinking_trace")}


@router.post("/{incident_id}/hunt", dependencies=[_analyst])
async def generate_incident_hunt(incident_id: str) -> dict:
    """Generate proactive threat-hunt hypotheses from this incident's ATT&CK
    techniques + entities, and stream a ``hunt.generated`` event to the war room."""
    from app.schemas.events import make_event
    from app.services.redis_client import publish_event
    from app.services.threat_hunt import generate_hunt_plan

    row = await incidents_db.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="incident not found")

    triage = _as_dict(row.get("triage_result"))
    techniques = [
        t.get("technique_id")
        for t in (triage.get("attack_techniques") or [])
        if isinstance(t, dict) and t.get("technique_id")
    ]
    context = {
        "affected_service": row.get("affected_service"),
        "alert_message": row.get("alert_message"),
        "severity": row.get("severity"),
        "root_cause_category": triage.get("root_cause_category"),
        "entities": _as_dict(row.get("correlated_entities")),
    }
    plan = await generate_hunt_plan(seed=incident_id, technique_ids=techniques, context=context)
    await publish_event(
        incident_id,
        make_event(
            "hunt.generated",
            incident_id,
            hypotheses=len(plan.hypotheses),
            summary=plan.summary,
        ),
    )
    return plan.model_dump(mode="json")


@router.get("/{incident_id}/pir")
async def get_pir(incident_id: str) -> dict:
    row = await incidents_db.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="incident not found")
    return {"incident_id": incident_id, "pir_report": row.get("pir_report")}


@router.get("/{incident_id}/steps")
async def get_steps(incident_id: str) -> dict:
    """REST rehydration: return all remediation (containment) steps for an
    incident so the dashboard can restore approval cards on refresh."""
    row = await incidents_db.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="incident not found")
    steps = await incidents_db.list_steps(incident_id)
    return {"incident_id": incident_id, "steps": steps, "count": len(steps)}


@router.get("/{incident_id}/events")
async def get_events(incident_id: str, limit: int = Query(500, le=1000)) -> dict:
    """REST rehydration: return the recent SSE dashboard events for an incident
    so a reconnecting client can restore the war-room view."""
    from app.services.redis_client import fetch_event_log

    events = await fetch_event_log(incident_id, limit=limit)
    return {"incident_id": incident_id, "events": events, "count": len(events)}


def detection_rule_path(incident_id: str, technique: str) -> tuple[str, str]:
    """Return (relative_path, absolute_path) for a generated Sigma rule.

    The technique comes from model-refined output, so it is reduced to a safe
    filename component before being joined onto the detections directory.
    """
    safe_technique = re.sub(r"[^A-Za-z0-9._-]", "_", technique).strip("._") or "unknown"
    filename = f"{incident_id[:8]}_{safe_technique}.yaml"
    rel_path = os.path.join(settings.detections_dir, filename)
    return rel_path, os.path.abspath(rel_path)


@router.post("/{incident_id}/detection-rule", dependencies=[_analyst])
async def generate_detection_rule(incident_id: str) -> dict:
    """Generate a Sigma detection rule from this incident's IOCs + MITRE
    techniques. Returns the rule dict, YAML string, and relative file path."""
    from app.db.audit import write_audit
    from app.schemas.events import EventType, make_event
    from app.services.redis_client import publish_event
    from app.services.sigma_gen import generate_detection_rule as _generate

    row = await incidents_db.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="incident not found")

    rule, yaml_str = await _generate(row)
    technique = rule.get("tags", ["attack.unknown"])[-1].replace("attack.", "")
    rel_path, full_path = detection_rule_path(incident_id, technique)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)  # noqa: ASYNC240
    with open(full_path, "w", encoding="utf-8") as f:  # noqa: ASYNC230
        f.write(yaml_str)

    await write_audit(
        incident_id=incident_id,
        actor="system:sigma_gen",
        action="detection.rule_generated",
        details={"technique": technique, "path": rel_path},
    )
    await publish_event(
        incident_id,
        make_event(
            EventType.DETECTION_RULE_GENERATED, incident_id, technique=technique, path=rel_path
        ),
    )
    return {"rule": rule, "yaml": yaml_str, "path": rel_path}


@router.get("/{incident_id}/export/stix")
async def export_stix(incident_id: str) -> Any:
    from fastapi.responses import JSONResponse

    from app.services.stix_export import build_stix_bundle

    row = await incidents_db.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="incident not found")
    bundle = build_stix_bundle(row)
    filename = f"incident-{incident_id[:8]}.stix.json"
    return JSONResponse(
        content=bundle,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


class FeedbackBody(BaseModel):
    human_verdict: str
    human_severity: str | None = None
    note: str | None = None


@router.post("/{incident_id}/feedback")
async def submit_feedback(
    incident_id: str,
    body: FeedbackBody,
    operator: dict = Depends(require_role(*ANALYST_ROLES)),
) -> dict:
    from app.db.audit import write_audit
    from app.db.connection import execute as db_execute
    from app.schemas.events import EventType, make_event
    from app.services.redis_client import publish_event

    if body.human_verdict not in (
        "TRUE_POSITIVE",
        "FALSE_POSITIVE",
        "BENIGN_ANOMALY",
        "NEEDS_HUMAN",
    ):
        raise HTTPException(status_code=422, detail="invalid verdict")

    row = await incidents_db.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="incident not found")

    triage = _as_dict(row.get("triage_result"))
    ai_verdict = triage.get("verdict") if isinstance(triage, dict) else None
    ai_severity = row.get("severity")

    given_by = operator_id(operator)

    await db_execute(
        """
        INSERT INTO triage_feedback (incident_id, given_by, ai_verdict, human_verdict,
                                     ai_severity, human_severity, note)
        VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (incident_id, given_by) DO UPDATE SET
            human_verdict = EXCLUDED.human_verdict,
            human_severity = EXCLUDED.human_severity,
            note = EXCLUDED.note,
            created_at = NOW()
        """,
        incident_id,
        given_by,
        ai_verdict,
        body.human_verdict,
        ai_severity,
        body.human_severity,
        body.note,
    )

    await write_audit(
        incident_id=incident_id,
        actor=given_by,
        action="triage.feedback",
        details={"human_verdict": body.human_verdict, "note": body.note},
    )
    await publish_event(
        incident_id,
        make_event(
            EventType.FEEDBACK_RECEIVED,
            incident_id,
            human_verdict=body.human_verdict,
            given_by=given_by,
        ),
    )
    return {"status": "recorded"}
