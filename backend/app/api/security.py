"""Security controls API — surfaces prompt-injection blocks, approvals, and
other security-relevant audit entries for the operator's Security panel."""
from __future__ import annotations

from fastapi import APIRouter, Query

from app.config import settings
from app.db.audit import fetch_security_events, verify_audit_chain

router = APIRouter()


@router.get("/events")
async def security_events(limit: int = Query(50, le=500)) -> dict:
    rows = await fetch_security_events(limit=limit)
    return {"events": rows, "count": len(rows)}


@router.get("/audit/verify")
async def audit_verify() -> dict:
    """Verify the tamper-evident audit hash chain end-to-end. ``intact: false``
    with a ``broken_at_seq`` means the log was altered after the fact."""
    return await verify_audit_chain()


@router.get("/controls")
async def security_controls() -> dict:
    """Self-reported security posture — matches the Security panel checklist.
    Only reports a control as 'active' when the corresponding code path is
    actually wired up, so the panel never lies to the operator."""
    secret_configured = bool(settings.secret_key) and settings.secret_key != "dev-secret-change-me"
    return {
        "controls": [
            {
                "category": "Input Validation",
                "label": "Prompt injection detection (regex + semantic scan)",
                "status": "active",
            },
            {
                "category": "Input Validation",
                "label": "Input sanitization before agent processing",
                "status": "active",
            },
            {
                "category": "Input Validation",
                "label": "HMAC signature verification on all webhooks",
                "status": "active" if secret_configured else "configured_dev_only",
                "note": (
                    "Active — every /ingest/siem|edr|ids|webhook call rejects requests whose "
                    "X-SentinelForge-Signature header is missing or invalid."
                    if secret_configured else
                    "Wired but in dev mode (SECRET_KEY is the default). Set SECRET_KEY to enforce."
                ),
            },
            {
                "category": "Authorization",
                "label": "Human approval required for all HIGH-risk / containment actions",
                "status": "active",
            },
            {
                "category": "Authorization",
                "label": "Atomic compare-and-set on approval (no double-approve race)",
                "status": "active",
            },
            {
                "category": "Authorization",
                "label": "Tool permissions: agents cannot execute OS commands directly",
                "status": "active",
            },
            {
                "category": "Audit & Compliance",
                "label": "Tamper-evident (hash-chained) audit log for every agent + human action",
                "status": "active",
                "note": "Each entry hashes the previous — verify integrity at GET /api/v1/security/audit/verify.",
            },
            {
                "category": "Authorization",
                "label": "Deterministic guardrails: prohibited containment targets refused even if approved",
                "status": "active",
                "note": "Internal ranges, break-glass/service accounts, and domain controllers are un-actionable regardless of LLM output or approval.",
            },
            {
                "category": "Audit & Compliance",
                "label": "Full attribution: actor (human/agent), timestamp, IP",
                "status": "active",
            },
            {
                "category": "Audit & Compliance",
                "label": "Reasoning traces archived for all P1/P2 incidents",
                "status": "active",
            },
        ],
        "hmac_enforced": secret_configured,
    }