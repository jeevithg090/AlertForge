from __future__ import annotations

from fastapi import APIRouter

from app.db.connection import fetch, fetchval

router = APIRouter()


@router.get("/mttr")
async def mttr() -> dict:
    rows = await fetch(
        """
        SELECT
            COALESCE(AVG(mttr_seconds), 0)::float AS avg_mttr,
            COUNT(*) AS resolved_count
        FROM incidents WHERE status = 'RESOLVED' AND mttr_seconds IS NOT NULL
        """
    )
    avg = float(rows[0]["avg_mttr"]) if rows and rows[0]["avg_mttr"] is not None else 0.0
    count = int(rows[0]["resolved_count"]) if rows and rows[0]["resolved_count"] is not None else 0
    return {"avg_mttr_seconds": avg, "resolved_count": count}


@router.get("/by-service")
async def by_service() -> dict:
    rows = await fetch(
        """
        SELECT affected_service, COUNT(*) AS count
        FROM incidents GROUP BY affected_service ORDER BY count DESC LIMIT 20
        """
    )
    return {"services": [dict(r) for r in rows]}


@router.get("/by-verdict")
async def by_verdict() -> dict:
    """Count of incidents per triage verdict (TRUE_POSITIVE / FALSE_POSITIVE /
    BENIGN_ANOMALY / NEEDS_HUMAN / UNKNOWN)."""
    rows = await fetch(
        """
        SELECT
            COALESCE((triage_result->>'verdict'), 'UNKNOWN') AS verdict,
            COUNT(*) AS count
        FROM incidents
        WHERE triage_result IS NOT NULL
        GROUP BY verdict ORDER BY count DESC
        """
    )
    return {"verdicts": [dict(r) for r in rows]}


@router.get("/by-severity")
async def by_severity() -> dict:
    rows = await fetch(
        """
        SELECT severity, COUNT(*) AS count
        FROM incidents GROUP BY severity ORDER BY count DESC
        """
    )
    return {"severities": [dict(r) for r in rows]}


@router.get("/top-techniques")
async def top_techniques() -> dict:
    """Top MITRE ATT&CK techniques observed across all triaged incidents."""
    rows = await fetch(
        """
        SELECT
            t->>'technique_id' AS technique_id,
            t->>'name'        AS name,
            t->>'tactic'      AS tactic,
            COUNT(*) AS count
        FROM incidents, jsonb_array_elements(triage_result->'attack_techniques') AS t
        WHERE triage_result ? 'attack_techniques'
        GROUP BY technique_id, name, tactic
        ORDER BY count DESC
        LIMIT 15
        """
    )
    return {"techniques": [dict(r) for r in rows]}


@router.get("/token-usage")
async def token_usage() -> dict:
    rows = await fetch(
        """
        SELECT qwen_model,
               COALESCE(SUM(qwen_input_tokens),0)  AS input_tokens,
               COALESCE(SUM(qwen_output_tokens),0) AS output_tokens,
               COALESCE(SUM(qwen_thinking_tokens),0) AS thinking_tokens,
               COUNT(*) AS calls
        FROM audit_log WHERE qwen_model IS NOT NULL
        GROUP BY qwen_model ORDER BY calls DESC
        """
    )
    return {"usage": [dict(r) for r in rows]}


@router.get("/correlation")
async def correlation() -> dict:
    """Alert-fatigue reduction: how many raw alerts collapsed into how few
    incidents. ``noise_reduction_pct`` is the headline SOC efficiency metric."""
    row = await fetch(
        """
        SELECT
            COUNT(*)                               AS incidents,
            COALESCE(SUM(alert_count), 0)          AS total_alerts,
            COALESCE(SUM(alert_count) - COUNT(*), 0) AS alerts_folded,
            COALESCE(MAX(alert_count), 0)          AS largest_cluster
        FROM incidents
        """
    )
    r = row[0] if row else {}
    total_alerts = int(r.get("total_alerts") or 0)
    incidents = int(r.get("incidents") or 0)
    folded = int(r.get("alerts_folded") or 0)
    pct = round(100.0 * folded / total_alerts, 1) if total_alerts else 0.0
    return {
        "incidents": incidents,
        "total_alerts_ingested": total_alerts,
        "alerts_folded": folded,
        "largest_cluster": int(r.get("largest_cluster") or 0),
        "noise_reduction_pct": pct,
    }


@router.get("/feedback")
async def feedback_analytics() -> dict:
    rows = await fetch(
        """
        SELECT ai_verdict, human_verdict, COUNT(*) AS count
        FROM triage_feedback
        GROUP BY ai_verdict, human_verdict
        """
    )
    by_pair = [dict(r) for r in rows]
    total = sum(r["count"] for r in by_pair)
    agreements = sum(r["count"] for r in by_pair if r["ai_verdict"] == r["human_verdict"])
    agreement_rate = round(agreements / total, 3) if total else 0.0
    false_negatives = sum(
        r["count"] for r in by_pair
        if r["ai_verdict"] in ("FALSE_POSITIVE", "BENIGN_ANOMALY")
        and r["human_verdict"] == "TRUE_POSITIVE"
    )
    false_positives_confirmed = sum(
        r["count"] for r in by_pair
        if r["ai_verdict"] == "TRUE_POSITIVE"
        and r["human_verdict"] in ("FALSE_POSITIVE", "BENIGN_ANOMALY")
    )
    return {
        "total": total,
        "agreement_rate": agreement_rate,
        "false_negatives": false_negatives,
        "false_positives_confirmed": false_positives_confirmed,
        "by_pair": by_pair,
    }


@router.get("/navigator-layer")
async def navigator_layer() -> dict:
    from app.services.stix_export import build_navigator_layer

    rows = await fetch(
        """
        SELECT
            t->>'technique_id' AS technique_id,
            t->>'name'        AS name,
            COUNT(*) AS count
        FROM incidents, jsonb_array_elements(triage_result->'attack_techniques') AS t
        WHERE triage_result ? 'attack_techniques'
        GROUP BY technique_id, name
        ORDER BY count DESC
        """
    )
    return build_navigator_layer([dict(r) for r in rows])


@router.get("/purple")
async def purple_results() -> dict:
    import json
    import os

    path = os.path.join("purple_results", "latest.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {"available": False}


@router.get("/summary")
async def summary() -> dict:
    """One-shot SOC overview for the analytics page header."""
    total = await fetchval("SELECT COUNT(*) FROM incidents")
    resolved = await fetchval("SELECT COUNT(*) FROM incidents WHERE status='RESOLVED'")
    escalated = await fetchval("SELECT COUNT(*) FROM incidents WHERE status='ESCALATED'")
    dismissed = await fetchval("SELECT COUNT(*) FROM incidents WHERE status='DISMISSED'")
    total_alerts = await fetchval("SELECT COALESCE(SUM(alert_count),0) FROM incidents")
    total_alerts = int(total_alerts or 0)
    incidents = int(total or 0)
    folded = max(0, total_alerts - incidents)
    return {
        "total": incidents,
        "resolved": int(resolved or 0),
        "escalated": int(escalated or 0),
        "dismissed": int(dismissed or 0),
        "total_alerts_ingested": total_alerts,
        "alerts_folded": folded,
        "noise_reduction_pct": round(100.0 * folded / total_alerts, 1) if total_alerts else 0.0,
    }