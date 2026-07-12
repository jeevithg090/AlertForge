"""Export triage feedback as EvalCase entries for the CI eval corpus.

This module converts analyst feedback rows into ``EvalCase`` dicts suitable
for appending to :mod:`app.eval.corpus`. The export is deliberately
human-in-the-loop: a person reviews the output before committing corpus changes.

Usage:
    python -m app.eval.feedback_export
"""
from __future__ import annotations

import logging

logger = logging.getLogger("sentinelforge.feedback_export")


def agreement_stats(rows: list[dict]) -> dict:
    """Compute agreement statistics from feedback rows (pure function).

    Each row should have keys: ai_verdict, human_verdict, count.
    """
    total = sum(r.get("count", 1) for r in rows)
    agreements = sum(
        r.get("count", 1) for r in rows if r.get("ai_verdict") == r.get("human_verdict")
    )
    agreement_rate = round(agreements / total, 3) if total else 0.0
    false_negatives = sum(
        r.get("count", 1) for r in rows
        if r.get("ai_verdict") in ("FALSE_POSITIVE", "BENIGN_ANOMALY")
        and r.get("human_verdict") == "TRUE_POSITIVE"
    )
    false_positives_confirmed = sum(
        r.get("count", 1) for r in rows
        if r.get("ai_verdict") == "TRUE_POSITIVE"
        and r.get("human_verdict") in ("FALSE_POSITIVE", "BENIGN_ANOMALY")
    )
    return {
        "total": total,
        "agreement_rate": agreement_rate,
        "false_negatives": false_negatives,
        "false_positives_confirmed": false_positives_confirmed,
        "by_pair": rows,
    }


def feedback_row_to_eval_case(row: dict) -> dict:
    """Convert a feedback DB row to an EvalCase dict."""
    incident_id = (row.get("incident_id") or "")[:8]
    return {
        "name": f"fb_{incident_id}",
        "raw_text": row.get("alert_message", ""),
        "expected_verdict": row.get("human_verdict", "TRUE_POSITIVE"),
        "expected_severity": row.get("human_severity") or row.get("ai_severity") or "P3_MEDIUM",
        "expected_techniques": [],
    }


async def fetch_feedback_cases() -> list[dict]:
    """Fetch all feedback rows and convert to EvalCase dicts."""
    from app.db.connection import fetch

    rows = await fetch(
        """
        SELECT f.incident_id::text, i.alert_message,
               f.ai_verdict, f.human_verdict,
               f.ai_severity, f.human_severity
        FROM triage_feedback f
        JOIN incidents i ON i.id = f.incident_id
        """
    )
    return [feedback_row_to_eval_case(dict(r)) for r in rows]
