from __future__ import annotations

import contextlib
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.db.connection import get_pool

logger = logging.getLogger("sentinelforge.audit")

GENESIS = "GENESIS"
# Constant advisory-lock key that serializes appends so the hash chain can't fork.
_AUDIT_CHAIN_LOCK = 918273645


def compute_entry_hash(
    prev_hash: str,
    *,
    actor: str,
    action: str,
    incident_id: str | None,
    timestamp_iso: str,
    details: dict[str, Any] | None,
) -> str:
    """Deterministic hash linking this entry to the previous one.

    Covers actor / action / incident / timestamp / details, so any tamper —
    editing a field, reordering rows, deleting or inserting an entry — breaks the
    chain from that point forward.
    """
    payload = {
        "prev": prev_hash,
        "actor": actor,
        "action": action,
        "incident_id": str(incident_id) if incident_id else "",
        "ts": timestamp_iso,
        "details": json.dumps(details or {}, sort_keys=True, separators=(",", ":"), default=str),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def verify_chain(rows: list[dict[str, Any]]) -> tuple[bool, int | None]:
    """Verify a seq-ordered list of audit rows. Returns (intact, first_broken_seq)."""
    prev = GENESIS
    for r in rows:
        expected = compute_entry_hash(
            prev,
            actor=r.get("actor", ""),
            action=r.get("action", ""),
            incident_id=r.get("incident_id"),
            timestamp_iso=r.get("timestamp", ""),
            details=r.get("details") or {},
        )
        if r.get("prev_hash") != prev or r.get("entry_hash") != expected:
            return False, r.get("seq")
        prev = r["entry_hash"]
    return True, None


async def write_audit(
    *,
    incident_id: str | None,
    actor: str,
    action: str,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
    qwen_model: str | None = None,
    qwen_input_tokens: int | None = None,
    qwen_output_tokens: int | None = None,
    qwen_thinking_tokens: int | None = None,
) -> None:
    """Append a tamper-evident audit entry. Never raises — audit failures are logged.

    The append is serialized by a transaction-scoped advisory lock and chained to
    the previous entry's hash, so the log is append-only *and* verifiable.
    """
    try:
        pool = get_pool()
        async with pool.acquire() as conn, conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock($1)", _AUDIT_CHAIN_LOCK)
            prev = await conn.fetchval("SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            prev = prev or GENESIS
            ts = datetime.now(timezone.utc)
            entry_hash = compute_entry_hash(
                prev,
                actor=actor,
                action=action,
                incident_id=incident_id,
                timestamp_iso=ts.isoformat(),
                details=details or {},
            )
            await conn.execute(
                """
                INSERT INTO audit_log
                    (incident_id, timestamp, actor, action, details, ip_address,
                     qwen_model, qwen_input_tokens, qwen_output_tokens, qwen_thinking_tokens,
                     prev_hash, entry_hash)
                VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11, $12)
                """,
                incident_id,
                ts,
                actor,
                action,
                json.dumps(details or {}, default=str),
                ip_address,
                qwen_model,
                qwen_input_tokens,
                qwen_output_tokens,
                qwen_thinking_tokens,
                prev,
                entry_hash,
            )
    except Exception as exc:
        logger.warning("audit write failed (%s): %s", action, exc)


async def verify_audit_chain() -> dict[str, Any]:
    """Walk the entire audit chain and report integrity."""
    from app.db.connection import fetch

    rows = await fetch(
        """
        SELECT seq, incident_id, timestamp, actor, action, details, prev_hash, entry_hash
        FROM audit_log ORDER BY seq ASC
        """
    )
    normalized = [
        {
            "seq": r["seq"],
            "incident_id": str(r["incident_id"]) if r["incident_id"] else None,
            "timestamp": r["timestamp"].isoformat()
            if isinstance(r["timestamp"], datetime)
            else r["timestamp"],
            "actor": r["actor"],
            "action": r["action"],
            "details": json.loads(r["details"])
            if isinstance(r["details"], str)
            else (r["details"] or {}),
            "prev_hash": r["prev_hash"],
            "entry_hash": r["entry_hash"],
        }
        for r in rows
    ]
    intact, broken_at = verify_chain(normalized)
    return {"entries": len(normalized), "intact": intact, "broken_at_seq": broken_at}


async def fetch_audit_for_incident(incident_id: str, limit: int = 200) -> list[dict[str, Any]]:
    from app.db.connection import fetch

    rows = await fetch(
        """
        SELECT id, incident_id, timestamp, actor, action, details, ip_address,
               qwen_model, qwen_input_tokens, qwen_output_tokens, qwen_thinking_tokens
        FROM audit_log
        WHERE incident_id = $1
        ORDER BY timestamp DESC
        LIMIT $2
        """,
        incident_id,
        limit,
    )
    return [_row_to_dict(r) for r in rows]


async def fetch_security_events(limit: int = 50) -> list[dict[str, Any]]:
    from app.db.connection import fetch

    rows = await fetch(
        """
        SELECT id, incident_id, timestamp, actor, action, details, ip_address
        FROM audit_log
        WHERE action LIKE 'prompt_injection%' OR action LIKE 'security.%'
           OR action LIKE '%approved%' OR action LIKE '%webhook%'
        ORDER BY timestamp DESC
        LIMIT $1
        """,
        limit,
    )
    return [_row_to_dict(r) for r in rows]


def _row_to_dict(row) -> dict[str, Any]:
    d = dict(row)
    if isinstance(d.get("timestamp"), datetime):
        d["timestamp"] = d["timestamp"].isoformat()
    if isinstance(d.get("details"), str):
        with contextlib.suppress(Exception):
            d["details"] = json.loads(d["details"])
    return d
