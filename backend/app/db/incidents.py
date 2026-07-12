from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from app.db.connection import execute, fetch, fetchrow, fetchval, get_pool


def _new_id() -> str:
    return str(uuid.uuid4())


async def create_incident(
    *,
    signal_id: str | None = None,
    severity: str = "P3_MEDIUM",
    category: str = "UNKNOWN",
    source: str = "generic",
    affected_service: str = "unknown",
    affected_hosts: list[str] | None = None,
    alert_message: str = "",
    status: str = "INGESTED",
    correlation_key: str | None = None,
    correlated_entities: dict | None = None,
) -> str:
    sid = signal_id or _new_id()
    incident_id = await fetchval(
        """
        INSERT INTO incidents
            (signal_id, severity, category, status, source, affected_service,
             affected_hosts, alert_message, correlation_key, correlated_entities,
             last_seen_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, NOW())
        RETURNING id::text
        """,
        uuid.UUID(sid) if "—" not in sid else sid,
        severity,
        category,
        status,
        source,
        affected_service,
        affected_hosts or [],
        alert_message,
        correlation_key,
        json.dumps(correlated_entities or {}, default=str),
    )
    return str(incident_id)


# Statuses that are still "open" and therefore eligible to absorb a new alert.
OPEN_STATUSES = (
    "INGESTED", "TRIAGING", "INVESTIGATING", "PLANNING",
    "AWAITING_APPROVAL", "EXECUTING", "ESCALATED",
)


async def find_correlatable_incident(
    entities: dict, fingerprint: str, window_seconds: int
) -> tuple[dict[str, Any], str] | None:
    """Find an OPEN incident within the time window that this alert correlates to.

    Returns ``(incident_dict, reason)`` for the first (strongest) match, or None.
    Exact-fingerprint matches are considered first, then entity overlap. The
    correlation decision itself lives in :mod:`app.pipeline.correlation`.
    """
    from app.pipeline.correlation import Entities, correlation_reason

    rows = await fetch(
        """
        SELECT * FROM incidents
        WHERE status = ANY($1::text[])
          AND last_seen_at >= NOW() - make_interval(secs => $2::int)
        ORDER BY (correlation_key = $3) DESC, last_seen_at DESC
        LIMIT 50
        """,
        list(OPEN_STATUSES),
        int(window_seconds),
        fingerprint or "",
    )
    new_ent = Entities.from_dict(entities)
    for r in rows:
        d = _row_to_dict(r)
        existing_ent = Entities.from_dict(_coerce_json(d.get("correlated_entities")))
        reason = correlation_reason(
            new_ent, fingerprint, existing_ent, d.get("correlation_key") or ""
        )
        if reason:
            return d, reason
    return None


async def attach_signal(
    incident_id: str, signal: dict[str, Any], reason: str, merged_entities: dict
) -> dict[str, Any]:
    """Fold a correlated alert into an existing incident (no new pipeline run).

    Increments ``alert_count``, appends an audit record to ``related_signals``,
    refreshes ``last_seen_at``, and stores the entity union so subsequent alerts
    keep matching.
    """
    rec = {
        "signal_id": signal.get("signal_id"),
        "at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "source": signal.get("source"),
        "alert_message": (signal.get("alert_message") or "")[:300],
    }
    row = await fetchrow(
        """
        UPDATE incidents
        SET alert_count = alert_count + 1,
            last_seen_at = NOW(),
            related_signals = COALESCE(related_signals, '[]'::jsonb) || $2::jsonb,
            correlated_entities = $3::jsonb,
            updated_at = NOW()
        WHERE id = $1::uuid
        RETURNING id::text, alert_count
        """,
        _as_uuid(incident_id),
        json.dumps([rec], default=str),
        json.dumps(merged_entities, default=str),
    )
    return _row_to_dict(row) if row else {"id": incident_id, "alert_count": None}


def _advisory_key(key: str) -> int:
    """Map a correlation-group key to a signed 64-bit int for advisory locking."""
    return int.from_bytes(hashlib.sha1(key.encode("utf-8")).digest()[:8], "big", signed=True)


async def correlate_or_create(
    *,
    entities: dict,
    fingerprint: str,
    lock_key: str,
    window_seconds: int,
    signal: dict[str, Any],
    create_kwargs: dict[str, Any],
) -> tuple[str, bool, str | None, int]:
    """Atomically correlate a signal into an open incident or create a new one.

    A per-correlation-group transaction-scoped **advisory lock** serializes
    concurrent alerts that belong together (e.g. an alert storm), so two workers
    can't both `find (none) → create` and split one incident into two. Returns
    ``(incident_id, correlated, reason, alert_count)``.
    """
    from app.pipeline.correlation import Entities, correlation_reason, merge_entities

    new_ent = Entities.from_dict(entities)
    lock_int = _advisory_key(lock_key)
    pool = get_pool()
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock($1)", lock_int)

        rows = await conn.fetch(
            """
                SELECT * FROM incidents
                WHERE status = ANY($1::text[])
                  AND last_seen_at >= NOW() - make_interval(secs => $2::int)
                ORDER BY (correlation_key = $3) DESC, last_seen_at DESC
                LIMIT 50
                """,
            list(OPEN_STATUSES), int(window_seconds), fingerprint or "",
        )
        for r in rows:
            d = _row_to_dict(r)
            existing_ent = Entities.from_dict(_coerce_json(d.get("correlated_entities")))
            reason = correlation_reason(
                new_ent, fingerprint, existing_ent, d.get("correlation_key") or ""
            )
            if not reason:
                continue
            merged = merge_entities(existing_ent, new_ent).as_dict()
            rec = {
                "signal_id": signal.get("signal_id"),
                "at": datetime.now(timezone.utc).isoformat(),
                "reason": reason,
                "source": signal.get("source"),
                "alert_message": (signal.get("alert_message") or "")[:300],
            }
            new_count = await conn.fetchval(
                """
                    UPDATE incidents
                    SET alert_count = alert_count + 1,
                        last_seen_at = NOW(),
                        related_signals = COALESCE(related_signals, '[]'::jsonb) || $2::jsonb,
                        correlated_entities = $3::jsonb,
                        updated_at = NOW()
                    WHERE id = $1::uuid
                    RETURNING alert_count
                    """,
                _as_uuid(d["id"]), json.dumps([rec], default=str), json.dumps(merged, default=str),
            )
            return d["id"], True, reason, int(new_count or 0)

        # No correlation → create a fresh incident (still holding the lock).
        sid = create_kwargs.get("signal_id") or _new_id()
        incident_id = await conn.fetchval(
            """
                INSERT INTO incidents
                    (signal_id, severity, category, status, source, affected_service,
                     affected_hosts, alert_message, correlation_key, correlated_entities,
                     last_seen_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, NOW())
                RETURNING id::text
                """,
            uuid.UUID(sid) if "—" not in str(sid) else sid,
            create_kwargs.get("severity", "P3_MEDIUM"),
            create_kwargs.get("category", "SECURITY"),
            create_kwargs.get("status", "INGESTED"),
            create_kwargs.get("source", "generic"),
            create_kwargs.get("affected_service", "unknown"),
            create_kwargs.get("affected_hosts") or [],
            create_kwargs.get("alert_message", ""),
            fingerprint,
            json.dumps(entities, default=str),
        )
        return str(incident_id), False, None, 1


async def get_incident(incident_id: str) -> dict[str, Any] | None:
    row = await fetchrow("SELECT * FROM incidents WHERE id = $1::uuid", _as_uuid(incident_id))
    return _row_to_dict(row) if row else None


async def list_incidents(
    *,
    status: str | None = None,
    severity: str | None = None,
    service: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    where = []
    args: list[Any] = []
    idx = 1
    if status:
        where.append(f"status = ${idx}"); args.append(status); idx += 1
    if severity:
        where.append(f"severity = ${idx}"); args.append(severity); idx += 1
    if service:
        where.append(f"affected_service ILIKE ${idx}"); args.append(f"%{service}%"); idx += 1
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    args += [limit, offset]
    rows = await fetch(
        f"SELECT * FROM incidents {clause} ORDER BY created_at DESC LIMIT ${idx} OFFSET ${idx+1}",
        *args,
    )
    return [_row_to_dict(r) for r in rows]


async def update_incident(
    incident_id: str,
    *,
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
    triage_result: dict | None = None,
    investigation_finding: dict | None = None,
    remediation_plan: dict | None = None,
    pir_report: str | None = None,
    is_false_positive: bool | None = None,
    auto_resolved: bool | None = None,
    mttr_seconds: int | None = None,
    qwen_tokens_used: int | None = None,
) -> None:
    fields = []
    args: list[Any] = []
    idx = 1
    for name, val in [
        ("severity", severity), ("category", category), ("status", status),
        ("is_false_positive", is_false_positive), ("auto_resolved", auto_resolved),
        ("mttr_seconds", mttr_seconds),
    ]:
        if val is not None:
            fields.append(f"{name} = ${idx}"); args.append(val); idx += 1
    for name, val in [
        ("triage_result", triage_result), ("investigation_finding", investigation_finding),
        ("remediation_plan", remediation_plan),
    ]:
        if val is not None:
            fields.append(f"{name} = ${idx}::jsonb"); args.append(json.dumps(val, default=str)); idx += 1
    if pir_report is not None:
        fields.append(f"pir_report = ${idx}"); args.append(pir_report); idx += 1
    if qwen_tokens_used is not None:
        fields.append(f"qwen_tokens_used = COALESCE(qwen_tokens_used,0) + ${idx}"); args.append(qwen_tokens_used); idx += 1
    if status == "RESOLVED":
        fields.append(f"resolved_at = ${idx}"); args.append(datetime.now(timezone.utc)); idx += 1
    fields.append("updated_at = NOW()")
    args.append(_as_uuid(incident_id))
    await execute(
        f"UPDATE incidents SET {', '.join(fields)} WHERE id = ${idx}",
        *args,
    )


# ---------- Remediation steps ----------

async def create_steps(incident_id: str, steps: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    for i, step in enumerate(steps, start=1):
        sid = await fetchval(
            """
            INSERT INTO remediation_steps
                (incident_id, step_number, action_type, description, status, risk_level,
                 requires_approval, rollback_procedure, validation_check, tool_to_invoke, tool_parameters)
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)
            RETURNING id::text
            """,
            _as_uuid(incident_id),
            step.get("step_number", i),
            step.get("action_type", "human_action"),
            step.get("description", ""),
            step.get("status", "PENDING"),
            step.get("risk_level", "MEDIUM"),
            step.get("requires_human_approval", step.get("requires_approval", False)),
            step.get("rollback_procedure"),
            step.get("validation_check"),
            step.get("tool_to_invoke"),
            json.dumps(step.get("tool_parameters") or {}, default=str),
        )
        ids.append(str(sid))
    return ids


async def get_step(step_id: str) -> dict[str, Any] | None:
    row = await fetchrow("SELECT * FROM remediation_steps WHERE id = $1::uuid", _as_uuid(step_id))
    return _row_to_dict(row) if row else None


async def list_steps(incident_id: str) -> list[dict[str, Any]]:
    rows = await fetch(
        "SELECT * FROM remediation_steps WHERE incident_id = $1::uuid ORDER BY step_number",
        _as_uuid(incident_id),
    )
    return [_row_to_dict(r) for r in rows]


async def list_pending_steps() -> list[dict[str, Any]]:
    rows = await fetch(
        "SELECT * FROM remediation_steps WHERE status = 'AWAITING_APPROVAL' ORDER BY created_at"
    )
    return [_row_to_dict(r) for r in rows]


async def update_step(step_id: str, **fields) -> None:
    if not fields:
        return
    sets = []
    args: list[Any] = []
    idx = 1
    for name, val in fields.items():
        if name in ("tool_parameters",):
            sets.append(f"{name} = ${idx}::jsonb"); args.append(json.dumps(val, default=str))
        else:
            sets.append(f'{name} = ${idx}'); args.append(val)
        idx += 1
    args.append(_as_uuid(step_id))
    await execute(
        f"UPDATE remediation_steps SET {', '.join(sets)} WHERE id = ${idx}",
        *args,
    )


async def cas_update_step(step_id: str, *, from_status: str, to_status: str, approved_by: str | None = None) -> bool:
    """Atomic compare-and-set on step status.

    Returns True if a row was actually updated (i.e. the step was in ``from_status``
    and is now in ``to_status``). Used by the timeout auto-approve sweeper and the
    approval endpoints to prevent the two-operators-approve-same-step race.
    """
    args: list[Any] = [to_status]
    idx = 2
    extra_sets = ""
    if approved_by is not None:
        extra_sets = f", approved_by = ${idx}"; args.append(approved_by); idx += 1
    args += [_as_uuid(step_id), from_status]
    rowcount = await fetchval(
        f"""
        WITH updated AS (
            UPDATE remediation_steps
            SET status = $1{extra_sets}
            WHERE id = ${idx}::uuid AND status = ${idx + 1}
            RETURNING id
        )
        SELECT count(*) FROM updated
        """,
        *args,
    )
    return bool(rowcount and int(rowcount) > 0)


async def next_pending_step(incident_id: str) -> dict[str, Any] | None:
    row = await fetchrow(
        """
        SELECT * FROM remediation_steps
        WHERE incident_id = $1::uuid AND status IN ('PENDING','APPROVED')
        ORDER BY step_number LIMIT 1
        """,
        _as_uuid(incident_id),
    )
    return _row_to_dict(row) if row else None


def _as_uuid(incident_id: str):
    try:
        return uuid.UUID(str(incident_id))
    except (ValueError, TypeError):
        return incident_id


def _coerce_json(value: Any) -> Any:
    """asyncpg returns JSONB columns as strings (no codec registered). Decode."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return {}
    return value or {}


def _row_to_dict(row) -> dict[str, Any]:
    d = dict(row)
    for k, v in list(d.items()):
        if isinstance(v, datetime):
            d[k] = v.isoformat()
        if isinstance(v, (uuid.UUID,)):
            d[k] = str(v)
    return d
