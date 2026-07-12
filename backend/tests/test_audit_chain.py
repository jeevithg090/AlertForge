# fmt: off
"""Tamper-evident audit chain — pure verification logic (no DB required)."""
from __future__ import annotations

import os

os.environ.setdefault("DASHSCOPE_API_KEY", "")

from app.db.audit import GENESIS, compute_entry_hash, verify_chain  # noqa: E402


def _build_chain(entries: list[dict]) -> list[dict]:
    """Build a valid seq-ordered chain from (actor, action, details) entries."""
    rows = []
    prev = GENESIS
    for i, e in enumerate(entries, start=1):
        eh = compute_entry_hash(
            prev, actor=e["actor"], action=e["action"], incident_id=e.get("incident_id"),
            timestamp_iso=e["timestamp"], details=e.get("details") or {},
        )
        rows.append({**e, "seq": i, "prev_hash": prev, "entry_hash": eh})
        prev = eh
    return rows


_ENTRIES = [
    {"actor": "system:triage_agent", "action": "triage.complete", "incident_id": "inc-1",
     "timestamp": "2026-07-06T10:00:00+00:00", "details": {"verdict": "TRUE_POSITIVE", "severity": "P2_HIGH"}},
    {"actor": "human:analyst@corp", "action": "remediation_step.approved", "incident_id": "inc-1",
     "timestamp": "2026-07-06T10:01:00+00:00", "details": {"step": 1}},
    {"actor": "system:guardrails", "action": "action.denied", "incident_id": "inc-1",
     "timestamp": "2026-07-06T10:02:00+00:00", "details": {"rule": "protected_ip", "target": "10.0.0.1"}},
]


def test_valid_chain_verifies():
    rows = _build_chain(_ENTRIES)
    intact, broken = verify_chain(rows)
    assert intact is True
    assert broken is None


def test_tampered_field_is_detected():
    rows = _build_chain(_ENTRIES)
    # An attacker edits an approved-by actor after the fact (repudiation attempt).
    rows[1]["actor"] = "human:someone_else@corp"
    intact, broken = verify_chain(rows)
    assert intact is False
    assert broken == 2


def test_tampered_details_is_detected():
    rows = _build_chain(_ENTRIES)
    # Change a denied action's target to make it look like a different decision.
    rows[2]["details"] = {"rule": "protected_ip", "target": "8.8.8.8"}
    intact, broken = verify_chain(rows)
    assert intact is False
    assert broken == 3


def test_deleted_entry_is_detected():
    rows = _build_chain(_ENTRIES)
    del rows[1]  # drop the approval to hide it
    intact, broken = verify_chain(rows)
    assert intact is False
    assert broken == 3  # the next entry's prev_hash no longer matches


def test_reordered_entries_detected():
    rows = _build_chain(_ENTRIES)
    rows[1], rows[2] = rows[2], rows[1]
    intact, _ = verify_chain(rows)
    assert intact is False


def test_empty_chain_is_intact():
    assert verify_chain([]) == (True, None)
