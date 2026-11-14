"""Incident finite-state machine (Section 7 / 16).

Pure functions over status strings — no hidden state. The orchestrator drives
transitions; invalid transitions raise so a bug surfaces immediately.
"""

from __future__ import annotations

from app.schemas.incident import IncidentStatus

# legal transitions: from -> {to, ...}
_TRANSITIONS: dict[str, set[str]] = {
    IncidentStatus.INGESTED.value: {
        IncidentStatus.TRIAGING.value,
        IncidentStatus.DISMISSED.value,
        IncidentStatus.ESCALATED.value,
    },
    IncidentStatus.TRIAGING.value: {
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.DISMISSED.value,
        IncidentStatus.ESCALATED.value,
    },
    IncidentStatus.INVESTIGATING.value: {
        IncidentStatus.PLANNING.value,
        IncidentStatus.ESCALATED.value,
    },
    IncidentStatus.PLANNING.value: {
        IncidentStatus.AWAITING_APPROVAL.value,
        IncidentStatus.ESCALATED.value,
    },
    IncidentStatus.AWAITING_APPROVAL.value: {
        IncidentStatus.EXECUTING.value,
        IncidentStatus.DISMISSED.value,
        IncidentStatus.ESCALATED.value,
    },
    IncidentStatus.EXECUTING.value: {IncidentStatus.RESOLVED.value, IncidentStatus.ESCALATED.value},
    IncidentStatus.DISMISSED.value: set(),
    IncidentStatus.RESOLVED.value: set(),
    IncidentStatus.ESCALATED.value: {
        IncidentStatus.AWAITING_APPROVAL.value,
        IncidentStatus.EXECUTING.value,
    },
}


def can_transition(from_status: str, to_status: str) -> bool:
    return to_status in _TRANSITIONS.get(from_status, set())


def assert_transition(from_status: str, to_status: str) -> None:
    if not can_transition(from_status, to_status):
        raise ValueError(f"illegal transition {from_status} -> {to_status}")


# Step-level FSM (Section 7.4)
_STEP_TRANSITIONS = {
    "PENDING": {"AWAITING_APPROVAL", "APPROVED"},
    "AWAITING_APPROVAL": {"APPROVED", "REJECTED", "ESCALATED", "TIMEOUT_APPROVED"},
    "APPROVED": {"EXECUTING"},
    "EXECUTING": {"VALIDATING", "FAILED"},
    "VALIDATING": {"SUCCESS", "FAILED"},
    "FAILED": {"ROLLING_BACK"},
    "ROLLING_BACK": {"ROLLED_BACK", "ROLLBACK_FAILED"},
    "SUCCESS": {"NEXT"},
    "REJECTED": set(),
    "ESCALATED": set(),
    "ROLLED_BACK": set(),
    "ROLLBACK_FAILED": set(),
}


def can_step_transition(from_status: str, to_status: str) -> bool:
    return to_status in _STEP_TRANSITIONS.get(from_status, set())
