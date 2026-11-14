from __future__ import annotations

from enum import Enum
from typing import Any


class EventType(str, Enum):
    INCIDENT_CREATED = "incident.created"
    ALERT_CORRELATED = "alert.correlated"
    TRIAGE_STARTED = "triage.started"
    THINKING_CHUNK = "thinking.chunk"
    TRIAGE_COMPLETE = "triage.complete"
    INVESTIGATION_STARTED = "investigation.started"
    INVESTIGATION_TOOLS_SELECTED = "investigation.tools_selected"
    TOOL_CALLED = "tool.called"
    TOOL_RESULT = "tool.result"
    INVESTIGATION_COMPLETE = "investigation.complete"
    HUNT_GENERATED = "hunt.generated"
    PLAN_GENERATED = "plan.generated"
    APPROVAL_REQUIRED = "approval.required"
    APPROVAL_RECEIVED = "approval.received"
    STEP_EXECUTING = "step.executing"
    STEP_COMPLETE = "step.complete"
    STEP_FAILED = "step.failed"
    ROLLBACK_TRIGGERED = "rollback.triggered"
    INCIDENT_RESOLVED = "incident.resolved"
    PIR_STREAMING = "pir.streaming"
    PIR_COMPLETE = "pir.complete"
    AGENT_MESSAGE = "agent.message"
    SECURITY_EVENT = "security.event"
    JIRA_TICKET_CREATED = "jira.ticket_created"
    DETECTION_RULE_GENERATED = "detection.rule_generated"
    FEEDBACK_RECEIVED = "feedback.received"


def make_event(event_type: EventType | str, incident_id: str, **extra: Any) -> dict:
    """Build a dashboard event envelope."""
    return {
        "type": event_type.value if isinstance(event_type, EventType) else event_type,
        "incident_id": incident_id,
        **extra,
    }


__all__ = ["EventType", "make_event"]
