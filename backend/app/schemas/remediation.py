from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class RemediationRisk(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"


class ContainmentActionType(str, Enum):
    """ "Action vocabulary for the SOC containment plan."""

    NOTIFICATION = "notification"  # alert humans — auto-approve
    QUARANTINE_FILE = "quarantine_file"
    ROTATE_CREDENTIALS = "rotate_credentials"
    BLOCK_IP = "block_ip"
    SUSPEND_ACCOUNT = "suspend_account"
    ISOLATE_HOST = "isolate_host"
    FIREWALL_CHANGE = "firewall_change"
    SHELL_COMMAND = "shell_command"
    API_CALL = "api_call"
    CONFIGURATION_CHANGE = "configuration_change"
    HUMAN_ACTION = "human_action"  # out-of-band action for the analyst


# Action types that must always require a human to approve, regardless of severity.
ALWAYS_MANUAL_ACTION_TYPES: set[str] = {
    ContainmentActionType.ISOLATE_HOST.value,
    ContainmentActionType.SUSPEND_ACCOUNT.value,
    ContainmentActionType.BLOCK_IP.value,
    ContainmentActionType.FIREWALL_CHANGE.value,
    ContainmentActionType.ROTATE_CREDENTIALS.value,
    ContainmentActionType.QUARANTINE_FILE.value,
    ContainmentActionType.CONFIGURATION_CHANGE.value,
    ContainmentActionType.SHELL_COMMAND.value,
}


class RemediationStep(BaseModel):
    """A single containment action; produced by the Containment Agent."""

    step_number: int
    action_type: str = Field(
        description=(
            "One of: notification, quarantine_file, rotate_credentials, block_ip, "
            "suspend_account, isolate_host, firewall_change, shell_command, api_call, "
            "configuration_change, human_action"
        )
    )
    description: str = Field(description="Human-readable description of what this step does")
    tool_to_invoke: str | None = Field(
        default=None,
        description="Which SentinelForge tool to call for this step (e.g. block_ip, suspend_account)",
    )
    tool_parameters: dict | None = None
    estimated_duration_seconds: int = 30
    risk_level: RemediationRisk = RemediationRisk.MEDIUM
    rollback_procedure: str | None = Field(
        default=None,
        description="How to undo this step if it makes things worse (re-add IP to allowlist etc.)",
    )
    validation_check: str | None = Field(
        default=None,
        description="How to verify this step succeeded (e.g. 'ip no longer appears in auth logs')",
    )
    requires_human_approval: bool = False


class RemediationPlan(BaseModel):
    """Strict structured output from the Containment Agent (smart tier).

    Despite the legacy name, this is a *containment* plan for a security finding.
    Kept as ``RemediationPlan`` because the DB column / orchestrator / hitl_gate /
    audit_log all reference this name and renaming churns more than it gains.
    """

    incident_id: str
    root_cause_summary: str = Field(description="One-line summary of the security root cause")
    confidence_score: float = Field(ge=0.0, le=1.0)
    estimated_total_duration_minutes: int = 5
    steps: list[RemediationStep]
    alternative_approaches: list[str] | None = None
    escalation_recommendation: str | None = Field(
        default=None,
        description="If confidence < 0.6, who to escalate to (e.g. SecOps lead / IR lead)",
    )
    post_resolution_monitoring: str = Field(
        default=(
            "Monitor SIEM for recurrence of the matched indicators (source IPs, "
            "user principals, host hashes) for 24 hours post-containment."
        )
    )


# Back-compat aliases used by older code paths
ContainmentPlan = RemediationPlan
ContainmentStep = RemediationStep
