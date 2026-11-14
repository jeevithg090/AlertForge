"""Typed models for the action safety layer."""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone


class TargetKind(str, enum.Enum):
    IP = "ip"
    USER = "user"
    HOST = "host"
    FILE_HASH = "file_hash"
    CONFIG = "config"
    SHELL = "shell"
    NONE = "none"


# action_type -> (is_mutating, target_kind). Anything not listed is treated as a
# non-mutating, unknown action and is denied by default unless it's a notification.
ACTION_SPEC: dict[str, tuple[bool, TargetKind]] = {
    "notification": (False, TargetKind.NONE),
    "human_action": (False, TargetKind.NONE),
    "block_ip": (True, TargetKind.IP),
    "firewall_change": (True, TargetKind.IP),
    "suspend_account": (True, TargetKind.USER),
    "rotate_credentials": (True, TargetKind.USER),
    "isolate_host": (True, TargetKind.HOST),
    "quarantine_file": (True, TargetKind.FILE_HASH),
    "configuration_change": (True, TargetKind.CONFIG),
    "shell_command": (True, TargetKind.SHELL),
    "api_call": (True, TargetKind.CONFIG),
}


def is_mutating(action_type: str) -> bool:
    return ACTION_SPEC.get(action_type, (True, TargetKind.NONE))[0]


def target_kind_for(action_type: str) -> TargetKind:
    return ACTION_SPEC.get(action_type, (True, TargetKind.NONE))[1]


@dataclass(frozen=True)
class ActionRequest:
    """A single proposed containment action, normalized for authorization."""

    action_type: str
    target: str  # primary target value (an IP / username / hostname / …)
    incident_id: str
    severity: str = "P3_MEDIUM"
    reason: str = ""
    requested_by: str = "system:execution_agent"
    params: dict = field(default_factory=dict)

    @property
    def target_kind(self) -> TargetKind:
        return target_kind_for(self.action_type)

    @property
    def is_mutating(self) -> bool:
        return is_mutating(self.action_type)

    @property
    def idempotency_key(self) -> str:
        basis = f"{self.incident_id}|{self.action_type}|{self.target.strip().lower()}"
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]


class Decision(str, enum.Enum):
    ALLOW = "ALLOW"  # non-mutating, safe → may run without a human
    DENY = "DENY"  # prohibited — never runs, even with approval
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"  # mutating — needs one human approver
    REQUIRE_TWO_PERSON = "REQUIRE_TWO_PERSON"  # high-stakes — needs two distinct approvers


@dataclass(frozen=True)
class GuardrailDecision:
    decision: Decision
    reasons: tuple[str, ...] = ()
    matched_rule: str | None = None

    @property
    def blocked(self) -> bool:
        return self.decision == Decision.DENY

    @property
    def needs_human(self) -> bool:
        return self.decision in (Decision.REQUIRE_APPROVAL, Decision.REQUIRE_TWO_PERSON)

    @property
    def approvers_required(self) -> int:
        return {Decision.REQUIRE_TWO_PERSON: 2}.get(self.decision, 1 if self.needs_human else 0)


@dataclass(frozen=True)
class GuardrailContext:
    """Everything the (pure) policy needs beyond the request itself.

    Injected rather than read from globals so evaluation is deterministic and
    trivially testable.
    """

    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    incident_action_count: int = 0  # mutating actions already taken on this incident
    window_action_count: int = 0  # mutating actions across the whole system in the window
    approvers: tuple[str, ...] = ()  # distinct human approvers who have signed off


class ActionStatus(str, enum.Enum):
    PROPOSED = "PROPOSED"
    DENIED = "DENIED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    SKIPPED_DUPLICATE = "SKIPPED_DUPLICATE"
    DRY_RUN_OK = "DRY_RUN_OK"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass
class ActionResult:
    status: ActionStatus
    request: ActionRequest
    decision: GuardrailDecision | None = None
    effect: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)
    rolled_back: bool = False
    error: str | None = None

    @property
    def executed(self) -> bool:
        return self.status in (ActionStatus.VERIFIED, ActionStatus.DRY_RUN_OK)
