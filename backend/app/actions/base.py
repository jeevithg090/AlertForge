"""Action adapter contract.

Every containment action is a typed adapter implementing the same lifecycle so
the executor can treat firewalls, IdPs, and EDRs uniformly — and so every
mutating action has a *tested, mandatory rollback path*. Real adapters (a cloud
security-group revoke, an Okta suspend) drop in behind this interface unchanged.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

from app.actions.models import ActionRequest


@dataclass
class BlastRadius:
    """What a proposed action would touch — surfaced to the operator pre-execution."""

    summary: str
    entities: list[str] = field(default_factory=list)
    reversible: bool = True


@dataclass
class PlannedEffect:
    """The simulated result of a dry-run (no mutation performed)."""

    summary: str
    details: dict = field(default_factory=dict)


class ActionAdapter(abc.ABC):
    """Lifecycle: preflight → dry_run → execute → verify → (rollback)."""

    action_type: str = "unknown"
    simulated: bool = True  # real adapters set False

    @abc.abstractmethod
    async def preflight(self, req: ActionRequest) -> BlastRadius:
        """Compute what this action will touch. No mutation."""

    @abc.abstractmethod
    async def dry_run(self, req: ActionRequest) -> PlannedEffect:
        """Simulate the action and return the effect that *would* happen."""

    @abc.abstractmethod
    async def execute(self, req: ActionRequest) -> dict:
        """Perform the action for real. Must be idempotent given req.idempotency_key."""

    @abc.abstractmethod
    async def verify(self, req: ActionRequest, effect: dict) -> bool:
        """Confirm the action actually took effect."""

    @abc.abstractmethod
    async def rollback(self, req: ActionRequest, effect: dict) -> bool:
        """Undo the action. Mandatory for every mutating adapter."""
