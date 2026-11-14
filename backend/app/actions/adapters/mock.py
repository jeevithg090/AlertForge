"""Simulation adapters.

These implement the full adapter lifecycle against an in-memory fake so the
system is end-to-end exercisable (and unit-testable) without real firewalls/IdPs.
Every result is tagged ``simulated: True`` so it's never mistaken for a real
mutation. Swapping in a real adapter is a drop-in: implement the same five
methods against the vendor API and set ``simulated = False``.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone

from app.actions.base import ActionAdapter, BlastRadius, PlannedEffect
from app.actions.models import ActionRequest


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class _SimAdapter(ActionAdapter):
    """Shared simulation behavior: an in-memory 'applied' set gives idempotency
    and lets verify()/rollback() be meaningful."""

    simulated = True
    _verb = "act on"
    _noun = "resource"

    def __init__(self) -> None:
        self._applied: dict[str, dict] = {}

    async def preflight(self, req: ActionRequest) -> BlastRadius:
        return BlastRadius(
            summary=f"Would {self._verb} 1 {self._noun}: {req.target}",
            entities=[req.target],
            reversible=True,
        )

    async def dry_run(self, req: ActionRequest) -> PlannedEffect:
        return PlannedEffect(
            summary=f"[DRY-RUN] would {self._verb} {req.target} (no change made)",
            details={"action_type": req.action_type, "target": req.target, "simulated": True},
        )

    async def execute(self, req: ActionRequest) -> dict:
        key = req.idempotency_key
        if key in self._applied:  # idempotent
            return {**self._applied[key], "idempotent_replay": True}
        effect = {
            "action_type": req.action_type,
            "target": req.target,
            "ref_id": f"{req.action_type}-{random.randint(10000, 99999)}",
            "applied_at": _now(),
            "reason": req.reason or "SentinelForge containment",
            "simulated": True,
        }
        self._applied[key] = effect
        return effect

    async def verify(self, req: ActionRequest, effect: dict) -> bool:
        return req.idempotency_key in self._applied and not effect.get("error")

    async def rollback(self, req: ActionRequest, effect: dict) -> bool:
        self._applied.pop(req.idempotency_key, None)
        return True


class MockFirewallAdapter(_SimAdapter):
    action_type = "block_ip"
    _verb = "block IP at the edge firewall"
    _noun = "IP address"


class MockIdPSuspendAdapter(_SimAdapter):
    action_type = "suspend_account"
    _verb = "suspend account in the IdP"
    _noun = "user principal"


class MockIdPRotateAdapter(_SimAdapter):
    action_type = "rotate_credentials"
    _verb = "rotate credentials for"
    _noun = "user principal"


class MockEDRIsolateAdapter(_SimAdapter):
    action_type = "isolate_host"
    _verb = "isolate host via EDR"
    _noun = "host"


class MockQuarantineAdapter(_SimAdapter):
    action_type = "quarantine_file"
    _verb = "quarantine file"
    _noun = "file"


def default_adapters() -> list[ActionAdapter]:
    return [
        MockFirewallAdapter(),
        MockIdPSuspendAdapter(),
        MockIdPRotateAdapter(),
        MockEDRIsolateAdapter(),
        MockQuarantineAdapter(),
    ]
