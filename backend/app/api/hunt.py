"""Proactive threat-hunting API.

``POST /api/v1/hunt`` turns a MITRE technique or free-text seed into a hunt plan
with runnable queries — usable standalone (hunt of the week) or wired to an
incident's techniques. The incident-scoped variant lives on the incidents
router (``POST /api/v1/incidents/{id}/hunt``).
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from app.schemas.hunt import HuntPlan
from app.services.threat_hunt import generate_hunt_plan

router = APIRouter()


class HuntRequest(BaseModel):
    seed: str | None = None
    technique_id: str | None = None
    technique_ids: list[str] | None = None
    context: dict | None = None


@router.post("")
async def create_hunt(req: HuntRequest) -> HuntPlan:
    tids = req.technique_ids or ([req.technique_id] if req.technique_id else [])
    seed = req.seed or (", ".join(tids) if tids else "ad-hoc hunt")
    return await generate_hunt_plan(seed=seed, technique_ids=tids, context=req.context)
