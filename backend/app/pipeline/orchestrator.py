"""Pipeline orchestrator — Redis stream consumer that drives all agents.

Runs as a separate worker process (``python -m app.pipeline.orchestrator``).
Consumes each stream with a consumer group and dispatches to the matching agent.

                alerts:raw ─► triage_agent ─► alerts:triaged
              alerts:triaged ─► investigation_agent ─► alerts:investigated
        alerts:investigated ─► remediation_agent ─► alerts:planned
              alerts:planned ─► hitl_gate ─► execution_agent ─► alerts:executing
              alerts:resolved ─► pir_agent
"""
from __future__ import annotations

import asyncio
import logging
import signal
import time
import uuid
from typing import Any

from app.db import incidents as incidents_db
from app.schemas.events import make_event
from app.services.redis_client import (
    ack_message,
    move_to_dlq,
    publish_event,
    publish_to_stream,
    read_from_group,
)

logger = logging.getLogger("sentinelforge.orchestrator")

CONSUMER = f"worker-{uuid.uuid4().hex[:6]}"
_RUNNING = True


async def _dispatch_triage(msg_id: str, payload: dict[str, Any]) -> None:
    from app.agents.triage_agent import TriageAgent
    from app.schemas.triage import Verdict

    incident_id = payload["incident_id"]
    await incidents_db.update_incident(incident_id, status="TRIAGING")
    await publish_event(incident_id, make_event("triage.started", incident_id))
    agent = TriageAgent()
    result = await agent.run(incident_id, payload.get("signal", {}))

    verdict = result.verdict
    # FALSE_POSITIVE -> dismiss; BENIGN_ANOMALY -> dismiss (not malicious); NEEDS_HUMAN -> escalate;
    # TRUE_POSITIVE -> investigate.
    if verdict == Verdict.FALSE_POSITIVE or verdict == Verdict.BENIGN_ANOMALY:
        await incidents_db.update_incident(
            incident_id,
            status="DISMISSED",
            severity=result.severity.value,
            category=result.root_cause_category.value,
            triage_result=result.model_dump(mode="json"),
            is_false_positive=(verdict == Verdict.FALSE_POSITIVE),
        )
    elif verdict == Verdict.NEEDS_HUMAN or not result.auto_investigatable:
        await incidents_db.update_incident(
            incident_id,
            status="ESCALATED",
            severity=result.severity.value,
            category=result.root_cause_category.value,
            triage_result=result.model_dump(mode="json"),
        )
    else:
        await incidents_db.update_incident(
            incident_id,
            severity=result.severity.value,
            category=result.root_cause_category.value,
            triage_result=result.model_dump(mode="json"),
            status="INVESTIGATING",
        )
        await publish_to_stream("triaged", {"incident_id": incident_id, "triage": result.model_dump(mode="json")})
    await publish_event(incident_id, make_event("triage.complete", incident_id, severity=result.severity.value, verdict=verdict.value))


async def _dispatch_investigation(msg_id: str, payload: dict[str, Any]) -> None:
    from app.agents.investigation_agent import InvestigationAgent

    incident_id = payload["incident_id"]
    await publish_event(incident_id, make_event("investigation.started", incident_id))
    agent = InvestigationAgent()
    finding = await agent.run(incident_id)
    await incidents_db.update_incident(
        incident_id,
        status="PLANNING",
        investigation_finding=finding.model_dump(mode="json"),
    )
    await publish_event(incident_id, make_event("investigation.complete", incident_id, confidence=finding.confidence_score))
    await publish_to_stream("investigated", {"incident_id": incident_id, "finding": finding.model_dump(mode="json")})


async def _dispatch_remediation(msg_id: str, payload: dict[str, Any]) -> None:
    from app.agents.remediation_agent import RemediationAgent
    from app.pipeline.hitl_gate import apply_gate

    incident_id = payload["incident_id"]
    incident = await incidents_db.get_incident(incident_id)
    if not incident:
        return
    agent = RemediationAgent()
    plan = await agent.run(incident_id, incident.get("investigation_finding") or payload.get("finding") or {})
    await incidents_db.update_incident(
        incident_id,
        remediation_plan=plan.model_dump(mode="json"),
    )
    await publish_event(
        incident_id,
        make_event("plan.generated", incident_id, steps=len(plan.steps), confidence=plan.confidence_score),
    )
    if plan.confidence_score < 0.6 and plan.escalation_recommendation:
        await incidents_db.update_incident(incident_id, status="ESCALATED")
        return
    await apply_gate(incident_id, incident["severity"], [s.model_dump() for s in plan.steps])


async def _dispatch_execution(msg_id: str, payload: dict[str, Any]) -> None:
    from app.agents.execution_agent import ExecutionAgent

    incident_id = payload["incident_id"]
    if payload.get("resume"):
        # a step was approved; ack and let the execution agent pick up pending steps
        pass
    await incidents_db.update_incident(incident_id, status="EXECUTING")
    agent = ExecutionAgent()
    resolved = await agent.run(incident_id)
    if resolved:
        await incidents_db.update_incident(incident_id, status="RESOLVED", auto_resolved=True)
        await publish_event(incident_id, make_event("incident.resolved", incident_id))
        await publish_to_stream("resolved", {"incident_id": incident_id})


async def _dispatch_pir(msg_id: str, payload: dict[str, Any]) -> None:
    from app.agents.pir_agent import PIRAgent

    incident_id = payload["incident_id"]
    agent = PIRAgent()
    report = await agent.run(incident_id)
    await incidents_db.update_incident(incident_id, pir_report=report)
    await publish_event(incident_id, make_event("pir.complete", incident_id))


_HANDLERS = {
    "raw": ("triage", _dispatch_triage),
    "triaged": ("investigation", _dispatch_investigation),
    "investigated": ("remediation", _dispatch_remediation),
    "planned": ("execution", _dispatch_execution),
    "resolved": ("pir", _dispatch_pir),
}


async def _consume_stage(stage: str) -> None:
    group_key, handler = _HANDLERS[stage]
    while _RUNNING:
        try:
            messages = await read_from_group(stage, f"{CONSUMER}-{group_key}", count=5, block_ms=2000)
        except Exception as exc:
            logger.warning("read_from_group(%s) failed: %s", stage, exc)
            await asyncio.sleep(2)
            continue
        for msg_id, payload in messages:
            try:
                t0 = time.monotonic()
                await handler(msg_id, payload)
                from app.services.metrics import record_stage
                record_stage(group_key, time.monotonic() - t0)
                await ack_message(stage, msg_id)
            except Exception as exc:
                logger.exception("handler %s failed for %s: %s", stage, msg_id, exc)
                await move_to_dlq(stage, msg_id, payload, str(exc))


async def run() -> None:
    global _RUNNING
    from app.db.connection import init_db
    from app.services.redis_client import init_redis

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-5s [%(name)s] %(message)s")
    logger.info("orchestrator %s starting", CONSUMER)
    await init_db()
    await init_redis()

    loop = asyncio.get_event_loop()
    stop = loop.create_future()

    def _stop(*_):
        _RUNNING = False
        if not loop.is_closed():
            loop.call_soon_threadsafe(stop.set_result, None)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except NotImplementedError:
            pass

    tasks = [asyncio.create_task(_consume_stage(stage)) for stage in _HANDLERS]
    # HITL timeout auto-approve sweeper
    tasks.append(asyncio.create_task(_safely_run_sweeper()))
    await stop
    logger.info("orchestrator shutting down")
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


async def _safely_run_sweeper() -> None:
    """Run the HITL auto-approve sweeper, restarting it if it ever exits."""
    from app.pipeline.hitl_gate import scheduled_auto_approve

    while _RUNNING:
        try:
            await scheduled_auto_approve(interval_seconds=30)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("auto-approve sweeper crashed: %s — restarting", exc)
            await asyncio.sleep(10)


if __name__ == "__main__":
    asyncio.run(run())
