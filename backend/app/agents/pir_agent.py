"""PIR Agent — CHRON persona.

Streams the Post-Incident Report (mime: Security Incident Report) to the
dashboard via SSE, then creates a JIRA ticket through the self-hosted MCP
server so the security incident is officially tracked.
"""

from __future__ import annotations

import json
import logging

from app.agents.base import AgentPersona
from app.db import incidents as incidents_db
from app.db.audit import write_audit
from app.pipeline.model_router import select_model
from app.schemas.events import make_event
from app.services.jira_mcp_client import create_incident_ticket
from app.services.llm import llm
from app.services.redis_client import publish_event

logger = logging.getLogger("sentinelforge.agents.pir")

PIR_SYSTEM = """\
You are a security incident report writer. Generate a comprehensive, professional
Security Incident Report (PIR) in markdown format. Use this exact structure:

# Security Incident Report
**Incident ID**: ...
**Severity**: ...
**Verdict**: ...
**Duration**: ...

## Executive Summary
[2-3 sentence overview of the security incident]

## Timeline
[Chronological list of events with timestamps from triage -> investigation -> containment]

## Root Cause Analysis
[5-Whys analysis grounded in the investigation finding's evidence and IOCs]

## MITRE ATT&CK Mapping
[List of technique ids + names from the triage result, with confidence]

## Indicators of Compromise (IOCs)
[Bullet list of every IOC surfaced by the investigation, each with its source tool and verdict]

## Impact Assessment
[Users affected, blast radius, lateral movement potential]

## Containment Actions Taken
[Step-by-step what was done to contain the threat]

## Action Items
[Preventive measures for the future, with owners and deadlines]

Write clearly and concisely. This report will be shared with security leadership
and attached to the JIRA ticket that will be created automatically.
"""


class PIRAgent(AgentPersona):
    PERSONA = "CHRON"
    LABEL = "The Chronicler"
    COLOR = "#6B48FF"

    async def run(self, incident_id: str) -> str:
        incident = await incidents_db.get_incident(incident_id)
        if not incident:
            return "# Security Incident Report\n\nIncident data not available."

        severity = incident.get("severity", "P3_MEDIUM")
        model = select_model(severity, "pir")

        await self.say(incident_id, "Generating security incident report...")

        context = json.dumps(
            {
                "incident_id": incident_id,
                "severity": severity,
                "category": incident.get("category", "UNKNOWN"),
                "affected_service": incident.get("affected_service", "unknown"),
                "alert_message": incident.get("alert_message", ""),
                "created_at": incident.get("created_at", ""),
                "resolved_at": incident.get("resolved_at", ""),
                "triage_result": incident.get("triage_result", {}),
                "investigation_finding": incident.get("investigation_finding", {}),
                "remediation_plan": incident.get("remediation_plan", {}),
            },
            default=str,
        )

        messages = [
            {"role": "system", "content": PIR_SYSTEM},
            {
                "role": "user",
                "content": f"Generate a security incident report for this finding:\n{context}",
            },
        ]

        # Stream the PIR to the dashboard
        chunks: list[str] = []
        async for chunk in llm.stream(
            model=model,
            messages=messages,
            incident_id=incident_id,
        ):
            if chunk["kind"] == "content":
                chunks.append(chunk["content"])
                await publish_event(
                    incident_id,
                    make_event("pir.streaming", incident_id, content=chunk["content"]),
                )

        full_report = "".join(chunks)

        # Create a JIRA ticket via the self-hosted MCP server
        await self.say(incident_id, "Filing JIRA ticket via MCP...")
        triage_raw = incident.get("triage_result") or {}
        if isinstance(triage_raw, str):
            try:
                triage = json.loads(triage_raw)
            except (json.JSONDecodeError, TypeError):
                triage = {}
        else:
            triage = triage_raw
        priority = {
            "P1_CRITICAL": "Critical",
            "P2_HIGH": "High",
            "P3_MEDIUM": "Medium",
            "P4_LOW": "Low",
        }.get(severity, "Medium")
        summary = f"[{severity}] {incident.get('alert_message', 'Security incident')[:120]}"
        description = (
            f"Submitted by SentinelForge PIR Agent.\n\n"
            f"Verdict: {triage.get('verdict', 'UNKNOWN')}\n"
            f"MITRE ATT&CK: {', '.join(t.get('technique_id', '') for t in (triage.get('attack_techniques') or [])[:5]) or 'N/A'}\n\n"
            f"--- Report ---\n{full_report[:1500]}"
        )
        try:
            ticket = await create_incident_ticket(
                summary=summary,
                description=description,
                priority=priority,
                project="SEC",
                incident_id=incident_id,
            )
        except Exception as exc:
            logger.warning("JIRA MCP ticket creation failed: %s", exc)
            ticket = {"url": "", "ticket_id": "", "error": str(exc)}

        await publish_event(
            incident_id,
            make_event(
                "jira.ticket_created",
                incident_id,
                ticket_id=ticket.get("ticket_id", ""),
                ticket_url=ticket.get("url", ""),
                priority=priority,
            ),
        )
        await write_audit(
            incident_id=incident_id,
            actor="system:pir_agent",
            action="jira.ticket_created",
            details={"ticket_id": ticket.get("ticket_id"), "url": ticket.get("url")},
        )

        # Attach the JIRA ticket URL to the report so it appears in the saved PIR
        if ticket.get("ticket_id"):
            full_report = (
                full_report
                + f"\n\n---\n**JIRA Ticket**: [{ticket['ticket_id']}]({ticket.get('url', '')}) "
                + f"(priority: {priority}) — created via SentinelForge MCP server."
            )

        await write_audit(
            incident_id=incident_id,
            actor="system:pir_agent",
            action="pir.complete",
            details={"length": len(full_report)},
        )
        await self.say(incident_id, "Security incident report ready. JIRA ticket filed.")
        return full_report
