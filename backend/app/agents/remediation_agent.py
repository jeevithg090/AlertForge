"""Containment Agent — STRAT persona (SOC edition).

Uses the smart-tier model with strict structured output to generate a validated
containment plan (RemediationPlan in the data layer). Double-validated: JSON
schema strict + Pydantic business rules.
"""

from __future__ import annotations

import json
import logging

from app.agents.base import AgentPersona
from app.db import incidents as incidents_db
from app.db.audit import write_audit
from app.pipeline.model_router import select_model
from app.schemas.remediation import RemediationPlan, RemediationRisk, RemediationStep
from app.services.llm import llm

logger = logging.getLogger("sentinelforge.agents.remediation")

CONTAINMENT_SYSTEM = """\
You are a senior security engineer (SOC + incident response) responsible for
writing containment plans. Given an investigation finding (root cause, IOCs,
evidence), produce a concrete, executable containment plan.

Each step MUST be atomic (one action, one verification).

Action vocabulary (use ONLY these for action_type):
- notification            — alert humans (auto-approved, LOW risk)
- block_ip                — block an IP at the edge firewall
- suspend_account         — suspend a user principal in the IdP
- isolate_host            — quarantine a host via EDR
- rotate_credentials      — rotate a user/service credential in the IdP
- quarantine_file         — quarantine a malicious file via EDR
- firewall_change         — apply a firewall rule change
- shell_command           — run an explicit shell command
- api_call                — invoke an external API
- configuration_change    — apply a configuration change
- human_action            — must be performed out-of-band by the analyst

Risk level assignment:
- LOW: read-only actions, notifications
- MEDIUM: configuration reads, non-destructive API calls, perimeter blocks of single IPs
- HIGH: configuration writes, suspending an account, rotating creds, isolating a host
- REQUIRES_APPROVAL: anything that could cause data loss, widespread service
  interruption, or impact to many users

For every HIGH-risk step, include a `rollback_procedure`. For every step, include
a concrete `validation_check` describing how the operator verifies it succeeded
(e.g. "the IP no longer appears in SIEM auth logs within 10 minutes").

Prefer the TOOLS the system exposes when possible:
- block_ip          — tool to invoke: "block_ip"
- suspend_account   — tool: "suspend_account"
- isolate_host      — tool: "isolate_host"
- rotate_credentials — tool: "rotate_credentials"

Rules:
- Confidence score < 0.6 must trigger an escalation_recommendation.
- post_resolution_monitoring is MANDATORY.
- Never silently take an irreversible action — set requires_human_approval=true.

Return a valid RemediationPlan JSON object.
"""


class RemediationAgent(AgentPersona):
    PERSONA = "STRAT"
    LABEL = "The Strategist"
    COLOR = "#FFB800"

    async def run(self, incident_id: str, investigation_finding: dict) -> RemediationPlan:
        incident = await incidents_db.get_incident(incident_id)
        severity = incident.get("severity", "P3_MEDIUM") if incident else "P3_MEDIUM"
        model = select_model(severity, "remediation")

        await self.say(incident_id, "Drafting containment plan from the investigation finding...")

        messages = [
            {"role": "system", "content": CONTAINMENT_SYSTEM},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "incident_id": incident_id,
                        "severity": severity,
                        "affected_service": incident.get("affected_service", "unknown")
                        if incident
                        else "unknown",
                        "triage_result": incident.get("triage_result", {}) if incident else {},
                        "investigation_finding": investigation_finding,
                    },
                    default=str,
                ),
            },
        ]

        if not llm.enabled:
            plan = self._heuristic_plan(incident_id, incident or {}, investigation_finding)
        else:
            plan = await llm.structured(
                model=model,
                messages=messages,
                schema_model=RemediationPlan,
                incident_id=incident_id,
            )
        plan.incident_id = incident_id

        if plan.confidence_score < 0.6 and not plan.escalation_recommendation:
            plan.escalation_recommendation = f"Low containment confidence ({plan.confidence_score:.0%}) — escalate to SecOps / IR lead"

        await self.say(
            incident_id,
            f"Containment plan ready: {len(plan.steps)} steps. "
            f"{sum(1 for s in plan.steps if s.requires_human_approval)} require approval.",
        )
        await write_audit(
            incident_id=incident_id,
            actor="system:remediation_agent",
            action="remediation.plan_generated",
            details={"steps": len(plan.steps), "confidence": plan.confidence_score},
        )
        return plan

    def _heuristic_plan(self, incident_id: str, incident: dict, finding: dict) -> RemediationPlan:
        """Deterministic containment plan for zero-key demo mode."""
        iocs = finding.get("iocs") or []
        steps: list[RemediationStep] = []
        n = 1
        # 1. Block every malicious / suspicious IP from the IOCs
        for ioc in iocs:
            if ioc.get("type") != "ip":
                continue
            ip = ioc.get("value", "")
            if not ip:
                continue
            already = any(
                s.tool_parameters and s.tool_parameters.get("ip_address") == ip for s in steps
            )
            if already:
                continue
            steps.append(
                RemediationStep(
                    step_number=n,
                    action_type="block_ip",
                    description=f"Block malicious IP {ip} at the edge firewall",
                    tool_to_invoke="block_ip",
                    tool_parameters={"ip_address": ip},
                    estimated_duration_seconds=15,
                    risk_level=RemediationRisk.REQUIRES_APPROVAL,
                    rollback_procedure=f"Remove firewall rule for {ip} to restore connectivity.",
                    validation_check=f"{ip} no longer appears in SIEM auth logs within 10 minutes.",
                    requires_human_approval=True,
                )
            )
            n += 1
        # 2. Suspend every suspicious / privileged user
        for ioc in iocs:
            if ioc.get("type") != "user":
                continue
            user = ioc.get("value", "")
            if not user:
                continue
            already = any(
                s.tool_parameters and s.tool_parameters.get("username") == user for s in steps
            )
            if already:
                continue
            steps.append(
                RemediationStep(
                    step_number=n,
                    action_type="suspend_account",
                    description=f"Suspend compromised account {user}",
                    tool_to_invoke="suspend_account",
                    tool_parameters={"username": user},
                    estimated_duration_seconds=15,
                    risk_level=RemediationRisk.HIGH,
                    rollback_procedure=f"Re-enable {user} in the IdP after credentials are rotated.",
                    validation_check=f"No new sessions for {user} in SIEM auth logs within 10 minutes.",
                    requires_human_approval=True,
                )
            )
            n += 1
        # 3. Isolate every compromised host
        for h in incident.get("affected_hosts", []) or []:
            steps.append(
                RemediationStep(
                    step_number=n,
                    action_type="isolate_host",
                    description=f"Isolate compromised host {h} via EDR",
                    tool_to_invoke="isolate_host",
                    tool_parameters={"hostname": h},
                    estimated_duration_seconds=30,
                    risk_level=RemediationRisk.HIGH,
                    rollback_procedure=f"Release EDR isolation on {h}.",
                    validation_check=f"{h} shows no outbound network connections in EDR.",
                    requires_human_approval=True,
                )
            )
            n += 1
        # 4. Always end with a SOC notification
        steps.append(
            RemediationStep(
                step_number=n,
                action_type="notification",
                description="Notify on-call SecOps lead in #soc-primary",
                tool_to_invoke=None,
                estimated_duration_seconds=5,
                risk_level=RemediationRisk.LOW,
                rollback_procedure=None,
                validation_check="Slack message acknowledged.",
                requires_human_approval=False,
            )
        )

        return RemediationPlan(
            incident_id=incident_id,
            root_cause_summary=finding.get("root_cause", "Security finding under investigation")[
                :200
            ],
            confidence_score=min(0.85, 0.55 + 0.08 * len(steps)),
            estimated_total_duration_minutes=2,
            steps=steps,
            post_resolution_monitoring=(
                "Monitor SIEM for 24h for recurrence of matched IOCs (source IPs, user principals, host hashes)."
            ),
        )
