from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    source: str
    detail: str
    timestamp: datetime | None = None


class CVEReference(BaseModel):
    cve_id: str
    severity: str
    url: str | None = None


class TimelineEvent(BaseModel):
    timestamp: datetime
    event: str
    severity: str | None = None


class IOC(BaseModel):
    """An indicator of compromise surfaced during investigation."""

    type: str = Field(description="ip | user | host | file_hash | url | cve")
    value: str
    verdict: str = Field(default="UNKNOWN", description="MALICIOUS | SUSPICIOUS | BENIGN | UNKNOWN")
    source: str = Field(default="", description="tool that produced this IOC (e.g. virustotal)")


class InvestigationFinding(BaseModel):
    """Output of the Investigation Agent (smart tier + concurrent tool calls + MCP)."""

    incident_id: str
    root_cause: str
    evidence: list[Evidence] = Field(default_factory=list)
    confidence_score: float = Field(ge=0.0, le=1.0)
    contributing_factors: list[str] = Field(default_factory=list)
    affected_dependencies: list[str] = Field(default_factory=list)
    related_cves: list[CVEReference] | None = None
    relevant_runbook_id: str | None = None
    timeline: list[TimelineEvent] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    total_investigation_duration_seconds: float = 0.0
    iocs: list[IOC] = Field(
        default_factory=list,
        description="Indicators of compromise surfaced by the investigatory tools",
    )
    blast_radius_assessment: str | None = Field(
        default=None,
        description="Narrative assessment of how far the attacker could have moved",
    )