from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from app.schemas.incident import BlastRadius, RootCauseCategory, Severity


class Verdict(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN_ANOMALY = "BENIGN_ANOMALY"
    NEEDS_HUMAN = "NEEDS_HUMAN"


class AttackTechnique(BaseModel):
    """A single MITRE ATT&CK mapping for the finding."""

    technique_id: str = Field(description="ATT&CK technique id e.g. T1110 (Brute Force)")
    name: str = Field(default="")
    tactic: str = Field(
        default="",
        description="ATT&CK tactic (Initial Access / Credential Access / Exfiltration / ...)",
    )
    confidence: float = Field(default=0.7, ge=0.0, le=1.0, description="0..1 mapping confidence")


class TriageResult(BaseModel):
    """Output of the Triage Agent (smart tier, + reasoning trace on P1/P2)."""

    incident_id: str
    severity: Severity = Severity.P3_MEDIUM
    verdict: Verdict = Verdict.NEEDS_HUMAN
    is_false_positive: bool = False
    false_positive_reason: str | None = None
    root_cause_category: RootCauseCategory = RootCauseCategory.SECURITY
    affected_services: list[str] = Field(default_factory=list)
    estimated_users_affected: int | None = None
    blast_radius: BlastRadius = BlastRadius.SERVICE
    attack_techniques: list[AttackTechnique] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique mappings — empty if 'BENIGN_ANOMALY' or 'FALSE_POSITIVE'.",
    )
    investigation_priority: list[str] = Field(
        default_factory=list,
        description="Ordered list of what to investigate first (e.g. 'check source IP reputation').",
    )
    similar_past_incidents: list[str] | None = Field(
        default=None, description="Incident IDs from history that look similar"
    )
    auto_investigatable: bool = Field(
        default=True,
        description="Can this be investigated automatically or does it need immediate human attention?",
    )
    thinking_trace: str | None = Field(
        default=None,
        description="Model's reasoning process if thinking mode was used",
    )