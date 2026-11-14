"""Threat-hunt schemas.

A hunt turns a *reactive* finding into *proactive* searching: "we saw brute
force against one host — where else is this actor active, and did any attempt
succeed?" Each hypothesis is falsifiable and ships with concrete, runnable
queries so an analyst can execute the hunt immediately instead of translating a
vague idea into SIEM syntax.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class HuntPriority(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class HuntQuery(BaseModel):
    """A concrete, copy-pasteable detection query for one platform."""

    platform: str = Field(
        default="spl",
        description="Query language / platform: spl (Splunk) | eql | kql | lucene | sigma | sql",
    )
    query: str = Field(description="The runnable query text")
    description: str = Field(default="", description="What this query looks for")


class HuntHypothesis(BaseModel):
    """One falsifiable hunt idea derived from a technique or incident."""

    title: str = Field(
        description="Short imperative hypothesis, e.g. 'Brute force succeeded and lateral movement began'"
    )
    rationale: str = Field(default="", description="Why this is worth hunting given the finding")
    mitre_technique_id: str = Field(default="", description="Primary ATT&CK technique, e.g. T1110")
    mitre_technique_name: str = Field(default="")
    tactic: str = Field(default="", description="ATT&CK tactic")
    data_sources: list[str] = Field(
        default_factory=list,
        description="Where to look: auth logs, EDR process events, netflow, proxy, etc.",
    )
    queries: list[HuntQuery] = Field(default_factory=list)
    expected_findings: str = Field(
        default="", description="What a positive result looks like (confirms the hypothesis)"
    )
    false_positive_notes: str = Field(
        default="", description="Benign explanations to rule out before escalating"
    )
    priority: HuntPriority = HuntPriority.MEDIUM


class HuntPlan(BaseModel):
    """A set of hunt hypotheses generated for a technique, incident, or free text."""

    generated_from: str = Field(description="Technique id, incident id, or free-text seed")
    summary: str = Field(default="", description="One-line framing of the overall hunt")
    hypotheses: list[HuntHypothesis] = Field(default_factory=list)
