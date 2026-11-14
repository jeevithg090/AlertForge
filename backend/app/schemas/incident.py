from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class AlertSource(str, Enum):
    SIEM = "siem"
    EDR = "edr"
    IDS = "ids"
    EMAIL = "email"  # phishing reports / SOAR email ingestion
    SLACK = "slack"  # analyst-pasted alerts
    PAGERDUTY = "pagerduty"
    WEBHOOK = "webhook"
    GENERIC = "generic"
    # Legacy alias kept so older payloads still normalize cleanly
    PROMETHEUS = "siem"


class IncidentStatus(str, Enum):
    INGESTED = "INGESTED"
    TRIAGING = "TRIAGING"
    INVESTIGATING = "INVESTIGATING"
    PLANNING = "PLANNING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"  # false positive
    ESCALATED = "ESCALATED"


class Severity(str, Enum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


class RootCauseCategory(str, Enum):
    SECURITY = "SECURITY"  # default for a SOC triage
    CREDENTIAL_ABUSE = "CREDENTIAL_ABUSE"
    MALWARE = "MALWARE"
    EXPLOIT = "EXPLOIT"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    RECONNAISSANCE = "RECONNAISSANCE"
    MISCONFIGURATION = "MISCONFIGURATION"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    APPLICATION = "APPLICATION"
    DATA = "DATA"
    NETWORK = "NETWORK"
    CAPACITY = "CAPACITY"


class BlastRadius(str, Enum):
    SINGLE_HOST = "SINGLE_HOST"
    SINGLE_USER = "SINGLE_USER"
    SERVICE = "SERVICE"
    CLUSTER = "CLUSTER"
    WORKSPACE = "WORKSPACE"
    REGION = "REGION"
    GLOBAL = "GLOBAL"


class IncidentSignal(BaseModel):
    """Normalized finding produced by the Ingestion Gateway (fast-tier structured output).

    Domain: SOC — security alert. Extracts security-relevant fields: source IPs,
    user principals, hostnames, ATT&CK-relevant symptoms, technologies/versions.
    """

    signal_id: str = Field(default_factory=lambda: str(UUID(int=0)))
    raw_input: str = Field(description="Preserved verbatim for audit")
    source: AlertSource = AlertSource.GENERIC
    affected_service: str = "unknown"
    affected_hosts: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(
        default_factory=list,
        description="User principals / accounts referenced by the finding",
    )
    source_ips: list[str] = Field(
        default_factory=list,
        description="External / suspicious IP addresses pulled from the finding",
    )
    affected_region: str | None = None
    metric_name: str | None = None
    metric_value: float | None = None
    metric_threshold: float | None = None
    technologies: list[str] = Field(
        default_factory=list,
        description="Affected product/vendor strings (e.g. 'nginx 1.21.4') used for CVE enrichment",
    )
    alert_message: str = ""
    first_seen_at: datetime = Field(default_factory=datetime.utcnow)
    ingested_at: datetime = Field(default_factory=datetime.utcnow)
    raw_labels: dict = Field(default_factory=dict)


class Incident(BaseModel):
    incident_id: str
    signal_id: str
    status: IncidentStatus = IncidentStatus.INGESTED
    severity: Severity = Severity.P3_MEDIUM
    category: RootCauseCategory = RootCauseCategory.SECURITY
    source: AlertSource = AlertSource.GENERIC
    affected_service: str
    affected_hosts: list[str] = Field(default_factory=list)
    alert_message: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
