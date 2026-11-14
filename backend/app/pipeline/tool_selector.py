"""Deterministic tool selection for the Investigation Agent.

Open-source models degrade when handed 20 tool schemas at once — more prompt
tokens per round, and a much higher rate of hallucinated / wrong tool calls.
This module picks a small, relevant, **read-only** toolset for a given finding
from cheap deterministic signals (the triage category, MITRE techniques, and
which entity types are present). No model call is needed to choose tools.

Containment tools (block_ip / suspend_account / isolate_host / rotate_credentials)
are intentionally never selected here — those run only in the Execution Agent
after the human-in-the-loop gate, never during read-only investigation.
"""

from __future__ import annotations

# Always-useful investigative starting points.
CORE_TOOLS = ["search_runbook", "query_siem_auth_logs", "query_elasticsearch"]

# MITRE technique / category → additional tools worth calling.
_TECHNIQUE_TOOLS: list[tuple[frozenset[str], tuple[str, ...]]] = [
    (
        frozenset({"T1110", "T1078", "T1621", "T1556"}),  # credential access
        ("query_siem_auth_logs", "enrich_user_identity", "lookup_ip_reputation"),
    ),
    (
        frozenset({"T1486", "T1059", "T1204", "T1055", "T1027"}),  # execution / malware
        ("query_edr_endpoint", "search_runbook"),
    ),
    (
        frozenset({"T1041", "T1048", "T1567", "T1030"}),  # exfiltration
        ("query_elasticsearch", "lookup_ip_reputation", "get_service_dependencies"),
    ),
    (
        frozenset({"T1190", "T1203", "T1211", "T1505"}),  # exploit public app
        ("search_cve_database", "query_elasticsearch", "get_recent_deployments"),
    ),
    (
        frozenset({"T1021", "T1210", "T1570", "T1550"}),  # lateral movement
        ("query_edr_endpoint", "enrich_user_identity", "get_kubernetes_pod_status"),
    ),
    (
        frozenset({"T1595", "T1046", "T1590", "T1592"}),  # reconnaissance
        ("lookup_ip_reputation", "query_elasticsearch"),
    ),
    (
        frozenset({"T1071", "T1572", "T1090", "T1568"}),  # command & control / network
        ("lookup_ip_reputation", "check_firewall_rules"),
    ),
]

_CATEGORY_TOOLS: dict[str, tuple[str, ...]] = {
    "CREDENTIAL_ABUSE": ("query_siem_auth_logs", "enrich_user_identity", "lookup_ip_reputation"),
    "MALWARE": ("query_edr_endpoint", "search_runbook"),
    "DATA_EXFILTRATION": (
        "query_elasticsearch",
        "lookup_ip_reputation",
        "get_service_dependencies",
    ),
    "EXPLOIT": ("search_cve_database", "query_elasticsearch", "get_recent_deployments"),
    "LATERAL_MOVEMENT": ("query_edr_endpoint", "enrich_user_identity", "get_kubernetes_pod_status"),
    "RECONNAISSANCE": ("lookup_ip_reputation", "query_elasticsearch"),
    "NETWORK": ("lookup_ip_reputation", "check_firewall_rules"),
}


def select_investigation_tools(
    *,
    category: str | None = None,
    technique_ids: list[str] | None = None,
    has_ips: bool = False,
    has_users: bool = False,
    has_hosts: bool = False,
    has_tech: bool = False,
    max_tools: int = 8,
) -> list[str]:
    """Return an ordered, de-duplicated list of tool names to expose (<= max_tools)."""
    picked: list[str] = []

    def add(*names: str) -> None:
        for n in names:
            if n not in picked:
                picked.append(n)

    add(*CORE_TOOLS)

    # Entity-driven enrichment: only offer a tool if its entity type is present.
    if has_ips:
        add("lookup_ip_reputation")
    if has_users:
        add("enrich_user_identity")
    if has_hosts:
        add("query_edr_endpoint")
    if has_tech:
        add("search_cve_database")

    cat = (category or "").upper()
    if cat in _CATEGORY_TOOLS:
        add(*_CATEGORY_TOOLS[cat])

    tset = {t.strip().upper() for t in (technique_ids or []) if t}
    # Normalize sub-techniques (T1110.001 -> T1110) so mappings still match.
    tset |= {t.split(".")[0] for t in tset}
    for ids, tools in _TECHNIQUE_TOOLS:
        if tset & ids:
            add(*tools)

    return picked[:max_tools]
