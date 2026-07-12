"""SIEM auth-log query tool.

Mocks a searchable auth-log/event store (Wazuh/Splunk-style). Pass a query
string plus an optional time window. Gated: returns real data when
ELASTICSEARCH_URL is set; otherwise returns scenario-aware mock events.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from app.config import settings
from app.tools.registry import tool


@tool(
    name="query_siem_auth_logs",
    description=(
        "Query the SIEM (Wazuh/Splunk-style) for authentication and security events. "
        "Use this to surface failed logins, suspicious user activity, privilege use, "
        "and correlated events in a time window around the finding."
    ),
    parameters={
        "type": "object",
        "properties": {
            "index": {
                "type": "string",
                "description": "e.g. 'auth-*' or 'linux-auth-*'. Defaults to 'auth-*'.",
                "default": "auth-*",
            },
            "query": {
                "type": "string",
                "description": "Lucene/KQL query string (e.g. 'event.action:logged_in*').",
            },
            "time_from": {"type": "string", "description": "ISO 8601 timestamp (optional)"},
            "time_to": {"type": "string", "description": "ISO 8601 timestamp (optional)"},
            "hours_back": {
                "type": "integer",
                "default": 1,
                "description": "If time_from/time_to omitted: query this many hours back from now.",
            },
            "size": {"type": "integer", "default": 50},
        },
        "required": ["query"],
    },
)
async def query_siem_auth_logs(
    query: str,
    index: str = "auth-*",
    time_from: str = "",
    time_to: str = "",
    hours_back: int = 1,
    size: int = 50,
) -> dict:
    if settings.elasticsearch_url and not settings.use_mock_tools:
        return await _real_siem(index, query, time_from, time_to, hours_back, size)
    return _mock_siem(index, query, time_from, time_to, hours_back, size)


async def _real_siem(index, query, time_from, time_to, hours_back, size) -> dict:
    from app.tools.elasticsearch_tools import _real_query

    now = datetime.now(timezone.utc)
    tf = time_from or (now - timedelta(hours=hours_back)).isoformat()
    tt = time_to or now.isoformat()
    return await _real_query(index, query, tf, tt, size)


def _mock_siem(index, query, time_from, time_to, hours_back, size) -> dict:
    q = (query or "").lower()
    now = datetime.now(timezone.utc)
    tf = datetime.fromisoformat(time_from) if time_from else now - timedelta(hours=hours_back)
    tt = datetime.fromisoformat(time_to) if time_to else now
    span_min = max(1, int((tt - tf).total_seconds() // 60))

    malicious_pool = ["203.0.113.42", "198.51.100.7", "45.142.120.99", "193.32.162.144"]
    users = ["j.doe", "admin", "svc-account", "root", "analyst1"]
    events: list[dict] = []

    if "failed" in q or "logon" in q or "login" in q or "auth" in q:
        n = min(int(size), 40)
        for _ in range(n):
            ts = tt - timedelta(seconds=random.randint(0, span_min * 60))
            ip = random.choice(malicious_pool + ["10.0.4.18"] * 2)
            user = random.choice(users)
            events.append(
                {
                    "@timestamp": ts.isoformat(),
                    "event.action": "failed_login",
                    "user": user,
                    "source_ip": ip,
                    "host": random.choice(["bastion-01", "prod-app-03", "k8s-worker-7"]),
                    "message": f"Failed password for invalid user {user} from {ip}",
                    "level": "WARN",
                }
            )
    elif "privileged" in q or "sudo" in q or "admin" in q:
        for _ in range(min(int(size), 10)):
            ts = tt - timedelta(seconds=random.randint(0, span_min * 60))
            user = random.choice(["admin", "root", "svc-account"])
            events.append(
                {
                    "@timestamp": ts.isoformat(),
                    "event.action": "privileged_action",
                    "user": user,
                    "host": random.choice(["bastion-01", "prod-db-02"]),
                    "message": f"User {user} performed sudo /bin/bash on host",
                    "level": "INFO",
                }
            )
    else:
        for _ in range(min(int(size), 8)):
            ts = tt - timedelta(seconds=random.randint(0, span_min * 60))
            events.append(
                {
                    "@timestamp": ts.isoformat(),
                    "event.action": "successful_login",
                    "user": random.choice(users),
                    "source_ip": random.choice(malicious_pool + ["10.0.4.18", "192.168.1.40", "172.16.4.5"]),
                    "host": "bastion-01",
                    "message": "Accepted publickey for user from internal IP",
                    "level": "INFO",
                }
            )

    return {
        "index": index,
        "query": query,
        "events": events,
        "hits": events,
        "total": len(events),
        "time_from": tf.isoformat(),
        "time_to": tt.isoformat(),
    }