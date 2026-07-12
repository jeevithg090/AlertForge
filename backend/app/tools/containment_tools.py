"""Containment action tools — invoked by the Execution Agent after HITL approval.

These are deliberately mock-safe: in production they would call the real
firewall API / IdP / EDR isolation endpoint, but they always return a credible
result so the demo can complete end to end.
"""
from __future__ import annotations

import asyncio
import random
from datetime import datetime, timezone

from app.tools.registry import tool


@tool(
    name="block_ip",
    description="Block an IP address at the edge firewall (after human approval). Returns the firewall rule id that was created.",
    parameters={
        "type": "object",
        "properties": {
            "ip_address": {"type": "string"},
            "duration_hours": {"type": "integer", "default": 24},
            "reason": {"type": "string"},
        },
        "required": ["ip_address"],
    },
)
async def block_ip(ip_address: str, duration_hours: int = 24, reason: str = "") -> dict:
    await asyncio.sleep(0.2)
    return {
        "ip_address": ip_address,
        "rule_id": f"fw-block-{random.randint(10000, 99999)}",
        "action": "block",
        "duration_hours": duration_hours,
        "applied_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason or "Blocked by SentinelForge containment",
    }


@tool(
    name="suspend_account",
    description="Suspend a user principal in the IdP (after human approval). Returns the suspension ticket id.",
    parameters={
        "type": "object",
        "properties": {
            "username": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["username"],
    },
)
async def suspend_account(username: str, reason: str = "") -> dict:
    await asyncio.sleep(0.2)
    return {
        "username": username,
        "suspended": True,
        "ticket_id": f"idp-suspend-{random.randint(10000, 99999)}",
        "applied_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason or "Suspended by SentinelForge containment",
    }


@tool(
    name="isolate_host",
    description="Quarantine a host from the network via EDR (after human approval). Returns the isolation job id.",
    parameters={
        "type": "object",
        "properties": {
            "hostname": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["hostname"],
    },
)
async def isolate_host(hostname: str, reason: str = "") -> dict:
    await asyncio.sleep(0.2)
    return {
        "hostname": hostname,
        "isolated": True,
        "job_id": f"edr-isolate-{random.randint(10000, 99999)}",
        "applied_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason or "Isolated by SentinelForge containment",
    }


@tool(
    name="rotate_credentials",
    description="Rotate credentials for a user principal in the IdP (after human approval). Returns the rotation ticket id.",
    parameters={
        "type": "object",
        "properties": {
            "username": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["username"],
    },
)
async def rotate_credentials(username: str, reason: str = "") -> dict:
    await asyncio.sleep(0.2)
    return {
        "username": username,
        "rotated": True,
        "ticket_id": f"idp-rotate-{random.randint(10000, 99999)}",
        "applied_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason or "Rotated by SentinelForge containment",
    }