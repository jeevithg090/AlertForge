"""Notification tools — Slack + PagerDuty."""

from __future__ import annotations

import aiohttp

from app.config import settings
from app.tools.registry import tool


@tool(
    name="send_slack_message",
    description="Send a message to a Slack channel. Use for incident notifications and status updates.",
    parameters={
        "type": "object",
        "properties": {
            "channel": {"type": "string", "description": "Slack channel ID or name"},
            "message": {"type": "string", "description": "Message text (supports Slack markdown)"},
            "severity": {"type": "string", "enum": ["info", "warning", "critical"]},
        },
        "required": ["channel", "message"],
    },
)
async def send_slack_message(channel: str, message: str, severity: str = "info") -> dict:
    if settings.slack_bot_token and not settings.use_mock_tools:
        return await _real_slack(channel, message, severity)
    return {
        "sent": True,
        "channel": channel,
        "message": message[:100],
        "severity": severity,
        "mock": True,
    }


async def _real_slack(channel, message, severity):
    color = {"info": "#36a64f", "warning": "#FFB800", "critical": "#FF4444"}.get(
        severity, "#36a64f"
    )
    payload = {
        "channel": channel,
        "attachments": [{"color": color, "text": message, "mrkdwn_in": ["text"]}],
    }
    headers = {
        "Authorization": f"Bearer {settings.slack_bot_token}",
        "Content-Type": "application/json",
    }
    async with (
        aiohttp.ClientSession() as session,
        session.post(
            "https://slack.com/api/chat.postMessage", json=payload, headers=headers
        ) as resp,
    ):
        data = await resp.json()
        return {"sent": data.get("ok", False), "channel": channel, "ts": data.get("ts")}


@tool(
    name="create_pagerduty_incident",
    description="Create or update a PagerDuty incident for escalation. Use when human on-call needs to be paged.",
    parameters={
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "severity": {"type": "string", "enum": ["critical", "error", "warning", "info"]},
            "service_id": {"type": "string", "description": "PagerDuty service ID"},
            "incident_id": {"type": "string", "description": "SentinelForge incident ID to link"},
        },
        "required": ["summary", "severity"],
    },
)
async def create_pagerduty_incident(
    summary: str, severity: str = "critical", service_id: str = "", incident_id: str = ""
) -> dict:
    return {
        "created": True,
        "pagerduty_incident_key": f"PD-{incident_id[:8] if incident_id else 'mock'}",
        "summary": summary[:200],
        "severity": severity,
        "mock": True,
    }
