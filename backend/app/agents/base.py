"""Base agent — common persona + event publishing helpers.

The war room personas (Addendum A) are central labels rendered in the UI:
CMDR / ANLST / STRAT / OPS / CHRON.
"""

from __future__ import annotations

import logging
from typing import Any

from app.schemas.events import make_event
from app.services.redis_client import publish_event

logger = logging.getLogger("sentinelforge.agents")


class AgentPersona:
    PERSONA = "AGENT"
    LABEL = "AGENT"
    COLOR = "#888888"

    async def say(self, incident_id: str, text: str, **extra: Any) -> None:
        """Emit a conversational war-room message the dashboard renders as a chat turn."""
        await publish_event(
            incident_id,
            make_event(
                "agent.message",
                incident_id,
                persona=self.PERSONA,
                label=self.LABEL,
                color=self.COLOR,
                text=text,
                **extra,
            ),
        )
