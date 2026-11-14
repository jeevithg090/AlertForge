from __future__ import annotations

import json

from fastapi import APIRouter, Request
from sse_starlette.sse import EventSourceResponse

from app.services.redis_client import (
    fetch_event_log,
    replay_events_from,
    subscribe,
    subscribe_all,
)

router = APIRouter()

# Events are sent as unnamed SSE messages so a browser EventSource receives all
# of them via ``onmessage``; the event kind is the ``type`` field of the JSON
# payload. (Named events would each need their own addEventListener.)


def _parse_last_event_id(request: Request) -> int:
    """SSE Last-Event-ID is sent by browsers automatically on reconnect."""
    raw = request.headers.get("last-event-id") or request.query_params.get("last_event_id")
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 0


@router.get("/incidents/{incident_id}/stream")
async def incident_stream(incident_id: str, request: Request):
    """SSE stream of real-time updates for one incident.

    On reconnect, replays any events the client missed using the bounded Redis
    event-log (Last-Event-ID convention: the event id is the index in the list).
    """

    async def event_generator():
        last_seen = _parse_last_event_id(request)
        # Replay missed events first, oldest-first.
        replayed = await replay_events_from(incident_id, after_index=last_seen)
        for i, event in enumerate(replayed, start=1):
            if await request.is_disconnected():
                return
            # The index after replay is the count of events the client has now seen.
            yield {
                "id": str(i),
                "data": json.dumps(event, default=str),
            }
        # Now stream live events.
        next_index = len(replayed) + 1
        async for event in subscribe(incident_id):
            if await request.is_disconnected():
                break
            yield {
                "id": str(next_index),
                "data": json.dumps(event, default=str),
            }
            next_index += 1

    return EventSourceResponse(event_generator())


@router.get("/incidents/stream/all")
async def all_incidents_stream(request: Request):
    """SSE stream of all active incidents (wildcard pub/sub)."""

    async def event_generator():
        async for event in subscribe_all():
            if await request.is_disconnected():
                break
            yield {"data": json.dumps(event, default=str)}

    return EventSourceResponse(event_generator())


@router.get("/incidents/{incident_id}/events/recent")
async def recent_events(incident_id: str, limit: int = 200):
    """REST rehydration endpoint (mirrors /incidents/{id}/events for convenience)."""
    events = await fetch_event_log(incident_id, limit=limit)
    return {"incident_id": incident_id, "events": events, "count": len(events)}
