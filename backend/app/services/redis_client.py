from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from typing import Any

import redis.asyncio as redis

from app.config import settings

logger = logging.getLogger("sentinelforge.redis")

_client: redis.Redis | None = None

# Stream names (Section 6 — Event Flow)
STREAMS = {
    "raw": "alerts:raw",
    "triaged": "alerts:triaged",
    "investigated": "alerts:investigated",
    "planned": "alerts:planned",
    "executing": "alerts:executing",
    "resolved": "alerts:resolved",
    "dlq": "alerts:dlq",
}

# Consumer groups
GROUPS = {
    "raw": "group:triage",
    "triaged": "group:investigation",
    "investigated": "group:remediation",
    "planned": "group:execution",
    "resolved": "group:pir",
}


async def init_redis() -> None:
    global _client
    if _client is not None:
        return
    _client = redis.from_url(settings.redis_url, decode_responses=True)
    await _client.ping()
    # Ensure consumer groups exist (idempotent)
    for stage, stream in STREAMS.items():
        group = GROUPS.get(stage)
        if not group:
            continue
        try:
            await _client.xgroup_create(stream, group, id="0-0", mkstream=True)
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                logger.warning("xgroup_create %s/%s: %s", stream, group, exc)
    logger.info("Redis connected + consumer groups ready")


async def close_redis() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
        logger.info("Redis closed")


def get_redis() -> redis.Redis:
    if _client is None:
        raise RuntimeError("Redis not initialised — did lifespan run?")
    return _client


# ---------- Streams ----------


async def publish_to_stream(stage: str, payload: dict[str, Any]) -> str:
    """Append a message to a pipeline stream. Returns the message id."""
    stream = STREAMS[stage]
    client = get_redis()
    msg_id = await client.xadd(stream, {"data": json.dumps(payload, default=str)})
    return msg_id


async def read_from_group(
    stage: str, consumer: str, count: int = 10, block_ms: int = 5000
) -> list[tuple[str, dict[str, Any]]]:
    """Read messages for a consumer group. Returns (message_id, payload) tuples."""
    stream = STREAMS[stage]
    group = GROUPS[stage]
    client = get_redis()
    resp = await client.xreadgroup(
        groupname=group,
        consumername=consumer,
        streams={stream: ">"},
        count=count,
        block=block_ms,
    )
    out: list[tuple[str, dict[str, Any]]] = []
    for _stream, entries in resp:
        for msg_id, fields in entries:
            try:
                payload = json.loads(fields.get("data", "{}"))
            except Exception:
                payload = {"_raw": fields}
            out.append((msg_id, payload))
    return out


async def ack_message(stage: str, msg_id: str) -> None:
    client = get_redis()
    await client.xack(STREAMS[stage], GROUPS[stage], msg_id)


async def move_to_dlq(stage: str, msg_id: str, payload: dict[str, Any], reason: str) -> None:
    client = get_redis()
    await client.xack(STREAMS[stage], GROUPS[stage], msg_id)
    await client.xadd(
        STREAMS["dlq"],
        {
            "source_stream": STREAMS[stage],
            "reason": reason,
            "data": json.dumps(payload, default=str),
        },
    )


# ---------- Pub/Sub (real-time dashboard) ----------


def _channel(incident_id: str) -> str:
    return f"incident:{incident_id}:events"


async def publish_event(incident_id: str, event: dict[str, Any]) -> None:
    """Push a real-time event for the SSE dashboard AND append it to a bounded
    Redis list keyed per-incident so a reconnecting client (or a fresh page
    load) can replay the recent event history."""
    client = get_redis()
    payload = json.dumps(event, default=str)
    await client.publish(_channel(incident_id), payload)
    # Bounded event log for REST rehydration + SSE Last-Event-ID replay.
    # The list is consumed LIFO (LPUSH) so the newest event is at index 0.
    list_key = f"incident:{incident_id}:event_log"
    pipe = client.pipeline()
    pipe.lpush(list_key, payload)
    pipe.ltrim(list_key, 0, 999)  # keep only the most recent 1000 events
    pipe.expire(list_key, 60 * 60 * 24)  # 24h TTL after the last write
    await pipe.execute()


async def fetch_event_log(incident_id: str, limit: int = 500) -> list[dict[str, Any]]:
    """Return the most-recent dashboard events for an incident (newest first)."""
    client = get_redis()
    raw = await client.lrange(f"incident:{incident_id}:event_log", 0, max(limit - 1, 0))
    out: list[dict[str, Any]] = []
    for r in raw:
        try:
            out.append(json.loads(r))
        except Exception:
            continue
    return out


async def replay_events_from(incident_id: str, after_index: int) -> list[dict[str, Any]]:
    """Return events strictly newer than ``after_index`` (0 = newest).

    ``after_index`` is the index the client last processed (per the SSE
    Last-Event-ID convention we expose the list index as the event id).
    Returns events oldest-first so they can be yielded in chronological order.
    """
    client = get_redis()
    # The newest event is at index 0; the index ``after_index`` was the newest
    # event the client saw, so anything from ``after_index - 1`` down to 0 is
    # new. We read up to ``after_index`` entries and skip the newest ``after_index``.
    if after_index <= 0:
        # client has never seen anything — give them everything (oldest-first)
        raw = await client.lrange(f"incident:{incident_id}:event_log", 0, -1)
    else:
        raw = await client.lrange(f"incident:{incident_id}:event_log", 0, after_index - 1)
    out: list[dict[str, Any]] = []
    for r in reversed(raw):  # reverse → oldest-first
        try:
            out.append(json.loads(r))
        except Exception:
            continue
    return out


async def subscribe(incident_id: str) -> AsyncIterator[dict[str, Any]]:
    """Async iterator yielding events for one incident."""
    client = get_redis()
    pubsub = client.pubsub()
    await pubsub.subscribe(_channel(incident_id))
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    yield json.loads(message["data"])
                except Exception:
                    continue
    finally:
        await pubsub.unsubscribe(_channel(incident_id))
        await pubsub.aclose()


async def subscribe_all() -> AsyncIterator[dict[str, Any]]:
    """Wildcard subscription for the dashboard 'all active incidents' stream."""
    client = get_redis()
    pubsub = client.pubsub()
    await pubsub.psubscribe("incident:*:events")
    try:
        async for message in pubsub.listen():
            if message["type"] == "pmessage":
                try:
                    yield json.loads(message["data"])
                except Exception:
                    continue
    finally:
        await pubsub.punsubscribe("incident:*:events")
        await pubsub.aclose()
