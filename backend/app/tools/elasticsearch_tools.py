"""Elasticsearch / OpenSearch log query tool."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import aiohttp

from app.config import settings
from app.tools.registry import tool


@tool(
    name="query_elasticsearch",
    description=(
        "Query Elasticsearch/OpenSearch for log events. Use this to look for "
        "error patterns, stack traces, and correlated events in a time window "
        "around the incident."
    ),
    parameters={
        "type": "object",
        "properties": {
            "index_pattern": {"type": "string", "description": "e.g. 'prod-app-logs-*'"},
            "query_string": {"type": "string", "description": "Lucene query string"},
            "time_from": {"type": "string", "description": "ISO 8601 timestamp"},
            "time_to": {"type": "string", "description": "ISO 8601 timestamp"},
            "size": {"type": "integer", "default": 50, "description": "Max log lines to return"},
        },
        "required": ["index_pattern", "query_string", "time_from", "time_to"],
    },
)
async def query_elasticsearch(
    index_pattern: str,
    query_string: str,
    time_from: str,
    time_to: str,
    size: int = 50,
) -> dict:
    if settings.elasticsearch_url and not settings.use_mock_tools:
        return await _real_query(index_pattern, query_string, time_from, time_to, size)
    return _mock_query(index_pattern, query_string, time_from, time_to, size)


async def _real_query(index_pattern, query_string, time_from, time_to, size):
    body = {
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": query_string}},
                    {"range": {"@timestamp": {"gte": time_from, "lte": time_to}}},
                ]
            }
        },
        "size": size,
        "sort": [{"@timestamp": "desc"}],
    }
    headers = {}
    if settings.elasticsearch_api_key:
        headers["Authorization"] = f"ApiKey {settings.elasticsearch_api_key}"
    async with aiohttp.ClientSession() as session:
        url = f"{settings.elasticsearch_url}/{index_pattern}/_search"
        async with session.post(
            url, json=body, headers=headers, timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            data = await resp.json()
            hits = data.get("hits", {}).get("hits", [])
            return {
                "total": data.get("hits", {}).get("total", {}).get("value", len(hits)),
                "hits": [h["_source"] for h in hits],
            }


def _mock_query(index_pattern, query_string, time_from, time_to, size):
    """Return realistic mock log data based on the query."""
    qs = query_string.lower()
    now = datetime.now(timezone.utc)
    hits = []
    n = int(size) if size is not None else 10

    if "oom" in qs or "outofmemory" in qs or "memory" in qs:
        for _i in range(min(n, 15)):
            ts = now - timedelta(minutes=random.randint(1, 30))
            hits.append(
                {
                    "@timestamp": ts.isoformat(),
                    "level": "ERROR",
                    "service": "checkout-service",
                    "message": f"java.lang.OutOfMemoryError: Java heap space (RSS: {random.randint(12, 16)}GB)",
                    "stack_trace": "at com.checkout.CartService.processCart(CartService.java:142)\n  at com.checkout.CheckoutHandler.handle(CheckoutHandler.java:89)",
                    "host": f"checkout-service-{random.randint(1, 5)}-pod-{random.randint(100, 999)}",
                }
            )
    elif "500" in qs or "error" in qs or "exception" in qs:
        for _i in range(min(n, 20)):
            ts = now - timedelta(minutes=random.randint(1, 25))
            hits.append(
                {
                    "@timestamp": ts.isoformat(),
                    "level": "ERROR",
                    "service": "checkout-service",
                    "message": f"HTTP 500 Internal Server Error: {random.choice(['Connection pool exhausted', 'Database timeout', 'Upstream service unavailable'])}",
                    "host": f"checkout-service-{random.randint(1, 5)}-pod-{random.randint(100, 999)}",
                    "status_code": 500,
                }
            )
    elif "503" in qs:
        for _i in range(min(n, 25)):
            ts = now - timedelta(minutes=random.randint(1, 20))
            hits.append(
                {
                    "@timestamp": ts.isoformat(),
                    "level": "ERROR",
                    "service": "checkout-service",
                    "message": "HTTP 503 Service Unavailable: upstream connection refused",
                    "host": f"checkout-service-{random.randint(1, 5)}-pod-{random.randint(100, 999)}",
                    "status_code": 503,
                }
            )
    elif "ssh" in qs or "login" in qs or "auth" in qs:
        for _i in range(min(n, 30)):
            ts = now - timedelta(minutes=random.randint(1, 10))
            hits.append(
                {
                    "@timestamp": ts.isoformat(),
                    "level": "WARN",
                    "service": "sshd",
                    "message": f"Failed password for invalid user {random.choice(['admin', 'root', 'test', 'user'])} from {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)} port {random.randint(40000, 65000)}",
                    "host": "bastion-01",
                }
            )
    else:
        for _i in range(min(n, 5)):
            ts = now - timedelta(minutes=random.randint(1, 60))
            hits.append(
                {
                    "@timestamp": ts.isoformat(),
                    "level": "INFO",
                    "service": "app",
                    "message": f"Request processed successfully (latency: {random.randint(50, 500)}ms)",
                    "host": f"app-{random.randint(1, 3)}-pod-{random.randint(100, 999)}",
                }
            )

    return {"total": len(hits), "hits": hits, "index": index_pattern, "query": query_string}
