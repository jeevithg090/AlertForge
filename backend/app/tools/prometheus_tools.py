"""Prometheus metrics query tool."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import aiohttp

from app.config import settings
from app.tools.registry import tool


@tool(
    name="query_prometheus_metrics",
    description="Run a PromQL query to get time-series metrics. Use this to understand trends before/after the alert fired.",
    parameters={
        "type": "object",
        "properties": {
            "promql": {"type": "string", "description": "Valid PromQL expression"},
            "start": {"type": "string"},
            "end": {"type": "string"},
            "step": {"type": "string", "description": "Resolution step, e.g. '1m' or '5m'"},
        },
        "required": ["promql", "start", "end"],
    },
)
async def query_prometheus_metrics(promql: str, start: str, end: str, step: str = "1m") -> dict:
    if settings.prometheus_url and not settings.use_mock_tools:
        return await _real_query(promql, start, end, step)
    return _mock_query(promql, start, end, step)


async def _real_query(promql, start, end, step):
    async with aiohttp.ClientSession() as session:
        url = f"{settings.prometheus_url}/api/v1/query_range"
        params = {"query": promql, "start": start, "end": end, "step": step}
        async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            return await resp.json()


def _mock_query(promql, start, end, step):
    promql_lower = promql.lower()
    now = datetime.now(timezone.utc)
    values = []
    for i in range(30):
        ts = now - timedelta(minutes=30 - i)
        if "memory" in promql_lower or "rss" in promql_lower:
            val = 8.0 + (i * 0.3) + random.uniform(-0.1, 0.1)
        elif "cpu" in promql_lower:
            val = 45.0 + random.uniform(-5, 15)
        elif "error" in promql_lower or "5" in promql_lower:
            val = random.randint(0, 120) if i > 15 else random.randint(0, 5)
        elif "connection" in promql_lower or "pool" in promql_lower:
            val = 60.0 + (i * 1.5) + random.uniform(-2, 2)
        else:
            val = random.uniform(0.5, 5.0)
        values.append([ts.timestamp(), str(round(val, 2))])

    return {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {
                    "metric": {"__name__": promql.split("{")[0], "instance": "prod-01"},
                    "values": values,
                }
            ],
        },
        "query": promql,
    }
