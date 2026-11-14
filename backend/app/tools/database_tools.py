"""Database status tool."""

from __future__ import annotations

import random

from app.tools.registry import tool


@tool(
    name="query_database_status",
    description="Query PostgreSQL database status — active connections, pool usage, replication lag, slow queries. Use for database-related incidents.",
    parameters={
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Database host or cluster name"},
            "include_slow_queries": {"type": "boolean", "default": True},
        },
        "required": ["host"],
    },
)
async def query_database_status(host: str, include_slow_queries: bool = True) -> dict:
    return _mock_db_status(host, include_slow_queries)


def _mock_db_status(host, include_slow):
    active = random.randint(80, 150)
    max_conn = 200
    result = {
        "host": host,
        "status": "healthy" if active < max_conn * 0.8 else "degraded",
        "active_connections": active,
        "max_connections": max_conn,
        "connection_pool_usage_pct": round(active / max_conn * 100, 1),
        "replication_lag_ms": random.randint(0, 50),
        "uptime_hours": random.randint(100, 2000),
        "cache_hit_ratio": round(random.uniform(0.92, 0.99), 3),
        "deadlocks": random.randint(0, 3),
        "disk_usage_pct": round(random.uniform(45, 78), 1),
    }
    if include_slow and active > 100:
        result["slow_queries"] = [
            {
                "query": "SELECT * FROM orders WHERE status = 'pending' AND created_at > NOW() - INTERVAL '1 hour'",
                "duration_ms": random.randint(2000, 8000),
                "pid": random.randint(1000, 9999),
            },
            {
                "query": "UPDATE inventory SET stock = stock - 1 WHERE product_id = $1",
                "duration_ms": random.randint(1500, 5000),
                "pid": random.randint(1000, 9999),
            },
        ]
    return result
