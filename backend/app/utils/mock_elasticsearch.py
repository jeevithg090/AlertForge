#!/usr/bin/env python3
"""Mock Elasticsearch server — returns realistic log data for demo scenarios.

Run: python -m app.utils.mock_elasticsearch
Listens on :9200 and responds to /_search requests with realistic mock data.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Mock Elasticsearch")


@app.post("/{index_pattern}/_search")
async def search(request: Request, index_pattern: str):
    body = await request.json()
    query = body.get("query", {})
    size = body.get("size", 50)

    # Extract query string
    qs = ""
    bool_q = query.get("bool", {})
    must = bool_q.get("must", [])
    for clause in must:
        if "query_string" in clause:
            qs = clause["query_string"].get("query", "")
            break

    hits = _generate_hits(qs, size)
    return JSONResponse(
        {
            "hits": {
                "total": {"value": len(hits), "relation": "eq"},
                "hits": [{"_source": h, "_id": f"mock_{i}"} for i, h in enumerate(hits)],
            }
        }
    )


@app.get("/_cluster/health")
async def health():
    return {"status": "green", "cluster_name": "mock-es", "number_of_nodes": 1}


def _generate_hits(query_string: str, size: int) -> list[dict]:
    qs = query_string.lower()
    now = datetime.now(timezone.utc)
    hits = []

    if "oom" in qs or "outofmemory" in qs or "memory" in qs:
        for _i in range(min(size, 15)):
            ts = now - timedelta(minutes=random.randint(1, 30))
            hits.append(
                {
                    "@timestamp": ts.isoformat(),
                    "level": "ERROR",
                    "service": "checkout-service",
                    "message": f"java.lang.OutOfMemoryError: Java heap space (RSS: {random.randint(12, 16)}GB)",
                    "stack_trace": "at com.checkout.CartService.processCart(CartService.java:142)",
                    "host": f"checkout-service-{random.randint(1, 5)}-pod-{random.randint(100, 999)}",
                }
            )
    elif "500" in qs or "error" in qs:
        for _i in range(min(size, 20)):
            ts = now - timedelta(minutes=random.randint(1, 25))
            hits.append(
                {
                    "@timestamp": ts.isoformat(),
                    "level": "ERROR",
                    "service": "checkout-service",
                    "message": f"HTTP 500: {random.choice(['Connection pool exhausted', 'Database timeout'])}",
                    "host": f"checkout-service-{random.randint(1, 5)}-pod-{random.randint(100, 999)}",
                    "status_code": 500,
                }
            )
    elif "503" in qs:
        for _i in range(min(size, 25)):
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
    elif "ssh" in qs or "login" in qs:
        for _i in range(min(size, 30)):
            ts = now - timedelta(minutes=random.randint(1, 10))
            hits.append(
                {
                    "@timestamp": ts.isoformat(),
                    "level": "WARN",
                    "service": "sshd",
                    "message": f"Failed password for invalid user {random.choice(['admin', 'root', 'test'])} from {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    "host": "bastion-01",
                }
            )
    else:
        for _i in range(min(size, 5)):
            ts = now - timedelta(minutes=random.randint(1, 60))
            hits.append(
                {
                    "@timestamp": ts.isoformat(),
                    "level": "INFO",
                    "service": "app",
                    "message": f"Request processed (latency: {random.randint(50, 500)}ms)",
                    "host": f"app-{random.randint(1, 3)}-pod-{random.randint(100, 999)}",
                }
            )

    return hits


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9200)
