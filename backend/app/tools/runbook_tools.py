"""Runbook semantic search tool."""

from __future__ import annotations

from app.tools.registry import tool


@tool(
    name="search_runbook",
    description="Semantic search over the internal runbook knowledge base. Use to find relevant troubleshooting procedures for this type of incident.",
    parameters={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Natural language description of the problem",
            },
            "top_k": {"type": "integer", "default": 3},
        },
        "required": ["query"],
    },
)
async def search_runbook(query: str, top_k: int = 3) -> dict:
    try:
        from app.services.runbook_indexer import search_runbooks

        results = await search_runbooks(query, top_k)
        if results:
            return {"query": query, "results": results, "count": len(results), "source": "chromadb"}
    except Exception:
        pass
    return _mock_search(query, top_k)


def _mock_search(query, top_k):
    q = query.lower()
    runbooks = []
    if "memory" in q or "oom" in q or "leak" in q:
        runbooks = [
            {
                "title": "Memory Leak — Java Service",
                "path": "runbooks/high-cpu/memory-leak.md",
                "relevance": 0.94,
                "summary": "Steps to diagnose and remediate Java heap memory leaks. Includes heap dump collection, GC tuning, and restart procedures.",
            },
            {
                "title": "CPU Throttling in Kubernetes",
                "path": "runbooks/high-cpu/cpu-throttling.md",
                "relevance": 0.72,
                "summary": "Identify CPU throttling via Prometheus metrics and adjust resource limits.",
            },
        ]
    elif "ssl" in q or "cert" in q or "certificate" in q:
        runbooks = [
            {
                "title": "SSL Certificate Expiry",
                "path": "runbooks/networking/ssl-expiry.md",
                "relevance": 0.96,
                "summary": "Automated certificate renewal via cert-manager and Let's Encrypt. Includes emergency manual renewal steps.",
            },
        ]
    elif "dns" in q or "network" in q:
        runbooks = [
            {
                "title": "DNS Resolution Failure",
                "path": "runbooks/networking/dns-resolution-failure.md",
                "relevance": 0.91,
                "summary": "Troubleshoot DNS resolution failures in Kubernetes clusters. CoreDNS debugging and fallback configuration.",
            },
        ]
    elif "ssh" in q or "login" in q or "brute" in q or "auth" in q:
        runbooks = [
            {
                "title": "Failed Login Spike / Brute Force",
                "path": "runbooks/security/failed-login-spike.md",
                "relevance": 0.95,
                "summary": "Respond to brute force SSH attacks. Includes IP blocking via firewall, fail2ban configuration, and incident escalation.",
            },
        ]
    elif "database" in q or "connection" in q or "pool" in q:
        runbooks = [
            {
                "title": "Database Connection Pool Exhaustion",
                "path": "runbooks/database/connection-pool-exhaustion.md",
                "relevance": 0.93,
                "summary": "Diagnose and fix PostgreSQL connection pool exhaustion. Includes pgBouncer tuning and application-side connection management.",
            },
        ]
    else:
        runbooks = [
            {
                "title": "General Incident Response",
                "path": "runbooks/general/incident-response.md",
                "relevance": 0.5,
                "summary": "Standard incident response procedure for unknown incident types.",
            },
        ]
    return {
        "query": query,
        "results": runbooks[:top_k],
        "count": len(runbooks[:top_k]),
        "source": "mock",
    }
