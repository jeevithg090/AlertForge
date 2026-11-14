"""Service dependency graph tool."""

from __future__ import annotations

from app.tools.registry import tool


@tool(
    name="get_service_dependencies",
    description="Get the upstream and downstream service dependencies for a given service. Use to trace blast radius through the dependency graph.",
    parameters={
        "type": "object",
        "properties": {
            "service": {"type": "string", "description": "Service name to query"},
            "direction": {
                "type": "string",
                "enum": ["upstream", "downstream", "both"],
                "default": "both",
            },
        },
        "required": ["service"],
    },
)
async def get_service_dependencies(service: str, direction: str = "both") -> dict:
    return _mock_deps(service, direction)


def _mock_deps(service, direction):
    graph = {
        "checkout-service": {
            "upstream": ["api-gateway", "web-frontend", "mobile-app"],
            "downstream": [
                "payment-gateway",
                "inventory-service",
                "user-auth",
                "postgres-primary",
                "redis-cache",
            ],
        },
        "payment-gateway": {
            "upstream": ["checkout-service", "subscription-service"],
            "downstream": ["stripe-api", "postgres-primary", "audit-logger"],
        },
        "user-auth": {
            "upstream": ["api-gateway", "checkout-service", "web-frontend"],
            "downstream": ["postgres-primary", "redis-cache", "ldap-server"],
        },
        "api-gateway": {
            "upstream": ["load-balancer", "cdn"],
            "downstream": ["checkout-service", "user-auth", "product-catalog", "search-service"],
        },
        "postgres-primary": {
            "upstream": ["checkout-service", "payment-gateway", "user-auth", "inventory-service"],
            "downstream": ["postgres-replica-1", "postgres-replica-2"],
        },
    }
    deps = graph.get(service, {"upstream": [], "downstream": []})
    result = {"service": service}
    if direction in ("upstream", "both"):
        result["upstream"] = deps["upstream"]
    if direction in ("downstream", "both"):
        result["downstream"] = deps["downstream"]
    return result
