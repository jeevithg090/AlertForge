"""Tool registry — auto-registration decorator + JSON schema export.

Each tool is a coroutine decorated with @tool(name, description, parameters).
The registry collects them and exposes:
- get_tool_schemas() -> list of OpenAI function tool definitions
- execute_tool(name, args) -> result
"""
from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("sentinelforge.tools")

_REGISTRY: dict[str, dict[str, Any]] = {}


def tool(
    name: str,
    description: str,
    parameters: dict[str, Any],
):
    """Decorator to register a tool function."""

    def decorator(fn: Callable):
        _REGISTRY[name] = {
            "fn": fn,
            "name": name,
            "description": description,
            "parameters": parameters,
        }
        return fn

    return decorator


def get_tool_schemas(names: list[str] | None = None) -> list[dict[str, Any]]:
    """Return OpenAI function tool definitions.

    Pass ``names`` to export only a subset (in the given order). Sending a small,
    relevant toolset instead of all ~20 tools is a major efficiency win for OSS
    models: fewer prompt tokens per round and far fewer hallucinated tool names.
    Unknown names are skipped.
    """
    items = (
        [_REGISTRY[n] for n in names if n in _REGISTRY]
        if names is not None
        else list(_REGISTRY.values())
    )
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["parameters"],
            },
        }
        for t in items
    ]


async def execute_tool(name: str, args: dict[str, Any]) -> Any:
    """Execute a registered tool by name."""
    if name not in _REGISTRY:
        raise ValueError(f"unknown tool: {name}")
    fn = _REGISTRY[name]["fn"]
    try:
        if inspect.iscoroutinefunction(fn):
            return await fn(**args)
        return fn(**args)
    except Exception as exc:
        logger.error("tool %s failed: %s", name, exc, exc_info=True)
        return {"error": str(exc), "tool": name}


def list_tools() -> list[str]:
    return list(_REGISTRY.keys())


# Import all tool modules to trigger registration.
# Order matters only for log readability; registration is idempotent.
from app.tools import (  # noqa: E402, F401
    cert_tools,
    containment_tools,
    database_tools,
    dependency_tools,
    deployment_tools,
    edr_tools,
    elasticsearch_tools,
    firewall_tools,
    identity_tools,
    k8s_tools,
    notification_tools,
    prometheus_tools,
    runbook_tools,
    # --- SOC pivot additions ---
    siem_tools,
    threat_intel_tools,
)
