"""Kubernetes pod status tool."""

from __future__ import annotations

import random

from app.tools.registry import tool


@tool(
    name="get_kubernetes_pod_status",
    description="Get current status of Kubernetes pods for a namespace/deployment. Use to check if pods are crashing, restarting, or OOMKilled.",
    parameters={
        "type": "object",
        "properties": {
            "namespace": {"type": "string"},
            "deployment": {"type": "string", "description": "Optional: filter by deployment name"},
            "include_events": {"type": "boolean", "default": True},
        },
        "required": ["namespace"],
    },
)
async def get_kubernetes_pod_status(
    namespace: str, deployment: str = "", include_events: bool = True
) -> dict:
    return _mock_pods(namespace, deployment, include_events)


def _mock_pods(namespace, deployment, include_events):
    dep = deployment or "checkout-service"
    pods = []
    for i in range(3):
        restarts = random.randint(0, 12) if i == 0 else random.randint(0, 2)
        status = (
            "OOMKilled" if restarts > 5 else ("CrashLoopBackOff" if restarts > 3 else "Running")
        )
        mem_mb = (
            random.randint(12000, 16000) if status == "OOMKilled" else random.randint(2000, 4000)
        )
        pod = {
            "name": f"{dep}-{random.randint(10000, 99999)}-{random.randint(10000, 99999)}",
            "namespace": namespace,
            "status": status,
            "restarts": restarts,
            "memory_mb": mem_mb,
            "memory_limit_mb": 16384,
            "cpu_usage": f"{random.randint(30, 95)}%",
            "ready": status == "Running",
            "age": f"{random.randint(1, 48)}h",
        }
        if include_events and status != "Running":
            pod["events"] = [
                {
                    "type": "Warning",
                    "reason": "OOMKilling",
                    "message": f"Container killed due to OOM (memory limit: 16Gi, usage: {mem_mb}Mi)",
                    "count": restarts,
                },
                {
                    "type": "Warning",
                    "reason": "BackOff",
                    "message": "Back-off restarting failed container",
                    "count": restarts,
                },
            ]
        pods.append(pod)
    return {"namespace": namespace, "deployment": dep, "pods": pods, "total": len(pods)}
