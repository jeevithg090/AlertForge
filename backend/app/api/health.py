from __future__ import annotations

from fastapi import APIRouter

from app.config import settings
from app.services.redis_client import get_redis

router = APIRouter()


@router.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "service": "SentinelForge",
        "environment": settings.environment,
        "llm_enabled": settings.llm_enabled,
        "llm_provider": settings.llm_provider,
        "models": {"smart": settings.llm_model_smart, "fast": settings.llm_model_fast},
    }


@router.get("/health/live")
async def liveness() -> dict:
    return {"status": "alive"}


@router.get("/health/ready")
async def readiness() -> dict:
    checks: dict[str, str] = {}
    try:
        await (await get_redis()).ping()
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"fail: {exc}"
    try:
        from app.db.connection import get_pool

        await get_pool().fetchval("SELECT 1")
        checks["postgres"] = "ok"
    except Exception as exc:
        checks["postgres"] = f"fail: {exc}"
    ready = all(v == "ok" for v in checks.values())
    return {"ready": ready, "checks": checks}
