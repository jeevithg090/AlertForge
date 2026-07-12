from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.api import (
    analytics,
    approvals,
    auth,
    health,
    hunt,
    incidents,
    ingestion,
    security,
    stream,
)
from app.config import settings
from app.db.connection import close_db, init_db
from app.services.auth import seed_default_admin
from app.services.redis_client import close_redis, init_redis
from app.utils.correlation import CorrelationIdMiddleware

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-5s [%(name)s] %(message)s",
)
logger = logging.getLogger("sentinelforge.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SentinelForge backend starting up (%s)", settings.environment)
    await init_db()
    await init_redis()
    await seed_default_admin()
    from app.services.metrics import set_approval_queue_size

    async def _approval_queue_sweeper():
        while True:
            try:
                from app.db.connection import get_db

                async with get_db() as conn:
                    row = await conn.fetchrow(
                        "SELECT COUNT(*) AS cnt FROM incidents WHERE status = 'AWAITING_APPROVAL'"
                    )
                    set_approval_queue_size(row["cnt"] if row else 0)
            except Exception as exc:
                logger.debug("approval queue sweeper: %s", exc)
            await asyncio.sleep(30)

    sweeper_task = asyncio.create_task(_approval_queue_sweeper())
    logger.info("Startup complete — DB + Redis ready")
    yield
    sweeper_task.cancel()
    logger.info("SentinelForge backend shutting down")
    await close_redis()
    await close_db()


app = FastAPI(
    title="SentinelForge — Autonomous SOC War Room",
    description="Autonomous SOC: multi-agent pipeline that triages, investigates, and contains security alerts with human-in-the-loop approval.",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url, "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(CorrelationIdMiddleware)

app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(ingestion.router, prefix="/api/v1/ingest", tags=["ingestion"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["incidents"])
app.include_router(approvals.router, prefix="/api/v1/approvals", tags=["approvals"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(stream.router, prefix="/api/v1", tags=["streaming"])
app.include_router(analytics.router, prefix="/api/v1/analytics", tags=["analytics"])
app.include_router(hunt.router, prefix="/api/v1/hunt", tags=["threat-hunt"])
app.include_router(security.router, prefix="/api/v1/security", tags=["security"])


@app.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/")
async def root() -> dict:
    return {
        "service": "SentinelForge",
        "tagline": "The Autonomous SOC War Room",
        "docs": "/docs",
        "health": "/api/v1/health",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=settings.environment == "development")
