from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

import asyncpg
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
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
from app.services.auth import (
    ANALYST_ROLES,
    READ_ROLES,
    require_role,
    require_stream_role,
    seed_default_admin,
)
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
    # Explicit origins only: a "*" origin combined with credentials would let
    # any website make authenticated requests on an operator's behalf.
    allow_origins=settings.allowed_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Last-Event-ID", "X-SentinelForge-Signature"],
)
app.add_middleware(CorrelationIdMiddleware)

_read = [Depends(require_role(*READ_ROLES))]

# Public: liveness/readiness probes and login.


@app.exception_handler(asyncpg.exceptions.DataError)
async def _bad_identifier(_request: Request, exc: asyncpg.exceptions.DataError) -> JSONResponse:
    """A malformed UUID in a path (e.g. a truncated incident link) can't match
    any row, so answer 404 like any other unknown id instead of a 500."""
    if "invalid UUID" in str(exc):
        return JSONResponse(status_code=404, content={"detail": "not found"})
    raise exc


app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
# Machine-to-machine webhooks are HMAC-verified; analyst endpoints check roles.
app.include_router(ingestion.router, prefix="/api/v1/ingest", tags=["ingestion"])
# Operator-facing APIs: any authenticated role may read; writes check per-route.
app.include_router(
    incidents.router, prefix="/api/v1/incidents", tags=["incidents"], dependencies=_read
)
app.include_router(
    approvals.router, prefix="/api/v1/approvals", tags=["approvals"], dependencies=_read
)
app.include_router(
    stream.router,
    prefix="/api/v1",
    tags=["streaming"],
    dependencies=[Depends(require_stream_role(*READ_ROLES))],
)
app.include_router(
    analytics.router, prefix="/api/v1/analytics", tags=["analytics"], dependencies=_read
)
app.include_router(
    hunt.router,
    prefix="/api/v1/hunt",
    tags=["threat-hunt"],
    dependencies=[Depends(require_role(*ANALYST_ROLES))],
)
app.include_router(
    security.router, prefix="/api/v1/security", tags=["security"], dependencies=_read
)


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

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=settings.is_development)
