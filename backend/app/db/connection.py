from __future__ import annotations

import logging
from typing import Any

import asyncpg

from app.config import settings

logger = logging.getLogger("sentinelforge.db")

_pool: asyncpg.Pool | None = None


async def init_db() -> None:
    global _pool
    if _pool is not None:
        return
    _pool = await asyncpg.create_pool(
        dsn=settings.database_url,
        min_size=2,
        max_size=10,
        command_timeout=30,
    )
    logger.info("asyncpg pool created")
    # ensure gen_random_uuid exists (pgcrypto)
    async with _pool.acquire() as conn:
        await conn.execute(
            "CREATE EXTENSION IF NOT EXISTS pgcrypto"
        )


async def close_db() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("asyncpg pool closed")


def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("DB pool not initialised — did lifespan run?")
    return _pool


async def fetchrow(sql: str, *args: Any) -> asyncpg.Record | None:
    return await get_pool().fetchrow(sql, *args)


async def fetch(sql: str, *args: Any) -> list[asyncpg.Record]:
    return await get_pool().fetch(sql, *args)


async def fetchval(sql: str, *args: Any) -> Any:
    return await get_pool().fetchval(sql, *args)


async def execute(sql: str, *args: Any) -> str:
    return await get_pool().execute(sql, *args)
