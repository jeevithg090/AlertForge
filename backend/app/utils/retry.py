from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("sentinelforge.retry")

__all__ = ["retry_async", "call_with_retry"]


def retry_async(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    jitter: bool = True,
    exceptions: tuple[type[BaseException], ...] = (Exception,),
):
    """Exponential backoff with optional jitter.

    Jitter is critical: without it, retries from concurrent agents all fire at
    the same time after a rate-limit, creating a thundering-herd problem.
    """
    import asyncio
    import random

    def decorator(fn):
        async def wrapper(*args, **kwargs):
            attempt = 0
            while True:
                attempt += 1
                try:
                    return await fn(*args, **kwargs)
                except exceptions as exc:
                    if attempt >= max_attempts:
                        logger.error("%s failed after %d attempts: %s", fn.__name__, attempt, exc)
                        raise
                    delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
                    if jitter:
                        delay = random.uniform(0, delay)
                    logger.warning(
                        "%s attempt %d failed (%s); retrying in %.2fs",
                        fn.__name__,
                        attempt,
                        exc,
                        delay,
                    )
                    await asyncio.sleep(delay)

        return wrapper

    return decorator


async def call_with_retry(
    coro_fn: Any,
    *args,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    **kwargs,
) -> Any:
    """Retry a coroutine factory."""
    import asyncio
    import random

    attempt = 0
    while True:
        attempt += 1
        try:
            return await coro_fn(*args, **kwargs)
        except Exception as exc:
            if attempt >= max_attempts:
                raise
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay = random.uniform(0, delay) if True else delay
            logger.warning("call failed attempt %d (%s); retrying in %.2fs", attempt, exc, delay)
            await asyncio.sleep(delay)
