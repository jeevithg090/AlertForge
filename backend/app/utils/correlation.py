from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_HEADER = "X-Correlation-Id"


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Attach a correlation id to every request so every log line and LLM call
    can be traced from ingestion to resolution."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        cid = request.headers.get(_HEADER) or f"af-{uuid.uuid4().hex[:16]}"
        request.state.correlation_id = cid
        response = await call_next(request)
        response.headers[_HEADER] = cid
        return response


def get_correlation_id(request: Request) -> str:
    return getattr(request.state, "correlation_id", "af-unknown")
