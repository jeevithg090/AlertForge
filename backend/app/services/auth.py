from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings
from app.db.audit import write_audit
from app.db.connection import fetchrow, fetchval

logger = logging.getLogger("sentinelforge.auth")

_bearer = HTTPBearer(auto_error=False)

ROLES: tuple[str, ...] = ("viewer", "analyst", "approver", "admin")
# Role groups used by the API routers. ``admin`` is always implicitly allowed.
READ_ROLES: tuple[str, ...] = ("viewer", "analyst", "approver")
ANALYST_ROLES: tuple[str, ...] = ("analyst", "approver")
APPROVER_ROLES: tuple[str, ...] = ("approver",)

_DEV_OPERATOR = {
    "sub": "dev:anonymous-admin",
    "role": "admin",
    "name": "Dev Anonymous Admin",
}

# ---------- password hashing (stdlib only) ----------


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt=salt.encode("utf-8"),
        iterations=600000,
        dklen=32,
    )
    return f"pbkdf2${salt}${hashed.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if not stored.startswith("pbkdf2$"):
        return False
    parts = stored.split("$")
    if len(parts) != 3:
        return False
    _, salt, expected_hex = parts
    try:
        computed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt=salt.encode("utf-8"),
            iterations=600000,
            dklen=32,
        )
        return hmac.compare_digest(computed.hex(), expected_hex)
    except Exception:
        return False


# ---------- JWT ----------


def create_token(operator: dict) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": operator["email"],
        "role": operator["role"],
        "name": operator.get("display_name", ""),
        "iat": now,
        "exp": now + timedelta(hours=8),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired") from None
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token") from None


# ---------- DB helpers ----------


async def get_operator_by_email(email: str) -> dict | None:
    row = await fetchrow("SELECT * FROM operators WHERE email = $1", email)
    if row is None:
        return None
    d = dict(row)
    for k, v in list(d.items()):
        if isinstance(v, uuid.UUID):
            d[k] = str(v)
    return d


async def create_operator(email: str, password: str, role: str, display_name: str = "") -> str:
    pw_hash = hash_password(password)
    operator_id = await fetchval(
        """
        INSERT INTO operators (email, display_name, password_hash, role)
        VALUES ($1, $2, $3, $4)
        RETURNING id::text
        """,
        email,
        display_name,
        pw_hash,
        role,
    )
    return str(operator_id)


async def seed_default_admin() -> None:
    count = await fetchval("SELECT COUNT(*) FROM operators")
    if count and int(count) > 0:
        return
    pw = settings.default_admin_password
    await create_operator(
        email="admin@sentinelforge.local",
        password=pw,
        role="admin",
        display_name="Default Admin",
    )
    await write_audit(
        incident_id=None,
        actor="system:auth_seeder",
        action="auth.seeded_default_admin",
        details={"email": "admin@sentinelforge.local"},
    )
    logger.info("Seeded default admin operator (admin@sentinelforge.local)")


# ---------- FastAPI dependencies ----------


def _operator_from_token(token: str | None) -> dict:
    if not token:
        if settings.dev_auth_bypass_active:
            return dict(_DEV_OPERATOR)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return decode_token(token)


def current_operator(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    """Resolve the caller from ``Authorization: Bearer <jwt>``.

    In development with ``AUTH_DEV_BYPASS=true`` an unauthenticated caller is
    treated as an anonymous admin so the docker-compose demo works without a
    login; that bypass is never honoured in any other environment.
    """
    return _operator_from_token(credentials.credentials if credentials else None)


def stream_operator(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    access_token: str | None = Query(default=None, include_in_schema=False),
) -> dict:
    """Like :func:`current_operator`, but also accepts ``?access_token=`` because
    browsers' ``EventSource`` cannot send an Authorization header."""
    token = credentials.credentials if credentials else access_token
    return _operator_from_token(token)


def _check_role(op: dict, roles: tuple[str, ...]) -> dict:
    if not role_allowed(str(op.get("role", "")), roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"requires one of {roles}",
        )
    return op


def require_role(*roles: str):
    """FastAPI dependency: the caller must hold one of ``roles`` (or be admin)."""

    async def _check(op: dict = Depends(current_operator)) -> dict:
        return _check_role(op, roles)

    return _check


def require_stream_role(*roles: str):
    """Role check for SSE endpoints (token may come from the query string)."""

    async def _check(op: dict = Depends(stream_operator)) -> dict:
        return _check_role(op, roles)

    return _check


# ---------- pure helper for testability ----------


def role_allowed(role: str, allowed: tuple[str, ...]) -> bool:
    if role == "admin":
        return True
    return role in allowed


def operator_id(op: dict) -> str:
    """Stable actor string for audit entries."""
    return str(op.get("sub") or "unknown")
