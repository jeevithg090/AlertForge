"""Identity / IdP enrichment tool.

Mocks an Active Directory / Okta / Entra-ID style lookup: groups, privileged
status, MFA, last-login, blast-radius indicator. Real path hooked via an
external identity API URL (kept as a stub — production would call Okta SCIM
or Azure Graph). Mock returns deterministic-ish plausible data keyed on the
username so the same alert replays consistently during a demo.
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

from app.config import settings
from app.tools.registry import tool


def _seed(username: str) -> int:
    return int(hashlib.md5(username.encode()).hexdigest(), 16)


@tool(
    name="enrich_user_identity",
    description=(
        "Enrich a user principal against the corporate IdP. Returns membership groups, "
        "privileged flag, MFA status, last login, and Total Days Active. "
        "Use this on every affected user principal to assesson blast radius."
    ),
    parameters={
        "type": "object",
        "properties": {
            "username": {"type": "string", "description": "user principal (e.g. j.doe@corp)"}
        },
        "required": ["username"],
    },
)
async def enrich_user_identity(username: str) -> dict:
    if settings.use_mock_tools:
        return _mock(username)
    # Real path stub — production would call Okta / Azure Graph here.
    return _mock(username)


def _mock(username: str) -> dict:
    seed = _seed(username)
    rng = random.Random(seed)
    is_priv = seed % 100 < 25 or username.lower() in (
        "admin",
        "root",
        "svc-account",
        "administrator",
    )
    last_login = datetime.now(timezone.utc) - timedelta(hours=rng.randint(1, 240))
    mfa = bool((seed >> 3) & 1) and username.lower() not in ("root", "svc-account")
    groups = []
    if is_priv:
        groups += ["Domain Admins", "Security Operators"]
    groups += ["Engineering", "All-Staff", "VPN-Users"]
    groups = list(dict.fromkeys(groups))
    return {
        "username": username,
        "is_privileged": is_priv,
        "mfa_enabled": mfa,
        "groups": groups,
        "last_login": last_login.isoformat(),
        "risk_score": round(
            min(1.0, 0.2 + (0.4 if is_priv else 0.0) + (0.2 if not mfa else 0.0)), 2
        ),
        "notes": (
            "Privileged account without MFA — high blast radius."
            if (is_priv and not mfa)
            else "Standard identity — bounded blast radius."
        ),
    }
