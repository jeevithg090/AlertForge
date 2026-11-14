"""SSL certificate check tool."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from app.tools.registry import tool


@tool(
    name="check_ssl_certificate",
    description="Check SSL/TLS certificate expiry and validity for a domain. Use for certificate-related alerts.",
    parameters={
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Domain name to check"},
            "port": {"type": "integer", "default": 443},
        },
        "required": ["domain"],
    },
)
async def check_ssl_certificate(domain: str, port: int = 443) -> dict:
    return _mock_cert(domain, port)


def _mock_cert(domain, port):
    now = datetime.now(timezone.utc)
    if "internal" in domain or "api." in domain:
        expiry = now + timedelta(days=random.randint(3, 8))
        issuer = "Let's Encrypt Authority X3"
    else:
        expiry = now + timedelta(days=random.randint(30, 365))
        issuer = "DigiCert SHA2 Extended Validation Server CA"
    return {
        "domain": domain,
        "port": port,
        "subject": f"CN={domain}",
        "issuer": issuer,
        "not_before": (now - timedelta(days=60)).isoformat(),
        "not_after": expiry.isoformat(),
        "days_until_expiry": (expiry - now).days,
        "is_valid": True,
        "is_expiring_soon": (expiry - now).days < 14,
        "san": [domain, f"*.{domain}"],
        "serial": f"{random.randint(100000, 999999):06x}",
    }
