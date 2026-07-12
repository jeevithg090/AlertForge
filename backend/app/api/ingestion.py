from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, Request

from app.services.ingestion_service import ingest_raw, verify_hmac

router = APIRouter()


async def _verified_body(request: Request, signature: str | None) -> tuple[str, bytes]:
    """Return (raw_text, raw_bytes). Verifies HMAC when a secret is configured."""
    raw_body = await request.body()
    ok, reason = verify_hmac(raw_body, signature)
    if not ok:
        raise HTTPException(status_code=401, detail=f"webhook signature verification failed: {reason}")
    try:
        text = raw_body.decode("utf-8") or "{}"
    except UnicodeDecodeError:
        text = str(raw_body)
    return text, raw_body


@router.post("/webhook")
async def ingest_webhook(request: Request, x_sentinelforge_signature: str | None = Header(default=None, alias="X-SentinelForge-Signature")):
    """Generic webhook receiver. HMAC-verified when a secret is configured."""
    text, _ = await _verified_body(request, x_sentinelforge_signature)
    return await ingest_raw(raw=text, source_hint="webhook")


@router.post("/siem")
async def ingest_siem(request: Request, x_sentinelforge_signature: str | None = Header(default=None, alias="X-SentinelForge-Signature")):
    """SIEM alert ingestion (Wazuh / Splunk / Elastic Security notable events)."""
    text, _ = await _verified_body(request, x_sentinelforge_signature)
    return await ingest_raw(raw=text, source_hint="siem")


@router.post("/edr")
async def ingest_edr(request: Request, x_sentinelforge_signature: str | None = Header(default=None, alias="X-SentinelForge-Signature")):
    """EDR alert ingestion (CrowdStrike / SentinelOne / Defender)."""
    text, _ = await _verified_body(request, x_sentinelforge_signature)
    return await ingest_raw(raw=text, source_hint="edr")


@router.post("/ids")
async def ingest_ids(request: Request, x_sentinelforge_signature: str | None = Header(default=None, alias="X-SentinelForge-Signature")):
    """IDS alert ingestion (Suricata / Zeek / Snort)."""
    text, _ = await _verified_body(request, x_sentinelforge_signature)
    return await ingest_raw(raw=text, source_hint="ids")


@router.post("/text")
async def ingest_text(payload: dict):
    """Plain text / Slack message ingestion (no HMAC — analyst-pasted)."""
    text = payload.get("text") or payload.get("message") or str(payload)
    return await ingest_raw(raw=text, source_hint="text")


@router.post("/email")
async def ingest_email(payload: dict):
    """Email content ingestion (phishing report, SOAR email forward)."""
    return await ingest_raw(raw=str(payload), source_hint="email")