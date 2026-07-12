"""Ingestion gateway + security-focused normalizer.

Normalizes any ingested finding (SIEM webhook like Wazuh/Splunk, EDR alert,
IDS alert, email phishing report, analyst-pasted SOAR alert, plain text) into
a unified IncidentSignal using the fast-tier model's structured output, then
runs alert correlation/dedup and — for genuinely new incidents — persists and
publishes to the ``alerts:raw`` Redis stream for the Triage Agent.

Every webhook endpoint verifies an HMAC signature when ``settings.secret_key``
is non-default, so unauthenticated alert injection is rejected at the edge.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from app.config import settings
from app.db import incidents as incidents_db
from app.db.audit import write_audit
from app.pipeline.correlation import (
    compute_fingerprint,
    correlation_lock_key,
    extract_entities,
)
from app.schemas.events import make_event
from app.schemas.incident import AlertSource, IncidentSignal
from app.services.llm import llm
from app.services.prompt_guard import validate_input
from app.services.redis_client import publish_event, publish_to_stream

logger = logging.getLogger("sentinelforge.ingestion")

def SECRET_CONFIGURED() -> bool:
    return bool(settings.secret_key) and settings.secret_key != "dev-secret-change-me"

NORMALIZER_SYSTEM = """\
You are a security finding ingestion normalizer. Given a raw security alert
payload (a SIEM/Wazuh alert, Splunk notable event, EDR alert, IDS alert, a
phishing email body, an analyst-pasted SOAR alert, or free-form text), extract
a normalized IncidentSignal with these security-relevant fields:

- affected_service: the most likely affected system/service (lowercase, hyphenated).
- affected_hosts: list of hostnames/IPs mentioned (empty if none).
- affected_users: list of user principals mentioned (empty if none).
- source_ips: list of suspicious / external IPs pulled from the payload (empty if none).
- technologies: list of <product> <version> strings (e.g. "nginx 1.21.4") used for CVE enrichment.
- metric_name / metric_value / metric_threshold: only if a numeric count is present (e.g. failed_login_count=240).
- alert_message: a clean one-sentence human-readable description of the security finding.
- source: one of siem|edr|ids|email|slack|pagerduty|webhook|generic.
- raw_labels: any key/value labels from the source.

Return ONLY a JSON object matching the requested IncidentSignal schema.
"""


def _detect_source_hint(raw: str, hint: str) -> AlertSource:
    text = raw.lower()
    if hint in ("siem", "wazuh", "splunk") or '"alerts"' in text and '"labels"' in text:
        return AlertSource.SIEM
    if hint in ("edr", "crowdstrike", "sentinelone") or '"endpoint"' in text:
        return AlertSource.EDR
    if hint in ("ids", "suricata", "zeek", "snort") or '"signature_id"' in text:
        return AlertSource.IDS
    if hint == "email" or "<html" in text:
        return AlertSource.EMAIL
    if hint == "slack" or "slack" in text:
        return AlertSource.SLACK
    if hint == "pagerduty" or "pagerduty" in text or '"event_type"' in text:
        return AlertSource.PAGERDUTY
    if hint in ("webhook", "generic_webhook"):
        return AlertSource.WEBHOOK
    return AlertSource.GENERIC


def _build_user_message(raw: str, hint: AlertSource) -> str:
    return (
        f"Source hint: {hint.value}\n"
        f"First seen at: {datetime.now(timezone.utc).isoformat()}\n"
        f"Raw security alert input:\n```\n{raw[:4000]}\n```"
    )


def verify_hmac(raw_body: bytes, signature_header: str | None) -> tuple[bool, str]:
    """Verify an ``X-SentinelForge-Signature`` header against the raw body.

    Header format: ``sha256=<hex>``. When no secret is configured we permit
    all traffic (dev/lab mode) and log a warning. When a secret IS configured
    but the header is missing/invalid we reject the request.
    """
    if not SECRET_CONFIGURED():
        return True, "no_secret_configured"
    if not signature_header:
        return False, "missing_signature"
    if not signature_header.startswith("sha256="):
        return False, "malformed_signature"
    expected = hmac.new(
        settings.secret_key.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    provided = signature_header.removeprefix("sha256=").strip()
    if not hmac.compare_digest(expected, provided):
        return False, "signature_mismatch"
    return True, "ok"


async def normalize(raw: str, source_hint: str = "generic") -> IncidentSignal:
    """Use the fast-tier model's structured output to normalize a raw alert."""
    hint = _detect_source_hint(raw, source_hint)
    signal_id = str(uuid.uuid4())
    if not settings.llm_enabled:
        return _heuristic_normalize(raw, hint, signal_id)

    try:
        result = await llm.structured(
            model=settings.llm_model_fast,
            messages=[
                {"role": "system", "content": NORMALIZER_SYSTEM},
                {"role": "user", "content": _build_user_message(raw, hint)},
            ],
            schema_model=IncidentSignal,
        )
        result.signal_id = signal_id
        result.raw_input = raw
        result.source = result.source if result.source in AlertSource else hint
        result.ingested_at = datetime.now(timezone.utc)
        if not result.first_seen_at:
            result.first_seen_at = result.ingested_at
        return result
    except Exception as exc:
        logger.warning("normalizer fell back to heuristic (%s)", exc)
        return _heuristic_normalize(raw, hint, signal_id)


SVC_KEYWORDS = (
    "checkout", "cart", "api-gateway", "prod-db", "checkout-service", "payment",
    "auth", "bastion", "k8s-worker", "vpn", "vpn-gateway", "vpn-server",
)


def _heuristic_normalize(raw: str, hint: AlertSource, signal_id: str) -> IncidentSignal:
    """Cheap keyword-based fallback for zero-key demo runs."""
    text = raw.lower()
    service = "unknown-service"
    for tok in SVC_KEYWORDS:
        if tok in text:
            service = tok
            break

    # Cheat-sheet ip / user extraction using the same heuristics used by the
    # investigation agent (kept self-contained here for the zero-key path).
    import re

    ips: list[str] = []
    for m in re.finditer(r"\b(\d{1,3}\.){3}\d{1,3}\b", raw):
        ip = m.group(0)
        if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.", "192.168.", "127.")):
            continue
        if ip not in ips:
            ips.append(ip)

    users: list[str] = []
    for m in re.finditer(r"user[=:\s]+([A-Za-z0-9._@\-]+)", raw, re.IGNORECASE):
        u = m.group(1).strip().strip("`\"'")
        if u and u.lower() not in ("unknown", "none") and u not in users:
            users.append(u)

    return IncidentSignal(
        signal_id=signal_id,
        raw_input=raw,
        source=hint,
        affected_service=service,
        affected_users=users,
        source_ips=ips,
        alert_message=raw[:200],
        first_seen_at=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        raw_labels={"heuristic": True},
    )


async def ingest_raw(raw: str, source_hint: str = "generic") -> dict[str, Any]:
    """End-to-end ingestion: validate -> normalize -> persist -> publish."""
    from app.services.metrics import record_correlated, record_ingested

    # 1. Prompt-injection guard (Addendum E) — must always run before any agent.
    guard = await validate_input(raw, source=source_hint)
    if not guard.is_safe:
        return {
            "accepted": False,
            "reason": "prompt_injection_blocked",
            "threat": guard.threat_detected,
        }

    # 2. Normalize
    signal = await normalize(guard.sanitized_input, source_hint)
    signal_dict = signal.model_dump(mode="json")

    # 2.5 Correlation / dedup — fold storms + multi-detection alerts into one
    # incident *before* spawning a pipeline run. Deterministic and model-free.
    # find-or-create is atomic (per-group advisory lock) so a burst of alerts
    # can't race two workers into splitting one incident in two.
    create_kwargs = dict(
        signal_id=signal.signal_id,
        severity="P3_MEDIUM",  # triage will refine
        category="SECURITY",
        source=signal.source.value,
        affected_service=signal.affected_service,
        affected_hosts=signal.affected_hosts,
        alert_message=signal.alert_message,
        status="INGESTED",
    )

    if settings.correlation_enabled:
        entities = extract_entities(signal_dict)
        fingerprint = compute_fingerprint(signal_dict)
        lock_key = correlation_lock_key(entities, fingerprint)
        incident_id, correlated, reason, alert_count = await incidents_db.correlate_or_create(
            entities=entities.as_dict(),
            fingerprint=fingerprint,
            lock_key=lock_key,
            window_seconds=settings.correlation_window_seconds,
            signal=signal_dict,
            create_kwargs=create_kwargs,
        )
        if correlated:
            record_correlated(reason or "")
            record_ingested(signal.source.value)
            await write_audit(
                incident_id=incident_id,
                actor="system:correlation_engine",
                action="alert.correlated",
                details={
                    "reason": reason,
                    "source": signal.source.value,
                    "alert_message": signal.alert_message,
                    "alert_count": alert_count,
                },
            )
            await publish_event(
                incident_id,
                make_event(
                    "alert.correlated",
                    incident_id,
                    reason=reason,
                    alert_count=alert_count,
                    source=signal.source.value,
                    alert_message=signal.alert_message,
                ),
            )
            logger.info(
                "alert %s correlated into incident %s (%s; count=%s)",
                signal.signal_id, incident_id, reason, alert_count,
            )
            return {
                "accepted": True,
                "correlated_into": incident_id,
                "reason": reason,
                "alert_count": alert_count,
                "signal_id": signal.signal_id,
            }
    else:
        incident_id = await incidents_db.create_incident(**create_kwargs)

    # 3. New incident — audit + publish.
    await write_audit(
        incident_id=incident_id,
        actor="system:ingestion_gateway",
        action="incident.created",
        details={
            "source": signal.source.value,
            "affected_service": signal.affected_service,
            "affected_users": signal.affected_users,
            "source_ips": signal.source_ips,
            "alert_message": signal.alert_message,
            "metric": signal.metric_name,
        },
    )

    # 4. Publish to pipeline + dashboard
    await publish_to_stream("raw", {"incident_id": incident_id, "signal": signal.model_dump(mode="json")})
    await publish_event(
        incident_id,
        make_event(
            "incident.created",
            incident_id,
            source=signal.source.value,
            affected_service=signal.affected_service,
            alert_message=signal.alert_message,
            signal=signal.model_dump(mode="json"),
        ),
    )
    logger.info("ingested incident %s (%s)", incident_id, signal.source.value)
    return {"accepted": True, "incident_id": incident_id, "signal_id": signal.signal_id}