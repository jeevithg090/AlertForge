"""Alert correlation & deduplication — the front line against alert fatigue.

Real SOCs drown in volume: a single SSH brute-force or a misconfigured scanner
can emit hundreds of near-identical alerts, and the same attack usually trips
several *different* detections (SIEM + EDR + IDS) that are really one incident.
Chasing each alert separately is how analysts burn out and how real threats get
lost in the noise.

This module folds related alerts together **before** they spawn independent
agent pipelines. It is deliberately deterministic and model-free — correlation
must be cheap, instant, and explainable, and it runs on every single alert.

Two alerts correlate when, within a time window, they either:
  * share a stable **fingerprint** (same source + asset + de-noised signature), or
  * share a strong **entity** (an external IP, a user principal, or a host).

Everything here is a pure function of its inputs so it is trivially testable;
the time-window filtering and persistence live in the DB layer.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

# Private/loopback/link-local ranges are not useful correlation keys.
_PRIVATE_PREFIXES = (
    "10.",
    "127.",
    "169.254.",
    "192.168.",
    *(f"172.{i}." for i in range(16, 32)),
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"\buser(?:name)?[=:\s]+([A-Za-z0-9._@\-]+)", re.IGNORECASE)
# Tokens to strip so volatile details don't defeat de-duplication.
_HEX_RE = re.compile(r"\b[0-9a-f]{6,}\b", re.IGNORECASE)  # hashes, request ids
_NUM_RE = re.compile(r"\d+")  # counts, ports, times
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)
_WS_RE = re.compile(r"\s+")


def is_public_ip(ip: str) -> bool:
    ip = ip.strip()
    if not ip or ip.startswith(_PRIVATE_PREFIXES):
        return False
    parts = ip.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


@dataclass(frozen=True)
class Entities:
    """The strong identifiers a correlation decision is made on."""

    service: str = "unknown"
    ips: frozenset[str] = field(default_factory=frozenset)
    users: frozenset[str] = field(default_factory=frozenset)
    hosts: frozenset[str] = field(default_factory=frozenset)

    def as_dict(self) -> dict:
        return {
            "service": self.service,
            "ips": sorted(self.ips),
            "users": sorted(self.users),
            "hosts": sorted(self.hosts),
        }

    @classmethod
    def from_dict(cls, d: dict | str | None) -> Entities:
        # Tolerate the raw JSON string asyncpg hands back for JSONB columns.
        if isinstance(d, str):
            try:
                d = json.loads(d)
            except (json.JSONDecodeError, TypeError):
                d = {}
        d = d or {}
        return cls(
            service=(d.get("service") or "unknown"),
            ips=frozenset(d.get("ips") or []),
            users=frozenset(d.get("users") or []),
            hosts=frozenset(d.get("hosts") or []),
        )


def merge_entities(a: Entities, b: Entities) -> Entities:
    """Union two entity sets (used when folding a new alert into an incident)."""
    service = a.service if a.service and a.service != "unknown" else b.service
    return Entities(
        service=service,
        ips=a.ips | b.ips,
        users=a.users | b.users,
        hosts=a.hosts | b.hosts,
    )


def normalize_signature(alert_message: str) -> str:
    """Collapse a message to a stable signature by removing volatile tokens.

    "Failed password for alice from 1.2.3.4 (attempt 240)" and the same line
    with attempt 241 / a different source port both reduce to one signature, so
    an alert storm shares a single fingerprint.
    """
    text = (alert_message or "").lower()
    text = _UUID_RE.sub("", text)
    text = _IP_RE.sub("", text)
    text = _HEX_RE.sub("", text)
    text = _NUM_RE.sub("", text)
    text = _WS_RE.sub(" ", text).strip()
    return text


def extract_entities(signal: dict) -> Entities:
    """Pull strong identifiers from a normalized IncidentSignal dict."""
    msg = signal.get("alert_message") or ""
    raw = signal.get("raw_input") or ""
    blob = f"{msg}\n{raw}"

    ips = {ip for ip in (signal.get("source_ips") or []) if is_public_ip(ip)}
    ips |= {ip for ip in _IP_RE.findall(blob) if is_public_ip(ip)}

    users = {u.strip().lower() for u in (signal.get("affected_users") or []) if u}
    users |= {m.group(1).strip().lower() for m in _USER_RE.finditer(blob)}
    users = {u for u in users if u and u not in ("unknown", "none", "null")}

    hosts = {h.strip().lower() for h in (signal.get("affected_hosts") or []) if h}

    return Entities(
        service=(signal.get("affected_service") or "unknown").strip().lower(),
        ips=frozenset(ips),
        users=frozenset(users),
        hosts=frozenset(hosts),
    )


def compute_fingerprint(signal: dict) -> str:
    """Stable 16-char fingerprint: source + service + de-noised signature.

    The signature is derived from the **verbatim raw input**, not the
    LLM-generated ``alert_message`` — so two identical raw alerts always
    fingerprint identically even if the model normalizes their wording
    differently. This is what makes correlation robust to LLM non-determinism.
    """
    source = signal.get("source") or "generic"
    service = (signal.get("affected_service") or "unknown").strip().lower()
    raw = signal.get("raw_input") or signal.get("alert_message") or ""
    signature = normalize_signature(raw)
    basis = f"{source}|{service}|{signature}"
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]


def correlation_lock_key(entities: Entities, fingerprint: str) -> str:
    """A stable key identifying the *correlation group* a signal belongs to.

    Used to serialize concurrent find-or-create so an alert storm can't race two
    workers into creating two incidents. Anchored on the strongest deterministic
    entity (public IP → host → user → service), falling back to the fingerprint.
    """
    if entities.ips:
        return f"ip:{sorted(entities.ips)[0]}"
    if entities.hosts:
        return f"host:{sorted(entities.hosts)[0]}"
    if entities.users and entities.service != "unknown":
        return f"user:{sorted(entities.users)[0]}@{entities.service}"
    return f"fp:{fingerprint}"


def correlation_reason(
    new: Entities,
    new_fp: str,
    existing: Entities,
    existing_fp: str,
) -> str | None:
    """Return a human-readable reason the two alerts correlate, else ``None``.

    Order matters: the most specific / trustworthy signal wins so the reason we
    surface to the analyst is the strongest one.
    """
    if new_fp and new_fp == existing_fp:
        return "duplicate signature"
    shared_ip = new.ips & existing.ips
    if shared_ip:
        return f"shared source IP {sorted(shared_ip)[0]}"
    shared_host = new.hosts & existing.hosts
    if shared_host:
        return f"shared host {sorted(shared_host)[0]}"
    # A shared user is only strong evidence when it's the same service/app.
    shared_user = new.users & existing.users
    if shared_user and new.service == existing.service and new.service != "unknown":
        return f"shared user {sorted(shared_user)[0]} on {new.service}"
    return None
