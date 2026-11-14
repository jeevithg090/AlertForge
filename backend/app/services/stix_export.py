from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any


def _sid(prefix: str) -> str:
    return f"{prefix}--{uuid.uuid4()}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _coerce_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return {}
    return value or {}


def _escape_single_quotes(v: str) -> str:
    return v.replace("'", "\\'")


def ioc_to_indicator(ioc: dict, now_iso: str) -> dict:
    ioc_type = ioc.get("type", "unknown")
    value = ioc.get("value", "")
    escaped = _escape_single_quotes(value)
    verdict = ioc.get("verdict", "UNKNOWN").lower()

    pattern_map = {
        "ip": f"[ipv4-addr:value = '{escaped}']",
        "user": f"[user-account:account_login = '{escaped}']",
        "host": f"[domain-name:value = '{escaped}']",
        "file_hash": f"[file:hashes.'SHA-256' = '{escaped}']",
        "url": f"[url:value = '{escaped}']",
    }
    pattern = pattern_map.get(ioc_type, f"[vulnerability:name = '{escaped}']")

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _sid("indicator"),
        "created": now_iso,
        "modified": now_iso,
        "name": f"{ioc_type}: {value}",
        "pattern_type": "stix",
        "valid_from": now_iso,
        "labels": [verdict],
        "pattern": pattern,
    }


def technique_to_attack_pattern(t: dict, now_iso: str) -> dict:
    tech_id = t.get("technique_id", "")
    tech_url = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": _sid("attack-pattern"),
        "created": now_iso,
        "modified": now_iso,
        "name": t.get("name", tech_id),
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": tech_id,
                "url": tech_url,
            }
        ],
    }


def build_stix_bundle(incident: dict) -> dict:
    now = _now_iso()
    objects: list[dict] = []

    indicators = []
    iocs = []
    finding = _coerce_json(incident.get("investigation_finding"))
    raw_iocs = finding.get("iocs") or []
    if isinstance(raw_iocs, list):
        iocs = raw_iocs
    for ioc in iocs:
        ind = ioc_to_indicator(ioc, now)
        indicators.append(ind)
        objects.append(ind)

    attack_patterns = []
    triage = _coerce_json(incident.get("triage_result"))
    techniques = triage.get("attack_techniques") or []
    if isinstance(techniques, list):
        for tech in techniques:
            ap = technique_to_attack_pattern(tech, now)
            attack_patterns.append(ap)
            objects.append(ap)

    # Relationships: indicators indicate the first attack-pattern
    first_ap = attack_patterns[0] if attack_patterns else None
    if first_ap and indicators:
        for ind in indicators:
            rel = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": _sid("relationship"),
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": ind["id"],
                "target_ref": first_ap["id"],
            }
            objects.append(rel)

    # Report
    report_id = _sid("report")
    object_refs = [o["id"] for o in objects]
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": now,
        "modified": now,
        "name": incident.get("alert_message", "SentinelForge Incident")[:256],
        "published": incident.get("created_at", now)
        if isinstance(incident.get("created_at"), str)
        else now,
        "object_refs": object_refs,
    }
    objects.insert(0, report)

    bundle = {
        "type": "bundle",
        "id": _sid("bundle"),
        "objects": objects,
    }
    return bundle


def build_navigator_layer(technique_counts: list[dict]) -> dict:
    counts = [int(t.get("count", 0)) for t in technique_counts]
    max_val = max(counts) if counts else 1

    techniques = []
    for t in technique_counts:
        techniques.append(
            {
                "techniqueID": t.get("technique_id", ""),
                "score": int(t.get("count", 0)),
                "comment": t.get("name", ""),
            }
        )

    return {
        "name": "SentinelForge observed techniques",
        "versions": {
            "attack": "16",
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": "MITRE ATT&CK techniques observed by SentinelForge across all triaged incidents.",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe766", "#ff6666"],
            "minValue": 0,
            "maxValue": max_val,
        },
    }
