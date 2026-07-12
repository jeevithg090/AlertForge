from __future__ import annotations

import os
import re

os.environ.setdefault("DASHSCOPE_API_KEY", "")
os.environ.setdefault("USE_MOCK_TOOLS", "true")

from app.services.stix_export import (
    build_navigator_layer,
    build_stix_bundle,
    ioc_to_indicator,
    technique_to_attack_pattern,
)


def _test_incident(**overrides):
    data = {
        "alert_message": "Brute force detected",
        "created_at": "2026-07-11T12:00:00Z",
        "triage_result": {
            "attack_techniques": [
                {"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
            ]
        },
        "investigation_finding": {
            "iocs": [
                {"type": "ip", "value": "203.0.113.9", "verdict": "MALICIOUS"},
                {"type": "user", "value": "j.doe", "verdict": "SUSPICIOUS"},
            ]
        },
    }
    data.update(overrides)
    return data


STIX_ID_RE = re.compile(r"^(bundle|indicator|attack-pattern|report|relationship)--[0-9a-f-]{36}$")


def test_bundle_has_type_and_ids():
    bundle = build_stix_bundle(_test_incident())
    assert bundle["type"] == "bundle"
    assert STIX_ID_RE.match(bundle["id"])


def test_all_objects_have_spec_version():
    bundle = build_stix_bundle(_test_incident())
    for obj in bundle["objects"]:
        assert obj.get("spec_version") == "2.1", f"{obj['type']} missing spec_version"


def test_report_refs_cover_all_objects():
    bundle = build_stix_bundle(_test_incident())
    report = bundle["objects"][0]
    assert report["type"] == "report"
    obj_ids = {o["id"] for o in bundle["objects"]}
    ref_ids = set(report["object_refs"])
    assert ref_ids == obj_ids - {report["id"]}, "report.object_refs should cover all non-report objects"


def test_ip_ioc_produces_ipv4_pattern():
    ind = ioc_to_indicator({"type": "ip", "value": "198.51.100.1", "verdict": "MALICIOUS"}, "2026-01-01T00:00:00Z")
    assert ind["pattern"] == "[ipv4-addr:value = '198.51.100.1']"


def test_single_quote_is_escaped():
    ind = ioc_to_indicator({"type": "ip", "value": "198.51.100.1' or 1=1--", "verdict": "MALICIOUS"}, "2026-01-01T00:00:00Z")
    assert "\\'" in ind["pattern"]


def test_empty_iocs_no_crash():
    bundle = build_stix_bundle({"alert_message": "x", "triage_result": {}, "investigation_finding": {}})
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) >= 1  # at least the report


def test_empty_techniques_no_crash():
    bundle = build_stix_bundle({"alert_message": "x", "triage_result": {"attack_techniques": []}, "investigation_finding": {"iocs": []}})
    report = bundle["objects"][0]
    assert report["object_refs"] == []


def test_navigator_layer_technique_ids():
    counts = [
        {"technique_id": "T1110", "name": "Brute Force", "count": 5},
        {"technique_id": "T1059", "name": "Command and Scripting", "count": 2},
    ]
    layer = build_navigator_layer(counts)
    assert layer["techniques"][0]["techniqueID"] == "T1110"
    assert layer["techniques"][0]["score"] == 5
    assert layer["gradient"]["maxValue"] == 5


def test_navigator_layer_empty():
    layer = build_navigator_layer([])
    assert layer["techniques"] == []
    assert layer["gradient"]["maxValue"] == 1


def test_technique_to_attack_pattern():
    ap = technique_to_attack_pattern({"technique_id": "T1110", "name": "Brute Force"}, "2026-01-01T00:00:00Z")
    assert ap["type"] == "attack-pattern"
    assert ap["external_references"][0]["external_id"] == "T1110"
    assert "attack.mitre.org" in ap["external_references"][0]["url"]
