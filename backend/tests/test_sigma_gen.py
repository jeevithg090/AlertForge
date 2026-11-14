from __future__ import annotations

import os

import yaml

os.environ.setdefault("DASHSCOPE_API_KEY", "")
os.environ.setdefault("USE_MOCK_TOOLS", "true")

from app.services.sigma_gen import (
    REQUIRED_FIELDS,
    build_sigma_rule,
    to_yaml,
)


def test_rule_has_required_fields():
    incident = {
        "severity": "P1_CRITICAL",
        "affected_service": "bastion",
        "alert_message": "Brute force detected from 203.0.113.9",
        "triage_result": {
            "verdict": "TRUE_POSITIVE",
            "attack_techniques": [
                {"technique_id": "T1110", "name": "Brute Force", "confidence": 0.95}
            ],
        },
        "investigation_finding": {
            "iocs": [
                {"type": "ip", "value": "203.0.113.9", "verdict": "MALICIOUS"},
            ]
        },
    }
    rule = build_sigma_rule(incident)
    for field in REQUIRED_FIELDS:
        assert field in rule, f"missing field: {field}"
    assert rule["status"] == "experimental"
    assert rule["author"] == "SentinelForge"


def test_tags_correct_format():
    incident = {
        "severity": "P1_CRITICAL",
        "affected_service": "bastion",
        "alert_message": "Brute force",
        "triage_result": {
            "attack_techniques": [
                {"technique_id": "T1110", "name": "Brute Force", "confidence": 0.9}
            ],
        },
        "investigation_finding": {"iocs": []},
    }
    rule = build_sigma_rule(incident)
    tags = rule["tags"]
    assert "attack.credential_access" in tags
    assert "attack.t1110" in tags


def test_ioc_ip_appears_in_detection():
    incident = {
        "severity": "P2_HIGH",
        "affected_service": "web",
        "alert_message": "Suspicious login",
        "triage_result": {
            "attack_techniques": [
                {"technique_id": "T1078", "name": "Valid Accounts", "confidence": 0.8}
            ],
        },
        "investigation_finding": {
            "iocs": [{"type": "ip", "value": "198.51.100.77", "verdict": "MALICIOUS"}],
        },
    }
    rule = build_sigma_rule(incident)
    detection = rule["detection"]
    ioc_found = False
    for selection in detection.values():
        if isinstance(selection, dict):
            for val in selection.values():
                if isinstance(val, list) and "198.51.100.77" in val:
                    ioc_found = True
    assert ioc_found, "IOC IP should appear in detection"


def test_yaml_round_trip():
    incident = {
        "severity": "P3_MEDIUM",
        "affected_service": "mail",
        "alert_message": "Phishing detected",
        "triage_result": {
            "attack_techniques": [
                {"technique_id": "T1566", "name": "Phishing", "confidence": 0.85}
            ],
        },
        "investigation_finding": {"iocs": []},
    }
    rule = build_sigma_rule(incident)
    yaml_str = to_yaml(rule)
    parsed = yaml.safe_load(yaml_str)
    assert parsed["id"] == rule["id"]
    assert parsed["title"] == rule["title"]


def test_level_follows_severity():
    low = build_sigma_rule(
        {
            "severity": "P4_LOW",
            "affected_service": "x",
            "alert_message": "x",
            "triage_result": {},
            "investigation_finding": {},
        }
    )
    assert low["level"] == "medium"

    high = build_sigma_rule(
        {
            "severity": "P1_CRITICAL",
            "affected_service": "x",
            "alert_message": "x",
            "triage_result": {},
            "investigation_finding": {},
        }
    )
    assert high["level"] == "high"


def test_unknown_technique_falls_back_to_generic():
    incident = {
        "severity": "P2_HIGH",
        "affected_service": "x",
        "alert_message": "Unknown activity",
        "triage_result": {
            "attack_techniques": [{"technique_id": "T9999", "name": "Unknown", "confidence": 0.5}],
        },
        "investigation_finding": {"iocs": []},
    }
    rule = build_sigma_rule(incident)
    assert "title" in rule
    assert rule["level"] == "high"


def test_technique_id_normalized():
    """T1110.003 should use the T1110 template."""
    incident = {
        "severity": "P1_CRITICAL",
        "affected_service": "bastion",
        "alert_message": "Brute force",
        "triage_result": {
            "attack_techniques": [
                {"technique_id": "T1110.003", "name": "Password Spray", "confidence": 0.9}
            ],
        },
        "investigation_finding": {"iocs": []},
    }
    rule = build_sigma_rule(incident)
    tags = rule["tags"]
    assert "attack.t1110" in tags


def test_detection_contains_condition():
    incident = {
        "severity": "P1_CRITICAL",
        "affected_service": "x",
        "alert_message": "test",
        "triage_result": {},
        "investigation_finding": {},
    }
    rule = build_sigma_rule(incident)
    assert "condition" in rule.get("detection", {}), "detection must contain a condition key"
