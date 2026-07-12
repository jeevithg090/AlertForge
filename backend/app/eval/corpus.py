"""Labeled triage evaluation corpus.

Ground-truth labels are what a competent SOC analyst would decide — not what any
particular classifier outputs. Cases span true positives across techniques,
false positives (authorized/testing/known-good), benign anomalies, and
genuinely ambiguous findings that should be escalated to a human.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EvalCase:
    name: str
    raw_text: str
    expected_verdict: str            # TRUE_POSITIVE | FALSE_POSITIVE | BENIGN_ANOMALY | NEEDS_HUMAN
    expected_severity: str           # P1_CRITICAL | P2_HIGH | P3_MEDIUM | P4_LOW
    expected_techniques: list[str] = field(default_factory=list)
    source_hint: str = "generic"


CORPUS: list[EvalCase] = [
    # ---- True positives across techniques ----
    EvalCase("ssh_brute_force",
             "SIEM: 5,847 failed SSH login attempts (brute force) from 203.0.113.9 targeting bastion-01",
             "TRUE_POSITIVE", "P2_HIGH", ["T1110"], "siem"),
    EvalCase("password_spray",
             "Failed login spike: 240 failed logins across 30 accounts from 198.51.100.7",
             "TRUE_POSITIVE", "P2_HIGH", ["T1110"], "siem"),
    EvalCase("ransomware",
             "EDR: ransomware behaviour — mass file-extension rename (.locked), 4108 files encrypted on prod-app-03",
             "TRUE_POSITIVE", "P1_CRITICAL", ["T1486"], "edr"),
    EvalCase("c2_beacon",
             "IDS: host prod-app-03 beaconing to 45.142.120.99, suspected c2 command and control channel",
             "TRUE_POSITIVE", "P1_CRITICAL", ["T1071"], "ids"),
    EvalCase("data_exfil",
             "Network anomaly: prod-db-02 data exfil, 4.8GB egress to external 198.51.100.7",
             "TRUE_POSITIVE", "P2_HIGH", ["T1041"], "siem"),
    EvalCase("phishing",
             "User-reported phishing email with malicious link to credential-harvesting page",
             "TRUE_POSITIVE", "P2_HIGH", ["T1566"], "email"),
    EvalCase("sqli_exploit",
             "WAF: SQL injection exploit against public-facing checkout app, sqli payloads observed",
             "TRUE_POSITIVE", "P2_HIGH", ["T1190"], "siem"),
    EvalCase("valid_accounts",
             "Valid account credential abuse: stolen token used from a new ASN for svc-billing",
             "TRUE_POSITIVE", "P2_HIGH", ["T1078"], "siem"),
    EvalCase("lolbin_powershell",
             "EDR: encoded powershell living off the land, winrm parent process on k8s-worker-7",
             "TRUE_POSITIVE", "P2_HIGH", ["T1059"], "edr"),
    EvalCase("endpoint_beacon",
             "EDR: endpoint beacon detected every 60s to a rare external domain",
             "TRUE_POSITIVE", "P2_HIGH", ["T1071"], "edr"),

    # ---- False positives (should be dismissed, not chased) ----
    EvalCase("authorized_pentest",
             "Authorized penetration test from the security team (pen test), scheduled scan in the approved change window",
             "FALSE_POSITIVE", "P4_LOW", [], "siem"),
    EvalCase("known_good_scanner",
             "Vulnerability scanner traffic from known good internal host; confirmed false positive by analyst",
             "FALSE_POSITIVE", "P4_LOW", [], "siem"),
    EvalCase("test_alert",
             "This is a test alert generated during a sanctioned red team exercise",
             "FALSE_POSITIVE", "P4_LOW", [], "generic"),

    # ---- Benign anomalies (unusual but not malicious) ----
    EvalCase("cert_renewal",
             "TLS certificate renewed automatically for api-gateway; health check passed, returned to normal",
             "BENIGN_ANOMALY", "P4_LOW", [], "generic"),
    EvalCase("backup_spike",
             "Egress spike on backup host — nightly backup completed successfully, within baseline for the window",
             "BENIGN_ANOMALY", "P4_LOW", [], "siem"),

    # ---- Needs human (genuinely ambiguous) ----
    EvalCase("ambiguous_login",
             "Unusual login pattern for a user but unclear intent; insufficient context, needs manual review",
             "NEEDS_HUMAN", "P3_MEDIUM", [], "siem"),
    EvalCase("ambiguous_config",
             "Config drift detected on a host; cannot determine if authorized, please advise",
             "NEEDS_HUMAN", "P3_MEDIUM", [], "generic"),
]
