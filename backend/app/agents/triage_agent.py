"""Triage Agent — CMDR persona (SOC edition).

Runs on the model router's "smart" tier for P1/P2 findings (an explicit
reasoning model when one is configured) and the cheap "fast" tier for P3/P4.

Reasoning trace on OSS models: open models on Groq don't emit a separate
``reasoning_content`` stream, so we get a *live* reasoning trace with a single
call by asking the model to think in plain prose, then emit a sentinel line
(``===TRIAGE_JSON===``) followed by the structured verdict. Everything before
the sentinel streams to the dashboard as the CMDR's thinking; everything after
is parsed as the TriageResult. Reasoning models that *do* stream thinking are
also handled transparently.

Output: a TriageResult with severity, verdict (TRUE_POSITIVE / FALSE_POSITIVE /
BENIGN_ANOMALY / NEEDS_HUMAN), MITRE ATT&CK technique mappings, and blast
radius. The orchestrator forwards true-positive / benign-only findings to the
Investigation Agent, dismisses false positives, and escalates NEEDS_HUMAN.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.agents.base import AgentPersona
from app.db.audit import write_audit
from app.pipeline.model_router import select_model, use_thinking
from app.schemas.events import make_event
from app.schemas.incident import BlastRadius, RootCauseCategory, Severity
from app.schemas.triage import AttackTechnique, TriageResult, Verdict
from app.services.llm import extract_json, llm
from app.services.redis_client import publish_event

logger = logging.getLogger("sentinelforge.agents.triage")

TRIAGE_SYSTEM = """\
You are a Senior SOC Analyst with 10+ years of experience in security operations
and incident response. Your job is to triage incoming security findings and classify
them accurately.

You will receive a normalized IncidentSignal JSON. Your output MUST be a valid
TriageResult JSON object with these fields:
- incident_id: string
- severity: one of P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW
- verdict: one of TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_ANOMALY, NEEDS_HUMAN
- is_false_positive: boolean (true iff verdict == FALSE_POSITIVE)
- false_positive_reason: string or null
- root_cause_category: one of SECURITY, CREDENTIAL_ABUSE, MALWARE, EXPLOIT,
  LATERAL_MOVEMENT, DATA_EXFILTRATION, RECONNAISSANCE, MISCONFIGURATION,
  POLICY_VIOLATION, INFRASTRUCTURE, APPLICATION, DATA, NETWORK, CAPACITY
- affected_services: list of strings
- estimated_users_affected: integer or null
- blast_radius: one of SINGLE_HOST, SINGLE_USER, SERVICE, CLUSTER, WORKSPACE, REGION, GLOBAL
- attack_techniques: list of {technique_id, name, tactic, confidence} — MITRE ATT&CK
  mappings. Empty list if verdict is FALSE_POSITIVE or BENIGN_ANOMALY.
- investigation_priority: ordered list of what to investigate first
- similar_past_incidents: list of incident IDs or null
- auto_investigatable: boolean (true if AI can investigate without immediate human)
- thinking_trace: string or null (your reasoning if thinking mode was used)

Triage priorities:
1. Determine if this finding is a true positive, false positive, benign anomaly, or
   needs immediate human review (verdict).
2. Map the finding to MITRE ATT&CK techniques (give a confidence 0..1 for each).
3. Assess blast radius — how many users/services/hosts are affected?
4. Classify the root cause category.
5. Determine severity: P1/CRITICAL, P2/HIGH, P3/MEDIUM, P4/LOW.

For CRITICAL/P1 findings: think carefully and methodically. Show your reasoning.
For LOW/P4 findings: be efficient — quick classification is more valuable than deep analysis.

Common MITRE ATT&CK technique ids you may use:
- T1110 Brute Force (Credential Access)
- T1078 Valid Accounts (Defense Evasion, Persistence, Privilege Escalation, Initial Access)
- T1059 Command and Scripting Interpreter (Execution)
- T1190 Exploit Public-Facing Application (Initial Access)
- T1071 Application Layer Protocol (Command and Control)
- T1041 Exfiltration Over C2 Channel (Exfiltration)
- T1566 Phishing (Initial Access)
- T1486 Data Encrypted for Impact (Impact)
- T1027 Obfuscated Files or Information (Defense Evasion)
- T1053 Scheduled Task/Job (Execution, Privilege Escalation, Persistence)
- T1213 Data from Information Repositories (Collection)
- T1485 Data Destruction (Impact)

Be specific — prefer the sub-technique id where appropriate.

OUTPUT FORMAT (important):
First, reason about the finding in a few short plain-language sentences (an
experienced analyst thinking out loud — what stands out, how bad it looks, why).
Then, on its own line, output the exact marker:
===TRIAGE_JSON===
and immediately after it output ONLY the TriageResult JSON object (no code
fences, no commentary after it).
"""

# Marker separating the streamed reasoning prose from the JSON verdict. Lets us
# surface a live reasoning trace on OSS models that don't emit reasoning_content.
TRIAGE_SENTINEL = "===TRIAGE_JSON==="


# ---- heuristic fallback (zero-key demo) ---------------------------------

KEYWORD_TO_TECHNIQUE = [
    (
        ("brute force", "brute-force", "failed login", "ssh brute", "failed password"),
        {"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ),
    (
        ("phish", "phishing", "malicious link", "spear phish"),
        {"technique_id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
    ),
    (
        ("beacon", "c2 ", "command and control", "dns tunnel", "reverse shell"),
        {
            "technique_id": "T1071",
            "name": "Application Layer Protocol",
            "tactic": "Command and Control",
        },
    ),
    (
        ("exfil", "data theft", "egress anomaly"),
        {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    ),
    (
        ("ransomware", "encrypted file", "file extension"),
        {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    ),
    (
        ("powershell", "shell_command", "lolbin", "living off the land"),
        {
            "technique_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
        },
    ),
    (
        ("sql injection", "sqli", "exploit public"),
        {
            "technique_id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
        },
    ),
    (
        ("valid account", "credential abuse", "stolen token"),
        {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
    ),
]


def _heuristic_techniques(text: str) -> list[AttackTechnique]:
    out: list[AttackTechnique] = []
    for kws, t in KEYWORD_TO_TECHNIQUE:
        if any(k in text for k in kws):
            out.append(AttackTechnique(**t, confidence=0.78))
    return out[:3]


# Markers that flip a finding away from a naive "everything is a true positive".
_FALSE_POSITIVE_MARKERS = (
    "authorized",
    "penetration test",
    "pen test",
    "pentest",
    "red team",
    "scheduled scan",
    "approved change",
    "known good",
    "false positive",
    "test alert",
    "expected behavior",
    "sanctioned",
)
_BENIGN_MARKERS = (
    "certificate renewed",
    "backup completed",
    "health check",
    "auto-resolved",
    "resolved automatically",
    "returned to normal",
    "within baseline",
)
_NEEDS_HUMAN_MARKERS = (
    "unclear",
    "ambiguous",
    "needs manual review",
    "cannot determine",
    "insufficient context",
    "please advise",
)


def _heuristic_triage(signal: dict[str, Any], incident_id: str) -> TriageResult:
    text = json.dumps(signal, default=str).lower()
    techniques = _heuristic_techniques(text)
    # Verdict: check the "not-actually-an-attack" markers first, then threat keywords.
    if any(k in text for k in _FALSE_POSITIVE_MARKERS):
        verdict, severity, techniques = Verdict.FALSE_POSITIVE, Severity.P4_LOW, []
    elif any(k in text for k in _BENIGN_MARKERS):
        verdict, severity, techniques = Verdict.BENIGN_ANOMALY, Severity.P4_LOW, []
    elif any(k in text for k in _NEEDS_HUMAN_MARKERS):
        verdict, severity = Verdict.NEEDS_HUMAN, Severity.P3_MEDIUM
    elif any(
        k in text for k in ("brute force", "failed login", "ransomware", "c2 ", "exfil", "phish")
    ):
        verdict = Verdict.TRUE_POSITIVE
        severity = (
            Severity.P1_CRITICAL if "ransomware" in text or "c2 " in text else Severity.P2_HIGH
        )
    elif "beacon" in text:
        verdict = Verdict.TRUE_POSITIVE
        severity = Severity.P2_HIGH
    else:
        verdict = Verdict.TRUE_POSITIVE
        severity = Severity.P3_MEDIUM
    return TriageResult(
        incident_id=incident_id,
        severity=severity,
        verdict=verdict,
        is_false_positive=(verdict == Verdict.FALSE_POSITIVE),
        root_cause_category=RootCauseCategory.SECURITY,
        affected_services=[signal.get("affected_service", "unknown")]
        if signal.get("affected_service")
        else [],
        blast_radius=BlastRadius.SERVICE,
        attack_techniques=techniques,
        investigation_priority=[
            "check source IP reputation",
            "enrich affected user identities",
            "query EDR for affected hosts",
        ],
        auto_investigatable=True,
        thinking_trace="(heuristic triage — no LLM key configured)",
    )


class TriageAgent(AgentPersona):
    PERSONA = "CMDR"
    LABEL = "The Commander"
    COLOR = "#FF4444"

    async def run(self, incident_id: str, signal: dict[str, Any]) -> TriageResult:
        """Run triage on a security finding. Returns TriageResult."""
        await self.say(incident_id, "Security finding received. Assembling investigation team.")

        initial_severity = self._guess_severity(signal)
        model = select_model(initial_severity, "triage")
        thinking = use_thinking(initial_severity, "triage")

        messages = [
            {"role": "system", "content": TRIAGE_SYSTEM},
            {"role": "user", "content": json.dumps(signal, default=str)},
        ]

        if not llm.enabled:
            await self.say(incident_id, "(No LLM key set — using heuristic SOC triage.)")
            result = _heuristic_triage(signal, incident_id)
            await self._publish_verdict(incident_id, result)
            await self._audit(incident_id, result)
            return result

        # Stream reasoning prose (live to the dashboard), then a sentinel, then
        # the JSON verdict. Works on OSS models with no reasoning_content stream.
        reason_buf = ""  # reasoning text accumulated so far (pre-sentinel)
        reason_emitted = 0  # chars of reason_buf already streamed to the UI
        json_buf: list[str] = []
        in_json = False

        async def _emit_reasoning(text: str) -> None:
            if text:
                await publish_event(
                    incident_id,
                    make_event("thinking.chunk", incident_id, content=text),
                )

        async for chunk in llm.stream(
            model=model,
            messages=messages,
            incident_id=incident_id,
            enable_thinking=thinking,
        ):
            kind = chunk["kind"]
            if kind == "thinking":
                # Native reasoning-model output — pass straight through.
                reason_buf += chunk["content"]
                reason_emitted = len(reason_buf)
                await _emit_reasoning(chunk["content"])
            elif kind == "content":
                if in_json:
                    json_buf.append(chunk["content"])
                    continue
                reason_buf += chunk["content"]
                idx = reason_buf.find(TRIAGE_SENTINEL)
                if idx != -1:
                    await _emit_reasoning(reason_buf[reason_emitted:idx])
                    reason_emitted = idx
                    in_json = True
                    json_buf.append(reason_buf[idx + len(TRIAGE_SENTINEL) :])
                else:
                    # Stream reasoning but hold back a possible partial sentinel.
                    safe = max(reason_emitted, len(reason_buf) - len(TRIAGE_SENTINEL))
                    if safe > reason_emitted:
                        await _emit_reasoning(reason_buf[reason_emitted:safe])
                        reason_emitted = safe

        thinking_trace = reason_buf[:reason_emitted].replace(TRIAGE_SENTINEL, "").strip() or None
        # If the sentinel never appeared, parse the whole response best-effort.
        json_text = "".join(json_buf) if in_json else reason_buf

        try:
            data = extract_json(json_text)
            if not isinstance(data, dict):
                raise ValueError("triage JSON was not an object")
        except Exception:
            logger.warning("triage parse failed; falling back to heuristic")
            result = _heuristic_triage(signal, incident_id)
            result.thinking_trace = thinking_trace or json_text[:500]
            await self._publish_verdict(incident_id, result)
            await self._audit(incident_id, result)
            return result

        data["incident_id"] = incident_id
        if thinking_trace and not data.get("thinking_trace"):
            data["thinking_trace"] = thinking_trace

        # Backfill verdict<->is_false_positive consistency.
        verdict_value = data.get("verdict")
        if verdict_value == Verdict.TRUE_POSITIVE.value:
            data["is_false_positive"] = False
        elif verdict_value in (Verdict.FALSE_POSITIVE.value, Verdict.BENIGN_ANOMALY.value):
            data["is_false_positive"] = verdict_value == Verdict.FALSE_POSITIVE.value
            data.setdefault("attack_techniques", [])
        elif verdict_value == Verdict.NEEDS_HUMAN.value:
            data["auto_investigatable"] = False

        result = TriageResult.model_validate(data)

        if result.verdict == Verdict.TRUE_POSITIVE:
            result.auto_investigatable = True

        await self._publish_verdict(incident_id, result)
        await self._audit(incident_id, result)
        return result

    async def _publish_verdict(self, incident_id: str, result: TriageResult) -> None:
        await self.say(
            incident_id,
            f"Verdict: {result.verdict.value}. Severity: {result.severity.value}. "
            f"Category: {result.root_cause_category.value}. Blast radius: {result.blast_radius.value}.",
        )
        await publish_event(
            incident_id,
            make_event(
                "triage.complete",
                incident_id,
                severity=result.severity.value,
                verdict=result.verdict.value,
                attack_techniques=[t.model_dump() for t in result.attack_techniques],
                blast_radius=result.blast_radius.value,
            ),
        )

    async def _audit(self, incident_id: str, result: TriageResult) -> None:
        await write_audit(
            incident_id=incident_id,
            actor="system:triage_agent",
            action="triage.complete",
            details={
                "severity": result.severity.value,
                "verdict": result.verdict.value,
                "category": result.root_cause_category.value,
                "techniques": [t.technique_id for t in result.attack_techniques],
            },
        )

    def _guess_severity(self, signal: dict[str, Any]) -> str:
        """Quick heuristic to pick initial model before triage refines severity."""
        text = json.dumps(signal, default=str).lower()
        if any(
            k in text
            for k in ("critical", "p1", "ransomware", "exfil", "data theft", "root", "breach")
        ):
            return Severity.P1_CRITICAL.value
        if any(k in text for k in ("high", "p2", "c2", "brute", "beacon", "isolat")):
            return Severity.P2_HIGH.value
        if any(k in text for k in ("medium", "p3", "warning", "slow", "phish", "failed login")):
            return Severity.P3_MEDIUM.value
        return Severity.P4_LOW.value
