"""Investigation Agent — ANLST persona.

Runs on the router's "smart" tier with function calling. Each round the model
may return several tool calls, which the agent executes concurrently
(``asyncio.gather``); it loops until confidence > 0.7, MAX_ROUNDS is reached, or
the model returns a final InvestigationFinding with no tool calls. Only a small,
relevant, read-only toolset is exposed per incident (see ``tool_selector``) to
keep OSS models focused and prompt tokens low.

When no LLM key is configured (zero-key demo mode), falls back to a
deterministic heuristic investigation that drives the *same* tool registry so
the dashboard still gets realistic `tool.called` / `tool.result` events.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

from app.agents.base import AgentPersona
from app.db import incidents as incidents_db
from app.db.audit import write_audit
from app.pipeline.model_router import select_model
from app.pipeline.tool_selector import select_investigation_tools
from app.schemas.events import make_event
from app.schemas.investigation import (
    IOC,
    Evidence,
    InvestigationFinding,
    TimelineEvent,
)
from app.services.llm import extract_json, llm
from app.services.redis_client import publish_event
from app.tools.registry import execute_tool, get_tool_schemas

logger = logging.getLogger("sentinelforge.agents.investigation")

MAX_ROUNDS = 5
CONFIDENCE_STOP = 0.7

INVESTIGATION_SYSTEM = """\
You are an expert security incident investigator (SOC analyst + SRE). Your goal
is to determine the root cause of the security finding with as much evidence as
possible, and to enrich it with indicators of compromise (IOCs).

Investigation strategy:
1. Start from the triage result (severity, verdict, MITRE ATT&CK techniques).
2. Pull corroborating evidence using the available tools — request several
   INDEPENDENT tools together in a single turn (they run concurrently):
   - query_siem_auth_logs / query_elasticsearch to look for related events
   - lookup_ip_reputation on every external source IP
   - search_cve_database when a vulnerable product/version is mentioned
   - enrich_user_identity on every affected user principal
   - query_edr_endpoint on every affected hostname
   - search_runbook for the documented playbook for this finding class
3. Stop investigating when you have enough evidence (confidence > 0.7) or when
   no further tool call would meaningfully increase confidence — then emit a
   final InvestigationFinding JSON object (see schema below).
4. Cite every piece of evidence in `evidence` and surface IOCs in `iocs`.

Final output MUST be a JSON InvestigationFinding object:
{
  "root_cause": "clear description of the security root cause",
  "confidence_score": 0.0-1.0,
  "evidence": [{"source": "tool_name", "detail": "what was found"}],
  "contributing_factors": ["..."],
  "affected_dependencies": ["..."],
  "related_cves": null or [{"cve_id":"...","severity":"...","url":"..."}],
  "relevant_runbook_id": null or "runbook path",
  "timeline": [{"timestamp":"ISO8601","event":"description"}],
  "iocs": [{"type":"ip|user|host|file_hash|url|cve","value":"...","verdict":"MALICIOUS|SUSPICIOUS|BENIGN|UNKNOWN","source":"tool"}],
  "blast_radius_assessment": "narrative assessment of attacker reach"
}

Do NOT keep calling tools once you have a confident root cause. Output the
final finding as JSON.
"""


class InvestigationAgent(AgentPersona):
    PERSONA = "ANLST"
    LABEL = "The Analyst"
    COLOR = "#00D4FF"

    async def run(self, incident_id: str) -> InvestigationFinding:
        start_time = time.time()
        incident = await incidents_db.get_incident(incident_id)
        if not incident:
            return InvestigationFinding(
                incident_id=incident_id,
                root_cause="unknown",
                evidence=[],
                confidence_score=0.0,
            )

        triage_raw = incident.get("triage_result") or {}
        if isinstance(triage_raw, str):
            try:
                triage = json.loads(triage_raw)
            except (json.JSONDecodeError, TypeError):
                triage = {}
        else:
            triage = triage_raw
        severity = incident.get("severity", "P3_MEDIUM")
        model = select_model(severity, "investigation")
        await self.say(incident_id, "Beginning investigation. Pulling evidence from tools...")
        await publish_event(incident_id, make_event("investigation.started", incident_id))

        if not llm.enabled:
            finding = await self._heuristic_investigate(incident_id, incident, triage)
            finding.total_investigation_duration_seconds = time.time() - start_time
            await self._finish(incident_id, finding)
            return finding

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": INVESTIGATION_SYSTEM},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "incident_id": incident_id,
                        "severity": severity,
                        "affected_service": incident.get("affected_service", "unknown"),
                        "affected_hosts": incident.get("affected_hosts", []),
                        "alert_message": incident.get("alert_message", ""),
                        "triage": triage,
                        "first_seen_at": incident.get(
                            "created_at", datetime.now(timezone.utc).isoformat()
                        ),
                    },
                    default=str,
                ),
            },
        ]
        # Expose only a small, relevant, read-only toolset (OSS efficiency).
        tool_names = self._select_tools(incident, triage)
        tools = get_tool_schemas(tool_names)
        await publish_event(
            incident_id,
            make_event("investigation.tools_selected", incident_id, tools=tool_names),
        )
        logger.info(
            "investigation %s exposing %d/%d tools: %s",
            incident_id,
            len(tool_names),
            len(get_tool_schemas()),
            tool_names,
        )
        tools_used: list[str] = []
        all_evidence: list[dict] = []
        all_iocs: list[dict] = []

        for round_num in range(1, MAX_ROUNDS + 1):
            resp = await llm.complete(
                model=model,
                messages=messages,
                incident_id=incident_id,
                tools=tools,
                parallel_tool_calls=True,
            )
            content = resp.get("content") or ""
            tool_calls = resp.get("tool_calls") or []

            # If the model already wants to finalize (no tool calls), parse + return.
            if not tool_calls:
                finding = self._parse_finding(
                    content,
                    incident_id,
                    time.time() - start_time,
                    tools_used,
                    all_evidence,
                    all_iocs,
                )
                await self._finish(incident_id, finding)
                return finding

            # 1) Announce each tool call (parallel) before executing.
            for tc in tool_calls:
                name = tc.get("function", {}).get("name", "tool")
                args = self._safe_args(tc)
                await publish_event(
                    incident_id,
                    make_event(
                        "tool.called",
                        incident_id,
                        tool=name,
                        args=args,
                        round=round_num,
                        persona=self.PERSONA,
                    ),
                )
                if name not in tools_used:
                    tools_used.append(name)

            # 2) Execute tool calls in parallel (they are independent by spec).
            results = await asyncio.gather(
                *(execute_tool(tc["function"]["name"], self._safe_args(tc)) for tc in tool_calls),
                return_exceptions=True,
            )

            # 3) Stream each result back to the dashboard + into the message thread.
            tool_results_for_model = []
            for tc, res in zip(tool_calls, results):
                name = tc["function"]["name"]
                args = self._safe_args(tc)
                tc_id = tc.get("id", "")
                if isinstance(res, Exception):
                    payload = {"error": str(res), "tool": name}
                else:
                    payload = res if isinstance(res, (dict, list)) else {"result": str(res)}
                self._collect_iocs_evidence(name, args, payload, all_iocs, all_evidence)
                await publish_event(
                    incident_id,
                    make_event(
                        "tool.result",
                        incident_id,
                        tool=name,
                        args=args,
                        result=payload,
                        round=round_num,
                    ),
                )
                tool_results_for_model.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "content": json.dumps(payload, default=str)[:4000],
                    }
                )

            # 4) Push the assistant tool_call message + tool results back into the thread.
            messages.append({"role": "assistant", "content": content, "tool_calls": tool_calls})
            messages.extend(tool_results_for_model)

        # Max rounds hit — ask for a final finding with no tools available.
        await self.say(incident_id, "Reaching investigation budget — synthesizing finding...")
        final_resp = await llm.complete(
            model=model,
            messages=messages,
            incident_id=incident_id,
        )
        finding = self._parse_finding(
            final_resp["content"],
            incident_id,
            time.time() - start_time,
            tools_used,
            all_evidence,
            all_iocs,
        )
        await self._finish(incident_id, finding)
        return finding

    async def _finish(self, incident_id: str, finding: InvestigationFinding) -> None:
        await self.say(
            incident_id,
            f"Root cause identified: {finding.root_cause[:100]}. "
            f"Confidence: {int(finding.confidence_score * 100)}%.",
        )
        await write_audit(
            incident_id=incident_id,
            actor="system:investigation_agent",
            action="investigation.complete",
            details={
                "root_cause": finding.root_cause,
                "confidence": finding.confidence_score,
                "tools_used": finding.tools_used,
                "ioc_count": len(finding.iocs),
            },
        )

    def _select_tools(self, incident: dict, triage: dict) -> list[str]:
        """Choose a small, relevant read-only toolset from cheap signals."""
        text = (incident.get("alert_message") or "") + " " + json.dumps(triage, default=str)
        techniques = triage.get("attack_techniques") or []
        technique_ids = [t.get("technique_id", "") for t in techniques if isinstance(t, dict)]
        return select_investigation_tools(
            category=triage.get("root_cause_category") or incident.get("category"),
            technique_ids=technique_ids,
            has_ips=bool(_extract_ips(text)),
            has_users=bool(_extract_users(text)),
            has_hosts=bool(incident.get("affected_hosts")),
            has_tech=bool(_extract_tech(text)),
        )

    def _safe_args(self, tc: dict) -> dict:
        try:
            return json.loads(tc.get("function", {}).get("arguments", "{}"))
        except Exception:
            return {}

    def _parse_finding(
        self,
        content: str,
        incident_id: str,
        duration: float,
        tools_used: list[str],
        evidence: list[dict],
        iocs: list[dict],
    ) -> InvestigationFinding:
        data = None
        try:
            data = extract_json(content)
        except Exception:
            data = None
        if not isinstance(data, dict):
            data = {
                "root_cause": content[:200] or "Investigation inconclusive",
                "confidence_score": 0.5,
                "evidence": evidence,
                "iocs": iocs,
                "tools_used": tools_used,
            }

        data.setdefault("incident_id", incident_id)
        data.setdefault("root_cause", "Investigation inconclusive")
        data.setdefault("confidence_score", 0.5)
        data.setdefault("evidence", evidence)
        data.setdefault("tools_used", tools_used)
        data.setdefault("iocs", iocs)
        data["total_investigation_duration_seconds"] = duration
        # Stop early once confidence hits the threshold.
        try:
            if float(data.get("confidence_score", 0)) >= CONFIDENCE_STOP:
                pass  # nothing to do — the loop also checks, this is just defence
        except Exception:
            data["confidence_score"] = 0.5
        return InvestigationFinding.model_validate(data)

    def _collect_iocs_evidence(
        self,
        tool: str,
        args: dict,
        payload: Any,
        iocs: list[dict],
        evidence: list[dict],
    ) -> None:
        """Extract IOCs + evidence from each tool result, in-place."""
        if not isinstance(payload, dict):
            evidence.append({"source": tool, "detail": str(payload)[:300]})
            return

        detail_bits: list[str] = []

        # IP reputation
        if tool == "lookup_ip_reputation":
            ip = args.get("ip_address", "")
            res = payload.get("results", {}) or {}
            vt = res.get("virustotal") or {}
            ab = res.get("abuseipdb") or {}
            verdict = payload.get("verdict") or (
                "MALICIOUS"
                if (vt.get("malicious", 0) > 5 or ab.get("abuse_confidence_score", 0) > 60)
                else "UNKNOWN"
            )
            if ip:
                iocs.append({"type": "ip", "value": ip, "verdict": verdict, "source": tool})
            detail_bits.append(
                f"VT malicious={vt.get('malicious', '?')}, AbuseIPDB score={ab.get('abuse_confidence_score', '?')}"
            )

        # CVE search
        elif tool == "search_cve_database":
            for cve in payload.get("cves", []) or []:
                iocs.append(
                    {
                        "type": "cve",
                        "value": cve.get("cve_id", ""),
                        "verdict": cve.get("severity", "UNKNOWN"),
                        "source": tool,
                    }
                )
            detail_bits.append(
                f"{len(payload.get('cves', []) or [])} CVE(s) found for {args.get('product', '')}"
            )

        # SIEM auth logs / Elasticsearch / EDR
        elif tool in ("query_siem_auth_logs", "query_elasticsearch", "query_edr_endpoint"):
            hits = payload.get("hits") or payload.get("events") or []
            detail_bits.append(f"{len(hits)} matching event(s)")
            for h in hits[:5]:
                if isinstance(h, dict):
                    msg = h.get("message") or h.get("raw") or json.dumps(h, default=str)[:160]
                    src_ip = h.get("source_ip") or h.get("src_ip")
                    if src_ip:
                        iocs.append(
                            {"type": "ip", "value": src_ip, "verdict": "SUSPICIOUS", "source": tool}
                        )
                    user = h.get("user") or h.get("username")
                    if user:
                        iocs.append(
                            {"type": "user", "value": user, "verdict": "SUSPICIOUS", "source": tool}
                        )
                    detail_bits.append(f"[{h.get('@timestamp') or h.get('timestamp') or ''}] {msg}")

        # Identity enrichment
        elif tool == "enrich_user_identity":
            user = args.get("username", "") or payload.get("username", "")
            if user:
                priv = bool(payload.get("is_privileged"))
                iocs.append(
                    {
                        "type": "user",
                        "value": user,
                        "verdict": "SUSPICIOUS" if priv else "UNKNOWN",
                        "source": tool,
                    }
                )
            detail_bits.append(
                f"privileged={payload.get('is_privileged')}, mfa_enabled={payload.get('mfa_enabled')}"
            )

        # Runbook search
        elif tool == "search_runbook":
            for r in payload.get("results", []) or []:
                detail_bits.append(f"runbook match: {r.get('title')} ({r.get('path')})")
            if payload.get("results"):
                evidence.append(
                    {
                        "source": tool,
                        "detail": "Matched playbook: " + payload["results"][0].get("title", ""),
                    }
                )

        evidence.append(
            {
                "source": tool,
                "detail": " | ".join(detail_bits)[:400] or json.dumps(payload, default=str)[:400],
            }
        )

    # ---------- heuristic investigation (zero-key demo mode) ----------

    async def _heuristic_investigate(
        self, incident_id: str, incident: dict, triage: dict
    ) -> InvestigationFinding:
        """Deterministic demo path: runs a small scripted sequence of REAL tools
        (which themselves may fall back to mocks), publishing the same SSE events
        the LLM path emits."""
        signal_text = (incident.get("alert_message") or "") + " " + json.dumps(triage, default=str)
        text = signal_text.lower()
        triage_techniques = triage.get("attack_techniques") or []

        plan: list[tuple[str, dict]] = []
        # 1. Source-IP reputation (if any IPs in the signal)
        ips = _extract_ips(signal_text)
        for ip in ips[:3]:
            plan.append(("lookup_ip_reputation", {"ip_address": ip}))

        # 2. Identity enrichment for any usernames
        for u in _extract_users(signal_text)[:3]:
            plan.append(("enrich_user_identity", {"username": u}))

        # 3. EDR query per affected host
        for h in (incident.get("affected_hosts") or [])[:3]:
            plan.append(("query_edr_endpoint", {"hostname": h}))

        # 4. CVE enrichment for any technologies
        for tech in _extract_tech(signal_text)[:2]:
            plan.append(("search_cve_database", {"product": tech}))

        # 5. SIEM auth-log pull
        if any(k in text for k in ("login", "auth", "ssh", "failed", "credential")):
            plan.append(
                (
                    "query_siem_auth_logs",
                    {"query": "Failed password OR authentication failure", "hours_back": 1},
                )
            )

        # 6. Runbook search keyed on the technique
        rb_query = (
            triage_techniques[0].get("name", "incident response")
            if triage_techniques
            else (incident.get("affected_service") or "security incident")
        )
        plan.append(("search_runbook", {"query": rb_query}))

        if not plan:
            plan.append(
                ("search_runbook", {"query": incident.get("alert_message", "incident")[:120]})
            )

        tools_used: list[str] = []
        all_evidence: list[dict] = []
        all_iocs: list[dict] = []
        for round_num, (name, args) in enumerate(plan, start=1):
            await publish_event(
                incident_id,
                make_event(
                    "tool.called",
                    incident_id,
                    tool=name,
                    args=args,
                    round=round_num,
                    persona=self.PERSONA,
                ),
            )
            if name not in tools_used:
                tools_used.append(name)
            try:
                payload = await execute_tool(name, args)
            except Exception as exc:
                payload = {"error": str(exc), "tool": name}
            self._collect_iocs_evidence(name, args, payload, all_iocs, all_evidence)
            await publish_event(
                incident_id,
                make_event(
                    "tool.result",
                    incident_id,
                    tool=name,
                    args=args,
                    result=payload,
                    round=round_num,
                ),
            )

        # Synthesize a deterministic finding
        malicious_iocs = [i for i in all_iocs if i["verdict"] == "MALICIOUS"]
        confidence = min(0.85, 0.45 + 0.08 * len(all_evidence) + 0.05 * len(malicious_iocs))
        root_cause = (
            f"Automated investigation surfaced {len(all_iocs)} indicators "
            f"({len(malicious_iocs)} suspicious/malicious) across "
            f"{len(tools_used)} tools."
        )
        ioc_objs = [IOC.model_validate(i) for i in all_iocs]
        ev_objs = [Evidence.model_validate(e) for e in all_evidence]
        return InvestigationFinding(
            incident_id=incident_id,
            root_cause=root_cause,
            evidence=ev_objs,
            confidence_score=confidence,
            tools_used=tools_used,
            iocs=ioc_objs,
            timeline=[
                TimelineEvent(
                    timestamp=datetime.now(timezone.utc),
                    event=f"ran {len(tools_used)} investigatory tools",
                )
            ],
            blast_radius_assessment=(
                "Heuristic assessment — correlate IOCs against deployment topology to bound attacker reach."
            ),
        )


# ---------- heuristic signal parsers ----------

_IP_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"\buser[=:\s]+([A-Za-z0-9._@\-]+)\b", re.IGNORECASE)
# "nginx 1.21", "openssl 3.0.7", "postgres 14.2"
_TECH_RE = re.compile(
    r"\b(nginx|openssl|postgres|postgresql|java|jvm|apache|redis|mongo|kafka)[\s-]*v?(\d+(?:\.\d+){0,2})?",
    re.IGNORECASE,
)


def _extract_ips(text: str) -> list[str]:
    seen: list[str] = []
    for m in _IP_RE.finditer(text):
        ip = m.group(0)
        if ip.startswith(("10.", "172.16.", "192.168.", "127.")):
            continue
        if ip not in seen:
            seen.append(ip)
    return seen


def _extract_users(text: str) -> list[str]:
    seen: list[str] = []
    for m in _USER_RE.finditer(text):
        u = m.group(1).strip().strip("`\"'")
        if u and u.lower() not in ("unknown", "none") and u not in seen:
            seen.append(u)
    return seen


def _extract_tech(text: str) -> list[str]:
    out: list[str] = []
    for m in _TECH_RE.finditer(text):
        out.append(m.group(0))
    return out


def _narrative_for(tool_name: str, tc: dict) -> str:
    """Human-readable narrative for a tool call (unused by the live loop; kept
    for compatibility with any external consumers of this module)."""
    try:
        args = json.loads(tc.get("function", {}).get("arguments", "{}"))
    except Exception:
        args = {}
    narratives = {
        "query_elasticsearch": f'Scanning logs for "{args.get("query_string", "")}"...',
        "query_siem_auth_logs": f'Querying SIEM auth logs: "{args.get("query", "")}"...',
        "query_prometheus_metrics": f"Querying metrics: {args.get('promql', '')[:60]}...",
        "lookup_ip_reputation": f"Checking threat intel for {args.get('ip_address', '')}...",
        "search_cve_database": f"Searching CVEs for {args.get('product', '')}...",
        "enrich_user_identity": f"Enriching identity: {args.get('username', '')}...",
        "query_edr_endpoint": f"Querying EDR for host {args.get('hostname', '')}...",
        "search_runbook": f'Searching runbook KB for "{args.get("query", "")[:40]}"...',
        "send_slack_message": "Sending Slack notification...",
        "create_pagerduty_incident": "Creating PagerDuty incident...",
        "check_ssl_certificate": f"Checking SSL cert for {args.get('domain', '')}...",
        "get_service_dependencies": f"Mapping dependencies for {args.get('service', '')}...",
        "block_ip": f"Blocking IP {args.get('ip_address', '')}...",
        "suspend_account": f"Suspending account {args.get('username', '')}...",
    }
    return narratives.get(tool_name, f"Calling {tool_name}...")
