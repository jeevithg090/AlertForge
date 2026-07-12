"""Threat-hunt hypothesis generator.

Given a MITRE technique (usually straight off a triage verdict), an incident, or
a free-text seed, produce a small set of falsifiable hunt hypotheses, each with
runnable queries. Proactive hunting is what turns a single contained alert into
"did this actor touch anything else?" — the question that actually catches
breaches.

Design for OSS models: a curated template library covers the most common
techniques deterministically (works with zero API key and is always sane), and
when a model is available it is *seeded* with those templates and asked to
refine/expand them rather than invent SIEM syntax from scratch — which is
exactly where small models are weakest.
"""
from __future__ import annotations

import json
import logging

from app.pipeline.model_router import select_model
from app.schemas.hunt import HuntHypothesis, HuntPlan, HuntPriority, HuntQuery
from app.services.llm import llm

logger = logging.getLogger("sentinelforge.hunt")

HUNT_SYSTEM = """\
You are an elite threat hunter. Given a MITRE ATT&CK technique and incident
context, produce 2-4 FALSIFIABLE hunt hypotheses that look for *related* attacker
activity the initial alert may have missed (successful follow-on, lateral
movement, persistence, staging, exfiltration).

For each hypothesis provide:
- title: a crisp, testable statement
- rationale: why it's worth hunting given this finding
- mitre_technique_id / mitre_technique_name / tactic
- data_sources: concrete telemetry to search (auth logs, EDR process events,
  proxy/netflow, cloud audit, DNS, email gateway, …)
- queries: 1-2 runnable queries. Use platform "spl" (Splunk SPL), "eql"
  (Elastic EQL), "kql", "lucene", "sigma", or "sql". Queries must be concrete,
  not placeholders.
- expected_findings: what a TRUE result looks like
- false_positive_notes: benign explanations to rule out
- priority: HIGH | MEDIUM | LOW

Refine and expand the provided starter hypotheses where given; keep queries
realistic. Respond as a HuntPlan JSON object.
"""


def _q(platform: str, query: str, description: str = "") -> HuntQuery:
    return HuntQuery(platform=platform, query=query, description=description)


# --------------------------------------------------------------------------- #
# Deterministic template library, keyed on base technique id.
# --------------------------------------------------------------------------- #

def _templates() -> dict[str, list[HuntHypothesis]]:
    return {
        "T1110": [  # Brute Force
            HuntHypothesis(
                title="A brute-force attempt eventually succeeded from the same source",
                rationale="Storms of failures often end in one success; the success is the real incident.",
                mitre_technique_id="T1110", mitre_technique_name="Brute Force",
                tactic="Credential Access",
                data_sources=["authentication logs", "VPN/SSO logs"],
                queries=[
                    _q("spl",
                       'index=auth (action=failure OR result=failed) src_ip=$SRC_IP '
                       '| stats count by user | join user [search index=auth action=success src_ip=$SRC_IP] '
                       '| where count > 20',
                       "Failures followed by a success from the same source IP"),
                    _q("sigma",
                       "detection:\n  sel_fail: {EventID: 4625}\n  sel_ok: {EventID: 4624}\n  "
                       "timeframe: 10m\n  condition: sel_fail | count() by IpAddress > 20 and sel_ok",
                       "Windows 4625 spike then a 4624 from the same IP"),
                ],
                expected_findings="A successful auth from an IP with a preceding failure spike.",
                false_positive_notes="Password-manager retries, expired-cert reconnects, load-balancer health checks.",
                priority=HuntPriority.HIGH,
            ),
            HuntHypothesis(
                title="The same source is spraying a few passwords across many accounts",
                rationale="Password spraying evades lockouts by staying low-and-slow per account.",
                mitre_technique_id="T1110.003", mitre_technique_name="Password Spraying",
                tactic="Credential Access",
                data_sources=["authentication logs"],
                queries=[
                    _q("spl",
                       'index=auth action=failure src_ip=$SRC_IP | stats dc(user) as users by src_ip '
                       '| where users > 15',
                       "One source failing against many distinct users"),
                ],
                expected_findings="A single IP failing auth against 15+ distinct accounts in a short window.",
                false_positive_notes="Shared NAT egress, misconfigured service account.",
                priority=HuntPriority.HIGH,
            ),
        ],
        "T1078": [  # Valid Accounts
            HuntHypothesis(
                title="A valid account is being used from an anomalous location or ASN",
                rationale="Stolen creds show up as impossible travel or new geo/ASN for the user.",
                mitre_technique_id="T1078", mitre_technique_name="Valid Accounts",
                tactic="Defense Evasion",
                data_sources=["SSO/IdP logs", "VPN logs"],
                queries=[
                    _q("kql",
                       "SigninLogs | where UserPrincipalName == '$USER' "
                       "| summarize by Location, IPAddress, bin(TimeGenerated, 1h) "
                       "| where Location != '$HOME_GEO'",
                       "Sign-ins for the user from an unexpected location"),
                ],
                expected_findings="Successful sign-in from a geo/ASN the user has never used.",
                false_positive_notes="Legitimate travel, corporate VPN egress, mobile carrier IP.",
                priority=HuntPriority.HIGH,
            ),
        ],
        "T1059": [  # Command and Scripting Interpreter
            HuntHypothesis(
                title="Encoded or suspicious PowerShell/shell executed post-alert",
                rationale="LOLBins and encoded commands indicate hands-on-keyboard execution.",
                mitre_technique_id="T1059.001", mitre_technique_name="PowerShell",
                tactic="Execution",
                data_sources=["EDR process events", "Windows Sysmon EventID 1"],
                queries=[
                    _q("eql",
                       'process where process.name == "powershell.exe" and '
                       'process.command_line : ("*-enc*", "*-EncodedCommand*", "*IEX*", "*DownloadString*")',
                       "Encoded / download-cradle PowerShell"),
                    _q("sigma",
                       "detection:\n  sel: {Image|endswith: '\\\\powershell.exe', "
                       "CommandLine|contains: ['-enc', 'FromBase64String', 'IEX']}\n  condition: sel",
                       "Suspicious PowerShell command lines"),
                ],
                expected_findings="Process events with encoded commands or in-memory download cradles.",
                false_positive_notes="Legit admin/automation scripts, SCCM, packaged installers.",
                priority=HuntPriority.HIGH,
            ),
        ],
        "T1190": [  # Exploit Public-Facing Application
            HuntHypothesis(
                title="Exploit attempt was followed by an outbound callback from the web host",
                rationale="Successful RCE typically produces an egress connection the app never makes normally.",
                mitre_technique_id="T1190", mitre_technique_name="Exploit Public-Facing Application",
                tactic="Initial Access",
                data_sources=["web/proxy logs", "netflow", "EDR network events"],
                queries=[
                    _q("spl",
                       'index=proxy src_host=$WEB_HOST | stats count by dest_ip dest_port '
                       '| where NOT (dest_port IN (80,443)) OR dest_ip NOT IN ($KNOWN_EGRESS)',
                       "Unusual egress from the web host after the exploit window"),
                    _q("lucene",
                       'host:$WEB_HOST AND (url:*.jsp OR url:*.php) AND http.response.status_code:200 '
                       'AND http.request.method:POST',
                       "Successful POSTs to script endpoints (possible webshell)"),
                ],
                expected_findings="New outbound connection or webshell interaction from the exposed host.",
                false_positive_notes="Scheduled outbound integrations, package mirrors, CDN.",
                priority=HuntPriority.HIGH,
            ),
        ],
        "T1071": [  # Application Layer Protocol (C2)
            HuntHypothesis(
                title="Beaconing to a low-reputation destination on a regular interval",
                rationale="C2 channels beacon with tell-tale periodicity and small, uniform payloads.",
                mitre_technique_id="T1071", mitre_technique_name="Application Layer Protocol",
                tactic="Command and Control",
                data_sources=["proxy logs", "netflow", "DNS logs"],
                queries=[
                    _q("spl",
                       'index=proxy src_host=$HOST | bin _time span=1m | stats count by dest_domain _time '
                       '| eventstats avg(count) as a stdev(count) as s by dest_domain '
                       '| where s < 1 AND a > 5',
                       "Low-variance periodic requests to a domain (beacon)"),
                ],
                expected_findings="Regular, uniform requests to a rare external domain.",
                false_positive_notes="Telemetry/agent check-ins, software update pollers, NTP.",
                priority=HuntPriority.HIGH,
            ),
        ],
        "T1041": [  # Exfiltration Over C2 Channel
            HuntHypothesis(
                title="Large or anomalous outbound transfer from a sensitive asset",
                rationale="Exfil shows up as an egress volume spike far above the host's baseline.",
                mitre_technique_id="T1041", mitre_technique_name="Exfiltration Over C2 Channel",
                tactic="Exfiltration",
                data_sources=["netflow", "proxy logs", "DLP"],
                queries=[
                    _q("spl",
                       'index=netflow src_host=$HOST | stats sum(bytes_out) as out by dest_ip '
                       '| where out > 500000000',
                       "Egress > ~500MB to a single destination"),
                ],
                expected_findings="Outbound bytes far exceeding the host's normal egress baseline.",
                false_positive_notes="Backups, log shipping, legitimate large uploads.",
                priority=HuntPriority.HIGH,
            ),
        ],
        "T1486": [  # Data Encrypted for Impact (ransomware)
            HuntHypothesis(
                title="Mass file rename/encryption and shadow-copy deletion on affected hosts",
                rationale="Ransomware canonically deletes VSS and rewrites files with a new extension at high rate.",
                mitre_technique_id="T1486", mitre_technique_name="Data Encrypted for Impact",
                tactic="Impact",
                data_sources=["EDR file events", "Windows Sysmon EventID 11", "process events"],
                queries=[
                    _q("eql",
                       'process where process.name in ("vssadmin.exe","wbadmin.exe") and '
                       'process.command_line : ("*delete*","*shadows*")',
                       "Shadow-copy deletion (inhibit recovery)"),
                    _q("spl",
                       'index=edr action=file_rename | stats count by host '
                       '| where count > 500',
                       "High-rate file rename bursts per host"),
                ],
                expected_findings="Shadow-copy deletion and/or a burst of file renames to a new extension.",
                false_positive_notes="Bulk migrations, backup software, disk-encryption rollouts.",
                priority=HuntPriority.HIGH,
            ),
        ],
        "T1566": [  # Phishing
            HuntHypothesis(
                title="Other recipients of the same phishing campaign clicked or replied",
                rationale="Phishing lands in many inboxes; the reported one is rarely the only click.",
                mitre_technique_id="T1566", mitre_technique_name="Phishing",
                tactic="Initial Access",
                data_sources=["email gateway logs", "proxy logs"],
                queries=[
                    _q("spl",
                       'index=email sender=$SENDER OR subject="$SUBJECT" | stats values(recipient) by url',
                       "All recipients of the same sender/subject/URL"),
                    _q("spl",
                       'index=proxy url=$PHISH_URL | stats count by src_user',
                       "Users who fetched the phishing URL"),
                ],
                expected_findings="Additional recipients who received or clicked the same lure.",
                false_positive_notes="Security-team detonation, mailbox rules, sandbox fetches.",
                priority=HuntPriority.HIGH,
            ),
        ],
    }


_DEFAULT_HYPOTHESIS = HuntHypothesis(
    title="Look for follow-on activity from the same actor/entity",
    rationale="Any confirmed finding warrants checking whether the same source, user, or host shows up elsewhere.",
    tactic="Discovery",
    data_sources=["SIEM (all sources)", "EDR", "proxy/netflow"],
    queries=[
        _q("spl", 'index=* (src_ip=$SRC_IP OR user=$USER OR host=$HOST) earliest=-7d '
                  '| stats count by index sourcetype',
           "Any telemetry mentioning the incident's key entities in the last 7 days"),
    ],
    expected_findings="Additional events tied to the incident's IPs/users/hosts beyond the original alert.",
    false_positive_notes="Normal activity by the same user/host; scope to anomalous behavior.",
    priority=HuntPriority.MEDIUM,
)


def _template_plan(seed: str, technique_ids: list[str], context: dict | None) -> HuntPlan:
    lib = _templates()
    hyps: list[HuntHypothesis] = []
    seen: set[str] = set()
    for tid in technique_ids:
        base = (tid or "").upper().split(".")[0]
        for h in lib.get(base, []):
            key = h.title
            if key not in seen:
                hyps.append(h.model_copy(deep=True))
                seen.add(key)
    if not hyps:
        hyps = [_DEFAULT_HYPOTHESIS.model_copy(deep=True)]
    return HuntPlan(
        generated_from=seed,
        summary=f"{len(hyps)} hunt hypothesis(es) for {', '.join(technique_ids) or seed}.",
        hypotheses=hyps,
    )


async def generate_hunt_plan(
    *,
    seed: str,
    technique_ids: list[str] | None = None,
    context: dict | None = None,
) -> HuntPlan:
    """Generate a hunt plan. Uses the LLM (seeded with templates) when available,
    otherwise returns the deterministic template plan."""
    technique_ids = [t for t in (technique_ids or []) if t]
    template = _template_plan(seed, technique_ids, context)

    if not llm.enabled:
        return template

    user_payload = {
        "seed": seed,
        "mitre_techniques": technique_ids,
        "incident_context": context or {},
        "starter_hypotheses": template.model_dump(mode="json")["hypotheses"],
    }
    try:
        plan = await llm.structured(
            model=select_model("P2_HIGH", "hunt"),
            messages=[
                {"role": "system", "content": HUNT_SYSTEM},
                {"role": "user", "content": json.dumps(user_payload, default=str)[:6000]},
            ],
            schema_model=HuntPlan,
        )
        if not plan.hypotheses:
            return template
        plan.generated_from = seed or plan.generated_from
        return plan
    except Exception as exc:  # noqa: BLE001
        logger.warning("hunt generation fell back to templates: %s", exc)
        return template
