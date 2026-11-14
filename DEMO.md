# SentinelForge — 3-Minute Demo Script

> One-sentence pitch: "SentinelForge is the autonomous SOC war room — it collapses alert storms into single incidents, then a team of open-source-model agents triages, investigates, contains, and hunts, while keeping a human in command of every irreversible action."

## Prerequisites

- Docker + docker compose
- (optional) an `LLM_API_KEY` in `.env` (a free Groq key) for live reasoning +
  tool calls. Without it, the same flow runs on heuristic paths so the demo
  never stalls.

## Bring up the stack

```bash
cp .env.example .env          # optionally add LLM_API_KEY + VIRUSTOTAL_API_KEY + ABUSEIPDB_API_KEY
docker compose up -d          # postgres, redis, mock-es, mcp-server, backend, worker, frontend
docker compose ps             # wait until backend is "healthy"
open http://localhost:3000    # the SOC war-room dashboard
```

## The 3-minute demo

### 0. Kill the noise first (~15s)

```bash
python demo/seed_alerts.py --storm 30
```

> "A single brute-force run fires 30 near-identical alerts. A traditional SOC
> opens 30 tickets. SentinelForge's correlation engine folds all 30 into **one**
> incident — watch the card show `×30 alerts folded`." Open `/analytics` and the
> **Alert Noise Reduction** hero shows ~97%.

### 1. Ingest a brute-force finding (~10s)

```bash
python demo/seed_alerts.py --scenario brute_force
```

> "SIEM reports 5,847 failed SSH logins from 193.32.162.144 against
> bastion-01. In a real SOC an analyst gets paged. SentinelForge activates
> immediately."

### 2. Watch the war room (~60s)

In the dashboard click the new incident card. You will see, in real time:

- **CMDR** streams its reasoning trace (expand the *Reasoning Trace* panel)
  then emits a verdict: `TRUE_POSITIVE`, severity `P2_HIGH`, blast radius
  `SERVICE`, and a chip row of MITRE ATT&CK techniques (T1110 Brute Force).
- **ANLST** announces it is pulling evidence. It's handed only the ~5 tools
  relevant to a credential-access finding (not all 20), then **calls them
  concurrently** — you see live `tool.called` → `tool.result` cards populate:
  - `lookup_ip_reputation` (193.32.162.144) → VirusTotal/AbuseIPDB shows MALICIOUS
  - `enrich_user_identity` (svc-account, admin) → "privileged, MFA disabled"
  - `query_edr_endpoint` (bastion-01) → running processes
  - `search_runbook` → "Failed Login Spike / Brute Force" playbook
  - `query_siem_auth_logs` → 40 masked failed-login events
- **STRAT** returns a containment plan summary and the dashboard rolls out:
  **⚠️ APPROVAL REQUIRED** cards appear for `block_ip` and `suspend_account`.

> "SentinelForge will not block a production IP or suspend a user on its own.
> It presents the plan, the evidence, the risk, and the rollback, and waits
> for a human."

### 3. Approve containment (~30s)

Click **✓ APPROVE** on the `block_ip` card. The OPS agent executes the
`block_ip` tool, runs the validation check, and streams `step.complete`.

For a `P1_CRITICAL` incident (try `--scenario ransomware`) the guardrails apply
the two-person rule: after the first approval the card comes back asking for a
second approver. Approve it again signed in as a *different* operator with the
`approver` role (the same operator is refused). In the default development
stack everyone is the anonymous admin, so create two approvers and sign in at
`/login` to see this.

### 4. PIR + JIRA ticket (~30s)

CHRON streams a formatted **Security Incident Report** (~Markdown rendered),
then calls the SentinelForge MCP server and a JIRA ticket link appears
(in the sidebar + appended to the PIR):
`https://sentinelforge.atlassian.net/browse/SEC-XXXXXX`.

> "And the incident is filed — the security lead wakes up to a real ticket,
> not just an alert."

### 5. Hunt for what you missed (~20s)

In the incident sidebar, click **Generate hunt** under *🎯 Threat Hunt*. From the
incident's ATT&CK techniques SentinelForge produces falsifiable hunt hypotheses
with **runnable queries** (Splunk/EQL/Sigma) — e.g. "did the brute force *succeed*
and lateral movement begin?" with the SPL to check.

> "Containing one alert isn't the job — finding everywhere else the actor
> touched is. That's a hunt, generated in seconds and ready to run."

Refresh the page mid-incident — approval cards + agent messages + PIR content
all restore from REST endpoints (no lost state when the SSE stream drops).

## Bonus demos (same stack)

```bash
python demo/seed_alerts.py --scenario c2_beacon            # C2 / DNS tunnelling
python demo/seed_alerts.py --scenario suspicious_powershell # Living off the Land (T1059)
python demo/seed_alerts.py --scenario data_exfil            # egress anomaly (T1041)
python demo/seed_alerts.py --scenario ransomware            # Impact + file rename (T1486)
python demo/seed_alerts.py --scenario phishing_email        # phishing (T1566), ingested via /email
python demo/seed_alerts.py --scenario siem_wazuh            # raw Wazuh-style webhook payload
python demo/seed_alerts.py --scenario injection_attempt     # should be blocked by PromptGuard — see the Security page
```

Open the **Analytics** page (`/analytics`) to see the headline **alert
noise-reduction %**, SOC-wide verdict distribution, top MITRE ATT&CK techniques
across incidents, and LLM token spend per model.

Open the **Security** page (`/security`) to see live prompt-injection blocks +
the security controls checklist (HMAC status is reported honestly).