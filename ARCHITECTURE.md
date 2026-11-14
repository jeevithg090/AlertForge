# SentinelForge — Architecture

## High-level data flow

```
SECURITY FINDING (SIEM/EDR/IDS webhook, phishing email, analyst paste)
  ↓ HMAC verification (X-SentinelForge-Signature header)
  ↓ Prompt-injection guard (regex + optional semantic)
  ↓ INGESTION — normalize via fast-tier structured output → IncidentSignal
  ↓ CORRELATION / DEDUP — fingerprint + entity overlap
        ├─ correlates to an open incident → fold in (alert_count++), STOP
        └─ new                            → Redis Stream  alerts:raw

TRIAGE        (smart tier, streamed reasoning trace) → verdict + MITRE ATT&CK chips
INVESTIGATION (smart tier, curated read-only toolset, concurrent calls + MCP) → root cause + IOCs
CONTAINMENT   (smart tier, JSON schema + Pydantic)   → block IP / suspend / isolate plan
HITL GATE     (auto-approve LOW/MED+P3/P4, human for HIGH/CONTAINMENT; timeout sweeper)
EXECUTION     (fast tier, tool calling; validate + rollback)
PIR           (smart tier, streaming)                → security incident report + ticket via MCP

THREAT HUNT   (on demand; smart tier + template library) → hunt hypotheses + runnable queries
```

Model tiers are provider-neutral (`smart` ≈ 70B, `fast` ≈ 8B). On the default Groq backend that's
`llama-3.3-70b-versatile` and `llama-3.1-8b-instant`. See the [model router](backend/app/pipeline/model_router.py).

Every stage publishes events to a Redis pub/sub channel
`incident:{id}:events` (consumed by the dashboard via SSE) **and** appends to a
bounded Redis list `incident:{id}:event_log` (used for REST rehydration +
SSE Last-Event-ID replay on reconnect).

## Alert correlation & dedup (`app/pipeline/correlation.py`)

The first thing every alert hits — and the system's main defence against alert
fatigue. It is **deterministic and model-free** so it's instant, free, and
explainable, which is exactly what you want running on 100% of alert volume.

For each normalized signal it computes:

- a **fingerprint** — `sha1(source | affected_service | de-noised signature)`. The
  signature normalizer strips volatile tokens (IPs, counters, ports, hashes,
  UUIDs) so "240 failed logins" and "241 failed logins" from the same source hash
  identically.
- the **strong entities** — public source IPs, user principals, hostnames.

`find_correlatable_incident()` (in `app/db/incidents.py`) queries **open**
incidents within `CORRELATION_WINDOW_SECONDS` (fingerprint match ordered first,
then entity overlap) and `correlation_reason()` returns the strongest match
reason (duplicate signature → shared IP → shared host → shared user on same
service). A match folds the alert into the existing incident
(`alert_count++`, appends to `related_signals`, unions the entity set, bumps
`last_seen_at`) and publishes `alert.correlated` — **no new pipeline run**.
Everything in the module is a pure function of its inputs and unit-tested.

## Tool selection (`app/pipeline/tool_selector.py`)

Rather than handing the Investigation Agent all ~20 tools every round (token-
expensive and a hallucination magnet for OSS models), a deterministic selector
picks a small, relevant, **read-only** toolset from the triage category, ATT&CK
techniques, and which entity types are present. Containment tools are never
exposed here — those run only in Execution, after the HITL gate.

## Redis Streams (durable, backpressured)

| Stream                 | Producer          | Consumer        |
|------------------------|-------------------|-----------------|
| `alerts:raw`           | Ingestion Gateway | Triage worker   |
| `alerts:triaged`       | Triage            | Investigation worker |
| `alerts:investigated`  | Investigation     | Containment worker   |
| `alerts:planned`       | Containment       | Execution worker (resumed on approval) |
| `alerts:executing`     | Execution         | (reserved)       |
| `alerts:resolved`      | Execution         | PIR worker       |
| `alerts:dlq`           | any               | (dead-letter, manual triage) |

Each stream has a consumer group; crashed worker messages are delivered to
another worker; failed handler invocations are acked and moved to the DLQ
with a reason. The orchestrator also runs an `asyncio.create_task` background
**HITL auto-approve sweeper** that periodically scans `AWAITING_APPROVAL`
rows whose severity's timeout has elapsed and atomically transitions them
to APPROVED (CAS on `from_status`).

## Five agents

### 1. Triage (CMDR)
Model router picks the `smart` tier on P1/P2 (an explicit reasoning model when
`LLM_MODEL_REASONING` is set) or the `fast` tier on P3/P4. On high-severity
findings it streams a **live reasoning trace**: the model emits prose reasoning,
then a `===TRIAGE_JSON===` sentinel, then the verdict JSON — everything before
the sentinel streams to the dashboard as `thinking.chunk`, everything after is
parsed. This gives a real reasoning trace on OSS models (which don't emit a
separate `reasoning_content` channel) in a single call.
Output is a `TriageResult` with: severity, **verdict**
(`TRUE_POSITIVE` / `FALSE_POSITIVE` / `BENIGN_ANOMALY` / `NEEDS_HUMAN`),
`attack_techniques: List[AttackTechnique]` (technique_id + name + tactic +
confidence), blast radius, and an `investigation_priority` ordering.

### 2. Investigation (ANLST)
The hero moment. `smart` tier with `tools=...`. Loops across up to
`MAX_ROUNDS=5` rounds; in each round the model returns 0..N tool calls that the
agent executes **concurrently** with `asyncio.gather`, publishing `tool.called`
+ `tool.result` SSE events for each and feeding the results back into the
thread. The loop stops when the model returns a finding with no tool calls OR
`confidence_score > 0.7`. Crucially, only a **curated read-only subset** of tools
is exposed per incident (see [Tool selection](#tool-selection-apppipelinetool_selectorpy)),
so an OSS model isn't drowning in 20 schemas.

20 tools are registered via the `@tool` decorator across 12 modules:

- **Threat intel** (`lookup_ip_reputation`, `search_cve_database`) — real
  VirusTotal/AbuseIPDB if env keys set, deterministic mock otherwise.
- **Logs** (`query_elasticsearch`, `query_siem_auth_logs`) — ES query if URL
  set; scenario-aware mock otherwise.
- **Identity / EDR** (`enrich_user_identity`, `query_edr_endpoint`) — IdP /
  EDR enrichment mocks keyed by username/hostname for deterministic demos.
- **Runbooks** (`search_runbook`) — ChromaDB semantic search, mock fallback.
- **Containment** (`block_ip`, `suspend_account`, `isolate_host`,
  `rotate_credentials`) — invoked by the Execution Agent only, after HITL.

When no LLM key is configured, the agent falls back to a deterministic
**heuristic path** that schedules the same real tool calls (against mocks)
and publishes the same SSE events, so the dashboard never looks empty.

### 3. Containment (STRAT)
`smart` tier structured output — strict `json_schema` where the provider
supports it (DashScope), else `json_object` mode with the schema in-prompt — in
both cases followed by Pydantic double-validation and one automatic repair
round-trip. Output `RemediationPlan` is a list of containment steps
(`RemediationStep`) where `action_type` is constrained to the SOC vocabulary
(`notification`/`block_ip`/`suspend_account`/`isolate_host`/...), each HIGH+ step
has a `rollback_procedure` + `validation_check`, and any confidence < 0.6 forces
an `escalation_recommendation`.

### 4. Execution (OPS)
`fast` tier tool calling. Executes approved steps sequentially, runs the
`validation_check`, and on a failed validation attempts rollback. Every
action is audit-logged; the immutable audit_log makes the whole IR trail
inspectable post-incident.

### 5. PIR (CHRON)
`smart` tier streaming; emits `pir.streaming` chunks live. When the report
is complete, it calls the **self-hosted MCP server** (`POST /messages` with
`tools/call` → `create_jira_ticket`) and publishes a `jira.ticket_created`
SSE event so the dashboard can render a live ticket link. If the MCP server
is unreachable, the client synthesises a believable ticket URL in-process so
the demo never stalls.

### Threat hunt (on demand)
Not a pipeline stage — a capability. `POST /api/v1/incidents/{id}/hunt` reads the
incident's ATT&CK techniques + entities and generates a `HuntPlan` of falsifiable
hypotheses with runnable queries (`app/services/threat_hunt.py`), publishing
`hunt.generated`. `POST /api/v1/hunt` does the same standalone from a technique id
or free text. A curated technique→hunt template library provides the zero-key
path and seeds the model so it refines real queries instead of inventing syntax.

## Human-in-the-Loop approval gate

The gate (`app/pipeline/hitl_gate.py`) persists every step, then for each:

- Always requires human for P1 steps **and** for any containment action that
  mutates production state (`block_ip`/`suspend_account`/`isolate_host`/
  `firewall_change`/`rotate_credentials`/`quarantine_file`/
  `configuration_change`/`shell_command`) — **regardless of severity**.
- Auto-approves `LOW` risk + `notification` + `MEDIUM` on P3/P4.
- `REQUIRES_APPROVAL` risk always forces a human.
- A background `scheduled_auto_approve` sweeper (seconds Resolution):
  P3 → 15min, P4 → 5min, P1/P2 → never.
- Approve / reject / escalate endpoints use an atomic compare-and-set
  (`cas_update_step`) to prevent two operators from acting on the same step.
- **Two-person rule:** when the guardrails return `REQUIRE_TWO_PERSON` (P1 by
  default), the execution agent puts the step back to `AWAITING_APPROVAL` with
  its first approver recorded. The next `approve` call from a *different*
  approver is stored as `second_approver`; the same approver gets `409`.

## Action safety layer (`app/actions/`)

The HITL gate decides *whether a human is needed*; the action safety layer
decides *whether the action may run at all* — and it, not the LLM, is the
authority. This is what makes containment trustworthy given that alerts are
attacker-influenced input.

Every mutating step the Execution Agent runs goes through:

```
propose → guardrails.evaluate() → (approval check) → adapter.preflight()
        → adapter.dry_run() → [adapter.execute() → verify() → rollback()]
```

- **`policy.py`** — `evaluate(policy, request, context)` is a pure, stdlib-only
  (`ipaddress` + `fnmatch`) function returning `ALLOW / DENY / REQUIRE_APPROVAL /
  REQUIRE_TWO_PERSON`. A **DENY is terminal and un-overridable** — no number of
  approvals and no model output can bypass it. Rules: protected IP CIDRs
  (RFC1918/loopback/link-local), protected accounts (break-glass/service/
  privileged globs), protected hosts (domain-controller globs), hard-denied
  shell, per-incident + windowed rate caps, kill switch, maintenance windows,
  and a two-person rule for CRITICAL severities.
- **`base.py` / `adapters/`** — a five-method adapter contract
  (`preflight/dry_run/execute/verify/rollback`); a mutating action without a
  tested rollback can't exist. Mock adapters ship by default (tagged
  `simulated: True`); real ones (cloud SG revoke, Okta suspend, EDR isolate) are
  drop-in replacements.
- **`executor.py`** — runs the lifecycle with an idempotency key, a persisted
  action state machine (`PROPOSED→DENIED/AWAITING/DRY_RUN_OK/VERIFIED/ROLLED_BACK`),
  live blast-radius/rate counters, and best-effort audit. `ACTION_DRY_RUN_ONLY`
  (default **true**) simulates mutations so prod is never touched until an
  adapter is explicitly promoted to live.

The guarantee is enforced by a **red-team test suite**
(`tests/test_actions.py`): jailbroken plans targeting loopback, break-glass,
domain controllers, or a shell are all DENIED — even with two approvers.

## Rehydration & SSE replay

- `GET /api/v1/incidents/{id}/steps` — REST snapshot of containment steps, used
  by the dashboard to restore approval cards on page refresh.
- `GET /api/v1/incidents/{id}/events` — REST snapshot of recent dashboard
  events.
- `GET /api/v1/incidents/{id}/stream` — the SSE endpoint honors
  `Last-Event-ID` headers and replays missed events from the bounded Redis
  list before streaming live.

## Security surface

- **Authentication / RBAC** (`app/services/auth.py`): JWT (HS256, signed with
  `SECRET_KEY`, 8h expiry) with roles `viewer` < `analyst` < `approver`, plus
  `admin`. Read APIs need any role; feedback, hunts, detection rules and
  analyst ingestion need `analyst`; approvals need `approver`. Identity for
  audit entries always comes from the verified token. SSE endpoints also
  accept `?access_token=` because `EventSource` cannot set headers.
  `AUTH_DEV_BYPASS` (anonymous admin) is honoured only when
  `ENVIRONMENT=development`, and the backend refuses to start in any other
  environment with a placeholder `SECRET_KEY` or the default admin password.
- **CORS** allows `FRONTEND_URL` plus `CORS_ORIGINS` — never `*`.
- **Prompt-injection guard** (regex + optional fast-tier semantic scan) on
  every ingested finding; blocked attempts are audit-logged and surfaced on
  the Security panel live via the `security.event` SSE channel.
- **HMAC webhook verification** (`X-SentinelForge-Signature: sha256=...`) on
  every `/ingest/siem|edr|ids|webhook` endpoint. Dev mode (default
  `SECRET_KEY`) keeps the controls page honest: it reports "configured, dev
  only"; set a real `SECRET_KEY` and the gate enforces.
- **Tamper-evident audit log** (`app/db/audit.py`): every agent + human action is
  appended under a transaction-scoped advisory lock and **hash-chained**
  (`entry_hash = sha256(prev_hash + canonical(entry))`). Any after-the-fact edit,
  deletion, insertion, or reorder breaks the chain from that point; verify the
  whole log at `GET /api/v1/security/audit/verify`. (Token columns retain their
  legacy `qwen_*` names but hold the current provider's counts.)
- Reasoning traces archived alongside every P1/P2 `triage_result`.

## Evaluation & trust (`app/eval/`)

Autonomy is only responsible if it's measured. The eval harness scores a
classifier against a labeled corpus (`corpus.py`) and computes verdict accuracy,
**false-positive suppression recall**, severity calibration (exact + within-one),
and MITRE technique precision/recall — all in a pure `score()` function. The
default classifier is the deterministic heuristic (so the gate runs in CI with
zero API key: ~0.94 verdict accuracy, 1.00 FP suppression); `--llm` scores the
real model. `python -m app.eval.harness` exits non-zero below the regression
floor (`DEFAULT_GATE`), so a prompt/model change can't silently degrade triage.

## Observability endpoints

`/api/v1/analytics/summary|correlation|mttr|by-service|by-verdict|by-severity|
top-techniques|token-usage` — used by the `/analytics` dashboard page to surface
SOC-wide trends: the headline **alert noise-reduction %** (correlation), verdict
distribution, top MITRE techniques, and per-model token spend.