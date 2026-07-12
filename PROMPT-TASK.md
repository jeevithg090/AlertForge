# PROMPT-TASK.md — Copy-paste prompts for each task in TASK.md

> **How to use:** for every task, paste the **COMMON CONTEXT** block first, then
> the task's prompt. Written for open-source coding models: explicit paths,
> exact signatures, acceptance criteria, and pitfalls. Do ONE task per session.

---

## COMMON CONTEXT (paste this before every task prompt)

```
You are working on SentinelForge, an autonomous SOC (security operations) app in
the `alertforge/` directory. Follow these repo facts EXACTLY — do not invent
alternatives:

STACK & LAYOUT
- Backend: Python 3.12, FastAPI, at alertforge/backend. Code in app/, tests in
  tests/, migrations in alembic/versions/ (latest revision is "0004"; chain new
  ones with revision="0005", down_revision="0004", etc.).
- DB: PostgreSQL via asyncpg with RAW SQL (no ORM). Helpers:
  `from app.db.connection import execute, fetch, fetchrow, fetchval, get_pool`.
  JSONB columns come back as JSON *strings* — decode with json.loads.
- Redis: streams + pub/sub via app/services/redis_client.py
  (`publish_event(incident_id, event)`, `publish_to_stream(stage, payload)`).
- Dashboard events: `from app.schemas.events import make_event, EventType` —
  add new event names to the EventType enum.
- LLM: `from app.services.llm import llm, extract_json`. Methods:
  `await llm.complete(model=..., messages=[...])`,
  `await llm.structured(model=..., messages=[...], schema_model=PydanticClass)`,
  `llm.enabled` (False when no API key → ALWAYS provide a deterministic
  fallback path so everything works with zero keys).
  Model ids come from `from app.pipeline.model_router import select_model`.
- Config: pydantic-settings in app/config.py. Add new settings as lowercase
  fields; env vars are the uppercase name. Mirror new vars in ../.env.example.
- Action safety layer: app/actions/ — `GuardrailPolicy` + pure `evaluate()` in
  policy.py; 5-method adapter contract (preflight/dry_run/execute/verify/
  rollback) in base.py; `ActionExecutor`/`get_executor()` in executor.py.
  NEVER let an LLM output bypass `evaluate()`; a DENY is un-overridable.
- Audit: `from app.db.audit import write_audit` (hash-chained; never raises).
- API routers live in app/api/*.py and are registered in app/main.py with
  `app.include_router(x.router, prefix="/api/v1/...", tags=[...])`.
- Frontend: Next.js 15 App Router + Tailwind at alertforge/frontend
  (pages in app/, API helpers in lib/api.ts, SSE in lib/sse.ts). Dark
  "war-room" theme uses classes like bg-warroom-surface, border-warroom-border.

QUALITY BARS (all must pass before you claim done)
- Tests: cd alertforge/backend && ./venv/bin/python -m pytest -q  (all pass;
  currently 76 tests — do not break any).
- Lint: ./venv/bin/python -m ruff check app tests  (line length 100).
- Eval gate: ./venv/bin/python -m app.eval.harness  (must print GATE: PASS).
- Frontend (if touched): cd alertforge/frontend && npx tsc --noEmit.
- New logic needs unit tests in alertforge/backend/tests/ as pure functions
  where possible (no DB/Redis needed — see tests/test_actions.py for style).
  Start test files with:
    import os
    os.environ.setdefault("DASHSCOPE_API_KEY", "")
    os.environ.setdefault("USE_MOCK_TOOLS", "true")

RULES
- Never hardcode secrets; read from settings. Everything must still run with
  ZERO API keys (mock/deterministic fallback).
- Match surrounding code style; type hints everywhere;
  `from __future__ import annotations` at top of new modules.
- Do not rename existing tables/columns/endpoints. Additive changes only.
```

---

## T1 — RBAC + signed approvals

```
TASK: Replace the forgeable approver string with authenticated, role-based
approvals (JWT + RBAC). Identity must come ONLY from a verified token.

WHY: Today alertforge/backend/app/api/approvals.py trusts an `approver` field
in the request body, and frontend/lib/api.ts sends a hardcoded
'human:operator@sentinelforge.local'. Anyone who can reach the API can approve
blocking production.

STEP 1 — Migration alembic/versions/005_operators.py (revision "0005",
down_revision "0004"): table `operators` with columns id UUID pk default
gen_random_uuid(), email TEXT unique not null, display_name TEXT,
password_hash TEXT not null, role TEXT not null CHECK (role IN
('viewer','analyst','approver','admin')), is_active BOOL default true,
created_at TIMESTAMPTZ default NOW().

STEP 2 — app/services/auth.py:
- Password hashing with hashlib.scrypt (stdlib; do NOT add bcrypt):
  hash_password(pw) -> "scrypt$<salt_hex>$<hash_hex>" and
  verify_password(pw, stored) -> bool using hmac.compare_digest.
- JWTs with the `jwt` package (PyJWT is already installed):
  create_token(operator: dict) -> str  (HS256, key=settings.secret_key,
  claims: sub=email, role, name, exp=now+8h, iat) and
  decode_token(token) -> dict (raise on invalid/expired).
- Async DB helpers: get_operator_by_email(email), create_operator(email,
  password, role, display_name) using app.db.connection helpers.
- seed_default_admin(): if the operators table is empty, create
  admin@sentinelforge.local / password from new setting
  `default_admin_password` (env DEFAULT_ADMIN_PASSWORD, default
  "changeme-admin") with role admin, and write_audit the seeding.
  Call it from the lifespan in app/main.py after init_db().

STEP 3 — app/api/auth.py router (register in main.py under /api/v1/auth):
- POST /login {email, password} -> {token, role, name}; 401 on bad creds;
  audit success and failure (action="auth.login" / "auth.login_failed").
- GET /me (requires token) -> current operator claims.
- POST /operators (admin only) -> create operator.

STEP 4 — FastAPI dependencies in app/services/auth.py:
- `current_operator` — reads Authorization: Bearer <token>, decodes, returns
  claims dict; raise HTTPException 401 if missing/invalid.
- `require_role(*roles)` — dependency factory; 403 if claim role not in roles
  (admin always passes).

STEP 5 — Enforce in app/api/approvals.py: approve/reject/escalate endpoints
now use `operator = Depends(require_role("approver", "admin"))` and IGNORE any
approver value in the body — set approved_by to the token's sub claim. Keep the
body's `rationale`. Audit each decision with the authenticated actor.

STEP 6 — Two-person rule: in app/agents/execution_agent.py the approvers tuple
passed to get_executor().run() currently has one entry (step approved_by).
Add a nullable TEXT column `second_approver` to remediation_steps in the same
0005 migration. Add endpoint POST /api/v1/approvals/{step_id}/second-approve
(approver/admin) that CAS-updates second_approver only if it differs from
approved_by (409 if same person). Pass both names in the approvers tuple.

STEP 7 — Frontend minimal: add login page frontend/app/login/page.tsx (email +
password → store token in localStorage key "sf_token"); in lib/api.ts add an
`authHeaders()` helper that injects Authorization from localStorage and use it
in approveStep/rejectStep/escalateStep (remove the hardcoded APPROVER const);
on 401 redirect to /login.

STEP 8 — Tests (tests/test_auth.py, pure — no DB):
- hash/verify roundtrip; wrong password fails; tampered stored hash fails.
- create_token/decode_token roundtrip; expired token raises (craft exp in the
  past); modified token raises.
- require_role logic as a pure function if you factor role-checking into
  `role_allowed(role, allowed: tuple) -> bool` — test viewer denied, approver
  allowed, admin always allowed.

PITFALLS: PyJWT's decode needs algorithms=["HS256"]. Don't log passwords or
tokens. Don't break existing tests that call approvals logic — check
tests/test_pure_functions.py still passes. Keep dev ergonomics: if
settings.environment == "development" AND no Authorization header, endpoints
may fall back to a "dev:anonymous-admin" identity ONLY when a new setting
auth_dev_bypass (env AUTH_DEV_BYPASS, default true) is true — set it false in
.env.example's production notes.

DONE WHEN: pytest all green (old + new), ruff clean, login flow works via
curl (login → token → approve with Bearer token → 403 for viewer role).
```

---

## T2 — Real containment adapter (Cloudflare IP block)

```
TASK: Implement a REAL, reversible block_ip adapter against Cloudflare's IP
Access Rules API (free tier), behind the existing adapter contract.

CONTEXT: The contract is app/actions/base.py (preflight/dry_run/execute/
verify/rollback). Mocks are in app/actions/adapters/mock.py and are registered
by default_adapters() in app/actions/adapters/__init__.py. Guardrails already
authorize everything upstream — the adapter ONLY talks to Cloudflare.

API FACTS (use exactly these):
- Base: https://api.cloudflare.com/client/v4
- Auth header: Authorization: Bearer <token>
- Create rule:  POST /zones/{zone_id}/firewall/access_rules/rules
  body: {"mode":"block","configuration":{"target":"ip","value":"<IP>"},
         "notes":"<reason>"} → response.result.id is the rule id.
- Read rules:   GET  /zones/{zone_id}/firewall/access_rules/rules?
  configuration.target=ip&configuration.value=<IP>&mode=block
- Delete rule:  DELETE /zones/{zone_id}/firewall/access_rules/rules/{rule_id}
- All responses: {"success": bool, "errors":[...], "result": ...}

STEP 1 — Settings in app/config.py: cloudflare_api_token: str = "" and
cloudflare_zone_id: str = "" (+ .env.example entries with a comment that a
free Cloudflare account + any zone works).

STEP 2 — app/actions/adapters/cloudflare.py: class CloudflareBlockIPAdapter
(ActionAdapter), action_type="block_ip", simulated=False. Use httpx.AsyncClient
(httpx already installed), 15s timeout, raise-for-4xx handled as returned
errors not exceptions where the contract expects a bool.
- preflight: BlastRadius(summary=f"Would create a Cloudflare block rule for
  {req.target} in zone …", entities=[req.target], reversible=True). No HTTP.
- dry_run: PlannedEffect describing the exact POST it would make (no HTTP).
- execute: idempotency FIRST — call the read endpoint; if a matching block rule
  exists return {"rule_id": ..., "already_existed": True}. Else POST and return
  {"rule_id": result.id, "target": req.target, "applied_at": iso-now}.
- verify: read endpoint again; True iff a block rule for that IP exists.
- rollback: needs rule_id from effect; DELETE it; True iff success. If
  rule_id missing, look it up by IP first.

STEP 3 — Wiring: in app/actions/adapters/__init__.py, default_adapters()
returns the Cloudflare adapter for block_ip WHEN both settings are non-empty,
otherwise the mock (import settings lazily inside the function to keep tests
deterministic). Everything else stays mock.

STEP 4 — Tests (tests/test_cloudflare_adapter.py) with NO real HTTP: use
respx if installed, otherwise monkeypatch httpx.AsyncClient.request with a
fake returning canned JSON. Cover: execute creates rule; execute is idempotent
when rule pre-exists; verify true/false paths; rollback deletes; Cloudflare
"success": false surfaces as failure. Also test default_adapters() selection
logic via monkeypatched settings.

PITFALLS: Do NOT hit the network in tests. Keep ACTION_DRY_RUN_ONLY=true as
the default — the live path only runs when an operator flips it. Never blocked:
guardrails still refuse internal IPs before the adapter is ever called; do not
re-implement policy checks in the adapter.

DONE WHEN: pytest green, ruff clean, and with real env vars set +
ACTION_DRY_RUN_ONLY=false, an approved block_ip on a public IP creates a rule
visible in the Cloudflare dashboard, verify passes, and rollback removes it.
```

---

## T3 — Detection-as-code (Sigma rule generation)

```
TASK: After an incident, generate a valid Sigma detection rule from its IOCs +
MITRE techniques, expose it via API + UI, and validate it with tests.

STEP 1 — app/services/sigma_gen.py:
- SIGMA_TEMPLATES: dict keyed by base technique id ("T1110", "T1059", "T1071",
  "T1486", "T1566", "T1078", "T1190", "T1041") → a template dict with
  logsource (e.g. {"category":"authentication"} for T1110;
  {"product":"windows","category":"process_creation"} for T1059) and a
  detection skeleton. Example T1110 detection:
    selection: {event.outcome: failure}
    filter_ips: {source.ip: [<IOC IPs go here>]}
    condition: selection and filter_ips | count() by source.ip > 20
- build_sigma_rule(incident: dict) -> dict (PURE function): read
  triage_result.attack_techniques (may be a JSON string — decode) and
  investigation_finding.iocs; pick the highest-confidence technique with a
  template (fallback: a generic template on the incident's key entities).
  Return a dict with EXACTLY these Sigma fields:
    title, id (uuid4 string), status: "experimental",
    description, references (ATT&CK url), author: "SentinelForge",
    date (YYYY/MM/DD), tags (["attack.credential_access","attack.t1110"] style:
    lowercase tactic with underscores + technique id), logsource, detection,
    falsepositives (list), level ("high" for P1/P2 else "medium").
  Inject IOC values (ips/users/hosts) into the detection where the template
  marks them.
- to_yaml(rule: dict) -> str using yaml.safe_dump(sort_keys=False). PyYAML is
  already installed.
- async generate_detection_rule(incident: dict) -> tuple[dict, str]: build
  deterministically; if llm.enabled, ONE llm.complete call may refine ONLY the
  title/description/falsepositives strings (parse with extract_json, apply
  only those keys, wrap in try/except so failure keeps the deterministic
  rule). Never let the LLM touch logsource/detection/tags.

STEP 2 — API in app/api/incidents.py: POST /{incident_id}/detection-rule →
404 if incident missing; generate; save YAML to
<repo>/detections/generated/<incident_id[:8]>_<technique>.yaml (create dirs;
path from a new setting detections_dir defaulting to "detections/generated");
write_audit(action="detection.rule_generated"); publish_event with new
EventType DETECTION_RULE_GENERATED = "detection.rule_generated"; return
{"rule": rule_dict, "yaml": yaml_str, "path": relative_path}.

STEP 3 — Frontend: in frontend/app/incidents/[id]/page.tsx add a sidebar panel
"🧬 Detection Rule" with a Generate button (POST via new lib/api.ts helper
generateDetectionRule(id)), then show the YAML in a <pre> with a Copy button.
Follow the existing HuntPanel component's structure/styling exactly.

STEP 4 — Tests (tests/test_sigma_gen.py, pure): brute-force incident dict →
rule has tags ["attack.credential_access","attack.t1110"], IOC IP appears in
detection, yaml.safe_load(to_yaml(rule)) round-trips, required fields all
present (write REQUIRED = [...] and assert each), level follows severity,
unknown technique falls back to generic template, technique id like
"T1110.003" normalizes to the T1110 template.

PITFALLS: Sigma tag format is exact: "attack.t1110" lowercase. detection MUST
contain a "condition" key. Don't put datetime objects into YAML (strings only).
Incident JSONB fields may be strings — reuse the _as_dict helper already in
app/api/incidents.py.

DONE WHEN: pytest green, ruff clean, endpoint returns valid YAML that
yaml.safe_load parses, file lands in detections/generated/, UI button works
(npx tsc --noEmit clean).
```

---

## T4 — Purple-team self-assessment mode

```
TASK: Build a purple-team harness that replays multi-stage MITRE attack chains
through the REAL ingestion pipeline and scores end-to-end detection, emitting a
Detection Scorecard.

STEP 1 — app/purple/chains.py: dataclasses ChainStep(name, raw_text,
source_hint, expected_technique, delay_seconds) and AttackChain(name,
description, steps, expect_correlated: bool). Define 3 chains with realistic
alert text (reuse the flavor of demo/seed_alerts.py):
- "credential_assault": T1110 brute force (siem) → T1078 valid-account login
  from new ASN (siem) → T1041 exfil spike (siem); SAME attacker IP
  198.51.100.77 in all three; expect_correlated=True.
- "ransomware_run": T1566 phishing email → T1059 encoded powershell (edr) →
  T1486 mass rename (edr); shared host ws-fin-07; expect_correlated=True.
- "recon_probe": single T1595-ish scanning alert; expect_correlated=False.

STEP 2 — app/purple/runner.py (stdlib + httpx only, talks to a RUNNING stack):
async run_chain(chain, base_url="http://localhost:8000") →
- POST each step to {base_url}/api/v1/ingest/text with {"text": raw_text},
  await asyncio.sleep(step.delay_seconds) between steps; record each response
  (incident_id vs correlated_into).
- Wait up to 90s (poll every 5s) for the primary incident's status to leave
  INGESTED/TRIAGING via GET /api/v1/incidents/{id}.
- Collect: distinct incident ids created (expected 1 if expect_correlated),
  alert_count, triage verdict/severity, technique ids from
  triage_result.attack_techniques, timestamps for time-to-triage.

STEP 3 — app/purple/scorecard.py: PURE scoring —
score_chain(chain, observed: dict) -> dict with keys: chain, correlation_ok
(bool), incidents_created, alerts_folded, technique_hits (expected ∩ observed,
compare base ids: split "."[0]), technique_recall, verdict ("TRUE_POSITIVE"
expected for all chains), verdict_ok, time_to_triage_seconds, passed (bool =
correlation_ok and technique_recall >= 0.5 and verdict_ok).
aggregate(scores) -> {"chains": n, "passed": k, "detection_rate": k/n,
"avg_technique_recall": ..., "results": scores}.

STEP 4 — CLI app/purple/__main__.py: `python -m app.purple [--base-url ...]
[--chain NAME]` → run chains sequentially, print a fixed-width terminal
scorecard table plus a final "DETECTION SCORE: k/n chains" line, write the
aggregate JSON to purple_results/latest.json (configurable dir), exit 0 if all
passed else 1.

STEP 5 — API: GET /api/v1/analytics/purple → contents of
purple_results/latest.json or {"available": false}. (Optional UI: a card on
frontend/app/analytics/page.tsx showing detection_rate — copy an existing Card.)

STEP 6 — Tests (tests/test_purple.py, pure — NO network): score_chain with a
perfect observation → passed True; missed correlation (2 incidents) → False;
technique_recall math with sub-technique normalization; aggregate math; every
chain's steps have non-empty raw_text containing its expected technique's
signature keywords (guards against template drift).

PITFALLS: The runner needs the stack up (docker compose) — keep it out of
pytest entirely; only the pure scorer is unit-tested. LLM triage may take ~30s
per incident on Groq free tier — that's why the poll budget is 90s. Print
responses as they arrive so the run feels alive.

DONE WHEN: pytest green (pure tests), ruff clean, and with the stack running
`python -m app.purple` prints a real scorecard where credential_assault folds
into one incident with T1110 detected.
```

---

## T5 — STIX 2.1 + ATT&CK Navigator export

```
TASK: Export incidents as STIX 2.1 bundles and SOC-wide technique frequency as
an ATT&CK Navigator layer. Pure JSON generation, no new dependencies.

STEP 1 — app/services/stix_export.py (all PURE functions):
- _sid(prefix) -> f"{prefix}--{uuid4()}".
- ioc_to_indicator(ioc: dict, now_iso: str) -> STIX indicator dict:
  {"type":"indicator","spec_version":"2.1","id":_sid("indicator"),
   "created":now_iso,"modified":now_iso,"name":f"{ioc['type']}: {ioc['value']}",
   "pattern_type":"stix","valid_from":now_iso,
   "labels":[ioc.get("verdict","UNKNOWN").lower()],
   "pattern": one of
     ip    → "[ipv4-addr:value = '<v>']"
     user  → "[user-account:account_login = '<v>']"
     host  → "[domain-name:value = '<v>']"
     file_hash → "[file:hashes.'SHA-256' = '<v>']"
     url   → "[url:value = '<v>']"
     cve/other → "[vulnerability:name = '<v>']"  (escape single quotes in v)}
- technique_to_attack_pattern(t: dict, now_iso) -> attack-pattern dict with
  external_references: [{"source_name":"mitre-attack",
  "external_id":t["technique_id"],
  "url":f"https://attack.mitre.org/techniques/{t['technique_id'].replace('.','/')}/"}].
- build_stix_bundle(incident: dict) -> dict: {"type":"bundle",
  "id":_sid("bundle"),"objects":[...]} containing one report object (name =
  alert_message, published = created_at, object_refs = all other ids), all
  indicators from investigation_finding.iocs, all attack-patterns from
  triage_result.attack_techniques, and relationship objects
  (indicator "indicates" attack-pattern; use the first attack-pattern).
  JSONB fields may be JSON strings — decode defensively. Empty inputs are fine
  (bundle with just the report).
- build_navigator_layer(technique_counts: list[dict]) -> dict:
  {"name":"SentinelForge observed techniques","versions":{"attack":"16",
  "navigator":"5.1.0","layer":"4.5"},"domain":"enterprise-attack",
  "description":..., "techniques":[{"techniqueID":t["technique_id"],
  "score":int(t["count"]),"comment":t.get("name","")}],
  "gradient":{"colors":["#ffe766","#ff6666"],"minValue":0,
  "maxValue":max(counts, default=1)}}.

STEP 2 — API:
- In app/api/incidents.py: GET /{incident_id}/export/stix → 404 if missing,
  else JSONResponse of the bundle with header
  Content-Disposition: attachment; filename="incident-<id[:8]>.stix.json".
- In app/api/analytics.py: GET /navigator-layer → reuse the SQL from the
  existing top_techniques endpoint (jsonb_array_elements over
  triage_result->'attack_techniques'), feed rows to build_navigator_layer.

STEP 3 — Frontend: two small download links on the incident page sidebar
("Export STIX 2.1") and on the analytics page ("ATT&CK Navigator layer") —
plain <a href={...}> to the endpoints, styled like existing links.

STEP 4 — Tests (tests/test_stix_export.py, pure): bundle has type "bundle" and
ids match ^(bundle|indicator|attack-pattern|report|relationship)--[0-9a-f-]{36}$;
ip IOC produces the exact ipv4-addr pattern; a value containing a single quote
is escaped; every object has spec_version "2.1"; report.object_refs covers all
non-report objects; navigator layer techniqueID/score correct and maxValue =
max count; empty IOC/technique lists don't crash.

PITFALLS: STIX ids are lowercase UUIDs with a double hyphen after the type.
Don't import the heavyweight `stix2` library — hand-rolled dicts + tests are
the point. Dates must be ISO-8601 strings ending in Z or offset.

DONE WHEN: pytest green, ruff clean, downloading the layer file and loading it
at https://mitre-attack.github.io/attack-navigator/ colors the observed
techniques (manual check).
```

---

## T6 — Prometheus metrics + Grafana dashboard

```
TASK: Ops-grade observability: a /metrics endpoint with SOC-meaningful metrics
and a provisioned Grafana dashboard behind a compose profile.

STEP 1 — Add prometheus-client to alertforge/backend/pyproject.toml deps.

STEP 2 — app/services/metrics.py, defining (module-level, default registry):
- Counter sf_alerts_ingested_total{source}
- Counter sf_alerts_correlated_total{reason_kind}  (reason_kind: "signature",
  "shared_ip","shared_host","shared_user" — derive from the reason string)
- Counter sf_incidents_by_verdict_total{verdict}
- Histogram sf_stage_seconds{stage} buckets (0.5,1,2,5,10,30,60,120,300)
- Counter sf_actions_total{action_type,status}   (status = ActionStatus value)
- Counter sf_llm_tokens_total{model,kind}        (kind: input|output)
- Histogram sf_llm_latency_seconds{model}
- Gauge sf_approval_queue_size
Wrap every emit helper in try/except (metrics must NEVER break the pipeline)
and expose small functions like record_action(action_type, status) so call
sites stay one-liners.

STEP 3 — Instrument call sites:
- app/main.py: GET /metrics returning
  Response(generate_latest(), media_type=CONTENT_TYPE_LATEST).
- app/services/ingestion_service.py: ingested + correlated counters.
- app/pipeline/orchestrator.py: time each _dispatch_* handler → sf_stage_seconds.
- app/actions/executor.py: in _finish() → record_action(...).
- app/services/llm.py: token counts in _record(); latency around complete().
- HITL sweeper or an async task in main.py lifespan: every 30s set
  sf_approval_queue_size from SELECT count(*) FROM remediation_steps WHERE
  status='AWAITING_APPROVAL'.

STEP 4 — Compose profile "observability" in alertforge/docker-compose.yml:
- prometheus (prom/prometheus:latest), port 9090, mounting
  ./observability/prometheus.yml (scrape backend:8000/metrics every 15s).
- grafana (grafana/grafana:latest), port 3001 (3000 is the app!), anonymous
  admin enabled for demo, provisioning mounts:
  ./observability/grafana/datasources/prometheus.yml (points at
  http://prometheus:9090) and ./observability/grafana/dashboards/ containing a
  provider yml + sentinelforge.json dashboard with panels: alert ingest rate,
  noise-reduction % (folded/ingested), stage latency p95 by stage
  (histogram_quantile), actions by status (stacked), approval queue size, LLM
  tokens by model. Write the dashboard JSON by hand — keep it minimal but valid
  (schemaVersion 39, one row of stat panels + one row of timeseries).

STEP 5 — Tests (tests/test_metrics.py): import metrics module twice (no
duplicate-registration crash — guard with a try/except or a module singleton);
record_action("block_ip","DENIED") then assert the sample value via
prometheus_client.REGISTRY.get_sample_value("sf_actions_total",
{"action_type":"block_ip","status":"DENIED"}) == 1.0; reason_kind derivation
("shared source IP 1.2.3.4" → "shared_ip", "duplicate signature" →
"signature").

PITFALLS: Grafana must NOT take port 3000. Duplicate metric registration
crashes on module re-import in tests — use a get-or-create guard. Never let a
metrics exception propagate into pipeline code.

DONE WHEN: pytest green, ruff clean, `docker compose --profile observability
up -d` then localhost:9090/targets shows the backend UP and localhost:3001
renders the dashboard with live numbers after a storm seed.
```

---

## T7 — Analyst feedback flywheel

```
TASK: Let analysts correct triage verdicts; store the labels; expose agreement
analytics; export corrections as eval-corpus cases so human feedback tightens
the CI quality gate.

STEP 1 — Migration alembic/versions/006_feedback.py (chain from the current
head — check the latest revision id in alembic/versions/ first): table
triage_feedback: id UUID pk default gen_random_uuid(), incident_id UUID FK →
incidents ON DELETE CASCADE, given_by TEXT not null, ai_verdict TEXT,
human_verdict TEXT not null CHECK (IN ('TRUE_POSITIVE','FALSE_POSITIVE',
'BENIGN_ANOMALY','NEEDS_HUMAN')), ai_severity TEXT, human_severity TEXT,
note TEXT, created_at TIMESTAMPTZ default NOW(), UNIQUE(incident_id, given_by).

STEP 2 — app/api/incidents.py: POST /{incident_id}/feedback with body
{human_verdict, human_severity?, note?} (validate with a small pydantic model;
422 on bad verdict). Pull ai_verdict/ai_severity from the incident's
triage_result. given_by = authenticated operator if T1 is merged (use the
current_operator dependency), else "analyst:anonymous". Upsert (ON CONFLICT
(incident_id, given_by) DO UPDATE). write_audit(action="triage.feedback").
Publish event type FEEDBACK_RECEIVED = "feedback.received" (add to EventType).

STEP 3 — Analytics in app/api/analytics.py: GET /feedback →
{"total": n, "agreement_rate": share where ai_verdict = human_verdict,
"false_negatives": count(ai in (FALSE_POSITIVE,BENIGN_ANOMALY) AND human =
TRUE_POSITIVE)  # the dangerous miss,
"false_positives_confirmed": count(ai = TRUE_POSITIVE AND human in
(FALSE_POSITIVE,BENIGN_ANOMALY)),
"by_pair": [{"ai": ..., "human": ..., "count": ...}]}.

STEP 4 — Corpus export app/eval/feedback_export.py:
async fetch_feedback_cases() -> list[EvalCase] (name=f"fb_{incident_id[:8]}",
raw_text=incident.alert_message, expected_verdict=human_verdict,
expected_severity=human_severity or ai_severity or "P3_MEDIUM",
expected_techniques=[] ) and a CLI `python -m app.eval.feedback_export` that
prints ready-to-paste EvalCase(...) python literals for app/eval/corpus.py —
deliberately human-in-the-loop (a person reviews before committing corpus
changes; say so in the module docstring).

STEP 5 — Frontend: on the incident page sidebar add "Was this triage right?"
with four small buttons (✓ TP / ✗ FP / ~ Benign / ? Needs human) → POST
feedback via a new lib/api.ts helper; show "recorded ✓" after submit.

STEP 6 — Tests (tests/test_feedback.py, pure): the pydantic body model rejects
bad verdicts; agreement-rate math as a pure function agreement_stats(rows) →
factor the SQL-free aggregation into app/eval/feedback_export.py or a helper
so it's testable: perfect agreement → 1.0, the false_negative definition
counts exactly the dangerous case, by_pair grouping correct; EvalCase
construction from a feedback row.

PITFALLS: incident.triage_result may be a JSON string (decode). Don't block
feedback on missing triage (ai_verdict nullable). UNIQUE constraint → use
upsert, not blind INSERT.

DONE WHEN: pytest green, ruff clean, POST feedback twice from same analyst
updates instead of erroring, /api/v1/analytics/feedback returns sane numbers,
UI buttons work (npx tsc --noEmit clean).
```

---

## T8 — README + demo polish

```
TASK: Rewrite the top of alertforge/README.md so the first screen makes a
reviewer stop scrolling, add a Mermaid architecture diagram, a hard-numbers
table, and a Trust Model section. Do NOT invent numbers — pull real ones.

STEP 1 — Gather real numbers first (run these, use actual outputs):
- cd alertforge/backend && ./venv/bin/python -m pytest -q   → test count
- ./venv/bin/python -m app.eval.harness                     → eval metrics
- ./venv/bin/python -m pytest tests/test_actions.py -q      → red-team count
- If the stack is up: curl -s localhost:8000/api/v1/analytics/correlation
  → noise_reduction_pct; if T4 exists: purple_results/latest.json.

STEP 2 — README top section (keep everything that exists below, reorganize):
1. Title + one-line pitch + badges (CI, Python 3.12, License MIT, Tests: N).
2. "At a glance" table: Noise reduction | Triage eval (verdict acc, FP
   suppression) | Red-team guardrail tests | Total tests | Model stack (Groq
   Llama 3.3 70B / 8B).
3. Mermaid architecture diagram (```mermaid flowchart LR```): Alert sources →
   HMAC+Injection guard → Correlation engine (decision diamond: fold vs new) →
   Redis Streams → the 5 agents in a subgraph "War Room" → HITL gate →
   Guardrails (subgraph "Action Safety": policy → dry-run → execute → verify →
   rollback) → real world; side nodes: hash-chained audit, eval gate → CI,
   SSE → dashboard. Keep it under ~25 nodes so it renders cleanly on GitHub.
4. "Trust model" section (5 bullets): LLM proposes / deterministic guardrails
   dispose; DENY un-overridable; dry-run default; hash-chained audit;
   CI-gated triage quality.
5. 3-command quickstart (./demo.sh) + link to DEMO.md.

STEP 3 — Record a GIF (instructions for the human — put them in a comment at
the bottom of DEMO.md): screen-record ./demo.sh + the war-room incident page
(~30s), convert with `ffmpeg -i demo.mov -vf "fps=10,scale=960:-1" -loop 0
docs/demo.gif`, embed near the top of README with
![War room](docs/demo.gif). Create the docs/ dir with a .gitkeep.

STEP 4 — Consistency pass: make sure every feature the README claims exists in
the code TODAY (grep for the endpoints/files it names); update ARCHITECTURE.md
links; ensure TASK.md is linked from README's "Roadmap" line.

PITFALLS: GitHub Mermaid fails on some syntax — avoid parentheses inside node
labels and avoid `end` as a node id. Don't fabricate metrics; every number in
the table must be reproducible by a command listed in the README itself.

DONE WHEN: README renders cleanly on GitHub (mermaid included), every claim is
true, numbers are reproducible, and the first screenful communicates:
real-time SOC + correlation + guardrails + measured quality.
```

---

## Tips for running these with OSS models

1. **One task per session.** Paste COMMON CONTEXT + one prompt. Fresh context
   beats a long session.
2. **Make it run the checks.** End every session with: "Run pytest, ruff, and
   the eval gate and paste the output." OSS models skip verification unless
   forced.
3. **If it invents APIs**, paste the real file (e.g. app/actions/base.py) and
   say "conform to THIS exactly."
4. **Review DB migrations by hand** before applying — wrong down_revision is
   the most common OSS-model mistake here (check the latest file in
   alembic/versions/ first).
5. Commit after each green task: `git add -A && git commit -m "T<n>: <task>"`.
