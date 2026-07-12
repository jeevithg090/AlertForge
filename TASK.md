# SentinelForge — Resume-Maximizing Task Roadmap

> Goal: turn SentinelForge into the project a hiring engineer *remembers*.
> Each task below is chosen for one reason: it makes a reviewer say
> "wait, this person built *that*?" — and each has a ready-to-paste prompt in
> [PROMPT-TASK.md](PROMPT-TASK.md) written for OSS coding models.

## Already done (don't redo — build on top)

- 5-agent pipeline on Redis Streams + DLQ, HITL gate with CAS + timeout sweeper
- Alert correlation/dedup engine (deterministic, advisory-locked, ~67–97% noise reduction)
- Threat-hunt hypothesis generator (technique → runnable SPL/EQL/Sigma queries)
- **Action safety layer** (`app/actions/`): guardrails where a DENY is un-overridable,
  dry-run→execute→verify→rollback lifecycle, red-team test suite
- **CI-gated triage eval harness** (`app/eval/`) — 0.94 verdict acc, 1.00 FP suppression
- **Tamper-evident hash-chained audit log** + `/security/audit/verify`
- OSS-tuned LLM layer (tool selection, JSON repair, 2-tier routing), 76 passing tests

## The tasks (in priority order)

| # | Task | Why it blows minds | Effort |
|---|------|--------------------|--------|
| T1 | **RBAC + signed approvals** | "Blocking prod requires a *verified identity* with the approver role — the approver string can't be forged." Closes the biggest remaining trust gap. | M |
| T2 | **One REAL containment adapter (Cloudflare free tier)** | Kills the "it's all mocks" critique: a real API call blocks a real IP, verifies it, and rolls it back. | M |
| T3 | **Detection-as-code: auto-generated Sigma rules** | "The SOC writes its own detections" — after containment it emits a valid Sigma rule so the same attack is caught by the SIEM next time. Detection-engineering depth few candidates show. | M |
| T4 | **Purple-team self-assessment mode** | The project **red-teams itself**: replays multi-stage MITRE attack chains against its own pipeline and prints a Detection Scorecard (correlation %, technique accuracy, MTTR). A security tool that measures itself end-to-end is rare even in industry. | L |
| T5 | **STIX 2.1 + ATT&CK Navigator export** | Speaks the industry's interchange formats — incidents export as STIX bundles and Navigator heat-map layers that load into real tools. Instant credibility with SOC practitioners. | S |
| T6 | **Prometheus metrics + Grafana dashboard** | An ops-grade `/metrics` endpoint + a provisioned Grafana dashboard in compose. Screenshot gold + shows SRE maturity. | M |
| T7 | **Analyst feedback flywheel** | Analyst verdict overrides become labeled data that grows the eval corpus — a real continuous-learning loop, not a buzzword. | S |
| T8 | **README + demo polish (diagram, GIF, scorecard table)** | The first 30 seconds of a recruiter's attention. Mermaid architecture diagram, war-room GIF, hard numbers (noise reduction, eval scores, red-team results) above the fold. | S |

Effort: S ≈ 1–2h, M ≈ 3–5h, L ≈ 6–8h with an OSS model doing the typing.

## Task details

### T1 — RBAC + signed approvals
Today the approver is a hardcoded string sent in the request body
(`frontend/lib/api.ts` → `human:operator@sentinelforge.local`). Anyone who can
reach the API can "approve" blocking prod. Fix: an `operators` table, JWT login,
role checks (`viewer/analyst/approver/admin`) enforced as FastAPI dependencies,
and approval endpoints that take identity **from the verified token only**. The
two-person rule then means two *distinct authenticated* approvers.
**Resume line:** "Designed authenticated, non-repudiable approval flow (JWT + RBAC + two-person rule) for AI-proposed containment actions."

### T2 — Real containment adapter (Cloudflare)
Implement `CloudflareBlockIPAdapter` behind the existing 5-method contract
(`app/actions/base.py`) using Cloudflare's free-tier **IP Access Rules** API:
`execute` creates a block rule, `verify` reads it back, `rollback` deletes it.
Env-gated (`CLOUDFLARE_API_TOKEN`) with the mock as fallback; HTTP fully mocked
in tests. Guardrails still authorize everything.
**Resume line:** "Shipped a real, reversible firewall containment adapter (execute→verify→rollback) gated by deterministic guardrails."

### T3 — Detection-as-code (Sigma)
`POST /api/v1/incidents/{id}/detection-rule` generates a **valid Sigma YAML
rule** from the incident's IOCs + MITRE techniques (deterministic templates per
technique family, LLM refines title/description only), saves it under
`detections/generated/`, and surfaces it in the incident UI with a download
button. Include a validator test (required Sigma fields, parseable YAML).
**Resume line:** "Closed the IR loop with detection-as-code: every contained incident auto-generates a Sigma rule."

### T4 — Purple-team self-assessment
`python -m app.purple` (or `demo/purple_team.py`) replays scripted **attack
chains** (e.g. T1110 brute force → T1078 valid accounts → T1041 exfil) through
the real ingestion API with realistic timing/entities, waits for the pipeline,
then queries the DB/API and scores: alerts folded vs expected, techniques
correctly mapped, verdict accuracy, time-to-triage/containment, guardrail
blocks. Emits a **Detection Scorecard** (JSON + pretty terminal table) and a
`/purple` page showing the latest run.
**Resume line:** "Built a purple-team harness that adversarially replays MITRE attack chains against the SOC and scores its end-to-end detection performance."

### T5 — STIX 2.1 + ATT&CK Navigator export
`GET /api/v1/incidents/{id}/export/stix` → a STIX 2.1 bundle (indicators from
IOCs, attack-patterns from techniques, relationships, the incident as a report).
`GET /api/v1/analytics/navigator-layer` → an ATT&CK Navigator layer JSON where
technique scores = incident counts. Pure JSON generation, heavily unit-tested;
no new deps needed.
**Resume line:** "Interoperable with the SOC ecosystem: STIX 2.1 IOC bundles and ATT&CK Navigator heat maps."

### T6 — Prometheus + Grafana
`prometheus-client` metrics: pipeline stage latency histograms, alerts
ingested/folded counters, actions by decision (allowed/denied/rolled back), LLM
tokens/latency by model, approval-queue age gauge. `/metrics` endpoint, a
`prometheus` + `grafana` compose profile, and one provisioned dashboard JSON.
**Resume line:** "Ops-grade observability: Prometheus metrics and a shipped Grafana dashboard for SOC pipeline health."

### T7 — Analyst feedback flywheel
`POST /api/v1/incidents/{id}/feedback` lets an analyst correct the verdict
(+optional note). Store in a `triage_feedback` table, expose agreement-rate
analytics, and add an export that converts feedback rows into `EvalCase` lines
appended to the eval corpus — so human corrections directly tighten the CI gate.
**Resume line:** "Human feedback loop: analyst overrides become labeled eval data that ratchets the model-quality gate."

### T8 — README + demo polish
Mermaid architecture diagram; a hard-numbers table (noise reduction %, eval
metrics, red-team results, test count); a 30-second war-room GIF; a "Trust
model" section (LLM proposes / guardrails dispose, hash-chained audit); badges.
Rewrite the top of the README so the first screen sells everything above.

## Suggested order

T1 → T2 → T3 → T5 → T4 → T7 → T6 → T8 (finish with polish so the README
describes everything that now exists). T5 before T4 because the purple-team
scorecard can then link Navigator layers as evidence.
