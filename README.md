# SentinelForge — Autonomous SOC War Room

> Folds alert storms into single incidents, has a team of LLM agents triage, investigate
> and plan containment, and keeps a human approver in front of every action that changes
> production.

![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![PostgreSQL 16](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![Redis 7](https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white)
![Next.js 15](https://img.shields.io/badge/Next.js-15-000000?logo=nextdotjs&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-06B6D4?logo=tailwindcss&logoColor=white)
![Docker Compose](https://img.shields.io/badge/Docker_Compose-2496ED?logo=docker&logoColor=white)

![SentinelForge incident feed](docs/screenshots/dashboard.png)

## Contents

- [Overview](#overview)
- [Screenshots](#screenshots)
- [Key features](#key-features)
- [Tech stack](#tech-stack)
- [Architecture](#architecture)
- [Project structure](#project-structure)
- [Getting started](#getting-started)
- [Configuration](#configuration)
- [Usage](#usage)
- [API reference](#api-reference)
- [Scripts and commands](#scripts-and-commands)
- [Testing and quality](#testing-and-quality)
- [Deployment](#deployment)
- [Troubleshooting and FAQ](#troubleshooting-and-faq)
- [Known limitations](#known-limitations)
- [Roadmap ideas](#roadmap-ideas)
- [Contributing](#contributing)
- [License](#license)

## Overview

A security operations centre (SOC) drowns in alerts. One brute-force attempt can fire
thousands of near-identical SIEM events, the same host shows up in EDR and IDS at once,
and an analyst has to piece the story together before deciding whether to block an IP
or suspend an account. Automating that last step is risky: a model that "decides" to
block production traffic is a new attack surface.

SentinelForge splits the job:

1. **Ingest and correlate.** Findings arrive from SIEM / EDR / IDS webhooks, email
   reports or pasted text. A deterministic correlation engine folds duplicates and
   related alerts into one open incident (no model call involved).
2. **Let agents do the legwork.** Five specialist agents triage the incident (verdict,
   severity, MITRE ATT&CK mapping), investigate it with a small read-only toolset,
   draft a containment plan, execute approved steps and write the post-incident report.
3. **Keep humans and policy in charge.** Every mutating action passes a deterministic
   guardrail layer (protected targets, rate limits, kill switch, dry-run by default,
   two-person rule for critical incidents) and waits for a human approval. A guardrail
   DENY cannot be overridden by any model output or approval.
4. **Leave a trail.** Every agent and human action lands in a hash-chained audit log
   that detects edits, deletions and reordering.

The operator dashboard streams all of it live: the incident feed, the agents' timeline,
approval cards, analytics and the security posture.

**Who it's for:** security engineers and SOC teams exploring safe agentic automation,
and anyone who wants a working reference for "LLM proposes, policy decides, human
approves". It runs end to end **without any API keys**: without an LLM key every model
call falls back to deterministic heuristics, and external tools return realistic mocks.

## Screenshots

All screenshots are of the running app with the bundled demo scenarios
(`demo/seed_alerts.py`), no LLM key, captured at 2× from the production build.

| | |
|---|---|
| ![Incident with containment plan awaiting approval](docs/screenshots/incident-approval.png) **Incident view.** Severity, verdict and status up top; the containment plan comes first because it is the only thing waiting on a human. | ![Two-person rule](docs/screenshots/two-person-approval.png) **Two-person rule.** A P1 step approved by one operator goes back for a second, distinct approver. |
| ![Threat hunt and Sigma rule](docs/screenshots/incident-hunt-sigma.png) **Agent timeline and threat hunt.** Agent messages interleaved with tool calls; hunt hypotheses with runnable EQL / SPL queries. | ![Resolved incident with report and ticket](docs/screenshots/incident-report.png) **Resolved incident.** OPS executed the approved steps, CHRON filed the report and a ticket via the MCP server. (Without an LLM key the report body is a placeholder.) |
| ![Analytics](docs/screenshots/analytics.png) **Analytics.** Alert noise reduction, MTTR, verdicts, services and top ATT&CK techniques. | ![Security controls](docs/screenshots/security.png) **Security controls.** Self-reported guardrail posture and recent security events, such as a blocked prompt injection. |
| ![Sign in](docs/screenshots/login.png) **Sign in** with inline validation. | <img src="docs/screenshots/mobile-dashboard.png" alt="Dashboard on a phone" width="48%"> <img src="docs/screenshots/mobile-incident.png" alt="Incident on a phone" width="48%"> **Phone layout** (iPhone 13 viewport). |

## Key features

**Detection and triage**

- **Alert correlation and dedup.** Fingerprint and entity-overlap matching (IP, host,
  user) inside a configurable window folds storms and cross-tool duplicates into one
  incident. Pure functions, no model call: `python demo/seed_alerts.py --storm 30` turns
  30 alerts into one incident.
- **Five-agent pipeline on Redis Streams.** CMDR (triage, verdict, severity, ATT&CK
  mapping, streamed reasoning), ANLST (investigation with a per-incident subset of
  read-only tools, called concurrently), STRAT (containment plan), OPS (execution with
  verification and rollback) and CHRON (post-incident report, ticket via MCP).
- **Prompt-injection guard.** Text inputs are sanitised and scanned; injection attempts
  are rejected and logged as security events.

**Safe containment**

- **Deterministic guardrails.** Every mutating action runs
  `propose → guardrails → dry-run → execute → verify → rollback`. Protected targets
  (RFC1918/loopback, break-glass and service accounts, domain controllers, plus your own
  lists), per-incident and global rate limits, a kill switch, an enabled-action list,
  dry-run by default, and a **two-person rule** for configured severities.
- **One real containment adapter.** Cloudflare IP Access Rules: execute creates a block
  rule, verify reads it back, rollback deletes it. Env-gated; mocked otherwise.
- **RBAC and attributable approvals.** JWT login with `viewer` / `analyst` / `approver` /
  `admin` roles enforced on every operator API. The approver identity always comes from
  the verified token, never from the request body.
- **Low-risk auto-approval timeouts** per severity (P2/P3/P4), so notifications don't
  stall overnight. P1 steps never auto-approve.

**Threat intel and detection engineering**

- **Sigma rule generation** from an incident's IOCs and techniques.
- **Threat-hunt generator.** From an incident, a technique or free text: falsifiable
  hypotheses with Splunk SPL / Elastic EQL / KQL / Sigma queries.
- **STIX 2.1 export** per incident and an **ATT&CK Navigator layer** across incidents.

**Quality and oversight**

- **Triage quality gate.** An offline harness scores triage against a labelled corpus and
  exits non-zero on regression. The deterministic baseline scores 0.94 verdict accuracy
  and 1.00 false-positive suppression on the bundled 17-case corpus; `--llm` scores a
  live model.
- **Analyst feedback loop.** Verdict corrections from the UI become labelled eval data
  (`app/eval/feedback_export.py`).
- **Purple-team self-assessment.** `python -m app.purple` replays scripted multi-stage
  attack chains through the real ingestion path and prints a detection scorecard.
- **Tamper-evident audit log.** Hash-chained entries;
  `GET /api/v1/security/audit/verify` reports whether the chain is intact.
- **Observability.** Prometheus `/metrics` (stage latency, alert/fold counters, action
  outcomes, LLM tokens, approval queue) and a provisioned Grafana dashboard.

**Operator dashboard**

- Live incident feed with search, severity and status filters, and in-place status
  updates over Server-Sent Events.
- Incident war room: approvals first, agent/tool timeline, reasoning trace, ATT&CK
  chips, investigation finding, correlated alerts, hunt, Sigma, feedback and STIX export.
- Analytics and security-controls pages; sign-in with role display and sign-out.
- Responsive from 375 px phones to wide desktops, keyboard accessible (skip link,
  visible focus, labelled controls, live regions), WCAG AA text contrast, and loading,
  empty, error and not-found states throughout.

## Tech stack

| Layer | Technology |
|-------|------------|
| API and workers | Python 3.12, FastAPI, asyncpg (raw SQL), Alembic, Pydantic v2, sse-starlette, PyJWT |
| Messaging | Redis 7: Streams (pipeline stages + dead-letter queue) and pub/sub (live events) |
| Storage | PostgreSQL 16; optional ChromaDB + sentence-transformers for semantic runbook search |
| LLM | Any OpenAI-compatible endpoint (Groq with Llama 3.3 70B / 3.1 8B by default) |
| Integrations | MCP server (runbooks + ticket stub), Cloudflare, VirusTotal, AbuseIPDB, Elasticsearch, Prometheus, Slack (all optional) |
| Frontend | Next.js 15 (App Router), React 19, TypeScript, Tailwind CSS 3, lucide-react icons, react-markdown |
| Observability | Prometheus client, Grafana (optional compose profile) |
| Tooling | Ruff, pytest, ESLint 9, TypeScript, Docker Compose, Make |

## Architecture

```mermaid
flowchart LR
    subgraph Sources
        SIEM[SIEM / EDR / IDS webhooks]
        TXT[Email / pasted text]
    end
    SIEM -->|HMAC| ING[Ingestion API]
    TXT -->|analyst token| ING
    ING --> PG[PromptGuard]
    PG -->|blocked| SEC[(Security events)]
    PG --> CORR{Correlation engine}
    CORR -->|fold into open incident| DB[(PostgreSQL)]
    CORR -->|new incident| DB
    CORR -->|new| RS[[Redis Streams]]

    subgraph Worker[Pipeline worker]
        T[CMDR · triage] --> I[ANLST · investigate] --> P[STRAT · plan]
        P --> H{HITL gate}
        H -->|approved| E[OPS · execute]
        E --> R[CHRON · report]
    end
    RS --> T
    I -.->|read-only tools| TOOLS[VirusTotal · AbuseIPDB · ES · mocks]
    R -.->|MCP-SSE| MCP[MCP server: runbooks, tickets]

    E --> G{Guardrails}
    G -->|DENY, final| AUDIT[(Hash-chained audit log)]
    G -->|allow| ACT[dry-run → execute → verify → rollback]
    ACT --> AUDIT

    Worker -->|events| PUB[[Redis pub/sub + event log]]
    PUB -->|SSE| UI[Next.js dashboard]
    UI -->|REST: approve / reject / escalate| API[FastAPI]
    API --> DB
```

**How a finding flows through the system**

1. A webhook or pasted alert hits `/api/v1/ingest/*`. Webhooks are HMAC-verified when a
   real `SECRET_KEY` is set; text and email ingestion need an analyst token.
2. PromptGuard sanitises the text and rejects injection attempts.
3. The correlation engine compares the alert's fingerprint and entities with open
   incidents inside `CORRELATION_WINDOW_SECONDS`. A match is folded into that incident
   (its `alert_count` grows); otherwise a new incident is created and queued.
4. The worker runs the agents stage by stage over Redis Streams, with a dead-letter
   queue for failures. Each stage publishes events to `incident:{id}:events` (pub/sub,
   streamed to browsers over SSE) and to a bounded per-incident log used to replay
   history when a browser connects or reconnects.
5. The plan's mutating steps stop at the HITL gate. When an approver decides in the UI,
   the worker resumes; OPS asks the guardrail layer before every action, applies it
   (dry-run unless `ACTION_DRY_RUN_ONLY=false`), verifies and rolls back on failure.
6. CHRON writes the report and files a ticket through the MCP server.

| Component | Path | Role |
|-----------|------|------|
| API server | `backend/app/main.py` | REST + SSE, auth, ingestion, approvals |
| Pipeline worker | `backend/app/pipeline/orchestrator.py` | Consumes Redis Streams and runs the agents |
| Agents | `backend/app/agents/` | Triage, investigation, remediation, execution, PIR |
| Correlation | `backend/app/pipeline/correlation.py` | Deterministic dedup |
| Action safety | `backend/app/actions/` | Guardrail policy, executor, adapters |
| MCP server | `mcp_server/` | Runbook search + stub ticketing over MCP-SSE |
| Dashboard | `frontend/` | Incident feed, war room, analytics, security controls |

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design (event schema, guardrail
order, audit chain, HITL timeouts).

## Project structure

```
.
├── backend/
│   ├── app/
│   │   ├── actions/          # guardrail policy, executor, Cloudflare + mock adapters
│   │   ├── agents/           # triage, investigation, remediation, execution, PIR agents
│   │   ├── api/              # FastAPI routers: ingestion, incidents, approvals, auth,
│   │   │                     #   stream (SSE), analytics, hunt, security, health
│   │   ├── db/               # asyncpg pool, incident repository, hash-chained audit log
│   │   ├── eval/             # labelled triage corpus, quality-gate harness, feedback export
│   │   ├── pipeline/         # orchestrator, correlation, HITL gate, tool selection
│   │   ├── purple/           # attack-chain replay + scorecard
│   │   ├── schemas/          # Pydantic models and event types
│   │   ├── services/         # LLM client, auth/RBAC, ingestion, Redis, Sigma, STIX, hunts
│   │   ├── tools/            # investigation tools (real API or mock)
│   │   ├── config.py         # all settings (env vars) + production safety checks
│   │   └── main.py           # FastAPI app, routers, CORS, metrics
│   ├── alembic/              # database migrations (0001 … 0006)
│   ├── tests/                # pytest suite (no database or Redis needed)
│   ├── Dockerfile            # non-root API/worker image
│   └── pyproject.toml        # dependencies, extras ([dev], [rag]), ruff + pytest config
├── frontend/
│   ├── app/                  # Next.js App Router
│   │   ├── dashboard/        #   incident feed, alert intake, live event log
│   │   ├── incidents/[id]/   #   incident war room
│   │   ├── analytics/        #   SOC metrics
│   │   ├── security/         #   guardrail posture + security events
│   │   ├── login/            #   operator sign-in
│   │   ├── not-found.tsx     #   404 page
│   │   ├── error.tsx         #   route error boundary
│   │   ├── icon.svg          #   favicon
│   │   └── opengraph-image.tsx # generated social preview card
│   ├── components/           # AppShell (header/nav), ui.tsx (cards, badges, states),
│   │                         #   ErrorNotice, Logo, Markdown (lazy-loaded)
│   ├── lib/                  # api.ts (typed client + session), sse.ts (stream hooks),
│   │                         #   format.ts (labels, colours, time helpers)
│   ├── tailwind.config.ts    # design tokens
│   └── Dockerfile            # standalone Next.js server image
├── mcp_server/               # MCP-SSE server: runbook search, JIRA-style ticket stub
├── runbooks/                 # markdown runbooks used by investigation and search
├── observability/            # Prometheus config + Grafana provisioning
├── demo/                     # alert seeder (seed_alerts.py) and a shell demo trigger
├── docs/screenshots/         # images used in this README
├── docker-compose.yml        # full stack; docker-compose.dev.yml adds hot reload
├── demo.sh                   # one-command demo (build, start, seed)
├── Makefile                  # common tasks (see "Scripts and commands")
├── ARCHITECTURE.md           # design deep-dive
└── DEMO.md                   # guided three-minute walkthrough
```

## Getting started

### Prerequisites

| For | You need |
|-----|----------|
| Docker quick start | Docker with Compose v2; Python 3 with `requests` (only for the demo seeder) |
| Local development | Python 3.12, Node.js 20+ (22 works), PostgreSQL 16, Redis 7 |
| Optional | An OpenAI-compatible LLM key (e.g. a free Groq key), Cloudflare / VirusTotal / AbuseIPDB / Slack credentials |

### Option A: Docker (recommended)

```bash
git clone https://github.com/jeevithg090/AlertForge.git
cd AlertForge
cp .env.example .env                   # works as-is; add LLM_API_KEY for live models
docker compose up -d --build --wait    # Postgres, Redis, mock ES, MCP, API, worker, UI

python3 -m pip install requests
python3 demo/seed_alerts.py --storm 30              # 30 alerts → 1 incident
python3 demo/seed_alerts.py --scenario brute_force  # full triage → contain run
```

Then open:

- Dashboard: <http://localhost:3000>
- API docs (Swagger UI): <http://localhost:8000/docs>

`./demo.sh` (or `make demo`) does all of the above in one go. Add Prometheus
(`:9090`) and Grafana (`:3001`) with `docker compose --profile observability up -d`.

### Option B: Local development (no Docker)

```bash
# 1. Database and Redis (any local install)
createuser -s sentinelforge && createdb -O sentinelforge sentinelforge
psql -c "alter user sentinelforge with password 'sentinelforge'"
redis-server --daemonize yes

# 2. Backend
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"            # add ,rag for semantic runbook search (pulls torch)
export DATABASE_URL=postgresql://sentinelforge:sentinelforge@localhost:5432/sentinelforge
export REDIS_URL=redis://localhost:6379/0 RUNBOOKS_DIR=../runbooks
alembic upgrade head
uvicorn app.main:app --reload --port 8000      # terminal 1: API
python -m app.pipeline.orchestrator            # terminal 2: pipeline worker

# 3. Frontend (terminal 3)
cd frontend
npm ci
npm run dev                                    # http://localhost:3000
```

The frontend proxies `/api/*` to `BACKEND_URL` (default `http://localhost:8000`), so no
extra configuration is needed locally. Set `NEXT_PUBLIC_API_URL` only if the browser
should call the API on a different origin.

`docker compose -f docker-compose.yml -f docker-compose.dev.yml up` gives the same hot
reload inside containers.

### Signing in

In development (`ENVIRONMENT=development` with `AUTH_DEV_BYPASS=true`) the API treats
unauthenticated requests as an anonymous admin, so you can use the dashboard without
signing in. To exercise real auth, sign in at `/login` as `admin@sentinelforge.local`
with your `DEFAULT_ADMIN_PASSWORD`, then create operators (see
[Usage](#create-operators-and-try-the-two-person-rule)).

## Configuration

All settings are environment variables. The backend reads `.env` from its working
directory; Docker Compose reads the root `.env` and forwards the variables to the
containers. [`.env.example`](.env.example) is the commented template and is safe to copy
as-is for local use.

### Core

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENVIRONMENT` | No | `development` | `development`/`dev`/`local`/`test` enable dev conveniences; anything else turns on production checks |
| `SECRET_KEY` | **Yes outside dev** | placeholder | Signs JWTs and webhook HMACs. Must be a real value of 32+ chars outside development, or the API refuses to start |
| `DEFAULT_ADMIN_PASSWORD` | **Yes outside dev** | `changeme-admin` | Password for `admin@sentinelforge.local`, seeded on first start. Must be changed outside development |
| `AUTH_DEV_BYPASS` | No | `true` | Anonymous admin access; only honoured when `ENVIRONMENT` is development |
| `LOG_LEVEL` | No | `INFO` | Python log level |
| `FRONTEND_URL` | No | `http://localhost:3000` | Always-allowed CORS origin |
| `CORS_ORIGINS` | No | empty | Extra allowed browser origins, comma-separated (`*` is ignored) |
| `BACKEND_URL` | No | `http://localhost:8000` | Backend base URL (also used by the Next.js `/api` proxy) |
| `DATABASE_URL` | Yes | `postgresql://sentinelforge:sentinelforge@postgres:5432/sentinelforge` | PostgreSQL connection string |
| `REDIS_URL` | Yes | `redis://redis:6379/0` | Redis connection string |
| `RUNBOOKS_DIR` | No | empty (auto) | Path to the `runbooks/` directory |
| `CHROMA_DIR` | No | empty | ChromaDB storage for semantic runbook search (`[rag]` extra) |
| `DETECTIONS_DIR` | No | `detections/generated` | Where generated Sigma rules are written |

### LLM

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LLM_API_KEY` | No | empty | OpenAI-compatible key. Blank = deterministic heuristics, no LLM calls |
| `LLM_BASE_URL` | No | `https://api.groq.com/openai/v1` | Any OpenAI-compatible endpoint (Together, vLLM, Ollama, …) |
| `LLM_PROVIDER` | No | `groq` | Label shown in health output |
| `LLM_MODEL_SMART` | No | `llama-3.3-70b-versatile` | Model for judgement and tool use |
| `LLM_MODEL_FAST` | No | `llama-3.1-8b-instant` | Model for cheap work |
| `LLM_MODEL_REASONING` | No | empty | Optional dedicated reasoning model for P1/P2 triage |
| `LLM_REQUEST_TIMEOUT_SECONDS` | No | `60` | Per-request timeout |
| `EMBEDDING_MODEL` | No | `all-MiniLM-L6-v2` | Local sentence-transformers model for runbook search |

Legacy aliases from the project's Qwen origins (`DASHSCOPE_API_KEY`, `QWEN_BASE_URL`,
`QWEN_MODEL_MAX`, `QWEN_MODEL_PLUS`, `QWEN_MODEL_FLASH`) are still accepted; the `LLM_*`
names take precedence.

### Integrations (all optional; blank = mock)

| Variable | Default | Description |
|----------|---------|-------------|
| `USE_MOCK_TOOLS` | `true` | Mock external tools whose keys are absent |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` | empty | Real IP/hash reputation lookups |
| `ELASTICSEARCH_URL`, `ELASTICSEARCH_API_KEY` | empty | Real SIEM log queries |
| `PROMETHEUS_URL` | empty | Real metric queries |
| `SLACK_BOT_TOKEN`, `SLACK_CHANNEL_ID` | empty | Real notifications |
| `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONE_ID` | empty | Enables the real Cloudflare IP-block adapter |
| `RUNBOOK_MCP_SSE_URL`, `JIRA_MCP_SSE_URL` | `http://mcp-server:8001/sse` | MCP server endpoints |
| `GITHUB_MCP_TOKEN`, `JIRA_MCP_TOKEN` | empty | Tokens for external MCP servers (not needed for the bundled one) |

### Correlation, approvals and guardrails

| Variable | Default | Description |
|----------|---------|-------------|
| `CORRELATION_ENABLED` | `true` | Fold related alerts into open incidents |
| `CORRELATION_WINDOW_SECONDS` | `1800` | How long an open incident absorbs related alerts |
| `AUTO_APPROVE_TIMEOUT_P2` / `_P3` / `_P4` | `2` / `15` / `5` | Minutes before low-risk steps auto-approve at that severity |
| `ACTION_DRY_RUN_ONLY` | `true` | Simulate every mutating action (safe default) |
| `ACTION_KILL_SWITCH` | `false` | Emergency stop for all mutating actions |
| `ACTION_ENABLED_TYPES` | `notification,block_ip,suspend_account,isolate_host,rotate_credentials,quarantine_file` | The only action types allowed to run |
| `ACTION_PROTECTED_IP_CIDRS` | empty | Extra never-block CIDRs (RFC1918 and loopback are always protected) |
| `ACTION_PROTECTED_USERS` | empty | Extra never-suspend users, globs allowed (break-glass/service accounts always protected) |
| `ACTION_PROTECTED_HOSTS` | empty | Extra never-isolate hosts, globs allowed |
| `ACTION_MAX_PER_INCIDENT` | `10` | Action budget per incident |
| `ACTION_MAX_PER_WINDOW` / `ACTION_WINDOW_SECONDS` | `25` / `300` | System-wide action rate limit |
| `ACTION_TWO_PERSON_SEVERITIES` | `P1_CRITICAL` | Severities whose mutating actions need two distinct approvers |

### Frontend and compose

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | empty in dev (same-origin proxy); `http://localhost:8000` in the Docker image | API origin for browser calls. Inlined at build time |
| `NEXT_PUBLIC_SITE_URL` | `http://localhost:3000` | Public URL used for absolute Open Graph image links |
| `BACKEND_URL` (frontend) | `http://localhost:8000` | Target of the Next.js `/api/*` rewrite |
| `GRAFANA_ADMIN_PASSWORD` | `sentinelforge` | Grafana admin password (observability profile) |

## Usage

### UI walkthrough

1. **Incident feed** (`/dashboard`). Summary stats, then every incident with severity,
   status, correlated-alert count and age. Search by service, message or ID; filter by
   severity or status ("Needs approval" shows the queue). Paste an alert into
   **Submit an alert** (or click **Use example**) and watch the live event log.
2. **Incident war room** (`/incidents/{id}`). The containment plan sits at the top:
   approve, reject or escalate each step, optionally with a rationale that goes into the
   audit log. Below it: ATT&CK techniques, the reasoning trace (with an LLM), the agent
   timeline with expandable tool results, and the investigation finding. The sidebar
   has incident details, the agent team, correlated alerts, **Threat hunt**,
   **Sigma detection rule**, triage feedback and STIX export.
3. **Analytics** (`/analytics`). Noise reduction, MTTR, verdict and service breakdowns,
   top ATT&CK techniques, LLM token usage, and a downloadable Navigator layer.
4. **Security** (`/security`). Guardrail posture and recent security events.

[DEMO.md](DEMO.md) is a scripted three-minute walkthrough.

### Seed demo scenarios

```bash
python3 demo/seed_alerts.py --scenario ransomware        # P1, triggers the two-person rule
python3 demo/seed_alerts.py --all                        # every scenario in sequence
python3 demo/seed_alerts.py --storm 25                   # correlation demo
python3 demo/seed_alerts.py --scenario injection_attempt # blocked by PromptGuard
```

Scenarios: `brute_force`, `c2_beacon`, `phishing_email`, `suspicious_powershell`,
`data_exfil`, `ransomware`, `siem_wazuh`, `ambiguous_text`, `injection_attempt`. Use
`--backend URL` for a remote API, and `--token` / `SENTINELFORGE_TOKEN` (plus
`SENTINELFORGE_SECRET` for HMAC signing) when auth is enforced.

### Ingest an alert over the API

```bash
curl -X POST localhost:8000/api/v1/ingest/text \
  -H 'Content-Type: application/json' \
  -d '{"text":"EDR alert: suspicious rundll32.exe spawning from winword.exe on host fin-ws-12, user m.lee"}'
```

```json
{"accepted": true, "incident_id": "3441c319-a7e9-4823-b234-f59eb4652ebe", "signal_id": "2d5daef9-8f94-4286-bbd7-73a154fbc8da"}
```

A related alert is folded instead:

```json
{"accepted": true, "correlated_into": "5bb8ff21-62ba-4340-b7c5-d4f811474533", "reason": "shared source IP 198.51.100.7", "alert_count": 2, "signal_id": "80245111-b084-4ab9-a3c6-43b5d2c55789"}
```

And an injection attempt is refused:

```json
{"accepted": false, "reason": "prompt_injection_blocked", "threat": "Injection pattern detected: 'ignore (previous|above|all) instructions'"}
```

Signed webhooks (`/ingest/siem`, `/edr`, `/ids`, `/webhook`) take the raw vendor JSON
with `X-SentinelForge-Signature: sha256=<hex hmac-sha256(SECRET_KEY, body)>`:

```bash
BODY='{"rule":{"description":"sshd: brute force"},"agent":{"name":"bastion-01"},"data":{"srcip":"203.0.113.9"}}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET_KEY" -hex | cut -d' ' -f2)
curl -X POST localhost:8000/api/v1/ingest/siem -H 'Content-Type: application/json' \
  -H "X-SentinelForge-Signature: sha256=$SIG" -d "$BODY"
```

### Sign in and call protected endpoints

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@sentinelforge.local","password":"changeme-admin"}' | jq -r .token)

curl -s localhost:8000/api/v1/analytics/summary -H "Authorization: Bearer $TOKEN"
```

```json
{"total": 8, "resolved": 2, "escalated": 0, "dismissed": 0, "total_alerts_ingested": 36, "alerts_folded": 28, "noise_reduction_pct": 77.8}
```

### Create operators and try the two-person rule

```bash
for u in alice bob; do
  curl -s -X POST localhost:8000/api/v1/auth/operators \
    -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" \
    -d "{\"email\":\"$u@example.test\",\"password\":\"change-me-$u\",\"role\":\"approver\",\"display_name\":\"$u\"}"
done
```

Fire `--scenario ransomware`, sign in as alice, approve the high-risk step: the card
comes back labelled **Second approver needed**. Approving again as alice is refused
(`409 already approved by you`); sign in as bob and approve to execute it.

### Approve, verify the audit chain, export

```bash
curl -s localhost:8000/api/v1/approvals/pending -H "Authorization: Bearer $TOKEN"
curl -s -X POST localhost:8000/api/v1/approvals/$STEP_ID/approve \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" \
  -d '{"rationale":"IP confirmed malicious by two feeds"}'
# → {"step_id": "…", "status": "APPROVED"}

curl -s localhost:8000/api/v1/security/audit/verify -H "Authorization: Bearer $TOKEN"
# → {"entries": 108, "intact": true, "broken_at_seq": null}

curl -s localhost:8000/api/v1/incidents/$ID/export/stix -H "Authorization: Bearer $TOKEN" > incident.stix.json
curl -s -X POST localhost:8000/api/v1/hunt -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" -d '{"technique_id":"T1110"}'
```

### Watch live events

```bash
curl -N "localhost:8000/api/v1/incidents/stream/all?access_token=$TOKEN"
```

Each stream opens with an SSE comment (`: connected`), then sends one unnamed `data:`
message per event with the kind in the JSON `type` field (`incident.created`,
`triage.complete`, `agent.message`, `tool.called`, `approval.required`, …).

## API reference

Interactive docs with request/response schemas are at `/docs` (Swagger UI) and
`/redoc`. "Read" means any signed-in role (`viewer`, `analyst`, `approver`, `admin`);
`admin` passes every role check. In development with `AUTH_DEV_BYPASS=true`, requests
without a token act as admin.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/health`, `/health/live`, `/health/ready` | Public | Health, liveness and readiness (DB + Redis) |
| POST | `/api/v1/auth/login` | Public | Exchange email + password for a JWT (8 h) |
| GET | `/api/v1/auth/me` | Read | The current operator |
| POST | `/api/v1/auth/operators` | admin | Create an operator with a role |
| POST | `/api/v1/ingest/webhook` | HMAC | Generic webhook receiver |
| POST | `/api/v1/ingest/siem` | HMAC | SIEM alerts (Wazuh / Splunk / Elastic) |
| POST | `/api/v1/ingest/edr` | HMAC | EDR alerts (CrowdStrike / SentinelOne / Defender) |
| POST | `/api/v1/ingest/ids` | HMAC | IDS alerts (Suricata / Zeek / Snort) |
| POST | `/api/v1/ingest/text` | analyst | Plain-text or pasted alert |
| POST | `/api/v1/ingest/email` | analyst | Phishing report / forwarded email |
| GET | `/api/v1/incidents` | Read | List incidents (`status`, `severity`, `service`, `limit`, `offset`) |
| GET | `/api/v1/incidents/pending` | Read | Incidents awaiting approval |
| GET | `/api/v1/incidents/{id}` | Read | Incident with triage result, finding, plan and report |
| GET | `/api/v1/incidents/{id}/timeline` | Read | Audit timeline for the incident |
| GET | `/api/v1/incidents/{id}/thinking` | Read | Archived reasoning trace |
| GET | `/api/v1/incidents/{id}/pir` | Read | Post-incident report |
| GET | `/api/v1/incidents/{id}/steps` | Read | Containment steps and their status |
| GET | `/api/v1/incidents/{id}/events` | Read | Recent dashboard events (newest first) |
| POST | `/api/v1/incidents/{id}/hunt` | analyst | Threat-hunt hypotheses from the incident |
| POST | `/api/v1/incidents/{id}/detection-rule` | analyst | Generate and save a Sigma rule |
| GET | `/api/v1/incidents/{id}/export/stix` | Read | STIX 2.1 bundle |
| POST | `/api/v1/incidents/{id}/feedback` | analyst | Record the human verdict for the triage |
| GET | `/api/v1/incidents/stream/all` | Read (SSE) | Live events for all incidents |
| GET | `/api/v1/incidents/{id}/stream` | Read (SSE) | Replay + live events for one incident (`Last-Event-ID` aware) |
| GET | `/api/v1/incidents/{id}/events/recent` | Read | Same as `/events`, for SSE clients |
| GET | `/api/v1/approvals/pending` | Read | Steps awaiting approval |
| POST | `/api/v1/approvals/{step_id}/approve` | approver | Approve (records the second approver when required) |
| POST | `/api/v1/approvals/{step_id}/second-approve` | approver | Explicit second approval |
| POST | `/api/v1/approvals/{step_id}/reject` | approver | Reject a step |
| POST | `/api/v1/approvals/{step_id}/escalate` | approver | Escalate a step |
| GET | `/api/v1/analytics/summary` | Read | Totals and noise reduction |
| GET | `/api/v1/analytics/mttr` | Read | Mean time to resolve |
| GET | `/api/v1/analytics/by-service`, `/by-verdict`, `/by-severity` | Read | Breakdowns |
| GET | `/api/v1/analytics/top-techniques` | Read | Most frequent ATT&CK techniques |
| GET | `/api/v1/analytics/correlation` | Read | Alert-fatigue reduction details |
| GET | `/api/v1/analytics/token-usage` | Read | LLM token usage per model |
| GET | `/api/v1/analytics/feedback` | Read | Analyst feedback vs. model verdicts |
| GET | `/api/v1/analytics/navigator-layer` | Read | ATT&CK Navigator layer JSON |
| GET | `/api/v1/analytics/purple` | Read | Latest purple-team results |
| POST | `/api/v1/hunt` | analyst | Hunt from a technique or free text |
| GET | `/api/v1/security/events` | Read | Security events (blocked injections, approvals, …) |
| GET | `/api/v1/security/controls` | Read | Self-reported security posture |
| GET | `/api/v1/security/audit/verify` | Read | Verify the audit hash chain |
| GET | `/metrics` | Public | Prometheus metrics (restrict at the network layer) |

Errors use FastAPI's `{"detail": "…"}` shape: `401` (missing or invalid token), `403`
(role not allowed), `404` (unknown or malformed ID), `409` (step not awaiting approval,
or same approver twice), `410` (another approver acted first).

## Scripts and commands

| Command | What it does |
|---------|--------------|
| `./demo.sh` / `make demo` | Build and start the stack, wait for health, seed a storm + brute-force incident |
| `make up` | `docker compose up -d --build --wait` |
| `make dev` | Stack with hot reload (`docker-compose.dev.yml`) |
| `make down` | Stop the stack (`make down ARGS=-v` also wipes volumes) |
| `make logs` | Tail backend and worker logs |
| `make seed` / `make storm` | Seed the brute-force incident / a 30-alert storm |
| `make install` | Create `backend/.venv` with dev deps and `npm ci` the frontend |
| `make test` | Backend unit tests |
| `make lint` | Ruff check + format check, and ESLint |
| `make format` | Auto-format the backend |
| `make eval` | Triage quality gate |
| `make frontend-check` | Frontend typecheck + production build |
| `make check` | lint + test + eval + frontend-check |
| `npm run dev` / `build` / `start` | Frontend dev server / production build / start (in `frontend/`) |
| `npm run lint` / `typecheck` | ESLint / `tsc --noEmit` (in `frontend/`) |
| `python -m app.purple` | Purple-team scorecard against a running stack (in `backend/`) |
| `python -m app.eval.harness [--llm]` | Score triage against the labelled corpus (in `backend/`) |
| `demo/simulate_incident.sh [scenario]` | Shell-only alternative to the seeder |

## Testing and quality

```bash
cd backend
pytest -q                          # 160 tests; no database or Redis needed
ruff check . && ruff format --check .
python -m app.eval.harness         # exits non-zero if triage quality regresses

cd ../frontend
npm run lint && npm run typecheck && npm run build
```

What the backend suite covers:

- **Guardrails and executor** (`test_actions.py`): protected targets, rate limits, kill
  switch, dry-run, two-person rule, and that a DENY can't be overridden.
- **API security** (`test_api_security.py`): RBAC per route, tampered/expired tokens,
  dev-bypass scoping, production config validation, CORS, the two-person approval flow,
  SSE stream format and immediate flush, Sigma path sanitisation, 404 for malformed IDs.
- **Auth, audit chain, Cloudflare adapter, Sigma, STIX, metrics, purple scoring,
  feedback export, eval harness** and pure helpers (correlation, parsing, routing).

The frontend has no unit tests; it is checked by ESLint (`next/core-web-vitals` +
`next/typescript`), strict TypeScript and the production build. The UI was verified by
scripted Playwright runs against the full local stack: sign-in validation and errors,
alert submission and validation, search/filter empty states, live event stream,
threat hunt, Sigma, feedback, single and two-person approvals, the not-found states,
keyboard skip link, and no horizontal overflow at 390, 768 and 1440 px.

A GitHub Actions workflow (`.github/workflows/ci.yml`) is included that runs the backend
lint, format check, tests and eval gate, the frontend lint, typecheck and build, and
validates both compose files.

## Deployment

The repository ships Dockerfiles for the API/worker (`backend/`), the frontend
(`frontend/`, Next.js standalone output) and the MCP server, plus a compose file that
wires them together. A production rollout looks like:

1. **Build images.** `docker compose build`, or build each Dockerfile. The frontend
   takes `NEXT_PUBLIC_API_URL` as a build argument because it is inlined into the client
   bundle; set it to your public API URL (or leave it empty and serve the UI and API
   from the same origin so the `/api` rewrite is used).
2. **Provision Postgres 16 and Redis 7** (managed services are fine) and set
   `DATABASE_URL` / `REDIS_URL`.
3. **Set secrets.** `ENVIRONMENT=production`, a random `SECRET_KEY`
   (`python -c "import secrets; print(secrets.token_urlsafe(48))"`), a strong
   `DEFAULT_ADMIN_PASSWORD`, and `FRONTEND_URL` / `CORS_ORIGINS` for your domain. The
   API refuses to start if the secret or admin password is still a placeholder.
4. **Migrate and run.** `alembic upgrade head`, then the API
   (`uvicorn app.main:app --host 0.0.0.0 --port 8000`), at least one worker
   (`python -m app.pipeline.orchestrator`) and the frontend (`node server.js` in the
   standalone image).
5. **Point sources at the webhooks** (`/api/v1/ingest/{siem,edr,ids,webhook}`) with HMAC
   signatures, and create operators with the right roles.
6. **Keep `ACTION_DRY_RUN_ONLY=true`** until each adapter has been validated against
   your environment; populate the `ACTION_PROTECTED_*` lists first.

Operational notes:

- The SSE endpoints accept the JWT as `?access_token=` because browser `EventSource`
  cannot send headers. Keep access logs private; tokens expire after 8 hours.
- If a reverse proxy sits in front of the API, disable response buffering for
  `/api/v1/*/stream` (the API already sends `X-Accel-Buffering: no`).
- `/metrics` is unauthenticated for Prometheus; restrict it at the network layer.

## Troubleshooting and FAQ

**The dashboard says "Cannot reach the SentinelForge API".**
The backend isn't reachable from the browser. Check `curl localhost:8000/api/v1/health`.
With `npm run dev`, requests go through the Next.js proxy to `BACKEND_URL`; with the
Docker image they go to `NEXT_PUBLIC_API_URL` (baked in at build time, so rebuild the
frontend after changing it).

**The live indicator stays "Offline".**
The browser can't hold the SSE connection. Check that the stream answers:
`curl -N localhost:8000/api/v1/incidents/stream/all` should print `: connected`
immediately. Behind nginx or another proxy, turn off buffering for stream paths. With
auth enforced, make sure you are signed in.

**Everything returns 401 / "Sign-in required".**
You're running with `ENVIRONMENT` other than development (or `AUTH_DEV_BYPASS=false`).
Sign in at `/login` or pass `Authorization: Bearer <token>`.

**The API refuses to start with a message about `SECRET_KEY` or the admin password.**
That's the production safety check. Set a real `SECRET_KEY` (32+ chars) and
`DEFAULT_ADMIN_PASSWORD`, or use `ENVIRONMENT=development` locally.

**Webhooks return 401.**
With a real `SECRET_KEY`, webhook bodies must be signed (see
[Ingest an alert](#ingest-an-alert-over-the-api)). Sign the exact bytes you send.

**My alert didn't create a new incident.**
It was probably correlated into an open incident that shares an IP, host, user or
fingerprint; the response includes `correlated_into` and the reason. Lower
`CORRELATION_WINDOW_SECONDS` or set `CORRELATION_ENABLED=false` to change that.

**Steps approved themselves.**
Low-risk steps auto-approve after `AUTO_APPROVE_TIMEOUT_P2/P3/P4` minutes. P1 steps
never do. The audit log records these as `system:hitl_timeout(...)`.

**Nothing was actually blocked after I approved.**
`ACTION_DRY_RUN_ONLY=true` is the default, and only the Cloudflare adapter performs real
changes (with `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ZONE_ID`).

**Triage looks simplistic / the report says "Mock streaming response".**
No `LLM_API_KEY` is set, so heuristics and mock responses are used. Add a key for live
reasoning, reports and token analytics.

**`alembic upgrade head` can't connect.**
`DATABASE_URL` defaults to the compose hostname `postgres`. Export a localhost URL for
local runs.

**Is there a light theme?**
No. The war room is dark-only by design (it's built for long sessions on wall screens),
and every text colour is checked against WCAG AA on the dark surfaces.

## Known limitations

- Without an LLM key, triage and planning use heuristics, the report body is a
  placeholder, and the purple-team scorecard is low.
- Investigation tools other than VirusTotal, AbuseIPDB, Elasticsearch, Prometheus and
  Slack are mocks, as is the ticketing side of the bundled MCP server.
- Cloudflare IP Access Rules is the only adapter that performs a real mutation.
- `/api/v1/auth/login` has no rate limiting or lockout yet.
- SSE authentication uses the JWT in the query string rather than short-lived stream
  tickets.
- An incident can be marked resolved while a low-risk notification step still awaits
  approval.
- The frontend has no automated unit or end-to-end test suite in the repository.
- The Docker images were not rebuilt as part of the latest changes in this branch; the
  services were verified by running them natively.

## Roadmap ideas

- Login rate limiting, account lockout and SSO (OIDC).
- Short-lived stream tickets instead of `?access_token=`.
- More real containment adapters (EDR host isolation, IdP account suspension).
- Playwright end-to-end tests for the main UI flows in CI.
- Per-tenant guardrail policies and approval routing (e.g. on-call schedules).
- A case-management view: notes, assignees and SLA timers per incident.

## Contributing

1. Fork and create a branch from `main`.
2. `make install`, then make your change with tests where it makes sense.
3. Run `make check` (backend lint, tests, eval gate, frontend typecheck and build) and
   `npm run lint` in `frontend/`.
4. Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
   `docs:` …) and open a pull request describing what changed and how you verified it.

Please don't commit secrets: `.env` is git-ignored, and `.env.example` must only contain
placeholders. Report security issues privately to the maintainer rather than in a
public issue.

## License

No license file is included yet, which means all rights are reserved by default. If you
intend others to use or contribute to the project, add one deliberately; MIT or
Apache-2.0 are common choices for a project like this.
