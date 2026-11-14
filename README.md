# SentinelForge — Autonomous SOC War Room

> A security-operations backend and dashboard that folds alert storms into single
> incidents, has a team of LLM agents triage, investigate and plan containment, and
> keeps a human approver in front of every action that changes production.

SentinelForge ingests findings from SIEM / EDR / IDS webhooks, phishing reports or
pasted text, deduplicates them with a deterministic correlation engine, and runs each
genuinely new incident through a five-stage agent pipeline on Redis Streams. Every
containment action passes a deterministic guardrail layer — the model proposes, the
policy decides — and every agent and human action lands in a hash-chained audit log.

It runs end to end **with no API keys**: without an LLM key every model call falls back
to deterministic heuristics, and external tools return realistic mocks. Add any
OpenAI-compatible endpoint (Groq by default) for live reasoning.

```mermaid
flowchart LR
    SRC[SIEM / EDR / IDS / email / paste] --> GUARD[HMAC + prompt-injection guard]
    GUARD --> CORR{Correlation engine}
    CORR -->|fold into open incident| INC[(Incident)]
    CORR -->|new| INC
    INC -->|Redis Streams| AGENTS

    subgraph AGENTS[Agent pipeline]
        T[Triage · CMDR] --> I[Investigate · ANLST] --> R[Plan · STRAT]
        R --> HITL{HITL gate}
        HITL --> E[Execute · OPS] --> P[Report · CHRON]
    end

    E --> G{Guardrails}
    G -->|DENY — final| AUDIT[(Hash-chained audit log)]
    G -->|allow| A[Dry-run → execute → verify → rollback]
    A --> AUDIT
    AGENTS -.->|SSE| UI[Next.js dashboard]
```

## Features

- **Alert correlation & dedup** — fingerprint + entity-overlap matching (IP, host, user)
  inside a configurable window folds storms and cross-tool duplicates into one incident.
  Pure functions, no model call. `python demo/seed_alerts.py --storm 30` turns 30 alerts
  into one incident.
- **Five-agent pipeline** — triage (verdict, severity, MITRE ATT&CK mapping, streamed
  reasoning), investigation (a small, read-only toolset chosen per incident), containment
  planning, execution with rollback, and a post-incident report filed through a bundled
  MCP server.
- **Deterministic action safety** — every mutating action goes
  `propose → guardrails → dry-run → execute → verify → rollback`. Protected targets
  (RFC1918, break-glass/service accounts, domain controllers, plus your own lists),
  blast-radius and rate limits, a kill switch, change freezes, dry-run by default, and a
  **two-person rule** for critical actions. A DENY cannot be overridden by any approval or
  model output; 24 guardrail tests encode this.
- **One real containment adapter** — Cloudflare IP Access Rules: execute creates a block
  rule, verify reads it back, rollback deletes it. Env-gated, mock fallback otherwise.
- **RBAC + signed approvals** — JWT login with `viewer` / `analyst` / `approver` / `admin`
  roles enforced on every operator API. Approver identity comes from the verified token,
  never from the request body.
- **Detection-as-code** — generate a Sigma rule from an incident's IOCs and techniques
  (`POST /api/v1/incidents/{id}/detection-rule`).
- **STIX 2.1 + ATT&CK Navigator export** — `GET /api/v1/incidents/{id}/export/stix`,
  `GET /api/v1/analytics/navigator-layer`.
- **Threat-hunt generator** — from a technique or free text, hunt hypotheses with
  Splunk SPL / Elastic EQL / KQL / Sigma queries.
- **Triage quality gate** — an offline harness scores triage against a labeled corpus and
  fails CI on regression. The deterministic baseline scores **0.94 verdict accuracy and
  1.00 false-positive suppression on the bundled 17-case corpus**; `--llm` scores a live
  model.
- **Analyst feedback loop** — verdict corrections become labeled eval data
  (`app/eval/feedback_export.py`).
- **Purple-team self-assessment** — `python -m app.purple` replays scripted multi-stage
  attack chains through the real ingestion path and prints a detection scorecard.
- **Tamper-evident audit** — hash-chained entries; `GET /api/v1/security/audit/verify`
  detects any edit, deletion or reorder.
- **Observability** — Prometheus `/metrics` (stage latency, alert/fold counters, action
  outcomes, LLM tokens, approval queue) and a provisioned Grafana dashboard.

## Tech stack

| Layer | Technology |
|-------|------------|
| API & workers | Python 3.12, FastAPI, asyncpg (raw SQL), Alembic, Pydantic v2 |
| Messaging | Redis 7 — Streams (pipeline stages + DLQ) and pub/sub (live events) |
| Storage | PostgreSQL 16; optional ChromaDB + sentence-transformers for runbook search |
| LLM | Any OpenAI-compatible endpoint (Groq Llama 3.3 70B / 3.1 8B by default) |
| Frontend | Next.js 15 (App Router), React 19, Tailwind CSS, Server-Sent Events |
| Tooling | Ruff, pytest, ESLint, TypeScript, Docker Compose, GitHub Actions |

## Architecture

| Component | Path | Role |
|-----------|------|------|
| API server | `backend/app/main.py` | REST + SSE, auth, ingestion, approvals |
| Pipeline worker | `backend/app/pipeline/orchestrator.py` | Consumes Redis Streams and runs the agents |
| Agents | `backend/app/agents/` | Triage, investigation, remediation, execution, PIR |
| Correlation | `backend/app/pipeline/correlation.py` | Deterministic dedup |
| Action safety | `backend/app/actions/` | Guardrail policy, executor, adapters |
| MCP server | `mcp_server/` | Runbook search + stub ticketing over MCP-SSE |
| Dashboard | `frontend/` | War room, incident view, analytics, security controls |

Each stage publishes events to `incident:{id}:events` (streamed to the browser over SSE)
and to a bounded per-incident log used to replay missed events on reconnect. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the full design.

## Quick start (Docker)

Requirements: Docker with Compose v2, and Python 3 with `requests` for the demo seeder.

```bash
cp .env.example .env           # works as-is; add LLM_API_KEY for live models
docker compose up -d --build --wait
open http://localhost:3000     # dashboard
open http://localhost:8000/docs  # OpenAPI docs

python3 -m pip install requests
python3 demo/seed_alerts.py --storm 30              # 30 alerts → 1 incident
python3 demo/seed_alerts.py --scenario brute_force  # full triage → contain run
```

Or run `./demo.sh` (equivalently `make demo`) to do all of the above. The stack runs
Postgres, Redis, a mock Elasticsearch, the MCP server, the API, the pipeline worker and
the frontend. Add Prometheus (`:9090`) and Grafana (`:3001`) with
`docker compose --profile observability up -d`.

In development mode the API accepts unauthenticated requests as an anonymous admin, so
the demo needs no login. To exercise real auth, sign in at `/login` as
`admin@sentinelforge.local` with `DEFAULT_ADMIN_PASSWORD`, then create operators:

```bash
curl -X POST localhost:8000/api/v1/auth/operators -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"email":"alice@corp.test","password":"…","role":"approver"}'
```

See [DEMO.md](DEMO.md) for a guided three-minute walk-through.

## Local development (without Docker)

You need Python 3.12, Node 20+, PostgreSQL 16 and Redis 7 running locally.

```bash
# Backend
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"            # add ",rag" for semantic runbook search (pulls torch)
export DATABASE_URL=postgresql://sentinelforge:sentinelforge@localhost:5432/sentinelforge
export REDIS_URL=redis://localhost:6379/0 RUNBOOKS_DIR=../runbooks
alembic upgrade head
uvicorn app.main:app --reload --port 8000      # API
python -m app.pipeline.orchestrator            # pipeline worker (second terminal)

# Frontend
cd frontend
npm ci
NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
```

`docker compose -f docker-compose.yml -f docker-compose.dev.yml up` gives the same hot
reload inside containers.

## Testing, linting and building

```bash
make check          # everything CI runs, or individually:

cd backend
pytest -q                      # 158 unit/API tests — no database or Redis needed
ruff check . && ruff format --check .
python -m app.eval.harness     # triage quality gate (exits non-zero on regression)
python -m app.purple           # purple-team scorecard (needs a running stack)

cd frontend
npm run lint && npm run typecheck && npm run build
```

CI (`.github/workflows/ci.yml`) runs backend lint, format check, tests and the eval gate,
the frontend lint, typecheck and production build, and validates both compose files.

## Configuration

All settings are environment variables (see [`.env.example`](.env.example) for the full,
commented list). The backend reads `.env` from its working directory; Docker Compose
reads the root `.env` and forwards the variables below.

| Variable | Default | Purpose |
|----------|---------|---------|
| `ENVIRONMENT` | `development` | Anything other than `development` enables production checks |
| `SECRET_KEY` | placeholder | Signs JWTs and webhook HMACs. **Required** (≥ 32 chars) outside development |
| `DEFAULT_ADMIN_PASSWORD` | `changeme-admin` | First-run admin password. Must be changed outside development |
| `AUTH_DEV_BYPASS` | `true` | Anonymous admin access — honoured only in development |
| `FRONTEND_URL` / `CORS_ORIGINS` | `http://localhost:3000` / empty | Allowed browser origins |
| `DATABASE_URL` / `REDIS_URL` | compose service URLs | Postgres and Redis |
| `LLM_API_KEY` | empty | OpenAI-compatible API key; blank = deterministic mocks |
| `LLM_BASE_URL` | Groq | Any OpenAI-compatible endpoint (Together, vLLM, Ollama, …) |
| `LLM_MODEL_SMART` / `LLM_MODEL_FAST` | Llama 3.3 70B / 3.1 8B | Model tiers |
| `LLM_MODEL_REASONING` | empty | Optional dedicated model for P1/P2 triage |
| `USE_MOCK_TOOLS` | `true` | Mock external tools when keys are absent |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `SLACK_BOT_TOKEN`, `SLACK_CHANNEL_ID` | empty | Optional real enrichments / notifications |
| `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONE_ID` | empty | Enables the real Cloudflare containment adapter |
| `ACTION_DRY_RUN_ONLY` | `true` | Simulate every mutating action |
| `ACTION_KILL_SWITCH` | `false` | Stop all mutating actions |
| `ACTION_PROTECTED_IP_CIDRS` / `_USERS` / `_HOSTS` | empty | Extra never-touch targets (added to built-ins) |
| `ACTION_TWO_PERSON_SEVERITIES` | `P1_CRITICAL` | Severities needing two distinct approvers |
| `CORRELATION_WINDOW_SECONDS` | `1800` | How long an open incident absorbs related alerts |
| `AUTO_APPROVE_TIMEOUT_P2/P3/P4` | `2` / `15` / `5` | Minutes before low-risk steps auto-approve |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | API URL baked into the frontend build |

## Deployment

1. Build the images: `docker compose build` (or build `backend/` and `frontend/`
   individually; the frontend takes `NEXT_PUBLIC_API_URL` as a build argument because it
   is inlined into the client bundle).
2. Provide managed Postgres and Redis and set `DATABASE_URL` / `REDIS_URL`.
3. Set `ENVIRONMENT=production`, a random `SECRET_KEY`
   (`python -c "import secrets; print(secrets.token_urlsafe(48))"`), a strong
   `DEFAULT_ADMIN_PASSWORD`, and `FRONTEND_URL` / `CORS_ORIGINS` for your domain. The API
   refuses to start if the secret or admin password is still a placeholder.
4. Run `alembic upgrade head`, then the API (`uvicorn app.main:app`) and at least one
   worker (`python -m app.pipeline.orchestrator`).
5. Point webhook sources at `/api/v1/ingest/{siem,edr,ids,webhook}` and have them sign
   bodies with `X-SentinelForge-Signature: sha256=<hmac-sha256(SECRET_KEY, body)>`.
6. Keep `ACTION_DRY_RUN_ONLY=true` until each adapter is validated against your
   environment.

Operational notes: the SSE endpoints accept the JWT as `?access_token=` because browsers'
`EventSource` cannot send headers, so keep access logs private (tokens expire after 8
hours). `/metrics` is unauthenticated for Prometheus scraping — restrict it at the
network layer.

## Project structure

```
.
├── backend/
│   ├── app/
│   │   ├── actions/      # guardrail policy, executor, Cloudflare + mock adapters
│   │   ├── agents/       # triage, investigation, remediation, execution, PIR
│   │   ├── api/          # FastAPI routers (ingest, incidents, approvals, auth, stream, …)
│   │   ├── db/           # asyncpg pool, incident repository, hash-chained audit log
│   │   ├── eval/         # labeled corpus + triage quality gate
│   │   ├── pipeline/     # orchestrator, correlation, HITL gate, tool selection, routing
│   │   ├── purple/       # attack-chain replay + scorecard
│   │   ├── schemas/      # Pydantic models and event types
│   │   ├── services/     # LLM client, auth, ingestion, Sigma, STIX, hunts, metrics
│   │   └── tools/        # investigation tools (real API or mock)
│   ├── alembic/          # database migrations
│   └── tests/            # pytest suite
├── frontend/
│   ├── app/              # Next.js routes: dashboard, incidents/[id], analytics, security, login
│   ├── components/       # shared UI
│   └── lib/              # typed API client and SSE hooks
├── mcp_server/           # MCP-SSE server (runbook search, ticket stub)
├── runbooks/             # markdown runbooks used by investigation
├── observability/        # Prometheus config + Grafana provisioning
├── demo/                 # alert seeder and demo scripts
├── docker-compose.yml    # full stack (docker-compose.dev.yml adds hot reload)
└── .github/workflows/    # CI
```

## Limitations

- Without an LLM key, triage and planning use heuristics; the purple-team scorecard is
  correspondingly low in that mode.
- Investigation tools other than VirusTotal, AbuseIPDB, Elasticsearch, Prometheus and
  Slack are mocks, as is the ticketing side of the MCP server.
- Cloudflare IP Access Rules is the only adapter that performs a real mutation.
