#!/usr/bin/env bash
# One-command SentinelForge demo:
#   builds + starts the full stack (db, redis, mock-es, mcp, backend, worker,
#   frontend), waits until healthy, then seeds a correlation storm + the hero
#   brute-force incident. Re-runnable.
set -euo pipefail
cd "$(dirname "$0")"

# 0. Preconditions ----------------------------------------------------------
if ! docker info >/dev/null 2>&1; then
  echo "❌ Docker isn't running. Start Docker Desktop, then re-run:  ./demo.sh"
  exit 1
fi
[ -f .env ] || { echo "▶ creating .env from .env.example (add LLM_API_KEY for live models)"; cp .env.example .env; }

# 1. Build + start everything and wait for healthchecks ---------------------
echo "▶ Building + starting the stack (first run pulls images + builds — a few minutes)…"
docker compose up -d --build --wait

# 2. Give the pipeline worker a moment to attach to Redis streams -----------
echo "▶ Waiting for the pipeline worker to attach…"
sleep 4

# 3. Seed ------------------------------------------------------------------
echo "▶ Seeding an alert STORM (30 alerts → 1 incident: correlation/dedup demo)…"
python3 demo/seed_alerts.py --storm 30 || echo "  (seed skipped — need: python3 -m pip install requests)"

echo "▶ Seeding the hero BRUTE-FORCE incident (full triage→contain pipeline)…"
python3 demo/seed_alerts.py --scenario brute_force || true

# 4. Done ------------------------------------------------------------------
cat <<'EOF'

✅ Demo is up:
   Dashboard  →  http://localhost:3000
   Analytics  →  http://localhost:3000/analytics   (alert noise-reduction %)
   API docs   →  http://localhost:8000/docs

   Follow logs :  docker compose logs -f backend worker
   Stop        :  docker compose down        (add -v to also wipe data)
EOF
open http://localhost:3000 >/dev/null 2>&1 || true
