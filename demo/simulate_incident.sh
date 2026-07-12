#!/bin/bash
# SentinelForge — One-command SOC demo trigger
# Usage: ./demo/simulate_incident.sh [scenario]

set -e

BACKEND="${BACKEND_URL:-http://localhost:8000}"
SCENARIO="${1:-brute_force}"

echo "🛡️  SentinelForge — Autonomous SOC War Room"
echo "============================================"
echo ""
echo "Firing scenario: $SCENARIO"
echo "Backend: $BACKEND"
echo ""

# Check backend health
if ! curl -sf "$BACKEND/api/v1/health" > /dev/null 2>&1; then
    echo "❌ Backend not reachable at $BACKEND"
    echo "   Start with: docker-compose up -d"
    exit 1
fi

echo "✅ Backend healthy"
echo ""

python3 "$(dirname "$0")/seed_alerts.py" --scenario "$SCENARIO" --backend "$BACKEND"

echo ""
echo "🎯 Dashboard: http://localhost:3000"
echo "   Watch the SOC war room activate in real-time!"
