from __future__ import annotations

import asyncio
import json
import logging

import httpx

from app.purple.chains import AttackChain

logger = logging.getLogger("sentinelforge.purple")

_TIMEOUT = 90.0
_POLL_INTERVAL = 5.0


async def run_chain(chain: AttackChain, base_url: str = "http://localhost:8000") -> dict:
    """Run a single attack chain against a running SentinelForge stack."""
    print(f"\n{'='*60}")
    print(f"  Chain: {chain.name} — {chain.description}")
    print(f"{'='*60}")

    async with httpx.AsyncClient(timeout=30.0) as client:
        incident_ids = []
        correlated_into = None

        for step in chain.steps:
            print(f"\n  ▶ Step: {step.name} ({step.expected_technique})")
            print(f"    POST {base_url}/api/v1/ingest/text")

            resp = await client.post(
                f"{base_url}/api/v1/ingest/text",
                json={"text": step.raw_text},
            )
            try:
                data = resp.json()
            except Exception:
                data = {"status": resp.status_code}

            print(f"    Response: {json.dumps(data, default=str)[:200]}")

            if data.get("correlated_into"):
                cid = data["correlated_into"]
                correlated_into = cid
                print(f"    → folded into {cid[:12]}...")
            elif data.get("incident_id"):
                iid = data["incident_id"]
                incident_ids.append(iid)
                print(f"    → NEW incident {iid[:12]}...")
            else:
                print(f"    → unexpected: {data}")

            if step.delay_seconds > 0:
                await asyncio.sleep(step.delay_seconds)

        # Determine the primary incident ID.
        primary_id = correlated_into or (incident_ids[0] if incident_ids else None)
        if not primary_id:
            return {"error": "no incident created", "incidents_created": 0}

        # Wait for triage to complete.
        print(f"\n  ⏳ Waiting for triage (polling every {_POLL_INTERVAL}s, timeout {_TIMEOUT}s)...")
        start = asyncio.get_event_loop().time()
        incident = None
        while (asyncio.get_event_loop().time() - start) < _TIMEOUT:
            resp = await client.get(f"{base_url}/api/v1/incidents/{primary_id}")
            if resp.status_code == 200:
                incident = resp.json()
                status = incident.get("status", "")
                if status not in ("INGESTED", "TRIAGING", "INVESTIGATING"):
                    break
            await asyncio.sleep(_POLL_INTERVAL)

        if not incident:
            return {"error": "incident not found after polling", "incidents_created": len(incident_ids)}

        # Collect results.
        triage = incident.get("triage_result") or {}
        if isinstance(triage, str):
            try:
                triage = json.loads(triage)
            except Exception:
                triage = {}

        techniques = triage.get("attack_techniques") or []
        if isinstance(techniques, str):
            try:
                techniques = json.loads(techniques)
            except Exception:
                techniques = []

        observed = {
            "incidents_created": len(incident_ids) + (1 if correlated_into else 0),
            "alerts_folded": len(chain.steps) - 1 if correlated_into else 0,
            "technique_ids": [t.get("technique_id", "") for t in techniques],
            "verdict": triage.get("verdict", ""),
            "time_to_triage_seconds": None,  # simplified — would need timestamps
        }

        print(f"\n  📊 Results for {chain.name}:")
        print(f"    Incidents created: {observed['incidents_created']}")
        print(f"    Alerts folded: {observed['alerts_folded']}")
        print(f"    Techniques: {observed['technique_ids']}")
        print(f"    Verdict: {observed['verdict']}")

        return observed
