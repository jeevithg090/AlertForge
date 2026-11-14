from __future__ import annotations

import asyncio
import json
import logging
import os

import httpx

from app.purple.chains import AttackChain

logger = logging.getLogger("sentinelforge.purple")

_TIMEOUT = 90.0
_POLL_INTERVAL = 5.0


def summarize_ingestion(responses: list[dict]) -> dict:
    """Reduce per-alert ingestion responses to what the scorecard needs.

    ``incidents_created`` counts the distinct incidents the chain landed in
    (new ones plus any it folded into), so a perfectly correlated chain is 1.
    """
    new_ids = [r["incident_id"] for r in responses if r.get("incident_id")]
    folded_into = [r["correlated_into"] for r in responses if r.get("correlated_into")]
    primary = new_ids[0] if new_ids else (folded_into[0] if folded_into else None)
    return {
        "primary_id": primary,
        "incidents_created": len(set(new_ids) | set(folded_into)),
        "alerts_folded": len(folded_into),
    }


async def run_chain(chain: AttackChain, base_url: str = "http://localhost:8000") -> dict:
    """Run a single attack chain against a running SentinelForge stack."""
    print(f"\n{'=' * 60}")
    print(f"  Chain: {chain.name} — {chain.description}")
    print(f"{'=' * 60}")

    token = os.environ.get("SENTINELFORGE_TOKEN", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
        responses: list[dict] = []

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

            responses.append(data)
            if data.get("correlated_into"):
                print(f"    → folded into {data['correlated_into'][:12]}...")
            elif data.get("incident_id"):
                print(f"    → NEW incident {data['incident_id'][:12]}...")
            else:
                print(f"    → unexpected: {data}")

            if step.delay_seconds > 0:
                await asyncio.sleep(step.delay_seconds)

        summary = summarize_ingestion(responses)
        primary_id = summary["primary_id"]
        if not primary_id:
            return {"error": "no incident created", "incidents_created": 0}

        # Wait for triage to complete.
        print(
            f"\n  ⏳ Waiting for triage (polling every {_POLL_INTERVAL}s, timeout {_TIMEOUT}s)..."
        )
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
            return {
                "error": "incident not found after polling",
                "incidents_created": summary["incidents_created"],
            }

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
            "incidents_created": summary["incidents_created"],
            "alerts_folded": summary["alerts_folded"],
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
