from __future__ import annotations

from datetime import datetime, timezone

import httpx

from app.actions.base import ActionAdapter, BlastRadius, PlannedEffect
from app.actions.models import ActionRequest

_API_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareBlockIPAdapter(ActionAdapter):
    action_type = "block_ip"
    simulated = False

    def __init__(self, api_token: str, zone_id: str) -> None:
        self._api_token = api_token
        self._zone_id = zone_id
        self._client = httpx.AsyncClient(
            base_url=_API_BASE,
            headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
            timeout=15.0,
        )

    async def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._api_token}", "Content-Type": "application/json"}

    async def preflight(self, req: ActionRequest) -> BlastRadius:
        return BlastRadius(
            summary=f"Would create a Cloudflare block rule for {req.target} in zone {self._zone_id[:8]}...",
            entities=[req.target],
            reversible=True,
        )

    async def dry_run(self, req: ActionRequest) -> PlannedEffect:
        return PlannedEffect(
            summary=f"[DRY-RUN] would POST /zones/{{zone}}/firewall/access_rules/rules to block {req.target}",
            details={
                "action_type": req.action_type,
                "target": req.target,
                "zone_id": self._zone_id[:8] + "...",
                "method": "POST",
                "endpoint": f"/zones/{self._zone_id}/firewall/access_rules/rules",
                "simulated": True,
            },
        )

    async def execute(self, req: ActionRequest) -> dict:
        ip = req.target
        zone = self._zone_id
        headers = await self._headers()

        # Idempotency: check if a block rule already exists for this IP.
        read_url = f"{_API_BASE}/zones/{zone}/firewall/access_rules/rules"
        read_params = {"configuration.target": "ip", "configuration.value": ip, "mode": "block"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(read_url, params=read_params, headers=headers)
            if resp.status_code >= 400:
                return {
                    "success": False,
                    "error": f"Cloudflare read error: {resp.status_code}",
                    "target": ip,
                }
            data = resp.json()
            existing = data.get("result", [])
            if existing:
                rule = existing[0]
                return {
                    "rule_id": rule["id"],
                    "target": ip,
                    "already_existed": True,
                    "applied_at": datetime.now(timezone.utc).isoformat(),
                }

            # Create a new block rule.
            body = {
                "mode": "block",
                "configuration": {"target": "ip", "value": ip},
                "notes": req.reason or f"Blocked by SentinelForge — {req.incident_id[:8]}",
            }
            create_resp = await client.post(
                f"{_API_BASE}/zones/{zone}/firewall/access_rules/rules",
                json=body,
                headers=headers,
            )
            if create_resp.status_code >= 400:
                err_body = create_resp.text
                return {
                    "success": False,
                    "error": f"Cloudflare create error: {create_resp.status_code} {err_body}",
                    "target": ip,
                }
            result = create_resp.json()
            if not result.get("success"):
                errors = result.get("errors", [])
                return {"success": False, "error": str(errors), "target": ip}
            rule = result["result"]
            return {
                "rule_id": rule["id"],
                "target": ip,
                "already_existed": False,
                "applied_at": datetime.now(timezone.utc).isoformat(),
            }

    async def verify(self, req: ActionRequest, effect: dict) -> bool:
        ip = req.target
        zone = self._zone_id
        headers = await self._headers()
        params = {"configuration.target": "ip", "configuration.value": ip, "mode": "block"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{_API_BASE}/zones/{zone}/firewall/access_rules/rules",
                params=params,
                headers=headers,
            )
            if resp.status_code >= 400:
                return False
            data = resp.json()
            return bool(data.get("result"))

    async def rollback(self, req: ActionRequest, effect: dict) -> bool:
        zone = self._zone_id
        headers = await self._headers()
        rule_id = effect.get("rule_id") if effect else None

        async with httpx.AsyncClient(timeout=15.0) as client:
            if rule_id:
                resp = await client.delete(
                    f"{_API_BASE}/zones/{zone}/firewall/access_rules/rules/{rule_id}",
                    headers=headers,
                )
                if resp.status_code < 400:
                    data = resp.json()
                    return bool(data.get("success"))
                # If delete by ID fails (e.g. wrong rule_id), fall through to IP lookup.

            # Look up rule by IP if rule_id is missing or the direct delete failed.
            ip = req.target
            params = {"configuration.target": "ip", "configuration.value": ip, "mode": "block"}
            resp = await client.get(
                f"{_API_BASE}/zones/{zone}/firewall/access_rules/rules",
                params=params,
                headers=headers,
            )
            if resp.status_code >= 400:
                return False
            data = resp.json()
            rules = data.get("result", [])
            if not rules:
                return True  # already gone
            rule_id = rules[0]["id"]
            del_resp = await client.delete(
                f"{_API_BASE}/zones/{zone}/firewall/access_rules/rules/{rule_id}",
                headers=headers,
            )
            if del_resp.status_code >= 400:
                return False
            del_data = del_resp.json()
            return bool(del_data.get("success"))
