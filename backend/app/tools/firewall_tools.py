"""Firewall rules check tool."""
from __future__ import annotations

from app.tools.registry import tool


@tool(
    name="check_firewall_rules",
    description="Check current firewall rules for a specific IP, port, or service. Use to verify network access or identify blocked traffic.",
    parameters={
        "type": "object",
        "properties": {
            "ip_address": {"type": "string", "description": "IP address to check rules for"},
            "port": {"type": "integer", "description": "Port number"},
            "direction": {"type": "string", "enum": ["inbound", "outbound", "both"], "default": "both"},
        },
        "required": [],
    },
)
async def check_firewall_rules(ip_address: str = "", port: int = 0, direction: str = "both") -> dict:
    return _mock_firewall(ip_address, port, direction)


def _mock_firewall(ip, port, direction):
    rules = [
        {"action": "ALLOW", "source": "10.0.0.0/8", "destination": "0.0.0.0/0", "port": "any", "protocol": "tcp", "description": "Internal network allow all"},
        {"action": "ALLOW", "source": "0.0.0.0/0", "destination": "0.0.0.0/0", "port": "443", "protocol": "tcp", "description": "HTTPS inbound"},
        {"action": "ALLOW", "source": "0.0.0.0/0", "destination": "0.0.0.0/0", "port": "80", "protocol": "tcp", "description": "HTTP inbound"},
        {"action": "DENY", "source": "0.0.0.0/0", "destination": "0.0.0.0/0", "port": "22", "protocol": "tcp", "description": "SSH blocked from external"},
        {"action": "ALLOW", "source": "10.0.0.0/8", "destination": "0.0.0.0/0", "port": "22", "protocol": "tcp", "description": "SSH allowed from internal"},
    ]
    if ip and not ip.startswith(("10.", "172.16.", "192.168.")):
        rules.append({
            "action": "DENY",
            "source": ip,
            "destination": "0.0.0.0/0",
            "port": "any",
            "protocol": "any",
            "description": f"Blocked IP: {ip} (threat intelligence match)",
        })
    return {"ip_filter": ip, "port_filter": port, "direction": direction, "rules": rules, "count": len(rules)}
