"""Realistic mock data generators for demo scenarios."""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone


def prometheus_alert(alertname: str, severity: str, service: str, description: str) -> dict:
    """Generate a realistic Prometheus Alertmanager webhook payload."""
    return {
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": alertname,
                    "severity": severity,
                    "service": service,
                    "instance": f"{service}-prod-01:9090",
                    "team": "platform",
                },
                "annotations": {
                    "summary": f"{alertname} on {service}",
                    "description": description,
                    "runbook_url": f"https://runbooks.internal/{service.lower()}/{alertname.lower()}",
                },
                "startsAt": datetime.now(timezone.utc).isoformat(),
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": f"http://prometheus:9090/graph?g0.expr={alertname}",
            }
        ],
        "groupLabels": {"alertname": alertname},
        "commonLabels": {"severity": severity, "service": service},
        "externalURL": "http://alertmanager:9093",
        "version": "4",
        "groupKey": f"{{alertname={alertname}}}",
    }


def grafana_alert(title: str, message: str, service: str) -> dict:
    """Generate a realistic Grafana alert webhook payload."""
    return {
        "title": title,
        "message": message,
        "state": "alerting",
        "ruleId": random.randint(100, 999),
        "ruleName": title,
        "evalMatches": [
            {"metric": f"{service}_errors_total", "value": random.randint(100, 5000), "tags": {"service": service}}
        ],
    }


def pagerduty_incident(summary: str, service: str, severity: str = "critical") -> dict:
    """Generate a realistic PagerDuty webhook payload."""
    return {
        "event": {
            "event_type": "trigger",
            "data": {
                "incident": {
                    "id": f"P{random.randint(10000, 99999)}",
                    "title": summary,
                    "service": {"name": service},
                    "urgency": "high" if severity == "critical" else "low",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            },
        }
    }
