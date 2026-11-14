from __future__ import annotations

import json
import logging
import uuid
from datetime import date

import yaml

from app.services.llm import extract_json, llm

logger = logging.getLogger("sentinelforge.sigma")

SIGMA_TEMPLATES: dict[str, dict] = {
    "T1110": {
        "logsource": {"category": "authentication"},
        "detection": {
            "selection": {"event.outcome": "failure"},
            "filter_ips": {"source.ip": ["<IOC_IPS>"]},
            "condition": "selection and filter_ips | count() by source.ip > 20",
        },
    },
    "T1059": {
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "EventID": 4688,
                "CommandLine|contains": ["<IOC_COMMANDS>"],
            },
            "condition": "selection",
        },
    },
    "T1071": {
        "logsource": {"category": "proxy"},
        "detection": {
            "selection": {
                "destination.ip": ["<IOC_IPS>"],
                "destination.domain": ["<IOC_DOMAINS>"],
            },
            "condition": "selection",
        },
    },
    "T1486": {
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {
                "EventID": 4656,
                "file.extension": ["<IOC_EXTENSIONS>"],
            },
            "condition": "selection",
        },
    },
    "T1566": {
        "logsource": {"category": "email"},
        "detection": {
            "selection": {
                "source.ip": ["<IOC_IPS>"],
                "email.sender": ["<IOC_EMAILS>"],
            },
            "condition": "selection",
        },
    },
    "T1078": {
        "logsource": {"category": "authentication"},
        "detection": {
            "selection": {
                "event.outcome": "success",
                "source.ip": ["<IOC_IPS>"],
            },
            "condition": "selection | count() by target.user.name > 1",
        },
    },
    "T1190": {
        "logsource": {"category": "webserver"},
        "detection": {
            "selection": {
                "source.ip": ["<IOC_IPS>"],
                "response.status": [200, 403, 500],
            },
            "condition": "selection",
        },
    },
    "T1041": {
        "logsource": {"category": "network_connection"},
        "detection": {
            "selection": {
                "destination.ip": ["<IOC_IPS>"],
                "bytes_out|gte": 10000000,
            },
            "condition": "selection",
        },
    },
}

GENERIC_TEMPLATE: dict = {
    "logsource": {"category": "generic"},
    "detection": {
        "selection": {
            "source.ip": ["<IOC_IPS>"],
        },
        "condition": "selection",
    },
}

TACTIC_MAP: dict[str, str] = {
    "T1110": "credential_access",
    "T1059": "execution",
    "T1071": "command_and_control",
    "T1486": "impact",
    "T1566": "initial_access",
    "T1078": "defense_evasion",
    "T1190": "initial_access",
    "T1041": "exfiltration",
}

IOC_MARKERS: dict[str, str] = {
    "<IOC_IPS>": "ips",
    "<IOC_COMMANDS>": "commands",
    "<IOC_DOMAINS>": "domains",
    "<IOC_EXTENSIONS>": "extensions",
    "<IOC_EMAILS>": "emails",
}

REQUIRED_FIELDS = [
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
    "level",
]


def _normalize_technique_id(tid: str) -> str:
    return tid.split(".")[0]


def _ioc_values(iocs: list[dict], ioc_type: str) -> list[str]:
    return [
        i.get("value", "") for i in (iocs or []) if i.get("type") == ioc_type and i.get("value")
    ]


def _inject_iocs(template: dict, iocs: list[dict]) -> dict:
    import copy

    detection = copy.deepcopy(template.get("detection", {}))
    ips = _ioc_values(iocs, "ip")
    users = _ioc_values(iocs, "user")
    hosts = _ioc_values(iocs, "host")
    for _selection_key, selection_val in detection.items():
        if not isinstance(selection_val, dict):
            continue
        for field, placeholder in list(selection_val.items()):
            if isinstance(placeholder, list):
                resolved = []
                for item in placeholder:
                    if item == "<IOC_IPS>":
                        resolved.extend(ips)
                    elif item == "<IOC_COMMANDS>":
                        resolved.extend(["powershell", "cmd.exe", "wscript"])
                    elif item == "<IOC_DOMAINS>":
                        resolved.extend(hosts)
                    elif item == "<IOC_EXTENSIONS>":
                        resolved.extend([".encrypted", ".locked", ".crypt"])
                    elif item == "<IOC_EMAILS>":
                        resolved.extend(users)
                    else:
                        resolved.append(item)
                selection_val[field] = resolved if resolved else [""]
    return detection


def _select_template(technique_id: str) -> dict:
    base_id = _normalize_technique_id(technique_id)
    return SIGMA_TEMPLATES.get(base_id, {})


def build_sigma_rule(incident: dict) -> dict:
    triage = incident.get("triage_result") or {}
    if isinstance(triage, str):
        triage = json.loads(triage)
    finding = incident.get("investigation_finding") or {}
    if isinstance(finding, str):
        finding = json.loads(finding)
    iocs = finding.get("iocs") or []
    if isinstance(iocs, str):
        iocs = json.loads(iocs)
    techniques = triage.get("attack_techniques") or []
    if isinstance(techniques, str):
        techniques = json.loads(techniques)

    severity = incident.get("severity", "P3_MEDIUM")

    # Pick the highest-confidence technique with a template.
    selected_tech = None
    best_confidence = -1
    for t in techniques:
        tid = t.get("technique_id", "") if isinstance(t, dict) else ""
        base_id = _normalize_technique_id(tid)
        if base_id in SIGMA_TEMPLATES:
            conf = t.get("confidence", 0) if isinstance(t, dict) else 0
            if isinstance(conf, (int, float)) and conf > best_confidence:
                selected_tech = t
                best_confidence = float(conf)

    if not selected_tech:
        # Use generic template based on entity types.
        template = dict(GENERIC_TEMPLATE)
        base_id = "T1078"
        tech_name = "Suspicious Activity"
        tech_tactic = "unknown"
    else:
        tech_id = selected_tech["technique_id"] if isinstance(selected_tech, dict) else "T1078"
        base_id = _normalize_technique_id(tech_id)
        template = dict(SIGMA_TEMPLATES.get(base_id, GENERIC_TEMPLATE))
        tech_name = (
            selected_tech.get("name", "Suspicious Activity")
            if isinstance(selected_tech, dict)
            else "Suspicious Activity"
        )
        tech_tactic = selected_tech.get("tactic", "") if isinstance(selected_tech, dict) else ""

    tactic_name = TACTIC_MAP.get(
        base_id, tech_tactic.lower().replace(" ", "_") if tech_tactic else "unknown"
    )

    detection = _inject_iocs(template, iocs)
    logsource = template.get("logsource", GENERIC_TEMPLATE["logsource"])

    rule_id = str(uuid.uuid4())
    today = date.today().strftime("%Y/%m/%d")

    level = "high" if severity in ("P1_CRITICAL", "P2_HIGH") else "medium"

    tags = [f"attack.{tactic_name}", f"attack.{base_id.lower()}"]

    description = f"Detects {tech_name.lower()} activity based on SentinelForge incident analysis."

    rule = {
        "title": f"Suspected {tech_name} — {incident.get('affected_service', 'unknown')}",
        "id": rule_id,
        "status": "experimental",
        "description": description,
        "references": [f"https://attack.mitre.org/techniques/{base_id.replace('.', '/')}/"],
        "author": "SentinelForge",
        "date": today,
        "tags": tags,
        "logsource": logsource,
        "detection": detection,
        "falsepositives": ["Unknown — generated automatically by SentinelForge"],
        "level": level,
    }
    return rule


def to_yaml(rule: dict) -> str:
    return yaml.safe_dump(rule, sort_keys=False, default_style=None, allow_unicode=True)


async def generate_detection_rule(incident: dict) -> tuple[dict, str]:
    rule = build_sigma_rule(incident)
    yaml_str = to_yaml(rule)

    if not llm.enabled:
        return rule, yaml_str

    triage = incident.get("triage_result") or {}
    if isinstance(triage, str):
        triage = json.loads(triage)
    findings = incident.get("investigation_finding") or {}
    if isinstance(findings, str):
        findings = json.loads(findings)

    prompt = (
        "You are a detection engineer. Given this incident, suggest improvements "
        "to the title, description, and falsepositives fields of a Sigma rule. "
        "Return ONLY a JSON object with keys 'title', 'description', 'falsepositives' "
        "(a list). Keep the title concise, description informative, and falsepositives realistic.\n\n"
        f"Incident alert: {incident.get('alert_message', '')}\n"
        f"Severity: {incident.get('severity', '')}\n"
        f"Service: {incident.get('affected_service', '')}\n"
        f"Verdict: {triage.get('verdict', '')}\n"
        f"Techniques: {triage.get('attack_techniques', [])}\n"
        f"Entities: {findings.get('iocs', [])}"
    )
    try:
        resp = await llm.complete(
            model=incident.get("_model", "llama-3.1-8b-instant"),
            messages=[{"role": "user", "content": prompt}],
        )
        content = resp.get("content", "")
        refined = extract_json(content)
        if isinstance(refined, dict):
            if "title" in refined:
                rule["title"] = refined["title"]
            if "description" in refined:
                rule["description"] = refined["description"]
            if "falsepositives" in refined and isinstance(refined["falsepositives"], list):
                rule["falsepositives"] = refined["falsepositives"]
        yaml_str = to_yaml(rule)
    except Exception as exc:
        logger.warning("LLM refinement failed for sigma rule: %s", exc)

    return rule, yaml_str
