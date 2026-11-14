"""Threat intelligence tools — IP reputation + CVE database."""

from __future__ import annotations

import random

import aiohttp

from app.config import settings
from app.tools.registry import tool


@tool(
    name="lookup_ip_reputation",
    description="Check IP address reputation against VirusTotal and AbuseIPDB. Use when logs contain suspicious external IPs.",
    parameters={
        "type": "object",
        "properties": {
            "ip_address": {"type": "string", "description": "IPv4 or IPv6 address to check"},
            "services": {
                "type": "array",
                "items": {"type": "string", "enum": ["virustotal", "abuseipdb", "shodan"]},
                "description": "Which services to query",
            },
        },
        "required": ["ip_address"],
    },
)
async def lookup_ip_reputation(ip_address: str, services: list[str] | None = None) -> dict:
    services = services or ["virustotal", "abuseipdb"]
    if settings.virustotal_api_key and not settings.use_mock_tools:
        return await _real_lookup(ip_address, services)
    return _mock_lookup(ip_address, services)


async def _real_lookup(ip, services):
    results = {}
    async with aiohttp.ClientSession() as session:
        if "virustotal" in services and settings.virustotal_api_key:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": settings.virustotal_api_key}
            async with session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = (
                        data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    )
                    results["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                    }
        if "abuseipdb" in services and settings.abuseipdb_api_key:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            async with session.get(
                url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results["abuseipdb"] = {
                        "abuse_confidence_score": data.get("data", {}).get(
                            "abuseConfidenceScore", 0
                        ),
                        "total_reports": data.get("data", {}).get("totalReports", 0),
                    }
    return {"ip": ip, "results": results}


def _mock_lookup(ip, services):
    is_private = ip.startswith(
        (
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.2",
            "172.30.",
            "172.31.",
            "192.168.",
            "127.",
        )
    )
    if is_private:
        return {"ip": ip, "results": {}, "note": "Private/internal IP — no threat intel available"}

    results = {}
    if "virustotal" in services:
        malicious = random.randint(5, 25)
        results["virustotal"] = {
            "malicious": malicious,
            "suspicious": random.randint(2, 8),
            "harmless": random.randint(50, 70),
        }
    if "abuseipdb" in services:
        results["abuseipdb"] = {
            "abuse_confidence_score": random.randint(60, 99),
            "total_reports": random.randint(50, 500),
        }
    if "shodan" in services:
        results["shodan"] = {
            "open_ports": [22, 80, 443, 3389],
            "os": "Linux",
            "isp": "Unknown Hosting Provider",
        }
    return {"ip": ip, "results": results, "verdict": "MALICIOUS" if results else "UNKNOWN"}


@tool(
    name="search_cve_database",
    description="Search for CVEs related to a software package and version. Use when the alert mentions a specific service version or when vulnerability exploitation is suspected.",
    parameters={
        "type": "object",
        "properties": {
            "product": {"type": "string"},
            "version": {"type": "string"},
            "severity_filter": {
                "type": "string",
                "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                "description": "Minimum CVSS severity to include",
            },
        },
        "required": ["product"],
    },
)
async def search_cve_database(
    product: str, version: str = "", severity_filter: str = "MEDIUM"
) -> dict:
    return _mock_cve_search(product, version, severity_filter)


def _mock_cve_search(product, version, severity):
    product_lower = product.lower()
    cves = []
    if "nginx" in product_lower:
        cves = [
            {
                "cve_id": "CVE-2024-7347",
                "severity": "HIGH",
                "cvss": 8.1,
                "description": "nginx mp4 module buffer over-read",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-7347",
            },
            {
                "cve_id": "CVE-2024-24990",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "description": "nginx HTTP/3 use-after-free vulnerability",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-24990",
            },
        ]
    elif "openssl" in product_lower or "ssl" in product_lower:
        cves = [
            {
                "cve_id": "CVE-2024-5535",
                "severity": "HIGH",
                "cvss": 7.5,
                "description": "OpenSSL SSL_select_next_proto memory overread",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-5535",
            },
        ]
    elif "java" in product_lower or "jvm" in product_lower:
        cves = [
            {
                "cve_id": "CVE-2024-21147",
                "severity": "CRITICAL",
                "cvss": 9.1,
                "description": "Java SE HotSpot remote code execution",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-21147",
            },
        ]
    elif "postgres" in product_lower or "pg" in product_lower:
        cves = [
            {
                "cve_id": "CVE-2024-10979",
                "severity": "HIGH",
                "cvss": 8.8,
                "description": "PostgreSQL PL/Perl environment variable change allows arbitrary code execution",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-10979",
            },
        ]
    else:
        cves = [
            {
                "cve_id": f"CVE-2024-{random.randint(1000, 9999)}",
                "severity": "MEDIUM",
                "cvss": 5.5,
                "description": f"Potential vulnerability in {product} {version}",
                "url": "https://nvd.nist.gov/",
            },
        ]
    return {"product": product, "version": version, "cves": cves, "count": len(cves)}
