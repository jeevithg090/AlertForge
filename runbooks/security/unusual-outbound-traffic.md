# Suspicious Outbound Traffic / C2 Beaconing

## Symptoms
- A host shows regular periodic outbound connections to a single external IP on
  a fixed port (e.g. TLS/443 every 60s).
- IDS (Suricata) signatures match known C2 protocol profiles.
- DNS query volume to one external domain is anomalously high; DNS tunnel
  signatures hit.
- Netflow shows a host that normally egresses <<1 MB/hour now sending KB bursts
  on a fixed cadence.

## Immediate Actions
1. **Identify the beaconing process** (EDR):
   ```bash
   # CrowdStrike Falcon — host connection inventory
   falcon-cli host-connections --host <host> --window 30m --external-only
   ```
2. **Check the destination IP reputation** via VirusTotal + AbuseIPDB
   (`lookup_ip_reputation` tool).
3. **Pull DNS query logs** for the host and look for high-entropy / long
   subdomain patterns (DNS tunnel indicators).
4. **Block the destination IP at the edge** (requires approval):
   ```bash
   # via the SentinelForge block_ip tool, or manually:
   iptables -A OUTPUT -d <c2_ip> -j DROP
   # or cloud egress firewall (ASG / NSG rule)
   ```
5. **Isolate the host** via EDR containment (`isolate_host` tool).
6. Capture host memory for forensic analysis before re-imaging.

## Validation
- No new outbound connections from the host to the blocked IP for 30 min.
- Netflow returns to baseline.
- No new DNS queries to the suspicious domain (DNS sinkholed or WAF-blocked).

## Prevention
- Deploy egress firewall default-deny; allow-list required destinations only.
- Subscribe to commercial C2 threat feeds; alert on every match.
- Run an IDS that profiles per-host baseline traffic and alerts on anomalies.
- Enable DNS query logging on the corporate resolver and alert on tunnel
  signatures (TXT records, high-entropy labels).