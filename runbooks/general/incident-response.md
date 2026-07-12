# General Security Incident Response

> Fallback runbook returned when no specific playbook matches the finding.
> Replace this with the most specific playbook possible once the triage output
> identifies an ATT&CK technique.

## Symptoms
- Triage verdict: `TRUE_POSITIVE` but no specific technique id was emitted.
- A security finding was ingested but the symptom set doesn't fit a known
  playbook.

## Immediate Actions
1. Surface all IOCs the investigation agent surfaced (IPs, users, hosts,
   files) and forward each to its enrichment tool (`lookup_ip_reputation`,
   `enrich_user_identity`, `query_edr_endpoint`).
2. Once a high-confidence MITRE ATT&CK technique is identified, switch to that
   technique's specific playbook (see siblings in this directory).
3. As a default-safe containment:
   - Block every source IP reported as MALICIOUS (`block_ip`, approval required)
   - Suspend every privileged user reported as SUSPICIOUS (`suspend_account`,
     approval required)
   - Isolate every host whose EDR reports compromise indicators
     (`isolate_host`, approval required)
4. Notify the on-call SecOps lead in #soc-primary.
5. Open a JIRA ticket via the SentinelForge MCP server.

## Validation
- No new `true_positive` events referencing the same IOCs in the next 24h.
- The JIRA ticket is duplicated or linked to existing matches by the SOC lead.

## Prevention
- Continuously enrich the runbook catalogue from post-incident review.
- Tune SIEM correlation rules so similar findings roll up into one incident
  rather than many.