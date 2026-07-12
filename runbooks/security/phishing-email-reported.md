# Phishing Email Reported

## Symptoms
- A user reported a phishing email (forwarded to the SOC alias).
- Payload or link inside targets a credential-harvesting page that mimics a
  corporate login UI.
- Recipient list may include more than the reporter — check the mailbox
  transport logs to see who else received it.

## Immediate Actions
1. **Extract indicators** from the email:
   - Sender envelope address vs display address
   - All URLs (especially shortened links)
   - Attachments — submit to a sandbox; query file hashes against the EDR
   - Reply-to and received headers
2. **Quarantine** the message across all mailboxes:
   ```bash
   # Microsoft 365 purge (via the security centre or Graph API)
   POST /security/attacksimulation/payloads/<id>/purge
   # or via the SentinelForge quarantine_file / api_call tool
   ```
3. **Block the landing-domain** at the corporate web proxy:
   ```bash
   pfctl -t phishing -T add <landing_domain>
   ```
4. **Suspend the reporter's credential if they clicked-through and entered
   creds**: rotate_credentials via the IdP (requires approval).
5. **Force a password reset + revoke all active tokens** for any user who
   received the email.
6. Notify the user that the email was a phishing attempt; train via the
   security-awareness program.

## Validation
- The landing domain is no longer reachable from inside the corp network.
- No new mail-flow entries reference the sender / subject hash for 24h.
- Audit log shows credentials rotated for every user who received the message.

## Prevention
- Deploy DMARC enforcement (p=reject). Train the mail gateway to reject
  on spf=softfail or dkim=none for unknown senders.
- Run inbound URL sandboxing / time-of-click rewriting (e.g. Safe Links).
- Run a quarterly phishing-simulation campaign; require a remediation module
  for any user who fails.