# Failed Login Spike / Brute Force Attack

## Symptoms
- Sudden spike in failed SSH/login attempts (>100/min)
- Single or multiple source IPs generating high volume
- Auth logs showing repeated "Failed password" entries

## Immediate Actions
1. **Identify source IPs**:
   ```bash
   grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20
   ```
2. **Check IP reputation** via threat intelligence (VirusTotal, AbuseIPDB)
3. **Block malicious IPs** via firewall (requires approval):
   ```bash
   iptables -A INPUT -s <malicious_ip> -j DROP
   # or via cloud firewall API
   ```
4. **Enable fail2ban** if not already running:
   ```bash
   systemctl status fail2ban
   fail2ban-client set sshd banip <malicious_ip>
   ```
5. **Escalate to security team** if attack volume > 1000 attempts/min

## Validation
- Failed login rate drops to baseline (<5/min)
- Blocked IPs no longer appear in auth logs
- No successful unauthorized logins during the attack window

## Prevention
- Enforce SSH key-only authentication (disable password auth)
- Deploy fail2ban with aggressive thresholds (5 failures = 1hr ban)
- Use bastion hosts with MFA for all SSH access
- Implement geo-IP blocking for non-business regions
