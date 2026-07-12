# Suspicious PowerShell / Living-off-the-Land

## Symptoms
- EDR reports `powershell.exe` spawned by a non-interactive service process
  (e.g. `winrmsvc.exe`, `taskhostw.exe`).
- Encoded (`-enc <base64>`) or hidden-window (`-w hidden`) invocation flags
  present on the command line.
- Process makes outbound network connections or writes to %APPDATA%.
- Tokens observed in the decoded payload that look like credential access or
  lateral movement commands (Invoke-Mimikatz, BloodHound, OneDrive recon).

## Immediate Actions
1. **Decode the base64 payload** the EDR observed:
   ```bash
   echo <base64> | base64 -d
   ```
2. **Check the parent process tree** to determine how it was spawned
   (scheduled task vs. interactive admin vs. service).
3. **Query EDR for matching hashes** across the fleet to bound the blast radius.
4. **Block the destination** if the decoded payload contains an IP/domain:
   ```bash
   SentinelForge block_ip --duration 24h
   ```
5. **Isolate the host via EDR** if the payload indicates active collection or
   exfiltration (`isolate_host` tool, approval required).
6. **Pull the host's local Windows event log (400/600 PowerShell)** for the
   previous 24h to find sibling beaconing.

## Validation
- EDR reports no new `powershell.exe` instances with high-risk flag combos
  on the host for 24h.
- Parent process tree shows what originally scheduled the task; that vector is
  closed (scheduled-task rule reverted / gpo updated).
- No outbound traffic to the destination IP from any host for 30 min.

## Prevention
- Enable PowerShell Constrained Language Mode for service accounts.
- Forward PowerShell 4104 (script-block) events to the SIEM and alert on
  `-enc`, `-w hidden`, `Invoke-Mimikatz`, `DownloadString`.
- Use ASR rules: "Block execution of potentially obfuscated scripts",
  "Block credential stealing from LSASS".
- Minimise interactive admin use of PowerShell; record sessions.