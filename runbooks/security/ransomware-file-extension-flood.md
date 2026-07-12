# Ransomware File Extension Flood

## Symptoms
- EDR reports rapid mass file-extension rename (e.g. `.locked`, `.encrypted`)
  on one or more hosts over a short window (hundreds–thousands of files in
  minutes).
- File-server audit log shows a single user account performing an abnormal
  number of writes — typically a service account with broad file-share access.
- Shadow copies / SnapManager backups being deleted (vssadmin delete shadows / wbadmin).

## Immediate Actions
1. **Isolate the affected host(s) via EDR immediately** (high blast radius).
   Use the SentinelForge `isolate_host` tool. This requires human approval.
2. **Suspend the responsible service account** in the IdP
   (`suspend_account` tool, requires approval).
3. **Disable the file-share write access** for the affected user at the cluster
   level to stop the spread.
4. **Pull host memory** before re-imaging — ransomware loaders often pack
   the encryption key in memory only.
5. **Triage scope**: enumerate every file-share the user touched in the last
  6 hours; flag all writes for forensic review.
6. Engage the IR vendor + notify legal/comms.

## Validation
- EDR shows zero new file-write events from the suspended user.
- File servers report no additional `.locked` files in the last 30 min.
-Backup integrity check confirms the last successful backup is not encrypted.

## Prevention
- Apply the principle of least privilege to service accounts that touch file
  shares; avoid granting broad share-write access.
- Enable controlled-folder access (Windows Defender) on file servers.
- Store immutable, off-network backups (object lock / WORM) updated at least
  daily; verify restore quarterly.
- Alert on `vssadmin delete shadows` and high-velocity file rename patterns.