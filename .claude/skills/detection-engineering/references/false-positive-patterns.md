# False Positive Documentation Patterns

`falsepositives` must list concrete, specific conditions. `Unknown` alone
means the analysis wasn't done — if you genuinely investigated and found
none, say `- None identified during testing` instead of leaving the
placeholder.

## Common legitimate-activity sources by technique category

### Credential access / dumping tools
- Legitimate use of PsExec, WMI, or PowerShell remoting by sysadmins for
  remote administration
- EDR/AV agents that briefly access LSASS for memory scanning (allowlist
  by signed vendor process if this fires)
- Password-recovery or migration tooling run by IT during account moves

### Process execution / LOLBins
- Backup software spawning child processes under common system parents
  (e.g. `svchost.exe`, `wmiprvse.exe`)
- Software deployment/patch-management tools (SCCM, Intune, Ansible)
  invoking scripting engines
- Developer or CI/CD tooling using the same binaries for legitimate
  automation

### Persistence (scheduled tasks, run keys, services)
- Approved monitoring/agent software registering its own scheduled task
  or service on install
- Group Policy or MDM-pushed startup scripts
- License-check or update utilities that self-register periodically

### Lateral movement / remote access
- Helpdesk or remote-support tools (TeamViewer, AnyDesk) used with user
  consent
- Configuration-management push jobs authenticating to many hosts in a
  short window
- Scheduled maintenance windows (patching, reboots) that look like burst
  authentication

### Network / exfiltration-adjacent
- Cloud-storage sync clients (OneDrive, Dropbox, Google Drive) uploading
  large volumes of data
- Legitimate backup jobs shipping data to an external or cloud endpoint
- VPN split-tunnel or proxy configs that make internal traffic look
  externally routed

## How to write the entry

Name the actor/tool and the condition, not just the tool:

Bad: `- Unknown`

Bad: `- PsExec`

Good: `- Legitimate sysadmin use of PsExec for remote administration`

Good: `- Backup software (Veeam) that spawns process copies under the same
parent PID during scheduled backup windows`

If a false-positive source is specific to this environment (a particular
internal tool, a scheduled job name), name it — that's more useful to the
next analyst than a generic category.
