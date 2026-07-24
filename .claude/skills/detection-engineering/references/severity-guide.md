# Severity Guide

Sigma `level` must be one of `low`, `medium`, `high`, `critical`. Pick based
on what the activity means if it's genuinely malicious, not on how noisy the
rule is expected to be (noise is a `falsepositives` problem, not a severity
problem).

### critical
Activity that is almost never legitimate and indicates likely active
compromise or imminent, severe impact if not stopped now.
Examples: ransomware-note drops, disabling of all EDR/AV services,
credential-dumping tooling execution (mimikatz, lsass dumping),
domain admin account creation from an unexpected host.

### high
Activity strongly associated with attack techniques, rarely done by
legitimate admin workflows, that needs prompt investigation.
Examples: LSASS access from an uncommon process, suspicious lateral
movement (PsExec-style service creation from a workstation), known
living-off-the-land binaries used for execution/bypass.

### medium
Activity that is a meaningful signal but has plausible legitimate uses,
so it needs context (asset criticality, time of day, surrounding events)
before escalating.
Examples: PowerShell with encoded commands, new scheduled task creation,
registry run-key persistence.

### low
Activity worth recording for correlation/hunting but weak as a
standalone signal — mostly informational or precursor behavior.
Examples: process creation with unusual but not inherently malicious
command-line flags, first-seen-on-host software installs.

## Writing the justification

The rule's `description` must state *why* the chosen level fits — tie it to
impact or attacker intent, not just what's being detected.

Bad: `description: Detects use of mimikatz`

Good: `description: Detects mimikatz command-line usage. High severity —
direct credential-dumping tooling has no legitimate business use and
indicates active compromise.`

If you can't articulate the "why" in one sentence, the level is probably
wrong — re-examine the technique against the tiers above.
