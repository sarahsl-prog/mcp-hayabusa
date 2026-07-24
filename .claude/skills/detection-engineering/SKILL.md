---
name: detection-engineering
description: Use when writing or creating Sigma rules, reviewing detection rules, discussing detection coverage, or working with YAML detection files in this repo. Enforces this project's Sigma rule standards (ATT&CK mapping, severity justification, false positives, test cases, naming).
---

# Detection Engineering Standards

This repo's Sigma rules (`rules/`, `rules/suggested/`) must meet the standards
below. Apply them whenever writing a new rule, editing an existing one, or
reviewing one for a PR — and flag any rule that doesn't meet them.

## Standards

### 1. ATT&CK technique mapping required

Every rule's `tags` list must include at least one technique tag in
`attack.tXXXX` format (lowercase, e.g. `attack.t1078`, `attack.t1003.001`
for sub-techniques). A rule with only tactic tags (`attack.credential-access`)
and no technique tag does not meet this standard.

```yaml
tags:
    - attack.credential-access
    - attack.t1003.001
```

### 2. Severity must be justified

`level` must be one of `low`, `medium`, `high`, `critical` — no other values,
no aliases (`informational` is a Hayabusa/scan-time severity, not a valid
Sigma `level`). The rule's `description` must state *why* that level was
chosen: what makes this activity that severe, not just what it detects.

Bad: `description: Detects use of mimikatz`
Good: `description: Detects mimikatz command-line usage. High severity — direct
credential-dumping tooling has no legitimate business use and indicates
active compromise.`

### 3. False positives must be documented

`falsepositives` must list concrete, specific conditions — not a bare
`Unknown`. If the rule genuinely has no known false-positive sources after
investigation, say so explicitly (`- None identified during testing`) rather
than leaving the placeholder. `Unknown` alone means the analysis wasn't done.

```yaml
falsepositives:
    - Legitimate sysadmin use of PsExec for remote administration
    - Backup software that spawns processes under the same parent
```

### 4. At least one test case required

Every rule needs at least one documented test case showing it fires on
expected malicious input. Sigma has no native test-case field, so record it
as a `references` entry pointing at a sample/PoC, or as a sibling
`<rule_name>.test.md` / comment block describing the exact log event (fields
and values) that should match. A rule with detection logic but no evidence
it was ever validated against a real or synthetic event does not meet this
standard.

### 5. Naming convention

Rule filenames (and `title`, loosely) should be lowercase with underscores,
matching the SigmaHQ convention already used in `rules/`:
`lnx_clear_syslog.yml`, `win_credential_access_mimikatz.yml`. No spaces, no
camelCase, no hyphens in filenames.

## Review checklist

When reviewing or writing a rule, verify all five before considering it done:

- [ ] `tags` includes at least one `attack.tXXXX` technique tag
- [ ] `level` is `low`/`medium`/`high`/`critical`, and `description` justifies it
- [ ] `falsepositives` lists specific conditions (not bare `Unknown`)
- [ ] At least one test case is documented (reference, PoC, or sample event)
- [ ] Filename and title use lowercase_with_underscores

## Using this project's tools

- `analyze_coverage` and the `detection://attack/techniques/{id}` resource
  show whether a technique already has coverage before writing a new rule —
  check for redundancy first.
- `suggest_rule` generates a skeleton in `rules/suggested/` for a coverage
  gap; that skeleton still needs all five standards applied by hand before
  it's a real rule (it ships with `TODO` placeholders, not a finished
  `logsource`/`detection`/test case).
