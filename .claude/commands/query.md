---
description: Run a saved Splunk SIEM query, analyze results for suspicious patterns, map to ATT&CK, and write an Obsidian-compatible investigation note
argument-hint: <query-file-path> [timerange]
allowed-tools: Bash(curl:*), Bash(mkdir:*), Bash(date:*), Read, Write, Grep
---

## Context

- Query file: $1
- Timerange: ${2:--24h} (Splunk relative time, e.g. `-24h`, `-7d@d`)
- `SPLUNK_HOST` and `SPLUNK_TOKEN` must be set in the environment. If either
  is missing, stop and tell the user which one — do not prompt for a token
  value or print its contents.
- ATT&CK technique metadata lives in `mappings/attack_techniques.json`
  (read via `attack_techniques.py` conventions in this repo) — use it to
  turn a technique ID into a name/tactic when writing findings, don't guess.
- Output goes in `investigations/`, created if missing.

## Steps

1. **Read the query.** Read the file at `$1`. If it doesn't exist or is
   empty, stop and report that — don't fabricate a query.

2. **Run it against Splunk.** Use the REST API (search job + results, not
   the deprecated one-shot `/search/jobs/export` unless the query is
   small), authenticating with a Bearer token:

   ```bash
   curl -sk "https://${SPLUNK_HOST}:8089/services/search/jobs" \
     -H "Authorization: Bearer ${SPLUNK_TOKEN}" \
     -d search="search $(cat "$1")" \
     -d earliest_time="${2:--24h}" \
     -d latest_time="now" \
     -d output_mode=json \
     -d exec_mode=oneshot
   ```

   Never echo `SPLUNK_TOKEN` itself into output. If the request fails
   (non-2xx, connection error, malformed JSON), stop and report the exact
   error — don't retry silently or invent results.

3. **Analyze results for suspicious patterns.** Look at the returned events
   for things like: known-bad process/command-line patterns (credential
   dumping tools, encoded PowerShell, LOLBins used unusually), anomalous
   auth (impossible travel, off-hours admin logons, spray-like failure
   patterns), unusual parent/child process relationships, and anything
   matching Sigma logic already in `rules/`. Note the result count and
   whether it's zero (a clean run is still a valid outcome — say so, don't
   pad findings).

4. **Map findings to ATT&CK techniques.** For each distinct suspicious
   pattern, identify the most specific applicable technique ID (prefer
   sub-techniques, e.g. `T1003.001` over `T1003`) and look up its name via
   `mappings/attack_techniques.json`. Don't assign a technique you can't
   justify from the actual returned data.

5. **Generate the Obsidian markdown note** with this structure:

   ```markdown
   ---
   date: <ISO 8601 date, from `date -u +%Y-%m-%dT%H:%M:%SZ`>
   tags: [investigation, splunk, <technique-ids-lowercase-e.g-t1003.001>]
   techniques: [T1003.001, ...]
   ---

   # Investigation: <short descriptive title>

   ## Summary

   <2-4 sentences: what was queried, what was found, overall assessment>

   ## Findings

   - <finding> — [[T1003.001]] OS Credential Dumping: LSASS Memory
   - ...

   (or "No suspicious activity identified." if the run was clean)

   ## Query

   - **File:** `$1`
   - **Timerange:** `${2:--24h}`
   - **Result count:** <N>

   ```spl
   <raw query text>
   ```

   ## Analyst Notes

   <!-- for human follow-up -->
   ```

   Use one `[[T1003.001]]`-style backlink per technique cited in Findings,
   inline with the finding it supports — not a separate dangling list.

6. **Save the output.** Create `investigations/` if it doesn't exist. Write
   the note to `investigations/<UTC-timestamp>-<slug>.md`, where `<slug>`
   is a short kebab-case summary of the query/finding (e.g.
   `20260724-143000-lsass-access-spike.md`). Report the path back to the
   user.
