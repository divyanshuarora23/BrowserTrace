# User guide

## 1. Before you start

- Work on a **copy or image** of the suspect system where possible. BrowserTrace never writes to
  the files it reads, but a live, running browser will keep changing its own database.
- Close the browsers on a live system, or the History file may be locked (BrowserTrace retries,
  then reports the file as failed and carries on with the others).
- Know the subject's **timezone**. Off-hours rules (R003) use `--tz`; the default is UTC.

## 2. Analyze

```bash
browsertrace analyze --evidence <PATH> --case <ID> --examiner <NAME> --out <CASE_DIR> [options]
```

`<PATH>` may be:
- a user profile folder (`C:\Users\alice`), a whole mounted drive (`E:\`), or any folder of
  collected evidence — BrowserTrace searches for
  `…/User Data/{Default,Profile N}/History` (Chrome, Edge, Brave; Opera's `Opera Software/Opera Stable/History`)
  and `…/Mozilla/Firefox/Profiles/*/places.sqlite`;
- a single `History` / `places.sqlite` file. Add `--browser` and `--profile` if the path doesn't
  reveal them (e.g. a renamed export).

| Option | Meaning |
|---|---|
| `--browser B` / `--profile P` | restrict discovery, or label a single file |
| `--tz Asia/Kolkata` | timezone for off-hours rules (IANA name, `UTC`, or `+05:30`) |
| `--off-hours 22:00-06:00` | override the off-hours window (may wrap midnight) |
| `--rules my.yaml` | use a custom rules file |
| `--timeline 50` | also print the first 50 timeline rows |

Exit codes: `0` success, `2` usage/input error, `3` every evidence target failed.

The case folder receives `case.db` and `evidence/<browser>/<profile>/` with the verified copies.

## 3. Review in the dashboard

```bash
browsertrace serve --case <CASE_DIR> [--port 8000]
```

Open <http://127.0.0.1:8000>. The server listens on localhost only. It reads case evidence and
allows the dashboard to save analyst review annotations to the case database.
Older case databases receive an additive review-table migration when opened; evidence copies are not changed.

- **Header:** case, examiner, tool version, and a badge showing whether all evidence copies still
  match their recorded hashes (hover for details).
- **Cards:** event totals per browser, findings per severity, synced events.
- **Findings:** sorted High → Low with reason and ATT&CK ID. Filter by rule severity and review
  status (all / not reviewed / reviewed). Click one to jump to its events in the timeline (they're
  highlighted and tagged FINDING).
- **Analyst review:** expand **Add analyst review** on a finding and choose a separate risk level
  (Low / Medium / High / Unclear), outcome (Concerning / Benign / Needs more context), confidence,
  and a rationale. The dashboard shows a working guide: isolated/contextual signals are Low, a
  specific or related signal with context missing is Medium, and multiple independent time-linked
  signals may be High; off-hours alone is not High. Reviewer name is optional. Save again to edit the
  current review. Rule severity stays unchanged; it remains the rule engine's original result. Review saves are recorded in the
  case audit log and carry forward on re-analysis only when the rule, severity, reason and linked event IDs
  remain identical. Reviewer names are free text, not authenticated identities.
- **Timeline:** server-side paginated; filter by text, browser, type, synced/local and UTC date
  range. Browser colours: Chrome blue, Edge green, Firefox orange, Brave red, Opera purple.
  `SYNCED` = the visit was made on another device signed into the same account (Chromium only).
  `RECOVERED` = partial record recovered from deleted data (not produced by this version).
- **ⓘ** opens the event with its source record (file, SHA-256, `table:rowid`, a SQL query to
  re-check it in the evidence copy). **⛓** shows the navigation chain that led to a visit.
- **Charts:** activity by hour (analysis timezone) and top visited domains.
- **Export:** CSV and PDF buttons.

## 4. Reports

```bash
browsertrace report --case <CASE_DIR> --format pdf  [--out file.pdf]
browsertrace report --case <CASE_DIR> --format csv  [--out file.csv]
browsertrace report --case <CASE_DIR> --format json [--out file.json]
```

- **PDF:** cover, evidence table with both hashes, methodology, executive summary, findings with up
  to 5 linked events each, current analyst review and rationale, timeline excerpt around High findings,
  limitations, signature block.
- **CSV:** Timesketch columns (`message`, `datetime`, `timestamp`, `timestamp_desc`) followed by all
  BrowserTrace fields, rule IDs and a `finding_review_json` column containing any review attached to
  each event's findings. Import directly into Timesketch.
- **JSON:** case metadata, evidence, custody log, findings with event IDs and a `review` object (or
  `null` when not reviewed), and all events.

## 5. Verify evidence integrity later

```bash
browsertrace verify --case <CASE_DIR>
```

Re-hashes every evidence copy and compares it with the custody log. Exit code 1 if anything changed.

## 6. Rules

```bash
browsertrace rules                 # validate and list
browsertrace rules --doc > RULES.md
browsertrace rules --rules my.yaml # validate a custom file
```

Rule file format (see `src/browsertrace/analysis/rules/default.yaml`):

```yaml
rules:
  - id: C001
    name: Visit to internal secrets wiki
    severity: High            # Low | Medium | High
    attack: T1213
    type: domain_match        # domain_match | keyword_match | extension_match | time_window | sequence | gap | burst
    domains: [secrets.example-corp.com]
    reason: "{count} event(s) involving {domain}, first at {time} ({url})"
```

Placeholders: `{domain} {url} {term} {time} {file} {delta} {count}` (plus `{keyword}`,
`{browser}`, `{profile}` where meaningful). Unknown keys and bad values are rejected with a message
naming the rule.

## 7. Validation against other tools

See `docs/VALIDATION.md`. In short: run NirSoft BrowsingHistoryView on the same profile copy, export
CSV with "Show Time In GMT", then

```bash
python validation/compare.py --browsertrace case\browsertrace_events.csv --reference bhv.csv
```

## 8. Synthetic demo data

`browsertrace demo --out demo_case` (or `python tools/make_scenario.py OUT`) builds fake Chrome,
Edge and Firefox profiles for a fictional employee with ~2,000 normal events and a planted
"insider data theft" sequence on 2024-03-14 between 02:10 and 02:16 UTC. `scenario_expected.json`
lists what should be found.
