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

Open <http://127.0.0.1:8000>. The server listens on localhost only and is read-only.

- **Header:** case, examiner, tool version, and a badge showing whether all evidence copies still
  match their recorded hashes (hover for details).
- **Cards:** event totals per browser, findings per severity, synced events.
- **Findings:** sorted High → Low with reason and ATT&CK ID. Click one to jump to its events in the
  timeline (they're highlighted and tagged FINDING).
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
  to 5 linked events each, timeline excerpt around High findings, limitations, signature block.
- **CSV:** Timesketch columns (`message`, `datetime`, `timestamp`, `timestamp_desc`) followed by all
  BrowserTrace fields and the IDs of rules that flagged each event. Import directly into Timesketch.
- **JSON:** case metadata, evidence, custody log, findings with event IDs, and all events.

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
