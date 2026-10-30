# Architecture

```
evidence root / file
   │  collector/discover.py      find History / places.sqlite, identify browser + profile
   ▼
collector/collect.py             SHA-256 original → copy DB + -wal/-shm → SHA-256 copy → compare
   │                             → evidence_files, custody_log, audit_log
   ▼  (scratch copy in <case>/work, opened with sqlite3 mode=ro, deleted afterwards)
parsers/chromium.py, firefox.py  PRAGMA table_info introspection → list[Event] (UTC ISO-8601)
   ▼
core/db.py  ingest_events        sort, flag future/out-of-order, dedupe (UNIQUE + INSERT OR IGNORE),
   │                             one transaction with executemany
   ▼
enrichment/chains.py             from_visit_id → from_event_id (same browser/profile/source file)
enrichment/zone_identifier.py    Mark-of-the-Web for downloads still present in the evidence tree
   ▼
analysis/engine.py + rules/*.yaml  findings (reason + linked event IDs), off-hours escalation
   ▼
case.db ──► cli.py (summary / timeline / verify)
        ──► api/app.py (read-only evidence API + local review updates) + static dashboard
        ──► report/pdf.py, report/export.py (CSV/JSON)
```

## Case folder

```
<case>/
  case.db                         SQLite case database
  evidence/<browser>/<profile>/   verified evidence copies (+ -wal / -shm)
  browsertrace_report.pdf         (after `report`)
  browsertrace_events.csv|json    (after `report`)
```

Evidence copy paths are stored **relative to the case folder** so a case can be moved or archived.

## Database tables

`case_meta`, `evidence_files`, `events`, `findings`, `finding_events`, `finding_reviews`, `audit_log`,
`custody_log`.
Indexes on `events(timestamp_utc)`, `events(url)`, `events(event_type)` and
`events(source_file, source_visit_id)` (chain resolution). Evidence and event endpoints open the DB
with `mode=ro`; review saves use a separate write connection for the annotation tables. The dashboard
and CLI apply this additive table migration when opening cases created by older versions.

## Design decisions (made without asking, per the brief)

1. **Chromium transition qualifier bits follow Chromium's source**, not the values in the brief.
   `ui/base/page_transition_types.h` defines BLOCKED=0x00800000, FORWARD_BACK=0x01000000,
   FROM_ADDRESS_BAR=0x02000000, HOME_PAGE=0x04000000, FROM_API=0x08000000, CHAIN_START=0x10000000,
   CHAIN_END=0x20000000, CLIENT_REDIRECT=0x40000000, SERVER_REDIRECT=0x80000000. The brief's table
   was shifted by one bit (and listed server_redirect as 0x100000); using it would mislabel real
   history (e.g. every typed URL would show as "home_page"). Core type 6 (AUTO_TOPLEVEL) keeps the
   brief's label `start_page`.
2. **Parsers never open the evidence copy.** They open a scratch copy in `<case>/work/` read-only.
   Even `mode=ro` SQLite can create `-shm` files next to a WAL database; using a scratch copy keeps
   the evidence copies byte-identical so `browsertrace verify` stays meaningful.
3. **`source_file` is the original path** as found in the evidence; `source_sha256` is the hash of
   the parsed copy (equal to the original when verified). `/api/event/{id}` resolves both to the
   evidence copy and prints the `SELECT ... WHERE rowid = ...` query to re-check the record.
4. **Default analysis timezone is UTC.** It is reproducible; examiners pass `--tz Asia/Kolkata`
   (or `+05:30`) for the subject's local time. The synthetic scenario's planted 02:10–02:16 UTC
   events therefore fall in the default 00:00–05:00 off-hours window.
5. **`tzdata` added as a dependency.** Windows has no IANA timezone database, so `zoneinfo`
   cannot resolve `Asia/Kolkata` without it. Considered essential.
6. **Search de-duplication:** URL-derived searches (exact visit time) win over
   `keyword_search_terms` rows for the same URL and term (approximate time).
7. **Grouping to avoid alert floods:** R001 groups per domain per day, R003 per off-hours session
   (events ≤30 min apart), R004/R007 per distinct term, R005 per archive download, R006 per gap,
   R008 per burst. A finding links at most 500 events.
8. **Escalation:** a non-off-hours finding with an event that is also in an R003 (time_window)
   finding is raised one level (Low→Medium→High), and the reason says so.
9. **R006 combines two signals** — a >48 h gap with ≥10 events in the 72 h before *and* after, and
   ≥20 missing visit IDs — and merges them when they border the same pair of events.
10. **Dashboard security:** strict CSP (`script-src 'self'`, no inline script/style), all evidence
    strings rendered as text nodes, server bound to 127.0.0.1 only. The only write route saves a
    finding review and requires a local same-origin `Origin`; evidence and event records are unchanged.
11. **Chart.js 4.4.1** is vendored as `api/static/chart.min.js` so the dashboard works offline.
12. **WAL recovery not implemented** (build step 12); R006 covers history-clearing detection instead.
13. **The scenario generator lives in `browsertrace/scenario.py`** so `browsertrace demo` works from an
    installed package; `tools/make_scenario.py` is a thin CLI wrapper.
14. **Firefox `moz_annos`** is the real table name (`moz_annotations` from the brief is also accepted),
    and Chromium's `downloads_url_chains` (the brief's `download_url_chains` is also accepted).
15. **Analyst reviews are separate from rule findings.** Each finding can have one current review
    (risk level, outcome, confidence, rationale, optional reviewer and UTC review time). Review values
    do not change rule severity. Exact matching findings retain their review when analysis is rerun;
    changed findings require a new review.

## Extending

- **New rule:** add an entry to a YAML file (`browsertrace rules --rules my.yaml` validates it).
- **New rule type:** add an evaluator in `analysis/engine.py` and its params to `RULE_TYPES`.
- **New browser:** add a parser with `parse(db_path, browser, profile, sha256, ...) -> list[Event]`,
  register it in `parsers/__init__.py`, and teach `collector/discover.py` its path layout.
