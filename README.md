# BrowserTrace

A Windows browser forensic triage tool: command line plus a local, offline web dashboard.
It acquires Chrome, Edge, Brave, Opera and Firefox history databases in a forensically sound way,
builds a single UTC timeline across browsers, flags suspicious patterns with explainable rules,
and produces a PDF report and Timesketch-compatible CSV/JSON exports.

> Findings are **investigative leads, not proof**. Every finding links to the exact source
> records (file, SHA-256, `table:rowid`) so an examiner can verify it.

## Features

- **Evidence handling:** SHA-256 of original and copy (plus `-wal`/`-shm`), custody log, audit log,
  read-only parsing of a scratch copy, `verify` command to re-hash evidence later.
- **Parsers:** Chromium `History` (visits, decoded transitions, sync origin, downloads with URL chains,
  keyword searches) and Firefox `places.sqlite` (visits, visit types, annotation downloads). Both
  derive searches from search-engine URLs. Schema introspection handles old and new versions.
- **Enrichment:** navigation chains (`from_visit`), Mark-of-the-Web (`Zone.Identifier`) for downloads.
- **Rules (YAML):** file-sharing sites, risky downloads, off-hours activity, anti-forensic searches,
  share-then-archive sequences, history gaps, anonymizers, download bursts — with MITRE ATT&CK IDs
  and off-hours severity escalation.
- **Analyst review:** record a separate risk level, outcome, confidence and rationale for each finding.
  Reviews stay attached to the finding and are included in CSV, JSON and PDF outputs.
- **Outputs:** terminal summary/timeline, dashboard, PDF report, CSV/JSON.

## Install

Python 3.11+.

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (Linux/macOS: source .venv/bin/activate)
pip install -e ".[dev]"
```

## Quick start (synthetic demo)

```bash
browsertrace demo --out ./demo_case
browsertrace serve --case ./demo_case          # http://127.0.0.1:8000
browsertrace report --case ./demo_case --format pdf
```

`python -m browsertrace ...` works everywhere `browsertrace ...` does.

## Real evidence

Close the browsers first (or, better, work from an image / Volume Shadow Copy), then:

```bash
browsertrace analyze --evidence "C:\Users\alice" --case CASE-2024-07 --examiner "Your Name" --out .\case07 --tz Asia/Kolkata
browsertrace serve --case .\case07
browsertrace report --case .\case07 --format pdf
browsertrace report --case .\case07 --format csv
browsertrace verify --case .\case07
```

A single database file works too: `--evidence path\to\History --browser Edge --profile Work`.

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for every command and option.

## Commands

| Command | What it does |
|---|---|
| `analyze` | collect → parse → normalize → store → enrich → rules, prints a summary (`--timeline N` prints rows) |
| `serve` | dashboard on 127.0.0.1 only; supports local analyst review annotations |
| `report` | `--format pdf\|csv\|json` |
| `timeline` | print timeline rows in the terminal |
| `demo` | build the synthetic scenario and analyze it |
| `rules` | validate rules; `--doc` prints the rule reference |
| `verify` | re-hash evidence copies against the custody log |
| `--version` | version |

## Building a Windows .exe

```bash
pip install pyinstaller
pyinstaller browsertrace.spec      # -> dist\browsertrace.exe
```

(The spec is provided but the build has not been tested in CI.)

## Development

```bash
pytest -q
ruff check .
python tools/make_scenario.py ./scenario_out     # synthetic evidence only
python validation/compare.py --help              # compare against NirSoft/Hindsight exports
```

## Documentation

- [docs/USER_GUIDE.md](docs/USER_GUIDE.md) — how to use it
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — pipeline, data model, design decisions
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md) — what it does not do (read this)
- [docs/VALIDATION.md](docs/VALIDATION.md) — validation results (template until measured)
- [CHANGELOG.md](CHANGELOG.md)
