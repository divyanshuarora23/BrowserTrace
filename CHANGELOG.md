# Changelog

## 0.1.0 — initial version

### Added
- Evidence discovery for Chrome, Edge, Brave, Opera and Firefox; forensic collection with SHA-256
  of originals and copies (including `-wal`/`-shm`), custody and audit logs, lock handling, `verify`.
- Chromium `History` parser (visits, transitions, sync origin, downloads + URL chains, keyword
  searches) and Firefox `places.sqlite` parser (visits, visit types, annotation downloads), with
  schema introspection and URL-derived searches for both.
- Case database with normalization (dedupe, sort, future/out-of-order flags); 100k-event ingest test.
- Navigation-chain resolution and Zone.Identifier enrichment.
- YAML rules engine with 7 rule types and default rules R001–R008, off-hours severity escalation,
  `rules --doc` reference.
- CLI (`analyze`, `serve`, `report`, `timeline`, `demo`, `rules`, `verify`, `--version`).
- Read-only FastAPI API and offline dashboard (vendored Chart.js, strict CSP).
- PDF report (ReportLab), Timesketch-compatible CSV and JSON exports.
- Synthetic "insider data theft" scenario generator with expected findings.
- `validation/compare.py` for comparison with NirSoft BrowsingHistoryView / generic CSV exports.
- PyInstaller spec, GitHub Actions CI (Windows, Linux, macOS).

### Not implemented
- WAL deleted-record recovery (`parsers/recovery.py` is a documented stub).
- Prefetch/Amcache execution correlation.
