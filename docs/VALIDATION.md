# Validation

This file is produced by `validation/compare.py`. **Numbers must come from running the
script against real exports; they are never filled in by hand or estimated.**

## Method

1. Copy a real browser profile (Chrome/Edge/Firefox) with the browser closed.
2. Run `browsertrace analyze --evidence <copy> ...` and export BrowserTrace CSV.
3. Run NirSoft BrowsingHistoryView or Hindsight on the **same copy**. For Hindsight, export JSONL.
   For BrowsingHistoryView, enable *Show Time In GMT* before exporting its CSV.
4. Compare with the matching format:
   - NirSoft: `python validation/compare.py --browsertrace browsertrace_events.csv --reference bhv.csv`
   - Hindsight: `python validation/compare.py --browsertrace browsertrace_events.csv --reference hindsight.jsonl --format hindsight-jsonl`
5. Spot-check 20 random entries against the browser's own history page and record them below.

The Hindsight JSONL mode compares visits and downloads by browser, profile, normalized URL and
timestamp. It collapses repeated download rows by profile and `download_id`, keeping the first
JSONL row for each download. Search artifacts and risk findings are not compared in this mode.

## Results

| Measure | Value |
|---|---|
| Reference tool | not yet measured |
| Records in both | not yet measured |
| Only in BrowserTrace | not yet measured |
| Only in reference | not yet measured |
| Timestamp difference (mean / max, s) | not yet measured |
| Match rate per browser | not yet measured |

## Manual spot-check against browser history page

| # | Browser | URL | Time shown by browser | Time in BrowserTrace | Match? |
|---|---|---|---|---|---|
| 1 | not yet measured | | | | |

## Examiner sign-off

Validated by: ____________  Date: ____________
