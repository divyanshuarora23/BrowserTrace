# Validation

This file is produced by `validation/compare.py`. **Numbers must come from running the
script against real exports; they are never filled in by hand or estimated.**

## Method

1. Copy a real browser profile (Chrome/Edge/Firefox) with the browser closed.
2. Run `browsertrace analyze --evidence <copy> ...` and `browsertrace report --format csv`.
3. Run NirSoft BrowsingHistoryView (or Hindsight) on the **same copy**, export CSV
   (BrowsingHistoryView: enable *Show Time In GMT*).
4. `python validation/compare.py --browsertrace browsertrace_events.csv --reference bhv.csv`
5. Spot-check 20 random entries against the browser's own history page and record them below.

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
