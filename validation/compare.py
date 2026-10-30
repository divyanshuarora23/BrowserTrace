"""Compare a BrowserTrace CSV export with a reference tool's export.

Usage:
    python validation/compare.py --browsertrace events.csv --reference bhv.csv [--reference-tz UTC]
                                 [--format nirsoft|generic] [--url-col ...] [--time-col ...]
                                 [--browser-col ...] [--time-format ...] [--tolerance 2] [--out docs/VALIDATION.md]
    python validation/compare.py --template [--out docs/VALIDATION.md]

Reference formats:
  * ``nirsoft``  NirSoft BrowsingHistoryView "Save all items" CSV (columns URL, Visit Time,
    Web Browser). Turn on "Options > Show Time In GMT" before exporting, or pass
    ``--reference-tz`` with the timezone the export was made in.
  * ``generic``  any CSV (e.g. Hindsight's XLSX saved as CSV) with ``--url-col`` and
    ``--time-col`` (and optionally ``--browser-col``) naming the columns.

Only BrowserTrace ``visit`` events are compared, because that is what both reference
tools list. Every number in the output is computed from the two input files; if no
reference file is given, the template is written with "not yet measured".
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

DEFAULT_OUT = Path(__file__).resolve().parents[1] / "docs" / "VALIDATION.md"
TIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
    "%d-%m-%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S",
    "%d.%m.%Y %H:%M:%S",
)
NIRSOFT = {"url": "URL", "time": "Visit Time", "browser": "Web Browser"}

TEMPLATE = """# Validation

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
"""


@dataclass
class Rec:
    browser: str
    url: str
    t: datetime


def norm_browser(s: str) -> str:
    s = (s or "").lower()
    for key, name in (("edge", "Edge"), ("chrome", "Chrome"), ("firefox", "Firefox"), ("brave", "Brave"),
                      ("opera", "Opera")):
        if key in s:
            return name
    return s or "unknown"


def norm_url(u: str) -> str:
    u = (u or "").strip()
    return u[:-1] if u.endswith("/") and u.count("/") == 3 else u


def parse_time(s: str, tz, fmt: str | None) -> datetime | None:
    s = (s or "").strip()
    if not s:
        return None
    formats = (fmt,) if fmt else TIME_FORMATS
    for f in formats:
        try:
            dt = datetime.strptime(s, f)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=tz)
        return dt.astimezone(timezone.utc)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=tz)).astimezone(timezone.utc)
    except ValueError:
        return None


def _read_csv(path: Path) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def load_browsertrace(path: Path) -> list[Rec]:
    out = []
    for r in _read_csv(path):
        if r.get("event_type") != "visit":
            continue
        t = parse_time(r.get("timestamp_utc", ""), timezone.utc, None)
        if t:
            out.append(Rec(norm_browser(r.get("browser", "")), norm_url(r.get("url", "")), t))
    return out


def load_reference(path: Path, cols: dict, tz, fmt: str | None) -> tuple[list[Rec], int]:
    rows = _read_csv(path)
    if rows and cols["url"] not in rows[0]:
        raise SystemExit(f"column {cols['url']!r} not in {path}; columns are: {', '.join(rows[0])}")
    out, bad = [], 0
    for r in rows:
        t = parse_time(r.get(cols["time"], ""), tz, fmt)
        if not t:
            bad += 1
            continue
        browser = norm_browser(r.get(cols["browser"], "")) if cols.get("browser") else "unknown"
        out.append(Rec(browser, norm_url(r.get(cols["url"], "")), t))
    return out, bad


def compare(bt: list[Rec], ref: list[Rec], tolerance_s: float) -> dict:
    by_key: dict[tuple[str, str], list[Rec]] = defaultdict(list)
    use_browser = any(r.browser != "unknown" for r in ref)
    for r in bt:
        by_key[(r.browser if use_browser else "unknown", r.url)].append(r)
    for v in by_key.values():
        v.sort(key=lambda x: x.t)
    matched, diffs = 0, []
    per_browser: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # [matched, reference total]
    used: set[int] = set()
    for r in ref:
        per_browser[r.browser][1] += 1
        best = None
        for cand in by_key.get((r.browser, r.url), []):
            if id(cand) in used:
                continue
            d = abs((cand.t - r.t).total_seconds())
            if d <= tolerance_s and (best is None or d < best[0]):
                best = (d, cand)
        if best:
            used.add(id(best[1]))
            matched += 1
            diffs.append(best[0])
            per_browser[r.browser][0] += 1
    # Only count BrowserTrace records for browsers the reference tool also covered.
    relevant = [r for r in bt if not use_browser or r.browser in per_browser]
    return {
        "both": matched,
        "only_browsertrace": len(relevant) - matched,
        "only_reference": len(ref) - matched,
        "diff_mean": statistics.fmean(diffs) if diffs else None,
        "diff_max": max(diffs) if diffs else None,
        "per_browser": {b: (m, n) for b, (m, n) in sorted(per_browser.items())},
    }


def render(result: dict, args, unparsed: int, n_bt: int, n_ref: int) -> str:
    def fmt(x):
        return "n/a (no matches)" if x is None else f"{x:.3f}"

    lines = [
        "# Validation", "",
        "Generated by `validation/compare.py` from the files below. All numbers are computed, not estimated.", "",
        f"- BrowserTrace export: `{args.browsertrace}` ({n_bt} visit records)",
        f"- Reference export: `{args.reference}` ({n_ref} records, format `{args.format}`, "
        f"reference timezone `{args.reference_tz}`, {unparsed} rows with unparseable time skipped)",
        f"- Match criterion: same browser (if the reference has one) + same URL + |Δt| ≤ {args.tolerance} s",
        f"- Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}", "",
        "## Results", "", "| Measure | Value |", "|---|---|",
        f"| Records in both | {result['both']} |",
        f"| Only in BrowserTrace | {result['only_browsertrace']} |",
        f"| Only in reference | {result['only_reference']} |",
        f"| Timestamp difference of matches (mean / max, s) | {fmt(result['diff_mean'])} / {fmt(result['diff_max'])} |",
        "", "### Match rate per browser (matched / reference records)", "", "| Browser | Matched | Reference | Rate |",
        "|---|---|---|---|",
    ]
    for b, (m, n) in result["per_browser"].items():
        lines.append(f"| {b} | {m} | {n} | {m / n:.1%} |" if n else f"| {b} | {m} | {n} | n/a |")
    lines += ["", "## Manual spot-check against browser history page", "",
              "| # | Browser | URL | Time shown by browser | Time in BrowserTrace | Match? |",
              "|---|---|---|---|---|---|", "| 1 | not yet measured | | | | |", "",
              "## Examiner sign-off", "", "Validated by: ____________  Date: ____________", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Compare BrowserTrace output with a reference tool.")
    ap.add_argument("--browsertrace", type=Path)
    ap.add_argument("--reference", type=Path)
    ap.add_argument("--format", choices=("nirsoft", "generic"), default="nirsoft")
    ap.add_argument("--url-col")
    ap.add_argument("--time-col")
    ap.add_argument("--browser-col")
    ap.add_argument("--time-format", help="strptime format of the reference time column")
    ap.add_argument("--reference-tz", default="UTC", help="timezone of reference times (IANA name)")
    ap.add_argument("--tolerance", type=float, default=2.0, help="max seconds between matching records")
    ap.add_argument("--template", action="store_true", help="only write the empty template")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    if args.template or not args.reference:
        if not args.template:
            print("No --reference given: writing the template with 'not yet measured'.", file=sys.stderr)
        args.out.write_text(TEMPLATE, encoding="utf-8")
        print(f"Wrote {args.out}")
        return 0
    if not args.browsertrace:
        ap.error("--browsertrace is required with --reference")
    cols = dict(NIRSOFT)
    if args.format == "generic":
        if not (args.url_col and args.time_col):
            ap.error("--format generic needs --url-col and --time-col")
        cols = {"url": args.url_col, "time": args.time_col, "browser": args.browser_col}
    tz = timezone.utc if args.reference_tz.upper() == "UTC" else ZoneInfo(args.reference_tz)
    bt = load_browsertrace(args.browsertrace)
    ref, unparsed = load_reference(args.reference, cols, tz, args.time_format)
    result = compare(bt, ref, args.tolerance)
    args.out.write_text(render(result, args, unparsed, len(bt), len(ref)), encoding="utf-8")
    print(f"Wrote {args.out}: {result['both']} matched, {result['only_browsertrace']} only in BrowserTrace, "
          f"{result['only_reference']} only in reference")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
