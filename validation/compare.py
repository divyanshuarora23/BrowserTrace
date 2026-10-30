"""Compare a BrowserTrace CSV export with a reference tool's export.

Usage:
    python validation/compare.py --browsertrace events.csv --reference bhv.csv [--reference-tz UTC]
                                 [--format nirsoft|generic|hindsight-jsonl] [--url-col ...] [--time-col ...]
                                 [--browser-col ...] [--time-format ...] [--tolerance 2] [--out docs/VALIDATION.md]
    python validation/compare.py --browsertrace events.csv --reference hindsight.jsonl
                                 --format hindsight-jsonl --out hindsight_validation.md
    python validation/compare.py --template [--out docs/VALIDATION.md]

Reference formats:
  * ``nirsoft``  NirSoft BrowsingHistoryView "Save all items" CSV (columns URL, Visit Time,
    Web Browser). Turn on "Options > Show Time In GMT" before exporting, or pass
    ``--reference-tz`` with the timezone the export was made in.
  * ``generic``  any CSV (e.g. Hindsight's XLSX saved as CSV) with ``--url-col`` and
    ``--time-col`` (and optionally ``--browser-col``) naming the columns.
  * ``hindsight-jsonl`` Hindsight JSONL output; compares visits and downloads by inferred
    browser/profile, normalized URL and timestamp. Repeated Hindsight downloads collapse
    by profile + download_id, retaining the first JSONL row.

NirSoft and generic CSV mode compare visits. Hindsight JSONL mode compares visits and
downloads. Every number in the output is computed from the two input files; if no
reference file is given, the template is written with "not yet measured".
"""

from __future__ import annotations

import argparse
import csv
import json
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
    profile: str = ""


def norm_browser(s: str) -> str:
    s = (s or "").lower()
    for key, name in (("edge", "Edge"), ("chromium", "Chromium"), ("chrome", "Chrome"),
                      ("firefox", "Firefox"), ("brave", "Brave"), ("opera", "Opera")):
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


def _hindsight_profile(value: str | None) -> tuple[str, str]:
    """Infer BrowserTrace's browser/profile labels from Hindsight's profile path."""
    parts = [p for p in (value or "").replace("\\", "/").split("/") if p]
    lower = [p.lower() for p in parts]
    browser = next((name for marker, name in (
        ("edge", "Edge"), ("opera", "Opera"), ("firefox", "Firefox"),
        ("brave", "Brave"), ("chromium", "Chromium"), ("chrome", "Chrome"),
    ) if marker in lower), "")
    if not browser or not parts:
        return "", ""

    profile = parts[-1]
    if browser == "Firefox" and "profiles" in lower:
        profile = parts[lower.index("profiles") + 1] if lower.index("profiles") + 1 < len(parts) else profile
    elif browser == "Opera" and profile.endswith("_Default"):
        profile = profile[:-len("_Default")]
    return browser, profile


def load_hindsight_jsonl(path: Path, tz) -> tuple[dict[str, list[Rec]], dict]:
    """Load Hindsight JSONL history/download records.

    Hindsight can emit multiple JSONL rows for a single Chromium download ID. Collapse
    those by inferred profile and download_id, retaining the first row as the canonical
    download record (matching BrowserTrace's one-event-per-download representation).
    """
    records: dict[str, list[Rec]] = {"visit": [], "download": []}
    stats = {"raw_visits": 0, "raw_downloads": 0, "download_duplicates": 0,
             "bad_json": 0, "bad_time": 0, "unknown_profile": 0, "unsupported": 0}
    seen_downloads: set[tuple[str, str, str]] = set()
    with path.open(encoding="utf-8-sig") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                stats["bad_json"] += 1
                continue
            data_type = str(row.get("data_type") or "").lower()
            if data_type.endswith("page_visited"):
                event_type = "visit"
                stats["raw_visits"] += 1
            elif data_type.endswith("file_downloaded"):
                event_type = "download"
                stats["raw_downloads"] += 1
            else:
                stats["unsupported"] += 1
                continue

            browser, profile = _hindsight_profile(row.get("profile"))
            if not browser or not profile:
                stats["unknown_profile"] += 1
                continue
            if event_type == "download":
                download_id = row.get("download_id")
                if download_id not in (None, ""):
                    identity = (browser, profile, str(download_id))
                    if identity in seen_downloads:
                        stats["download_duplicates"] += 1
                        continue
                    seen_downloads.add(identity)

            when = parse_time(str(row.get("datetime") or ""), tz, None)
            if when is None:
                stats["bad_time"] += 1
                continue
            records[event_type].append(Rec(browser, norm_url(str(row.get("url") or "")), when, profile))
    stats["unique_downloads"] = len(records["download"])
    return records, stats


def load_browsertrace_events(path: Path) -> dict[str, list[Rec]]:
    records: dict[str, list[Rec]] = {"visit": [], "download": []}
    for row in _read_csv(path):
        event_type = row.get("event_type")
        if event_type not in records:
            continue
        when = parse_time(row.get("timestamp_utc", ""), timezone.utc, None)
        if when is None:
            continue
        records[event_type].append(Rec(
            norm_browser(row.get("browser", "")),
            norm_url(row.get("url", "")),
            when,
            row.get("profile", ""),
        ))
    return records


def compare_profiled(bt: list[Rec], ref: list[Rec], tolerance_s: float) -> dict:
    """Compare one event type using one-to-one timestamp matching per profile and URL."""
    bt_groups: dict[tuple[str, str, str], list[Rec]] = defaultdict(list)
    ref_groups: dict[tuple[str, str, str], list[Rec]] = defaultdict(list)
    for rec in bt:
        bt_groups[(rec.browser, rec.profile, rec.url)].append(rec)
    for rec in ref:
        ref_groups[(rec.browser, rec.profile, rec.url)].append(rec)

    matched = only_bt = only_ref = 0
    diffs: list[float] = []
    per_profile: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0, 0])
    for key in bt_groups.keys() | ref_groups.keys():
        bt_rows = sorted(bt_groups.get(key, []), key=lambda rec: rec.t)
        ref_rows = sorted(ref_groups.get(key, []), key=lambda rec: rec.t)
        i = j = 0
        while i < len(bt_rows) and j < len(ref_rows):
            delta = (ref_rows[j].t - bt_rows[i].t).total_seconds()
            profile_stats = per_profile[(key[0], key[1])]
            if abs(delta) <= tolerance_s:
                matched += 1
                profile_stats[0] += 1
                diffs.append(abs(delta))
                i += 1
                j += 1
            elif delta > 0:
                only_bt += 1
                profile_stats[1] += 1
                i += 1
            else:
                only_ref += 1
                profile_stats[2] += 1
                j += 1
        remaining_bt, remaining_ref = len(bt_rows) - i, len(ref_rows) - j
        only_bt += remaining_bt
        only_ref += remaining_ref
        profile_stats = per_profile[(key[0], key[1])]
        profile_stats[1] += remaining_bt
        profile_stats[2] += remaining_ref

    return {
        "matched": matched,
        "only_browsertrace": only_bt,
        "only_hindsight": only_ref,
        "mean_delta": statistics.fmean(diffs) if diffs else None,
        "max_delta": max(diffs) if diffs else None,
        "browsertrace_count": len(bt),
        "hindsight_count": len(ref),
        "per_profile": dict(sorted(per_profile.items())),
    }


def render_hindsight_report(args, comparisons: dict, ref_stats: dict) -> str:
    def seconds(value):
        return "n/a" if value is None else f"{value:.6f}"

    lines = [
        "# BrowserTrace / Hindsight validation", "",
        "Generated from the supplied exports. These counts measure artifact agreement; they do not validate risk findings.", "",
        f"- BrowserTrace CSV: `{args.browsertrace}`",
        f"- Hindsight JSONL: `{args.reference}`",
        f"- Match rule: same browser, profile and normalized URL; timestamps within {args.tolerance:g} seconds.",
        "- Hindsight download rows collapsed by profile and download ID; the first row for each ID is retained.",
        f"- Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}", "",
        "## Results", "", "| Artifact | BrowserTrace | Hindsight | Matched | Only BrowserTrace | Only Hindsight | Mean / max Δt (s) |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for event_type in ("visit", "download"):
        result = comparisons[event_type]
        lines.append(
            f"| {event_type.title()} | {result['browsertrace_count']} | {result['hindsight_count']} | "
            f"{result['matched']} | {result['only_browsertrace']} | {result['only_hindsight']} | "
            f"{seconds(result['mean_delta'])} / {seconds(result['max_delta'])} |"
        )
    lines += ["", "## By browser and profile", "", "| Artifact | Browser | Profile | Matched | Only BrowserTrace | Only Hindsight |", "|---|---|---|---:|---:|---:|"]
    for event_type in ("visit", "download"):
        for (browser, profile), values in comparisons[event_type]["per_profile"].items():
            lines.append(f"| {event_type.title()} | {browser} | {profile} | {values[0]} | {values[1]} | {values[2]} |")
    lines += [
        "", "## Hindsight rows", "",
        f"- Visit rows: {ref_stats['raw_visits']}",
        f"- Download rows before ID collapse: {ref_stats['raw_downloads']}",
        f"- Repeated download rows collapsed: {ref_stats['download_duplicates']}",
        f"- Download records after ID collapse: {ref_stats['unique_downloads']}",
        f"- Malformed JSON lines: {ref_stats['bad_json']}",
        f"- Records with unparseable timestamps: {ref_stats['bad_time']}",
        f"- Records with unrecognized browser/profile paths: {ref_stats['unknown_profile']}",
        f"- Other Hindsight JSONL record types not compared: {ref_stats['unsupported']}",
        "", "Search artifacts and risk findings are not compared by this report.", "",
    ]
    return "\n".join(lines)


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
    ap.add_argument("--format", choices=("nirsoft", "generic", "hindsight-jsonl"), default="nirsoft")
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
    if args.tolerance < 0:
        ap.error("--tolerance must be zero or greater")
    if args.format == "hindsight-jsonl":
        tz = timezone.utc if args.reference_tz.upper() == "UTC" else ZoneInfo(args.reference_tz)
        bt = load_browsertrace_events(args.browsertrace)
        ref, ref_stats = load_hindsight_jsonl(args.reference, tz)
        comparisons = {
            event_type: compare_profiled(bt[event_type], ref[event_type], args.tolerance)
            for event_type in ("visit", "download")
        }
        args.out.write_text(render_hindsight_report(args, comparisons, ref_stats), encoding="utf-8")
        print(
            f"Wrote {args.out}: visits {comparisons['visit']['matched']}/{comparisons['visit']['hindsight_count']} matched; "
            f"downloads {comparisons['download']['matched']}/{comparisons['download']['hindsight_count']} matched"
        )
        return 0
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
