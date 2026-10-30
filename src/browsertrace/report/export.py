"""CSV and JSON export.

The CSV uses Timesketch's required columns (``message``, ``datetime``, ``timestamp_desc``,
plus ``timestamp`` in microseconds) followed by every BrowserTrace field, so it can be
imported into Timesketch as-is and still round-trips all provenance data.
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from pathlib import Path

from browsertrace.core.db import case_stats
from browsertrace.core.timeutil import parse_iso

EVENT_COLUMNS = [
    "event_id", "timestamp_utc", "browser", "browser_version", "profile", "event_type", "url",
    "title", "detail", "transition", "is_synced", "is_recovered", "source_visit_id", "from_visit_id",
    "from_event_id", "source_file", "source_sha256", "source_record_id",
]
TIMESKETCH_COLUMNS = ["message", "datetime", "timestamp", "timestamp_desc"]
CSV_COLUMNS = TIMESKETCH_COLUMNS + EVENT_COLUMNS + ["finding_rule_ids"]

TIMESTAMP_DESC = {
    "visit": "Last Visited Time",
    "download": "File Downloaded",
    "search": "Search Time",
    "deleted_visit": "Recovered Visit Time (partial)",
}


def _message(ev: dict) -> str:
    prefix = []
    if ev.get("is_recovered"):
        prefix.append("[RECOVERED/PARTIAL]")
    if ev.get("is_synced"):
        prefix.append("[SYNCED]")
    body = f"{ev['browser']} {ev['event_type']}: {ev.get('title') or ''} {ev.get('url') or ''}".strip()
    return " ".join(prefix + [body])


def _finding_map(conn: sqlite3.Connection) -> dict[int, str]:
    out: dict[int, list[str]] = {}
    for eid, rid in conn.execute(
        "SELECT fe.event_id, f.rule_id FROM finding_events fe JOIN findings f ON f.id = fe.finding_id"
    ):
        out.setdefault(eid, []).append(rid)
    return {k: ",".join(sorted(set(v))) for k, v in out.items()}


def iter_export_rows(conn: sqlite3.Connection):
    conn.row_factory = sqlite3.Row
    fmap = _finding_map(conn)
    for r in conn.execute("SELECT * FROM events ORDER BY timestamp_utc, event_id"):
        ev = dict(r)
        ts = ev["timestamp_utc"] or ""
        micros = ""
        if ts:
            dt = parse_iso(ts)
            micros = int(dt.timestamp()) * 1_000_000 + dt.microsecond
        row = {
            "message": _message(ev),
            "datetime": ts,
            "timestamp": micros,
            "timestamp_desc": TIMESTAMP_DESC.get(ev["event_type"], ev["event_type"]),
            **{c: ev.get(c) for c in EVENT_COLUMNS},
            "finding_rule_ids": fmap.get(ev["event_id"], ""),
        }
        row["is_synced"] = bool(row["is_synced"])
        row["is_recovered"] = bool(row["is_recovered"])
        yield row


def export_csv_text(conn: sqlite3.Connection, tz_name: str | None = None, zone=None) -> str:
    """CSV text. With ``zone``, two extra columns give each time in that timezone
    (the Timesketch ``datetime`` column always stays UTC)."""
    buf = io.StringIO()
    columns = CSV_COLUMNS + (["datetime_local", "local_timezone"] if zone is not None else [])
    w = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for row in iter_export_rows(conn):
        if zone is not None:
            ts = row["datetime"]
            row["datetime_local"] = parse_iso(ts).astimezone(zone).isoformat() if ts else ""
            row["local_timezone"] = tz_name
        w.writerow(row)
    return buf.getvalue()


def write_csv(conn: sqlite3.Connection, out: Path) -> Path:
    Path(out).write_text(export_csv_text(conn), encoding="utf-8", newline="")
    return Path(out)


def export_json_obj(conn: sqlite3.Connection) -> dict:
    conn.row_factory = sqlite3.Row
    meta = conn.execute("SELECT * FROM case_meta LIMIT 1").fetchone()
    findings = []
    for f in conn.execute("SELECT * FROM findings ORDER BY id"):
        f = dict(f)
        f["event_ids"] = [r[0] for r in conn.execute(
            "SELECT event_id FROM finding_events WHERE finding_id = ? ORDER BY event_id", (f["id"],))]
        findings.append(f)
    return {
        "disclaimer": "Findings are investigative leads produced by rules, not proof. Verify against the source records.",
        "case": dict(meta) if meta else {},
        "stats": case_stats(conn),
        "evidence_files": [dict(r) for r in conn.execute("SELECT * FROM evidence_files ORDER BY id")],
        "custody_log": [dict(r) for r in conn.execute("SELECT * FROM custody_log ORDER BY id")],
        "findings": findings,
        "events": list(iter_export_rows(conn)),
    }


def write_json(conn: sqlite3.Connection, out: Path) -> Path:
    Path(out).write_text(json.dumps(export_json_obj(conn), indent=2, default=str), encoding="utf-8")
    return Path(out)
