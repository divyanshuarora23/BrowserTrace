"""The case database: schema, ingestion, and normalization.

One SQLite file per case. Writers always go through :class:`CaseDB`; the API layer
opens the same file read-only.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import tzinfo
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from browsertrace.core.audit import AuditLog
from browsertrace.core.schema import EVENT_FIELD_NAMES, Event
from browsertrace.core.timeutil import now_utc_iso, parse_iso

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS case_meta (
    case_id TEXT PRIMARY KEY,
    examiner TEXT,
    created_utc TEXT,
    tool_version TEXT,
    host_timezone TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS evidence_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    browser TEXT,
    profile TEXT,
    original_path TEXT,
    copy_path TEXT,
    sha256_original TEXT,
    sha256_copy TEXT,
    verified INTEGER,
    browser_version TEXT,
    collected_utc TEXT,
    note TEXT
);

CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT,
    browser TEXT,
    browser_version TEXT,
    profile TEXT,
    event_type TEXT,
    url TEXT,
    title TEXT,
    detail TEXT,
    transition TEXT,
    is_synced INTEGER,
    source_visit_id INTEGER,
    from_visit_id INTEGER,
    from_event_id INTEGER,
    is_recovered INTEGER,
    source_file TEXT,
    source_sha256 TEXT,
    source_record_id TEXT,
    UNIQUE(browser, profile, timestamp_utc, event_type, url, source_record_id)
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_url ON events(url);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_visit ON events(source_file, source_visit_id);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT,
    name TEXT,
    severity TEXT,
    attack TEXT,
    reason TEXT,
    created_utc TEXT
);

CREATE TABLE IF NOT EXISTS finding_events (
    finding_id INTEGER,
    event_id INTEGER,
    PRIMARY KEY (finding_id, event_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT,
    action TEXT,
    detail TEXT,
    level TEXT
);

CREATE TABLE IF NOT EXISTS custody_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT,
    original_path TEXT,
    copy_path TEXT,
    sha256_original TEXT,
    sha256_copy TEXT,
    match INTEGER,
    note TEXT
);
"""


@dataclass
class IngestStats:
    inserted: int = 0
    duplicates: int = 0
    flagged_future: int = 0
    flagged_out_of_order: int = 0


class CaseDB:
    """Read-write handle onto a case's SQLite database."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        register_sql_functions(self.conn)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "CaseDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- case metadata -------------------------------------------------
    def set_case_meta(
        self,
        case_id: str,
        examiner: str,
        tool_version: str,
        host_timezone: str,
        notes: str = "",
    ) -> None:
        self.conn.execute(
            "INSERT INTO case_meta (case_id, examiner, created_utc, tool_version, "
            "host_timezone, notes) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(case_id) DO UPDATE SET examiner=excluded.examiner, "
            "tool_version=excluded.tool_version, host_timezone=excluded.host_timezone, "
            "notes=excluded.notes",
            (case_id, examiner, now_utc_iso(), tool_version, host_timezone, notes),
        )
        self.conn.commit()

    def get_case_meta(self) -> dict | None:
        row = self.conn.execute("SELECT * FROM case_meta LIMIT 1").fetchone()
        return dict(row) if row else None

    # ---- evidence / custody --------------------------------------------
    def record_evidence_file(self, **fields) -> int:
        cols = ", ".join(fields.keys())
        placeholders = ", ".join(["?"] * len(fields))
        cur = self.conn.execute(
            f"INSERT INTO evidence_files ({cols}) VALUES ({placeholders})",
            tuple(fields.values()),
        )
        self.conn.commit()
        return cur.lastrowid

    def record_custody(self, **fields) -> None:
        fields.setdefault("timestamp_utc", now_utc_iso())
        cols = ", ".join(fields.keys())
        placeholders = ", ".join(["?"] * len(fields))
        self.conn.execute(
            f"INSERT INTO custody_log ({cols}) VALUES ({placeholders})",
            tuple(fields.values()),
        )
        self.conn.commit()

    def append_audit(self, audit: AuditLog) -> None:
        rows = [(e.timestamp_utc, e.action, e.detail, e.level) for e in audit.entries]
        self.conn.executemany(
            "INSERT INTO audit_log (timestamp_utc, action, detail, level) VALUES (?, ?, ?, ?)",
            rows,
        )
        self.conn.commit()

    # ---- events ----------------------------------------------------------
    def ingest_events(self, events: Iterable[Event], collection_time_utc: str | None = None) -> IngestStats:
        """Normalize and bulk-insert events inside a single transaction.

        Normalization: dedupe exact duplicates (handled by the UNIQUE constraint +
        INSERT OR IGNORE), flag out-of-order or future timestamps in ``detail``.
        """
        stats = IngestStats()
        events = sorted(events, key=lambda e: e.timestamp_utc or "")
        collection_dt = parse_iso(collection_time_utc) if collection_time_utc else None

        last_ts: str | None = None
        rows = []
        for ev in events:
            detail = ev.detail
            if collection_dt is not None and ev.timestamp_utc:
                try:
                    if parse_iso(ev.timestamp_utc) > collection_dt:
                        detail = (detail + "; " if detail else "") + "future timestamp"
                        stats.flagged_future += 1
                except ValueError:
                    pass
            if last_ts is not None and ev.timestamp_utc and ev.timestamp_utc < last_ts:
                detail = (detail + "; " if detail else "") + "out-of-order timestamp"
                stats.flagged_out_of_order += 1
            if ev.timestamp_utc:
                last_ts = ev.timestamp_utc

            rows.append(
                (
                    ev.timestamp_utc,
                    ev.browser,
                    ev.browser_version,
                    ev.profile,
                    ev.event_type,
                    ev.url,
                    ev.title,
                    detail,
                    ev.transition,
                    int(ev.is_synced),
                    ev.source_visit_id,
                    ev.from_visit_id,
                    ev.from_event_id,
                    int(ev.is_recovered),
                    ev.source_file,
                    ev.source_sha256,
                    ev.source_record_id,
                )
            )

        cur = self.conn.cursor()
        cur.execute("BEGIN")
        before = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        cur.executemany(
            "INSERT OR IGNORE INTO events "
            "(timestamp_utc, browser, browser_version, profile, event_type, url, title, "
            "detail, transition, is_synced, source_visit_id, from_visit_id, from_event_id, "
            "is_recovered, source_file, source_sha256, source_record_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        after = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.conn.commit()
        stats.inserted = after - before
        stats.duplicates = len(rows) - stats.inserted
        return stats

    def resolve_event_ids_for_visit_chain(self) -> None:
        """Populate ``from_event_id`` by resolving ``from_visit_id`` within the same
        browser/profile/evidence file. Delegates the graph walk to enrichment.chains,
        this just writes the result back."""
        from browsertrace.enrichment.chains import resolve_chain_links

        resolve_chain_links(self.conn)

    def query_events(self, limit: int = 200, offset: int = 0, **filters) -> list[dict]:
        return query_events(self.conn, limit=limit, offset=offset, **filters)

    def count_events(self, **filters) -> int:
        return count_events(self.conn, **filters)

    def get_event(self, event_id: int) -> dict | None:
        row = self.conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return dict(row) if row else None

    def stats(self) -> dict:
        return case_stats(self.conn)

    # ---- findings ----------------------------------------------------------
    def clear_findings(self) -> None:
        self.conn.execute("DELETE FROM finding_events")
        self.conn.execute("DELETE FROM findings")
        self.conn.commit()

    def insert_finding(self, rule_id: str, name: str, severity: str, attack: str, reason: str,
                        event_ids: list[int]) -> int:
        cur = self.conn.execute(
            "INSERT INTO findings (rule_id, name, severity, attack, reason, created_utc) "
            "VALUES (?,?,?,?,?,?)",
            (rule_id, name, severity, attack, reason, now_utc_iso()),
        )
        finding_id = cur.lastrowid
        self.conn.executemany(
            "INSERT OR IGNORE INTO finding_events (finding_id, event_id) VALUES (?, ?)",
            [(finding_id, eid) for eid in event_ids],
        )
        self.conn.commit()
        return finding_id

    def list_findings(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM findings ORDER BY "
            "CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, id"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_finding(self, finding_id: int) -> dict | None:
        row = self.conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            return None
        finding = dict(row)
        event_ids = [
            r["event_id"]
            for r in self.conn.execute(
                "SELECT event_id FROM finding_events WHERE finding_id = ?", (finding_id,)
            ).fetchall()
        ]
        finding["event_ids"] = event_ids
        return finding

    def all_events_ordered(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM events ORDER BY timestamp_utc").fetchall()
        return [dict(r) for r in rows]


def _event_where(
    browser: str | None = None,
    event_type: str | None = None,
    ts_from: str | None = None,
    ts_to: str | None = None,
    q: str | None = None,
    synced: bool | None = None,
    domain: str | None = None,
    hour: int | None = None,
    tz: str | None = None,
    finding_id: int | None = None,
) -> tuple[str, list]:
    """Build the WHERE clause. ``domain``/``hour`` need :func:`register_sql_functions`."""
    clauses: list[str] = []
    params: list = []
    if domain:
        clauses.append("bt_domain(url) = ?")
        params.append(domain.lower().removeprefix("www."))
    if hour is not None:
        clauses.append("bt_local_hour(timestamp_utc, ?) = ?")
        params.extend([tz or "UTC", int(hour)])
    if finding_id is not None:
        clauses.append("event_id IN (SELECT event_id FROM finding_events WHERE finding_id = ?)")
        params.append(int(finding_id))
    if browser:
        clauses.append("browser = ?")
        params.append(browser)
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if ts_from:
        clauses.append("timestamp_utc >= ?")
        params.append(ts_from)
    if ts_to:
        clauses.append("timestamp_utc <= ?")
        params.append(ts_to)
    if q:
        clauses.append("(url LIKE ? OR title LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])
    if synced is not None:
        clauses.append("is_synced = ?")
        params.append(int(synced))
    return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), params


def query_events(conn: sqlite3.Connection, limit: int = 200, offset: int = 0, **filters) -> list[dict]:
    where, params = _event_where(**filters)
    sql = f"SELECT * FROM events {where} ORDER BY timestamp_utc, event_id LIMIT ? OFFSET ?"
    rows = conn.execute(sql, [*params, int(limit), int(offset)]).fetchall()
    return [dict(r) for r in rows]


def count_events(conn: sqlite3.Connection, **filters) -> int:
    where, params = _event_where(**filters)
    return conn.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0]


def case_stats(conn: sqlite3.Connection) -> dict:
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    by_browser = {
        r[0]: r[1] for r in conn.execute("SELECT browser, COUNT(*) FROM events GROUP BY browser")
    }
    by_type = {
        r[0]: r[1] for r in conn.execute("SELECT event_type, COUNT(*) FROM events GROUP BY event_type")
    }
    by_severity = {"High": 0, "Medium": 0, "Low": 0}
    for r in conn.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity"):
        by_severity[r[0]] = r[1]
    synced = conn.execute("SELECT COUNT(*) FROM events WHERE is_synced = 1").fetchone()[0]
    recovered = conn.execute("SELECT COUNT(*) FROM events WHERE is_recovered = 1").fetchone()[0]
    span = conn.execute("SELECT MIN(timestamp_utc), MAX(timestamp_utc) FROM events").fetchone()
    return {
        "total_events": total,
        "by_browser": by_browser,
        "by_type": by_type,
        "by_severity": by_severity,
        "synced_events": synced,
        "recovered_events": recovered,
        "first_event_utc": span[0],
        "last_event_utc": span[1],
    }


def url_domain(url: str | None) -> str:
    """Host of a URL without a leading ``www.`` ('' if none)."""
    try:
        host = urlsplit(url or "").hostname or ""
    except ValueError:
        return ""
    return host.lower().removeprefix("www.")


@lru_cache(maxsize=32)
def _zone(name: str) -> tzinfo:
    from browsertrace.analysis.engine import parse_tz

    return parse_tz(name)


def local_hour(ts: str | None, tz_name: str | None) -> int | None:
    if not ts:
        return None
    try:
        return parse_iso(ts).astimezone(_zone(tz_name or "UTC")).hour
    except ValueError:
        return None


def register_sql_functions(conn: sqlite3.Connection) -> None:
    """SQL helpers used by the dashboard filters (domain and hour-of-day in a timezone)."""
    conn.create_function("bt_domain", 1, url_domain, deterministic=True)
    conn.create_function("bt_local_hour", 2, local_hour, deterministic=True)


def open_readonly(path: Path) -> sqlite3.Connection:
    """Open a case DB read-only, for the API layer."""
    conn = sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    register_sql_functions(conn)
    return conn


__all__ = [
    "CaseDB",
    "IngestStats",
    "open_readonly",
    "query_events",
    "count_events",
    "case_stats",
    "SCHEMA_SQL",
    "EVENT_FIELD_NAMES",
]
