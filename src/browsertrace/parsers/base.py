"""Helpers shared by all parsers: read-only opening, schema introspection, URL helpers."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from browsertrace.core.audit import AuditLog

INTERNAL_PREFIXES = (
    "chrome://",
    "edge://",
    "brave://",
    "opera://",
    "about:",
    "chrome-extension://",
    "moz-extension://",
    "devtools://",
    "view-source:",
)
INTERNAL_FLAG = "internal page"
EMBED_FLAG = "embedded resource"
APPROX_FLAG = "timestamp approximate"


class ParserError(Exception):
    """The database could not be opened or is not the expected kind of file."""


def open_readonly(db_path: Path, audit: AuditLog | None = None) -> sqlite3.Connection:
    """Open a SQLite file strictly read-only.

    Callers must only ever pass a *working copy* of evidence, never the original.
    """
    uri = f"file:{Path(db_path).resolve().as_posix()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
        conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
    except sqlite3.DatabaseError as exc:
        raise ParserError(f"cannot open {db_path} read-only as SQLite: {exc}") from exc
    conn.row_factory = sqlite3.Row
    return conn


def has_table(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name = ?", (table,)
    ).fetchone()
    return row is not None


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    if not has_table(conn, table):
        return set()
    return {r[1] for r in conn.execute(f'PRAGMA table_info("{table}")').fetchall()}


def col_or_null(columns: set[str], name: str, alias: str | None = None, prefix: str = "") -> str:
    """SQL fragment selecting ``prefix.name`` if it exists, else ``NULL`` (aliased either way)."""
    alias = alias or name
    if name in columns:
        return f"{prefix}{name} AS {alias}"
    return f"NULL AS {alias}"


def is_internal(url: str) -> bool:
    return (url or "").lower().startswith(INTERNAL_PREFIXES)


def add_flag(detail: str, flag: str) -> str:
    if not flag:
        return detail
    if not detail:
        return flag
    if flag in detail.split("; "):
        return detail
    return f"{detail}; {flag}"


# --- search-term derivation, shared so Chromium and Firefox get identical treatment ----

# host suffix -> query parameters that hold the search term, in priority order
SEARCH_ENGINES: dict[str, tuple[str, ...]] = {
    "google.": ("q",),
    "bing.com": ("q",),
    "duckduckgo.com": ("q",),
    "search.yahoo.com": ("p", "q"),
    "search.brave.com": ("q",),
    "yandex.": ("text", "q"),
    "baidu.com": ("wd", "word", "q"),
    "ecosia.org": ("q",),
    "youtube.com": ("search_query",),
}
_GENERIC_PARAMS = ("q", "query", "search_query", "p")


def search_engine_for(host: str) -> str | None:
    host = (host or "").lower()
    for key in SEARCH_ENGINES:
        if key.endswith("."):
            # google.com, www.google.co.in, ...
            if host.startswith(key) or f".{key}" in host:
                return key
        elif host == key or host.endswith("." + key):
            return key
    return None


def extract_search_term(url: str) -> tuple[str, str] | None:
    """Return ``(engine, term)`` if ``url`` is a search-results URL of a known engine."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https"):
        return None
    engine = search_engine_for(parts.hostname or "")
    if engine is None:
        return None
    path = parts.path or "/"
    if engine == "google." and not path.startswith("/search"):
        return None
    if engine == "bing.com" and not path.startswith("/search"):
        return None
    qs = parse_qs(parts.query)
    params = SEARCH_ENGINES[engine] + _GENERIC_PARAMS
    for p in params:
        values = qs.get(p)
        if values and values[0].strip():
            return engine.rstrip("."), values[0].strip()
    return None
