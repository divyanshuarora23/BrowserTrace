"""Parser for Chromium-family ``History`` databases (Chrome, Edge, Brave, Opera).

Timestamps are WebKit microseconds (since 1601-01-01 UTC). Every query is preceded by
``PRAGMA table_info`` introspection so that older/newer schema variants degrade
gracefully instead of raising.
"""

from __future__ import annotations

from pathlib import Path

from browsertrace.core.audit import AuditLog
from browsertrace.core.schema import Event
from browsertrace.core.timeutil import webkit_to_utc
from browsertrace.parsers.base import (
    APPROX_FLAG,
    INTERNAL_FLAG,
    add_flag,
    col_or_null,
    extract_search_term,
    has_table,
    is_internal,
    open_readonly,
    table_columns,
)

# ---- page transitions --------------------------------------------------------------
# Values from Chromium's ui/base/page_transition_types.h. Core type is the low byte.
CORE_TYPES = {
    0: "link",
    1: "typed",
    2: "auto_bookmark",
    3: "auto_subframe",
    4: "manual_subframe",
    5: "generated",
    6: "start_page",  # PAGE_TRANSITION_AUTO_TOPLEVEL
    7: "form_submit",
    8: "reload",
    9: "keyword",
    10: "keyword_generated",
}
CORE_MASK = 0xFF

# Qualifier bits, low to high, exactly as defined in Chromium.
QUALIFIERS = (
    (0x00800000, "blocked"),
    (0x01000000, "forward_back"),
    (0x02000000, "from_address_bar"),
    (0x04000000, "home_page"),
    (0x08000000, "from_api"),
    (0x10000000, "chain_start"),
    (0x20000000, "chain_end"),
    (0x40000000, "client_redirect"),
    (0x80000000, "server_redirect"),
)


def decode_transition(value: int | None) -> str:
    """Decode a Chromium transition integer into e.g. ``"typed [from_address_bar]"``."""
    if value is None:
        return ""
    try:
        value = int(value) & 0xFFFFFFFF  # stored signed in SQLite on some versions
    except (TypeError, ValueError):
        return ""
    core = CORE_TYPES.get(value & CORE_MASK, f"unknown({value & CORE_MASK})")
    quals = [name for bit, name in QUALIFIERS if value & bit]
    return f"{core} [{', '.join(quals)}]" if quals else core


DOWNLOAD_STATES = {0: "in_progress", 1: "complete", 2: "cancelled", 3: "interrupted", 4: "interrupted"}
DANGER_TYPES = {
    0: "not_dangerous",
    1: "dangerous_file",
    2: "dangerous_url",
    3: "dangerous_content",
    4: "maybe_dangerous_content",
    5: "uncommon_content",
    6: "user_validated",
    7: "dangerous_host",
    8: "potentially_unwanted",
    9: "allowlisted_by_policy",
}


def parse(
    db_path: Path,
    browser: str,
    profile: str,
    sha256: str,
    *,
    browser_version: str = "unknown",
    source_file: str | None = None,
    audit: AuditLog | None = None,
) -> list[Event]:
    audit = audit if audit is not None else AuditLog()
    src = source_file or str(db_path)
    conn = open_readonly(Path(db_path), audit)
    try:
        common = dict(
            browser=browser,
            browser_version=browser_version,
            profile=profile,
            source_file=src,
            source_sha256=sha256,
        )
        events: list[Event] = []
        visits = _parse_visits(conn, common, audit, src)
        events.extend(visits)
        events.extend(_derive_url_searches(visits, common))
        events.extend(_parse_keyword_searches(conn, common, audit, src, visits))
        events.extend(_parse_downloads(conn, common, audit, src))
        audit.log("parse", f"{browser}/{profile}: {len(events)} events from {src}")
        return events
    finally:
        conn.close()


def _parse_visits(conn, common, audit: AuditLog, src: str) -> list[Event]:
    vcols = table_columns(conn, "visits")
    ucols = table_columns(conn, "urls")
    if not vcols or not ucols:
        audit.warning("parse", f"{src}: no visits/urls table; not a Chromium History file?")
        return []
    if "originator_cache_guid" not in vcols:
        audit.warning(
            "parse",
            f"{src}: visits.originator_cache_guid missing (older Chromium); sync origin cannot be determined",
        )
    sql = (
        "SELECT v.id AS vid, v.visit_time AS vtime, "
        f"{col_or_null(vcols, 'from_visit', prefix='v.')}, "
        f"{col_or_null(vcols, 'transition', prefix='v.')}, "
        f"{col_or_null(vcols, 'originator_cache_guid', prefix='v.')}, "
        f"{col_or_null(ucols, 'url', prefix='u.')}, "
        f"{col_or_null(ucols, 'title', prefix='u.')}, "
        "u.id AS url_id "
        "FROM visits v LEFT JOIN urls u ON u.id = v.url ORDER BY v.id"
    )
    out: list[Event] = []
    for r in conn.execute(sql):
        ts = webkit_to_utc(r["vtime"])
        detail = ""
        if ts is None:
            detail = add_flag(detail, f"invalid timestamp (raw={r['vtime']})")
            ts = ""
        url = r["url"] or ""
        if is_internal(url):
            detail = add_flag(detail, INTERNAL_FLAG)
        synced = bool(r["originator_cache_guid"])
        if synced:
            detail = add_flag(detail, "synced from another device")
        ev = Event(
            timestamp_utc=ts,
            event_type="visit",
            url=url,
            title=r["title"] or "",
            detail=detail,
            transition=decode_transition(r["transition"]),
            is_synced=synced,
            source_visit_id=r["vid"],
            from_visit_id=r["from_visit"] or None,
            source_record_id=f"visits:{r['vid']}",
            **common,
        )
        ev._url_id = r["url_id"]  # type: ignore[attr-defined]  # transient, for dedupe
        out.append(ev)
    return out


def _derive_url_searches(visits: list[Event], common) -> list[Event]:
    out = []
    for v in visits:
        found = extract_search_term(v.url)
        if not found:
            continue
        engine, term = found
        out.append(
            Event(
                timestamp_utc=v.timestamp_utc,
                event_type="search",
                url=v.url,
                title=term,
                detail=f"engine={engine}; derived from visited URL",
                transition=v.transition,
                is_synced=v.is_synced,
                source_visit_id=v.source_visit_id,
                source_record_id=v.source_record_id,
                **common,
            )
        )
    return out


def _parse_keyword_searches(conn, common, audit: AuditLog, src: str, visits: list[Event]) -> list[Event]:
    kcols = table_columns(conn, "keyword_search_terms")
    if not kcols:
        audit.warning("parse", f"{src}: keyword_search_terms table missing; relying on URL-derived searches")
        return []
    ucols = table_columns(conn, "urls")
    # URL ids already covered by a URL-derived search with an exact visit time.
    derived: set[tuple[int, str]] = set()
    for v in visits:
        found = extract_search_term(v.url)
        if found:
            derived.add((getattr(v, "_url_id", None), found[1].lower()))
    sql = (
        "SELECT k.rowid AS rid, k.term AS term, k.url_id AS url_id, "
        f"{col_or_null(ucols, 'url', prefix='u.')}, "
        f"{col_or_null(ucols, 'last_visit_time', prefix='u.')} "
        "FROM keyword_search_terms k LEFT JOIN urls u ON u.id = k.url_id"
    )
    out = []
    for r in conn.execute(sql):
        term = (r["term"] or "").strip()
        if not term or (r["url_id"], term.lower()) in derived:
            continue
        ts = webkit_to_utc(r["last_visit_time"]) or ""
        out.append(
            Event(
                timestamp_utc=ts,
                event_type="search",
                url=r["url"] or "",
                title=term,
                detail=f"source=keyword_search_terms; {APPROX_FLAG}",
                source_record_id=f"keyword_search_terms:{r['rid']}",
                **common,
            )
        )
    return out


def _parse_downloads(conn, common, audit: AuditLog, src: str) -> list[Event]:
    dcols = table_columns(conn, "downloads")
    if not dcols:
        audit.warning("parse", f"{src}: downloads table missing")
        return []
    chain_table = None
    for name in ("downloads_url_chains", "download_url_chains"):
        if has_table(conn, name):
            chain_table = name
            break
    chain_urls: dict[int, str] = {}
    if chain_table:
        # The last URL in the chain is the final (post-redirect) download URL.
        for r in conn.execute(f'SELECT id, chain_index, url FROM "{chain_table}" ORDER BY id, chain_index'):
            chain_urls[r["id"]] = r["url"]
    else:
        audit.warning("parse", f"{src}: no downloads_url_chains table; falling back to downloads.url/tab_url")

    path_col = "target_path" if "target_path" in dcols else ("full_path" if "full_path" in dcols else None)
    fields = [
        "id",
        col_or_null(dcols, "start_time"),
        f"{path_col} AS target_path" if path_col else "NULL AS target_path",
        col_or_null(dcols, "total_bytes"),
        col_or_null(dcols, "mime_type"),
        col_or_null(dcols, "referrer"),
        col_or_null(dcols, "tab_url"),
        col_or_null(dcols, "site_url"),
        col_or_null(dcols, "url"),
        col_or_null(dcols, "danger_type"),
        col_or_null(dcols, "state"),
    ]
    out = []
    for r in conn.execute(f"SELECT {', '.join(fields)} FROM downloads ORDER BY id"):
        url = chain_urls.get(r["id"]) or r["url"] or r["tab_url"] or r["site_url"] or ""
        ts = webkit_to_utc(r["start_time"]) or ""
        bits = [f"target={r['target_path'] or ''}"]
        if r["total_bytes"] is not None:
            bits.append(f"bytes={r['total_bytes']}")
        if r["mime_type"]:
            bits.append(f"mime={r['mime_type']}")
        if r["state"] is not None:
            bits.append(f"state={DOWNLOAD_STATES.get(r['state'], r['state'])}")
        if r["danger_type"] is not None:
            bits.append(f"danger={DANGER_TYPES.get(r['danger_type'], r['danger_type'])}")
        if r["referrer"]:
            bits.append(f"referrer={r['referrer']}")
        if r["tab_url"]:
            bits.append(f"tab_url={r['tab_url']}")
        out.append(
            Event(
                timestamp_utc=ts,
                event_type="download",
                url=url,
                title=Path(str(r["target_path"] or "").replace("\\", "/")).name,
                detail="; ".join(bits),
                source_record_id=f"downloads:{r['id']}",
                **common,
            )
        )
    return out
