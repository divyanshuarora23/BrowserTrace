"""Parser for Firefox ``places.sqlite``. Timestamps are PRTime (microseconds since 1970 UTC)."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import unquote, urlsplit

from browsertrace.core.audit import AuditLog
from browsertrace.core.schema import Event
from browsertrace.core.timeutil import prtime_to_utc
from browsertrace.parsers.base import (
    EMBED_FLAG,
    INTERNAL_FLAG,
    add_flag,
    col_or_null,
    extract_search_term,
    has_table,
    is_internal,
    open_readonly,
    table_columns,
)

VISIT_TYPES = {
    1: "link",
    2: "typed",
    3: "bookmark",
    4: "embed",
    5: "redirect_permanent",
    6: "redirect_temporary",
    7: "download",
    8: "framed_link",
    9: "reload",
}
FIREFOX_DOWNLOAD_STATES = {0: "in_progress", 1: "complete", 2: "failed", 3: "cancelled", 4: "paused"}


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
            is_synced=False,  # places.sqlite has no originator_cache_guid equivalent
        )
        visits = _parse_visits(conn, common, audit, src)
        events: list[Event] = list(visits)
        events.extend(_derive_url_searches(visits, common))
        events.extend(_parse_downloads(conn, common, audit, src, visits))
        audit.log("parse", f"{browser}/{profile}: {len(events)} events from {src}")
        audit.log(
            "limitation",
            f"{src}: Firefox does not record which device a visit came from; is_synced is always False",
        )
        return events
    finally:
        conn.close()


def _parse_visits(conn, common, audit: AuditLog, src: str) -> list[Event]:
    vcols = table_columns(conn, "moz_historyvisits")
    pcols = table_columns(conn, "moz_places")
    if not vcols or not pcols:
        audit.warning("parse", f"{src}: moz_historyvisits/moz_places missing; not a places.sqlite file?")
        return []
    sql = (
        "SELECT v.id AS vid, "
        f"{col_or_null(vcols, 'visit_date', prefix='v.')}, "
        f"{col_or_null(vcols, 'from_visit', prefix='v.')}, "
        f"{col_or_null(vcols, 'visit_type', prefix='v.')}, "
        f"{col_or_null(pcols, 'url', prefix='p.')}, "
        f"{col_or_null(pcols, 'title', prefix='p.')}, "
        "p.id AS place_id "
        "FROM moz_historyvisits v LEFT JOIN moz_places p ON p.id = v.place_id ORDER BY v.id"
    )
    out = []
    for r in conn.execute(sql):
        ts = prtime_to_utc(r["visit_date"])
        detail = ""
        if ts is None:
            detail = add_flag(detail, f"invalid timestamp (raw={r['visit_date']})")
            ts = ""
        url = r["url"] or ""
        vt = r["visit_type"]
        if vt == 4:
            detail = add_flag(detail, EMBED_FLAG)
        if is_internal(url):
            detail = add_flag(detail, INTERNAL_FLAG)
        ev = Event(
            timestamp_utc=ts,
            event_type="visit",
            url=url,
            title=r["title"] or "",
            detail=detail,
            transition=VISIT_TYPES.get(vt, f"unknown({vt})") if vt is not None else "",
            source_visit_id=r["vid"],
            from_visit_id=r["from_visit"] or None,
            source_record_id=f"moz_historyvisits:{r['vid']}",
            **common,
        )
        ev._place_id = r["place_id"]  # type: ignore[attr-defined]
        out.append(ev)
    return out


def _derive_url_searches(visits: list[Event], common) -> list[Event]:
    out = []
    for v in visits:
        if EMBED_FLAG in v.detail:
            continue
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
                source_visit_id=v.source_visit_id,
                source_record_id=v.source_record_id,
                **common,
            )
        )
    return out


def file_uri_to_path(uri: str) -> str:
    if not uri:
        return ""
    if uri.startswith("file://"):
        path = unquote(urlsplit(uri).path)
        # file:///C:/Users/... -> C:/Users/...
        if len(path) > 2 and path[0] == "/" and path[2] == ":":
            path = path[1:]
        return path
    return uri


def _parse_downloads(conn, common, audit: AuditLog, src: str, visits: list[Event]) -> list[Event]:
    anno_table = next((t for t in ("moz_annos", "moz_annotations") if has_table(conn, t)), None)
    out: list[Event] = []
    covered_places: set[int] = set()
    # visit_type 7 = "download" visits, keyed by place, for exact start times
    dl_visits: dict[int, Event] = {}
    for v in visits:
        if v.transition == "download":
            dl_visits.setdefault(getattr(v, "_place_id", None), v)

    if anno_table and has_table(conn, "moz_anno_attributes"):
        acols = table_columns(conn, anno_table)
        pcols = table_columns(conn, "moz_places")
        sql = (
            f"SELECT a.id AS aid, a.place_id AS place_id, attr.name AS name, a.content AS content, "
            f"{col_or_null(acols, 'dateAdded', prefix='a.')}, "
            f"{col_or_null(pcols, 'url', prefix='p.')} "
            f'FROM "{anno_table}" a JOIN moz_anno_attributes attr ON attr.id = a.anno_attribute_id '
            "LEFT JOIN moz_places p ON p.id = a.place_id "
            "WHERE attr.name IN ('downloads/destinationFileURI', 'downloads/metaData') ORDER BY a.id"
        )
        per_place: dict[int, dict] = {}
        for r in conn.execute(sql):
            rec = per_place.setdefault(r["place_id"], {"url": r["url"] or "", "rids": []})
            rec["rids"].append(r["aid"])
            if r["name"] == "downloads/destinationFileURI":
                rec["target"] = file_uri_to_path(r["content"] or "")
                rec["date_added"] = r["dateAdded"]
            else:
                try:
                    rec["meta"] = json.loads(r["content"] or "{}")
                except (json.JSONDecodeError, TypeError):
                    audit.warning("parse", f"{src}: unreadable downloads/metaData in annotation {r['aid']}")
                    rec["meta"] = {}
        for place_id, rec in per_place.items():
            covered_places.add(place_id)
            visit = dl_visits.get(place_id)
            ts = visit.timestamp_utc if visit else (prtime_to_utc(rec.get("date_added")) or "")
            meta = rec.get("meta", {})
            bits = [f"target={rec.get('target', '')}"]
            if "fileSize" in meta:
                bits.append(f"bytes={meta['fileSize']}")
            if "state" in meta:
                bits.append(f"state={FIREFOX_DOWNLOAD_STATES.get(meta['state'], meta['state'])}")
            if meta.get("endTime"):
                end = prtime_to_utc(int(meta["endTime"]) * 1000)  # endTime is milliseconds
                if end:
                    bits.append(f"end_time={end}")
            if not visit:
                bits.append("start time from annotation dateAdded")
            out.append(
                Event(
                    timestamp_utc=ts,
                    event_type="download",
                    url=rec["url"],
                    title=Path(rec.get("target", "")).name,
                    detail="; ".join(bits),
                    source_visit_id=visit.source_visit_id if visit else None,
                    source_record_id=f"{anno_table}:{min(rec['rids'])}",
                    **common,
                )
            )
    else:
        audit.warning("parse", f"{src}: no download annotations; using visit_type=7 visits only (no target path)")

    for place_id, visit in dl_visits.items():
        if place_id in covered_places:
            continue
        audit.log(
            "limitation",
            f"{src}: download of {visit.url} known only from a visit_type=7 record; target path unknown",
        )
        out.append(
            Event(
                timestamp_utc=visit.timestamp_utc,
                event_type="download",
                url=visit.url,
                title=Path(urlsplit(visit.url).path).name,
                detail="target=; from visit_type=7 only (no download metadata)",
                source_visit_id=visit.source_visit_id,
                source_record_id=visit.source_record_id,
                **common,
            )
        )
    return out
