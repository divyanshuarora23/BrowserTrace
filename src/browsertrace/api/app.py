"""Read-only FastAPI app serving one case's database and the offline dashboard."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, time
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from browsertrace.analysis.engine import (
    RuleError,
    _in_window,
    _parse_hhmm,
    load_rules,
    parse_off_hours,
    parse_tz,
)
from browsertrace.collector.collect import verify_case_evidence
from browsertrace.core.db import CaseDB, case_stats, count_events, open_readonly, query_events, url_domain
from browsertrace.core.timeutil import parse_iso
from browsertrace.enrichment.chains import get_chain
from browsertrace.pipeline import case_db_path
from browsertrace.report.export import export_csv_text, export_json_obj
from browsertrace.report.pdf import build_pdf
from browsertrace.version import __version__

STATIC_DIR = Path(__file__).parent / "static"
MAX_LIMIT = 1000


class FindingReviewInput(BaseModel):
    reviewed_by: str = Field(default="", max_length=120)
    risk_level: Literal["Low", "Medium", "High", "Unclear"]
    outcome: Literal["Concerning", "Benign", "Needs more context"]
    rationale: str = Field(min_length=1, max_length=2000)
    confidence: Literal["Low", "Medium", "High"]

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)


def _check_tz(name: str):
    try:
        return parse_tz(name)
    except ValueError:
        raise HTTPException(400, f"unknown timezone {name!r}") from None


def create_app(case_dir: Path) -> FastAPI:
    case_dir = Path(case_dir)
    db_path = case_db_path(case_dir)
    if not db_path.is_file():
        raise FileNotFoundError(f"no case database at {db_path}; run 'browsertrace analyze' first")

    # Apply additive schema updates for case databases created by earlier versions.
    with CaseDB(db_path):
        pass

    app = FastAPI(title="BrowserTrace", version=__version__, docs_url="/api/docs", redoc_url=None)
    verification: dict = {}

    @contextmanager
    def conn():
        c = open_readonly(db_path)
        try:
            yield c
        finally:
            c.close()

    def _verify(*, force: bool = False) -> dict:
        if force:
            verification.clear()
        if not verification:
            with conn() as c:
                results = verify_case_evidence(c, case_dir)
            verification["files"] = results
            verification["all_ok"] = bool(results) and all(r["status"] == "ok" for r in results)
        return verification

    @app.middleware("http")
    async def security_headers(request, call_next):
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/api/case")
    def case():
        with conn() as c:
            meta = c.execute("SELECT * FROM case_meta LIMIT 1").fetchone()
            evidence = [dict(r) for r in c.execute("SELECT * FROM evidence_files ORDER BY id")]
        return {"case": dict(meta) if meta else {}, "evidence_files": evidence, "verification": _verify(),
                "tool_version": __version__}

    @app.get("/api/stats")
    def stats():
        with conn() as c:
            return case_stats(c)

    def _evidence_payload(v: dict) -> dict:
        by_copy = {r["copy_path"]: r for r in v.get("files", [])}
        with conn() as c:
            files = []
            # Re-running collection on the same case folder adds a new row per target each
            # time; only the latest row per copy_path reflects the file as it is on disk now.
            for row in c.execute(
                "SELECT e.* FROM evidence_files e JOIN "
                "(SELECT copy_path, MAX(id) AS id FROM evidence_files GROUP BY copy_path) latest "
                "ON latest.copy_path = e.copy_path AND latest.id = e.id ORDER BY e.id"
            ):
                row = dict(row)
                result = by_copy.get(row["copy_path"], {})
                copy_file = Path(row["copy_path"] or "")
                if not copy_file.is_absolute():
                    copy_file = case_dir / copy_file
                row["size_bytes"] = copy_file.stat().st_size if copy_file.is_file() else None
                row["status"] = result.get("status", "unknown")
                files.append(row)
            custody_log = [dict(r) for r in c.execute("SELECT * FROM custody_log ORDER BY id")]
            audit_log = [dict(r) for r in c.execute("SELECT * FROM audit_log ORDER BY id")]
        return {"files": files, "custody_log": custody_log, "audit_log": audit_log, "all_ok": v.get("all_ok", False)}

    @app.get("/api/evidence")
    def evidence():
        return _evidence_payload(_verify())

    @app.post("/api/evidence/verify")
    def evidence_verify():
        return _evidence_payload(_verify(force=True))

    @app.get("/api/events")
    def events(
        browser: str | None = None,
        type: str | None = None,
        from_: str | None = Query(None, alias="from"),
        to: str | None = None,
        q: str | None = None,
        synced: bool | None = None,
        domain: str | None = None,
        hour: int | None = Query(None, ge=0, le=23),
        tz: str | None = None,
        finding: int | None = None,
        limit: int = Query(200, ge=1, le=MAX_LIMIT),
        offset: int = Query(0, ge=0),
    ):
        if tz:
            _check_tz(tz)
        filters = dict(browser=browser or None, event_type=type or None, ts_from=from_ or None, ts_to=to or None,
                       q=q or None, synced=synced, domain=domain or None, hour=hour, tz=tz or "UTC",
                       finding_id=finding)
        with conn() as c:
            return {
                "total": count_events(c, **filters),
                "limit": limit,
                "offset": offset,
                "events": query_events(c, limit=limit, offset=offset, **filters),
            }

    @app.get("/api/events/position/{event_id}")
    def event_position(event_id: int):
        """Index of an event in the unfiltered timeline, so the UI can page to it."""
        with conn() as c:
            row = c.execute("SELECT timestamp_utc FROM events WHERE event_id = ?", (event_id,)).fetchone()
            if not row:
                raise HTTPException(404, "event not found")
            pos = c.execute(
                "SELECT COUNT(*) FROM events WHERE timestamp_utc < ? OR (timestamp_utc = ? AND event_id < ?)",
                (row[0], row[0], event_id),
            ).fetchone()[0]
        return {"event_id": event_id, "position": pos}

    @app.get("/api/findings")
    def findings():
        with conn() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT f.*, r.reviewed_by, r.risk_level, r.outcome, r.rationale, r.confidence, r.reviewed_utc, "
                "COUNT(e.event_id) AS event_count, MIN(e.timestamp_utc) AS first_time, "
                "MAX(e.timestamp_utc) AS last_time "
                "FROM findings f LEFT JOIN finding_events fe ON fe.finding_id = f.id "
                "LEFT JOIN finding_reviews r ON r.finding_id = f.id "
                "LEFT JOIN events e ON e.event_id = fe.event_id GROUP BY f.id "
                "ORDER BY CASE f.severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, f.id")]
            for f in rows:
                f["event_ids"] = [r[0] for r in c.execute(
                    "SELECT event_id FROM finding_events WHERE finding_id = ? ORDER BY event_id", (f["id"],))]
        return rows

    @app.get("/api/findings/{finding_id}")
    def finding(finding_id: int):
        with conn() as c:
            row = c.execute(
                "SELECT f.*, r.reviewed_by, r.risk_level, r.outcome, r.rationale, r.confidence, r.reviewed_utc "
                "FROM findings f LEFT JOIN finding_reviews r ON r.finding_id = f.id WHERE f.id = ?",
                (finding_id,),
            ).fetchone()
            if not row:
                raise HTTPException(404, "finding not found")
            f = dict(row)
            f["events"] = [dict(r) for r in c.execute(
                "SELECT e.* FROM finding_events fe JOIN events e ON e.event_id = fe.event_id "
                "WHERE fe.finding_id = ? ORDER BY e.timestamp_utc", (finding_id,))]
        return f

    @app.put("/api/findings/{finding_id}/review")
    def save_finding_review(finding_id: int, review: FindingReviewInput, request: Request):
        origin = request.headers.get("origin")
        parsed_origin = urlsplit(origin) if origin else None
        if (parsed_origin is None or parsed_origin.scheme != "http"
                or parsed_origin.hostname not in {"127.0.0.1", "localhost"}):
            raise HTTPException(403, "review updates must come from the local BrowserTrace page")
        rationale = review.rationale.strip()
        if not rationale:
            raise HTTPException(422, "rationale cannot be blank")
        with CaseDB(db_path) as db:
            if not db.get_finding(finding_id):
                raise HTTPException(404, "finding not found")
            saved = db.save_finding_review(
                finding_id,
                reviewed_by=review.reviewed_by.strip(),
                risk_level=review.risk_level,
                outcome=review.outcome,
                rationale=rationale,
                confidence=review.confidence,
            )
        return saved

    @app.get("/api/chain/{event_id}")
    def chain(event_id: int):
        with conn() as c:
            c.row_factory = sqlite3.Row
            if not c.execute("SELECT 1 FROM events WHERE event_id = ?", (event_id,)).fetchone():
                raise HTTPException(404, "event not found")
            return {"event_id": event_id, "chain": get_chain(c, event_id)}

    @app.get("/api/event/{event_id}")
    def event(event_id: int):
        with conn() as c:
            row = c.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
            if not row:
                raise HTTPException(404, "event not found")
            ev = dict(row)
            table, _, rowid = (ev["source_record_id"] or "").partition(":")
            evidence = c.execute(
                "SELECT * FROM evidence_files WHERE original_path = ? AND sha256_copy = ? ORDER BY id DESC LIMIT 1",
                (ev["source_file"], ev["source_sha256"]),
            ).fetchone()
            findings_ = [dict(r) for r in c.execute(
                "SELECT f.id, f.rule_id, f.severity, f.name, r.risk_level, r.outcome, r.confidence "
                "FROM finding_events fe JOIN findings f ON f.id = fe.finding_id "
                "LEFT JOIN finding_reviews r ON r.finding_id = f.id "
                "WHERE fe.event_id = ?", (event_id,))]
        return {
            "event": ev,
            "source": {
                "file": ev["source_file"],
                "sha256": ev["source_sha256"],
                "table": table,
                "rowid": rowid,
                "evidence_copy": dict(evidence)["copy_path"] if evidence else None,
                "query": f"SELECT * FROM {table} WHERE rowid = {rowid};" if table and rowid.isdigit() else None,
            },
            "findings": findings_,
        }

    def _case_settings(c) -> tuple[str, dict]:
        row = c.execute("SELECT host_timezone, notes FROM case_meta LIMIT 1").fetchone()
        if not row:
            return "UTC", {}
        try:
            notes = json.loads(row["notes"] or "{}")
        except json.JSONDecodeError:
            notes = {}
        return row["host_timezone"] or "UTC", notes

    def _case_rules(notes: dict):
        path = notes.get("rules")
        try:
            return load_rules(Path(path) if path and path != "default" else None)
        except RuleError:
            return load_rules()  # the case's custom rules file moved; fall back to built-in

    def _off_hours(c) -> dict | None:
        """The off-hours window exactly as the rules engine used it (single source of truth)."""
        analysis_tz, notes = _case_settings(c)
        window_rule = next((r for r in _case_rules(notes) if r.type == "time_window"), None)
        if window_rule is None:
            return None
        override = notes.get("off_hours")
        if override and override != "rule default":
            start, end = parse_off_hours(override)
        else:
            start, end = str(window_rule.params["start"]), str(window_rule.params["end"])
        return {"rule_id": window_rule.id, "start": start, "end": end, "timezone": analysis_tz}

    @app.get("/api/rules")
    def rules():
        with conn() as c:
            _, notes = _case_settings(c)
            loaded = _case_rules(notes)
            window = _off_hours(c)
        return {
            "rules": [{"id": r.id, "name": r.name, "severity": r.severity, "attack": r.attack, "type": r.type,
                       "reason_template": r.reason} for r in loaded],
            "off_hours": window,
        }

    @app.get("/api/charts")
    def charts(tz: str | None = None):
        with conn() as c:
            analysis_tz, _ = _case_settings(c)
            tz_name = tz or analysis_tz
            zone = _check_tz(tz_name)
            window = _off_hours(c)

            # Off-hours (time_window) findings are context and link to most night-time visits;
            # they are counted separately so "linked to a finding" stays meaningful per domain.
            _, notes = _case_settings(c)
            context_rules = {r.id for r in _case_rules(notes) if r.type == "time_window"}
            event_findings: dict[int, set[int]] = defaultdict(set)
            event_context: dict[int, set[int]] = defaultdict(set)
            for fid, eid, rule_id in c.execute(
                "SELECT fe.finding_id, fe.event_id, f.rule_id FROM finding_events fe JOIN findings f ON f.id = fe.finding_id"
            ):
                (event_context if rule_id in context_rules else event_findings)[eid].add(fid)

            hours = [0] * 24
            hour_domains = [Counter() for _ in range(24)]
            hour_findings: list[set[int]] = [set() for _ in range(24)]
            dom: dict[str, dict] = {}
            total_events = total_visits = 0
            first_day = None
            for eid, ts, url, etype in c.execute(
                "SELECT event_id, timestamp_utc, url, event_type FROM events WHERE timestamp_utc != '' "
                "ORDER BY timestamp_utc"
            ):
                try:
                    local = parse_iso(ts).astimezone(zone)
                except ValueError:
                    continue
                first_day = first_day or local.date()
                total_events += 1
                h = local.hour
                hours[h] += 1
                hour_findings[h].update(event_findings.get(eid, ()), event_context.get(eid, ()))
                host = url_domain(url)
                if host:
                    hour_domains[h][host] += 1
                if etype != "visit" or not host:
                    continue
                total_visits += 1
                d = dom.setdefault(host, {"domain": host, "visits": 0, "urls": set(), "first_seen": ts,
                                          "findings": set(), "context": set()})
                d["visits"] += 1
                d["urls"].add(url)
                d["last_seen"] = ts
                d["findings"].update(event_findings.get(eid, ()))
                d["context"].update(event_context.get(eid, ()))

            off = [False] * 24
            if window and first_day:
                start, end = _parse_hhmm(window["start"]), _parse_hhmm(window["end"])
                wzone = parse_tz(window["timezone"])
                for h in range(24):
                    # Is the middle of this hour (in the viewing timezone) inside the rule's window?
                    mid = datetime.combine(first_day, time(h, 30), tzinfo=zone)
                    off[h] = _in_window(mid.astimezone(wzone), start, end)

            ranked = sorted(dom.values(), key=lambda d: (-d["visits"], d["domain"]))[:50]
        return {
            "timezone": tz_name,
            "total_events": total_events,
            "total_visits": total_visits,
            "domain_count": len(dom),
            "off_hours": window,
            "hours": [
                {"hour": h, "count": hours[h], "off_hours": off[h],
                 "top_domain": hour_domains[h].most_common(1)[0][0] if hour_domains[h] else None,
                 "top_domain_count": hour_domains[h].most_common(1)[0][1] if hour_domains[h] else 0,
                 "findings": len(hour_findings[h])}
                for h in range(24)
            ],
            "activity_by_hour": hours,
            "domains": [
                {"domain": d["domain"], "visits": d["visits"], "unique_urls": len(d["urls"]),
                 "first_seen": d["first_seen"], "last_seen": d["last_seen"], "findings": len(d["findings"]),
                 "context_findings": len(d["context"])}
                for d in ranked
            ],
            "top_domains": [{"domain": d["domain"], "count": d["visits"]} for d in ranked[:15]],
        }

    @app.get("/api/export.csv")
    def export_csv(tz: str | None = None):
        with conn() as c:
            text = export_csv_text(c, tz_name=tz, zone=_check_tz(tz) if tz else None)
        return PlainTextResponse(text, media_type="text/csv",
                                 headers={"Content-Disposition": 'attachment; filename="browsertrace_events.csv"'})

    @app.get("/api/export.json")
    def export_json():
        with conn() as c:
            payload = export_json_obj(c)
        return Response(json.dumps(payload, indent=2, default=str), media_type="application/json",
                         headers={"Content-Disposition": 'attachment; filename="browsertrace_export.json"'})

    @app.get("/api/report.pdf")
    def report_pdf():
        with conn() as c, tempfile.TemporaryDirectory() as tmp:
            out = build_pdf(c, Path(tmp) / "report.pdf")
            data = out.read_bytes()
        return Response(data, media_type="application/pdf",
                        headers={"Content-Disposition": 'attachment; filename="browsertrace_report.pdf"'})

    return app
