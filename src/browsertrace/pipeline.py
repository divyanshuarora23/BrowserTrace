"""End-to-end analysis: collect -> parse -> normalize/store -> enrich -> rules."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from browsertrace.analysis.engine import load_rules, parse_off_hours, parse_tz, run_rules
from browsertrace.collector.collect import (
    CollectionError,
    collect_target,
    make_working_copy,
    record_collection,
)
from browsertrace.collector.discover import DiscoveryError, find_targets
from browsertrace.core.audit import AuditLog
from browsertrace.core.db import CaseDB
from browsertrace.core.timeutil import now_utc_iso
from browsertrace.enrichment.chains import resolve_chain_links
from browsertrace.enrichment.zone_identifier import enrich_downloads
from browsertrace.parsers import get_parser
from browsertrace.parsers.base import ParserError
from browsertrace.version import __version__

CASE_DB_NAME = "case.db"


class AnalysisError(Exception):
    """An expected, user-facing failure (bad path, no evidence found, bad rules...)."""


@dataclass
class AnalysisSummary:
    case_dir: Path
    targets: list[dict] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    events_parsed: int = 0
    events_inserted: int = 0
    duplicates: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    chains_linked: int = 0
    downloads_enriched: int = 0


def case_db_path(case_dir: Path) -> Path:
    return Path(case_dir) / CASE_DB_NAME


def analyze(
    evidence: Path,
    case_dir: Path,
    case_id: str,
    examiner: str,
    browser: str | None = None,
    profile: str | None = None,
    tz: str = "UTC",
    off_hours: str | None = None,
    rules_path: Path | None = None,
) -> AnalysisSummary:
    evidence = Path(evidence)
    case_dir = Path(case_dir)
    # validate cheap things before touching anything
    try:
        parse_tz(tz)
        if off_hours:
            parse_off_hours(off_hours)
        rules = load_rules(rules_path)
        targets = find_targets(evidence, browser, profile)
    except (DiscoveryError, ValueError) as exc:
        raise AnalysisError(str(exc)) from exc
    if not targets:
        raise AnalysisError(
            f"no browser history databases found under {evidence}. Point --evidence at a user profile "
            "folder, a mounted image, or a History/places.sqlite file (with --browser)."
        )

    case_dir.mkdir(parents=True, exist_ok=True)
    audit = AuditLog()
    summary = AnalysisSummary(case_dir=case_dir)
    collection_time = now_utc_iso()
    audit.log("analyze", f"BrowserTrace {__version__}; evidence={evidence}; tz={tz}; off_hours={off_hours}")

    with CaseDB(case_db_path(case_dir)) as db:
        notes = {"evidence": str(evidence), "off_hours": off_hours or "rule default",
                 "rules": str(rules_path or "default"), "collection_time_utc": collection_time}
        db.set_case_meta(case_id, examiner, __version__, tz or "UTC", json.dumps(notes))
        all_events = []
        for t in targets:
            try:
                ct = collect_target(t, case_dir, audit)
                record_collection(db, ct, case_dir)
                work = make_working_copy(ct, case_dir)
                try:
                    parser = get_parser(t.browser)
                    events = parser(work, t.browser, t.profile, ct.db.sha256_copy,
                                    browser_version=ct.browser_version, source_file=str(t.path), audit=audit)
                finally:
                    shutil.rmtree(work.parent, ignore_errors=True)
            except (CollectionError, ParserError, OSError, ValueError) as exc:
                msg = f"{t.browser}/{t.profile} ({t.path}): {exc}"
                audit.error("target-failed", msg)
                summary.failures.append(msg)
                continue
            all_events.extend(events)
            summary.targets.append({
                "browser": t.browser, "profile": t.profile, "path": str(t.path),
                "events": len(events), "verified": ct.verified, "version": ct.browser_version,
            })
        shutil.rmtree(case_dir / "work", ignore_errors=True)

        summary.events_parsed = len(all_events)
        stats = db.ingest_events(all_events, collection_time_utc=collection_time)
        summary.events_inserted, summary.duplicates = stats.inserted, stats.duplicates
        audit.log("ingest", f"{stats.inserted} inserted, {stats.duplicates} duplicates, "
                  f"{stats.flagged_future} future, {stats.flagged_out_of_order} out-of-order")

        summary.chains_linked = resolve_chain_links(db.conn)
        roots = [evidence] if evidence.is_dir() else [evidence.parent]
        summary.downloads_enriched = enrich_downloads(db.conn, roots)
        audit.log("enrich", f"{summary.chains_linked} chain links; {summary.downloads_enriched} downloads with MotW")

        findings = run_rules(db.all_events_ordered(), rules, tz_name=tz or "UTC", off_hours=off_hours)
        db.clear_findings()
        for f in findings:
            db.insert_finding(f.rule_id, f.name, f.severity, f.attack, f.reason, f.event_ids)
        summary.findings_by_severity = {s: sum(1 for f in findings if f.severity == s) for s in ("High", "Medium", "Low")}
        audit.log("rules", f"{len(findings)} findings: {summary.findings_by_severity}")
        db.append_audit(audit)
    return summary
