"""PDF forensic report (ReportLab)."""

from __future__ import annotations

import json
import re
import sqlite3
import sys
from datetime import timedelta
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from browsertrace.core.db import case_stats
from browsertrace.core.timeutil import now_utc_iso, parse_iso
from browsertrace.version import __version__

SEV_COLORS = {"High": colors.HexColor("#b91c1c"), "Medium": colors.HexColor("#b45309"),
              "Low": colors.HexColor("#1d4ed8")}
MAX_EVENTS_PER_FINDING = 5
TIMELINE_WINDOW = timedelta(minutes=10)
TIMELINE_MAX_ROWS = 80

FALLBACK_LIMITATIONS = """
- Rules produce investigative leads, not proof; every finding must be verified against the source records.
- Deleted-record recovery from SQLite WAL files is not implemented; history clearing is only inferred (R006).
- Firefox does not record which device a visit came from, so synced Firefox visits cannot be identified.
- Chromium keyword search terms have no own timestamp; the URL's last visit time is used (approximate).
- Prefetch/Amcache execution correlation is out of scope.
- Results have not yet been validated against reference tools; see docs/VALIDATION.md.
"""


def _limitations_text() -> str:
    candidates = [
        Path(__file__).resolve().parents[3] / "docs" / "LIMITATIONS.md",  # source checkout
        Path(getattr(sys, "_MEIPASS", "")) / "docs" / "LIMITATIONS.md",  # PyInstaller build
        Path.cwd() / "docs" / "LIMITATIONS.md",
    ]
    for c in candidates:
        if c.is_file():
            return c.read_text(encoding="utf-8")
    return FALLBACK_LIMITATIONS


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("Cell", parent=ss["BodyText"], fontSize=7.5, leading=9, wordWrap="CJK"))
    ss.add(ParagraphStyle("CellMono", parent=ss["BodyText"], fontName="Courier", fontSize=6.5, leading=8,
                          wordWrap="CJK"))
    ss.add(ParagraphStyle("CoverTitle", parent=ss["Title"], fontSize=26, leading=32, alignment=TA_CENTER))
    ss.add(ParagraphStyle("Small", parent=ss["BodyText"], fontSize=8, leading=10, textColor=colors.grey))
    return ss


def _p(text, style) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "")), style)


def _p2(first, second, style) -> Paragraph:
    """URL on one line, title (if any) on the next."""
    text = escape(str(first or ""))
    if second:
        text += "<br/>" + escape(str(second))
    return Paragraph(text, style)


def _table(rows, widths, header=True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")))
    t.setStyle(TableStyle(style))
    return t


def _md_to_flowables(md: str, ss) -> list:
    out = []
    for line in md.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            level = len(s) - len(s.lstrip("#"))
            out.append(_p(s.lstrip("#").strip(), ss["Heading3" if level <= 2 else "Heading4"]))
        elif s.startswith(("- ", "* ")):
            out.append(Paragraph("• " + _inline_md(s[2:]), ss["BodyText"]))
        else:
            out.append(Paragraph(_inline_md(s), ss["BodyText"]))
    return out


def _inline_md(s: str) -> str:
    s = escape(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`(.+?)`", r"<font face='Courier'>\1</font>", s)
    return s


def build_pdf(conn: sqlite3.Connection, out: Path) -> Path:
    conn.row_factory = sqlite3.Row
    ss = _styles()
    meta = dict(conn.execute("SELECT * FROM case_meta LIMIT 1").fetchone() or {})
    case_id = meta.get("case_id", "unknown")
    stats = case_stats(conn)
    evidence = [dict(r) for r in conn.execute("SELECT * FROM evidence_files ORDER BY id")]
    findings = [dict(r) for r in conn.execute(
        "SELECT * FROM findings ORDER BY CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, id")]
    try:
        notes = json.loads(meta.get("notes") or "{}")
    except json.JSONDecodeError:
        notes = {}

    story: list = []
    # ---- cover
    story += [Spacer(1, 50 * mm), _p("BrowserTrace", ss["CoverTitle"]),
              _p("Browser Forensic Triage Report", ss["Title"]), Spacer(1, 15 * mm)]
    cover = [
        ["Case ID", case_id],
        ["Examiner", meta.get("examiner", "")],
        ["Report generated (UTC)", now_utc_iso()],
        ["Case created (UTC)", meta.get("created_utc", "")],
        ["Tool", f"BrowserTrace {meta.get('tool_version') or __version__} (report by {__version__})"],
        ["Analysis timezone", meta.get("host_timezone", "UTC")],
        ["Evidence source", notes.get("evidence", "")],
    ]
    story.append(_table([[_p(a, ss["Cell"]), _p(b, ss["Cell"])] for a, b in cover], [50 * mm, 110 * mm], header=False))
    story += [Spacer(1, 10 * mm), _p(
        "Findings in this report are investigative leads generated by rules. They are not proof of intent or "
        "wrongdoing and must be verified by the examiner against the referenced source records.", ss["Small"]),
        PageBreak()]

    # ---- evidence
    story.append(_p("1. Evidence", ss["Heading1"]))
    rows = [[_p(h, ss["Cell"]) for h in ("File", "Browser / profile", "SHA-256 original", "SHA-256 copy", "Verified")]]
    for e in evidence:
        rows.append([
            _p(e["original_path"], ss["Cell"]),
            _p(f"{e['browser']} / {e['profile']} (v{e['browser_version']})", ss["Cell"]),
            _p(e["sha256_original"], ss["CellMono"]),
            _p(e["sha256_copy"], ss["CellMono"]),
            _p("YES" if e["verified"] else "NO - see custody log", ss["Cell"]),
        ])
    story.append(_table(rows, [48 * mm, 30 * mm, 38 * mm, 38 * mm, 16 * mm]))

    # ---- methodology
    story += [Spacer(1, 6 * mm), _p("2. Methodology", ss["Heading1"])]
    for para in (
        "Pipeline: discover browser databases → hash original (SHA-256) → copy database plus -wal/-shm sidecars "
        "into the case folder → hash and compare copies → parse a scratch copy opened read-only "
        "(sqlite3 mode=ro) → normalize and store → enrich (navigation chains, Zone.Identifier) → evaluate rules.",
        "Timestamps: Chromium stores WebKit time (microseconds since 1601-01-01 UTC); Firefox stores PRTime "
        "(microseconds since 1970-01-01 UTC). Both are converted to UTC ISO-8601 at the parser boundary; all "
        "times in this report are UTC unless marked local.",
        "Read-only handling: originals are only ever opened for reading to hash and copy them. Parsers never "
        "open the evidence copies directly; they read a further scratch copy so the evidence copies stay "
        "byte-identical (re-checkable with 'browsertrace verify').",
        "Traceability: every event carries its source file, the SHA-256 of that file, and the source record "
        "id (table:rowid).",
    ):
        story.append(_p(para, ss["BodyText"]))

    # ---- executive summary
    story += [Spacer(1, 6 * mm), _p("3. Executive summary", ss["Heading1"])]
    sev = stats["by_severity"]
    summary_rows = [
        ["Total events", stats["total_events"]],
        ["Events by browser", ", ".join(f"{k}: {v}" for k, v in sorted(stats["by_browser"].items()))],
        ["Events by type", ", ".join(f"{k}: {v}" for k, v in sorted(stats["by_type"].items()))],
        ["Time span (UTC)", f"{stats['first_event_utc']} → {stats['last_event_utc']}"],
        ["Synced events (from another device)", stats["synced_events"]],
        ["Recovered (partial) events", stats["recovered_events"]],
        ["Findings", f"High {sev.get('High', 0)}, Medium {sev.get('Medium', 0)}, Low {sev.get('Low', 0)}"],
    ]
    story.append(_table([[_p(a, ss["Cell"]), _p(b, ss["Cell"])] for a, b in summary_rows], [60 * mm, 110 * mm],
                        header=False))

    # ---- findings
    story += [PageBreak(), _p("4. Findings (High → Low)", ss["Heading1"])]
    if not findings:
        story.append(_p("No rule produced a finding.", ss["BodyText"]))
    for f in findings:
        evs = [dict(r) for r in conn.execute(
            "SELECT e.* FROM finding_events fe JOIN events e ON e.event_id = fe.event_id "
            "WHERE fe.finding_id = ? ORDER BY e.timestamp_utc LIMIT ?", (f["id"], MAX_EVENTS_PER_FINDING))]
        total = conn.execute("SELECT COUNT(*) FROM finding_events WHERE finding_id = ?", (f["id"],)).fetchone()[0]
        head = Paragraph(
            f"<font color='{SEV_COLORS[f['severity']].hexval()}'><b>[{escape(f['severity'])}]</b></font> "
            f"<b>{escape(f['rule_id'])}</b> — {escape(f['name'])} &nbsp; <font size=8>ATT&amp;CK: {escape(f['attack'])}</font>",
            ss["Heading4"],
        )
        rows = [[_p(h, ss["Cell"]) for h in ("Event", "Time (UTC)", "Browser", "Type", "URL / title", "Source record")]]
        for e in evs:
            rows.append([
                _p(e["event_id"], ss["Cell"]), _p(e["timestamp_utc"], ss["Cell"]),
                _p(f"{e['browser']}/{e['profile']}", ss["Cell"]), _p(e["event_type"], ss["Cell"]),
                _p2(e["url"], e["title"], ss["Cell"]), _p(e["source_record_id"], ss["CellMono"]),
            ])
        block = [head, _p(f["reason"], ss["BodyText"]), Spacer(1, 2 * mm),
                 _table(rows, [12 * mm, 30 * mm, 26 * mm, 16 * mm, 66 * mm, 24 * mm])]
        if total > len(evs):
            block.append(_p(f"... {total - len(evs)} more linked event(s) in the case database.", ss["Small"]))
        block.append(Spacer(1, 5 * mm))
        story.append(KeepTogether(block))

    # ---- timeline excerpt
    story += [PageBreak(), _p("5. Timeline excerpt around High findings", ss["Heading1"])]
    high_times = [r[0] for r in conn.execute(
        "SELECT MIN(e.timestamp_utc) FROM findings f JOIN finding_events fe ON fe.finding_id = f.id "
        "JOIN events e ON e.event_id = fe.event_id WHERE f.severity = 'High' GROUP BY f.id")]
    excerpt: dict[int, dict] = {}
    for ts in sorted(t for t in high_times if t):
        center = parse_iso(ts)
        lo = (center - TIMELINE_WINDOW).isoformat().replace("+00:00", "Z")
        hi = (center + TIMELINE_WINDOW).isoformat().replace("+00:00", "Z")
        for r in conn.execute("SELECT * FROM events WHERE timestamp_utc BETWEEN ? AND ? ORDER BY timestamp_utc", (lo, hi)):
            excerpt[r["event_id"]] = dict(r)
    rows = [[_p(h, ss["Cell"]) for h in ("Time (UTC)", "Browser", "Type", "URL / title", "Flags")]]
    for e in sorted(excerpt.values(), key=lambda x: (x["timestamp_utc"], x["event_id"]))[:TIMELINE_MAX_ROWS]:
        flags = []
        if e["is_synced"]:
            flags.append("SYNCED")
        if e["is_recovered"]:
            flags.append("RECOVERED (partial)")
        rows.append([_p(e["timestamp_utc"], ss["Cell"]), _p(e["browser"], ss["Cell"]), _p(e["event_type"], ss["Cell"]),
                     _p2(e["url"], e["title"], ss["Cell"]), _p(" ".join(flags), ss["Cell"])])
    if len(rows) == 1:
        story.append(_p("No High findings, so no excerpt.", ss["BodyText"]))
    else:
        story.append(_p(f"Events within ±{int(TIMELINE_WINDOW.total_seconds() // 60)} minutes of each High finding.",
                        ss["Small"]))
        story.append(_table(rows, [32 * mm, 18 * mm, 18 * mm, 90 * mm, 20 * mm]))

    # ---- limitations
    story += [PageBreak(), _p("6. Limitations", ss["Heading1"])]
    story += _md_to_flowables(_limitations_text(), ss)

    # ---- signature
    story += [Spacer(1, 12 * mm), _p("7. Examiner declaration", ss["Heading1"]),
              _p("I confirm that this report was produced with the tool and method described above and that the "
                 "findings were reviewed by me against the source records.", ss["BodyText"]), Spacer(1, 15 * mm)]
    story.append(_table([["Examiner name:", meta.get("examiner", "")], ["Signature:", ""], ["Date:", ""]],
                        [40 * mm, 100 * mm], header=False))

    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawString(15 * mm, 10 * mm, f"Case {case_id} — BrowserTrace {__version__}")
        canvas.drawRightString(A4[0] - 15 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm,
                            bottomMargin=18 * mm, title=f"BrowserTrace report {case_id}", author=meta.get("examiner", ""))
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return Path(out)
