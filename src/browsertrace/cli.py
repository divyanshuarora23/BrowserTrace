"""Command-line interface: ``browsertrace <command>``."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from typing import Optional

import typer

from browsertrace.version import __version__

app = typer.Typer(
    name="browsertrace",
    help="BrowserTrace: Windows browser forensic triage (Chrome, Edge, Brave, Opera, Firefox).",
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)

SEV_COLORS = {"High": typer.colors.RED, "Medium": typer.colors.YELLOW, "Low": typer.colors.BLUE}


def _fail(msg: str, code: int = 2) -> None:
    typer.secho(f"error: {msg}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _version_cb(value: bool) -> None:
    if value:
        typer.echo(f"browsertrace {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=_version_cb, is_eager=True, help="Show version and exit."),
) -> None:
    pass


def _open_case(case: Path) -> sqlite3.Connection:
    from browsertrace.core.db import open_readonly
    from browsertrace.pipeline import case_db_path

    db = case_db_path(case)
    if not db.is_file():
        _fail(f"no case database found at {db}. Run 'browsertrace analyze ... --out {case}' first.")
    return open_readonly(db)


def _print_summary(summary, case_dir: Path, tz: str) -> None:
    from browsertrace.core.db import open_readonly
    from browsertrace.pipeline import case_db_path

    typer.secho("\nCollected evidence", bold=True)
    for t in summary.targets:
        ok = typer.style("hash OK", fg=typer.colors.GREEN) if t["verified"] else typer.style(
            "HASH CHANGED (see custody log)", fg=typer.colors.RED)
        typer.echo(f"  {t['browser']:<8} {t['profile']:<28} v{t['version']:<16} {t['events']:>7} events  {ok}")
    for f in summary.failures:
        typer.secho(f"  FAILED: {f}", fg=typer.colors.RED)
    typer.echo(
        f"\nEvents: {summary.events_parsed} parsed, {summary.events_inserted} stored, {summary.duplicates} duplicates; "
        f"{summary.chains_linked} navigation links; {summary.downloads_enriched} downloads with Zone.Identifier"
    )
    sev = summary.findings_by_severity
    typer.echo(f"Findings: High {sev.get('High', 0)}, Medium {sev.get('Medium', 0)}, Low {sev.get('Low', 0)}"
               f"  (off-hours evaluated in {tz})")
    conn = open_readonly(case_db_path(case_dir))
    try:
        for fid, rule_id, s, reason in conn.execute(
            "SELECT id, rule_id, severity, reason FROM findings ORDER BY "
            "CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, id"
        ):
            typer.echo("  " + typer.style(f"[{s:<6}]", fg=SEV_COLORS[s], bold=True) + f" #{fid} {rule_id}: {reason}")
    finally:
        conn.close()
    typer.echo("\nFindings are investigative leads, not proof.")
    typer.echo(f"Case folder: {case_dir}\nNext: browsertrace serve --case \"{case_dir}\"   |   "
               f"browsertrace report --case \"{case_dir}\" --format pdf")


@app.command()
def analyze(
    evidence: Path = typer.Option(..., "--evidence", "-e", help="User profile folder, mounted drive, evidence folder, or a single History/places.sqlite file."),
    case: str = typer.Option(..., "--case", "-c", help="Case identifier."),
    examiner: str = typer.Option(..., "--examiner", help="Examiner name."),
    out: Path = typer.Option(..., "--out", "-o", help="Case output folder (created if needed)."),
    browser: Optional[str] = typer.Option(None, "--browser", "-b", help="Only this browser, or the browser of a single file."),
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="Only this profile, or profile name for a single file."),
    tz: str = typer.Option("UTC", "--tz", help="Timezone for off-hours rules, e.g. Asia/Kolkata or +05:30."),
    off_hours: Optional[str] = typer.Option(None, "--off-hours", help="Off-hours window HH:MM-HH:MM (default from rules: 00:00-05:00)."),
    rules: Optional[Path] = typer.Option(None, "--rules", help="Custom rules YAML (default: built-in rules)."),
    timeline: int = typer.Option(0, "--timeline", help="Also print the first N timeline rows."),
) -> None:
    """Collect, parse, normalize, store, enrich and run rules on browser evidence."""
    from browsertrace.pipeline import AnalysisError
    from browsertrace.pipeline import analyze as run

    try:
        summary = run(evidence, out, case, examiner, browser, profile, tz, off_hours, rules)
    except AnalysisError as exc:
        _fail(str(exc))
    _print_summary(summary, out, tz)
    if timeline:
        _print_timeline(out, timeline, 0)
    if not summary.targets:
        _fail("every evidence target failed; see messages above", code=3)


def _print_timeline(case: Path, limit: int, offset: int, q: str | None = None, browser: str | None = None) -> None:
    from browsertrace.core.db import query_events

    conn = _open_case(case)
    try:
        rows = query_events(conn, limit=limit, offset=offset, q=q, browser=browser)
    finally:
        conn.close()
    typer.secho(f"\n{'Time (UTC)':<21} {'Browser':<8} {'Type':<9} URL / title", bold=True)
    for r in rows:
        flags = (" [SYNCED]" if r["is_synced"] else "") + (" [RECOVERED]" if r["is_recovered"] else "")
        label = r["title"] or ""
        typer.echo(f"{r['timestamp_utc']:<21} {r['browser']:<8} {r['event_type']:<9} {r['url']}"
                   + (f"  - {label}" if label else "") + flags)


@app.command()
def timeline(
    case: Path = typer.Option(..., "--case", help="Case folder."),
    limit: int = typer.Option(50, "--limit"),
    offset: int = typer.Option(0, "--offset"),
    q: Optional[str] = typer.Option(None, "--q", help="Text filter on URL/title."),
    browser: Optional[str] = typer.Option(None, "--browser"),
) -> None:
    """Print the case timeline in the terminal."""
    _print_timeline(case, limit, offset, q, browser)


@app.command()
def serve(
    case: Path = typer.Option(..., "--case", help="Case folder."),
    port: int = typer.Option(8000, "--port"),
) -> None:
    """Start the local dashboard on http://127.0.0.1:PORT (localhost only)."""
    import uvicorn

    from browsertrace.api.app import create_app

    try:
        application = create_app(case)
    except FileNotFoundError as exc:
        _fail(str(exc))
    typer.echo(f"BrowserTrace dashboard: http://127.0.0.1:{port}  (Ctrl+C to stop)")
    uvicorn.run(application, host="127.0.0.1", port=port, log_level="warning")


@app.command()
def report(
    case: Path = typer.Option(..., "--case", help="Case folder."),
    format: str = typer.Option("pdf", "--format", "-f", help="pdf | csv | json"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Output file (default: inside the case folder)."),
) -> None:
    """Write a PDF report or a CSV/JSON export."""
    fmt = format.lower()
    if fmt not in ("pdf", "csv", "json"):
        _fail("--format must be pdf, csv or json")
    conn = _open_case(case)
    default_name = "browsertrace_report.pdf" if fmt == "pdf" else f"browsertrace_events.{fmt}"
    target = out or Path(case) / default_name
    try:
        if fmt == "pdf":
            from browsertrace.report.pdf import build_pdf

            build_pdf(conn, target)
        elif fmt == "csv":
            from browsertrace.report.export import write_csv

            write_csv(conn, target)
        else:
            from browsertrace.report.export import write_json

            write_json(conn, target)
    except OSError as exc:
        _fail(f"cannot write {target}: {exc}")
    finally:
        conn.close()
    typer.echo(f"Wrote {target}")


@app.command()
def demo(
    out: Path = typer.Option(Path("demo_case"), "--out", "-o", help="Folder for the demo evidence and case."),
    tz: str = typer.Option("UTC", "--tz"),
) -> None:
    """Generate the synthetic 'insider data theft' scenario and analyze it end-to-end."""
    from browsertrace.pipeline import AnalysisError
    from browsertrace.pipeline import analyze as run
    from browsertrace.scenario import build_scenario

    evidence = Path(out) / "evidence_source"
    typer.echo(f"Generating synthetic evidence in {evidence} ...")
    build_scenario(evidence)
    try:
        summary = run(evidence, out, "DEMO-001", "Demo Examiner", tz=tz)
    except AnalysisError as exc:
        _fail(str(exc))
    _print_summary(summary, out, tz)


@app.command()
def rules(
    doc: bool = typer.Option(False, "--doc", help="Print the Markdown rule reference."),
    path: Optional[Path] = typer.Option(None, "--rules", help="Rules YAML to load (default: built-in)."),
) -> None:
    """Validate the rules file; with --doc print the rule reference."""
    from browsertrace.analysis.engine import RuleError, load_rules, rules_reference_markdown

    try:
        loaded = load_rules(path)
    except RuleError as exc:
        _fail(str(exc))
    if doc:
        sys.stdout.write(rules_reference_markdown(loaded))
    else:
        for r in loaded:
            typer.echo(f"{r.id}  {r.severity:<6}  {r.attack:<10}  {r.type:<15}  {r.name}")
        typer.echo(f"{len(loaded)} rules OK")


@app.command()
def verify(case: Path = typer.Option(..., "--case", help="Case folder.")) -> None:
    """Re-hash the evidence copies and compare with the stored hashes."""
    from browsertrace.collector.collect import verify_case_evidence

    conn = _open_case(case)
    try:
        results = verify_case_evidence(conn, case)
    finally:
        conn.close()
    if not results:
        _fail("case has no evidence records")
    bad = 0
    for r in results:
        ok = r["status"] == "ok"
        bad += not ok
        typer.echo(typer.style(f"{r['status']:<8}", fg=typer.colors.GREEN if ok else typer.colors.RED) + f" {r['copy_path']}")
    if bad:
        _fail(f"{bad} of {len(results)} evidence copies failed verification", code=1)
    typer.secho(f"All {len(results)} evidence copies match their recorded SHA-256.", fg=typer.colors.GREEN)


if __name__ == "__main__":
    app()
