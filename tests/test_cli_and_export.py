import csv
import json

from typer.testing import CliRunner

from browsertrace.cli import app
from browsertrace.version import __version__
from tests.conftest import make_chromium

runner = CliRunner()


def test_version():
    r = runner.invoke(app, ["--version"])
    assert r.exit_code == 0 and __version__ in r.stdout


def test_rules_doc():
    r = runner.invoke(app, ["rules", "--doc"])
    assert r.exit_code == 0 and "# BrowserTrace rule reference" in r.stdout and "R008" in r.stdout


def test_bad_rules_file_is_clean_error(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("rules: [{id: X}]")
    r = runner.invoke(app, ["rules", "--rules", str(p)])
    assert r.exit_code == 2 and "missing required" in r.output and "Traceback" not in r.output


def test_analyze_errors_are_clean(tmp_path):
    r = runner.invoke(app, ["analyze", "--evidence", str(tmp_path / "nope"), "--case", "C", "--examiner", "E",
                            "--out", str(tmp_path / "out")])
    assert r.exit_code == 2 and "does not exist" in r.output and "Traceback" not in r.output
    r = runner.invoke(app, ["analyze", "--evidence", str(tmp_path), "--case", "C", "--examiner", "E",
                            "--out", str(tmp_path / "out")])
    assert r.exit_code == 2 and "no browser history databases" in r.output
    r = runner.invoke(app, ["analyze", "--evidence", str(tmp_path), "--case", "C", "--examiner", "E",
                            "--out", str(tmp_path / "out"), "--tz", "Nowhere/Land"])
    assert r.exit_code == 2 and "unknown timezone" in r.output
    r = runner.invoke(app, ["verify", "--case", str(tmp_path / "nocase")])
    assert r.exit_code == 2 and "no case database" in r.output


def test_analyze_single_file_with_overrides_and_reports(tmp_path):
    db = make_chromium(tmp_path / "evidence" / "export.sqlite")
    out = tmp_path / "case"
    r = runner.invoke(app, ["analyze", "--evidence", str(db), "--browser", "Edge", "--profile", "Work",
                            "--case", "C9", "--examiner", "Ex", "--out", str(out), "--tz", "Asia/Kolkata",
                            "--timeline", "3"])
    assert r.exit_code == 0, r.output
    assert "Edge" in r.output and "Work" in r.output and "R002" in r.output
    assert runner.invoke(app, ["verify", "--case", str(out)]).exit_code == 0
    for fmt in ("csv", "json", "pdf"):
        rr = runner.invoke(app, ["report", "--case", str(out), "--format", fmt])
        assert rr.exit_code == 0, rr.output
    rows = list(csv.DictReader((out / "browsertrace_events.csv").open(encoding="utf-8")))
    assert rows and {"message", "datetime", "timestamp_desc", "source_record_id"} <= set(rows[0])
    assert any(r["finding_rule_ids"] == "R002" for r in rows)
    assert any(r["is_synced"] == "True" and r["message"].startswith("[SYNCED]") for r in rows)
    data = json.loads((out / "browsertrace_events.json").read_text(encoding="utf-8"))
    assert data["case"]["case_id"] == "C9" and data["findings"][0]["event_ids"]
    assert "not proof" in data["disclaimer"]
    assert (out / "browsertrace_report.pdf").read_bytes().startswith(b"%PDF")
    assert runner.invoke(app, ["report", "--case", str(out), "--format", "xml"]).exit_code == 2


def test_demo_command(tmp_path):
    r = runner.invoke(app, ["demo", "--out", str(tmp_path / "demo")])
    assert r.exit_code == 0, r.output
    assert "R004" in r.output and "R005" in r.output and "R006" in r.output
    assert (tmp_path / "demo" / "case.db").is_file()
