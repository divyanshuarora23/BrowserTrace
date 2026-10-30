"""End-to-end: synthetic scenario -> analyze -> expected findings (scenario_expected.json)."""

from browsertrace.core.db import CaseDB, count_events


def test_scenario_has_enough_normal_browsing(scenario):
    assert scenario["expected_file"]["normal_events_generated"] >= 2000
    assert {t["browser"] for t in scenario["summary"].targets} == {"Chrome", "Edge", "Firefox"}
    assert all(t["verified"] for t in scenario["summary"].targets)
    assert not scenario["summary"].failures


def test_expected_findings_present_with_expected_severity(scenario):
    expected = scenario["expected_file"]["expected_findings"]
    with CaseDB(scenario["case_dir"] / "case.db") as db:
        findings = db.list_findings()
        for exp in expected:
            matches = [f for f in findings if f["rule_id"] == exp["rule_id"] and exp["match"] in f["reason"]]
            assert matches, f"missing {exp}"
            assert any(f["severity"] == exp["severity"] for f in matches), f"wrong severity for {exp}: {matches}"
            for f in matches:
                assert db.get_finding(f["id"])["event_ids"], "finding without linked events"


def test_few_false_positives(scenario):
    exp = scenario["expected_file"]
    expected = exp["expected_findings"]
    with CaseDB(scenario["case_dir"] / "case.db") as db:
        findings = db.list_findings()
    unexpected = [f for f in findings
                  if not any(f["rule_id"] == e["rule_id"] and e["match"] in f["reason"] for e in expected)]
    assert len(unexpected) <= exp["max_unexpected_findings"], unexpected


def test_planted_events_present_and_traceable(scenario):
    with CaseDB(scenario["case_dir"] / "case.db") as db:
        for p in scenario["expected_file"]["planted_events"]:
            if "source_record_id" not in p:
                continue
            row = db.conn.execute(
                "SELECT * FROM events WHERE browser = ? AND source_record_id = ? AND timestamp_utc = ?",
                (p["browser"], p["source_record_id"], p["time_utc"])).fetchone()
            assert row is not None, p
            assert len(row["source_sha256"]) == 64 and row["source_file"]


def test_synced_visit_flagged(scenario):
    with CaseDB(scenario["case_dir"] / "case.db") as db:
        synced = [r["url"] for r in db.conn.execute("SELECT url FROM events WHERE is_synced = 1 AND event_type='visit'")]
        assert synced == scenario["expected_file"]["expected_synced_urls"]
        assert count_events(db.conn, browser="Firefox", synced=True) == 0


def test_download_enriched_with_motw(scenario):
    with CaseDB(scenario["case_dir"] / "case.db") as db:
        detail = db.conn.execute("SELECT detail FROM events WHERE title = 'project_files.zip'").fetchone()[0]
    assert "ZoneId=3 (Internet)" in detail and "HostUrl=https://download.wetransfer.com" in detail


def test_all_timestamps_utc_iso(scenario):
    with CaseDB(scenario["case_dir"] / "case.db") as db:
        bad = db.conn.execute("SELECT COUNT(*) FROM events WHERE timestamp_utc NOT LIKE '____-__-__T__:__:__%Z'").fetchone()[0]
    assert bad == 0
