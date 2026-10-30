import shutil

import pytest
from fastapi.testclient import TestClient

from browsertrace.api.app import create_app
from browsertrace.core.db import CaseDB
from browsertrace.core.schema import Event

XSS = '<img src=x onerror="alert(1)"><script>alert(2)</script>'


@pytest.fixture(scope="module")
def client(scenario, tmp_path_factory):
    # work on a copy so the XSS event doesn't leak into other tests
    case = tmp_path_factory.mktemp("apicase") / "case"
    shutil.copytree(scenario["case_dir"], case)
    with CaseDB(case / "case.db") as db:
        db.ingest_events([Event(timestamp_utc="2024-03-15T12:00:00Z", browser="Chrome", browser_version="1",
                                profile="Default", event_type="visit", url="https://evil.example/" + XSS,
                                title=XSS, source_record_id="visits:999999", source_file="x")])
    return TestClient(create_app(case))


def test_stats_and_case(client):
    s = client.get("/api/stats").json()
    assert s["total_events"] > 2000 and set(s["by_browser"]) == {"Chrome", "Edge", "Firefox"}
    c = client.get("/api/case").json()
    assert c["case"]["case_id"] == "TEST-001"
    assert c["verification"]["all_ok"] is True


def test_events_pagination_and_filters(client):
    r = client.get("/api/events", params={"limit": 50, "offset": 100}).json()
    assert len(r["events"]) == 50 and r["total"] > 2000
    r = client.get("/api/events", params={"browser": "Firefox", "type": "search", "q": "clear"}).json()
    assert r["total"] == 1 and r["events"][0]["title"] == "how to clear browser history"
    r = client.get("/api/events", params={"synced": "true"}).json()
    assert r["total"] == 1
    r = client.get("/api/events", params={"from": "2024-03-14T02:00:00Z", "to": "2024-03-14T03:00:00Z"}).json()
    assert 5 <= r["total"] <= 10
    assert client.get("/api/events", params={"limit": 100000}).status_code == 422


def test_findings_and_detail(client):
    findings = client.get("/api/findings").json()
    assert findings[0]["severity"] == "High"
    f = client.get(f"/api/findings/{findings[0]['id']}").json()
    assert f["events"] and f["reason"]
    assert client.get("/api/findings/999999").status_code == 404


def test_event_and_chain(client):
    ev = client.get("/api/events", params={"limit": 500}).json()["events"]
    linked = next(e for e in ev if e["from_event_id"])
    d = client.get(f"/api/event/{linked['event_id']}").json()
    assert d["source"]["table"] in ("visits", "moz_historyvisits") and d["source"]["sha256"]
    assert d["source"]["evidence_copy"].startswith("evidence/")
    chain = client.get(f"/api/chain/{linked['event_id']}").json()["chain"]
    assert len(chain) >= 2 and chain[-1]["event_id"] == linked["event_id"]
    assert client.get("/api/chain/99999999").status_code == 404
    pos = client.get(f"/api/events/position/{linked['event_id']}").json()
    assert pos["position"] >= 0


def test_charts_exports_and_report(client):
    c = client.get("/api/charts").json()
    assert len(c["activity_by_hour"]) == 24 and c["top_domains"]
    csv = client.get("/api/export.csv")
    assert csv.status_code == 200 and csv.text.startswith("message,datetime,timestamp,timestamp_desc")
    pdf = client.get("/api/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")


def test_dashboard_served_offline_with_csp(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert "cdn" not in r.text.lower() and "http://" not in r.text and "https://" not in r.text
    assert client.get("/static/chart.min.js").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_xss_title_is_returned_as_data_and_never_rendered_as_html(client):
    r = client.get("/api/events", params={"q": "evil.example"})
    assert r.headers["content-type"].startswith("application/json")
    ev = r.json()["events"][0]
    assert ev["title"] == XSS  # preserved verbatim as data (evidence must not be altered)
    # The page itself never contains event data, inline scripts are blocked by CSP,
    # and the client renders exclusively via textContent.
    html = client.get("/").text
    assert XSS not in html and "<script>" not in html.replace('<script src="/static/', "")
    js = client.get("/static/app.js").text
    assert "innerHTML" not in js and "outerHTML" not in js
    assert "insertAdjacentHTML" not in js and "document.write" not in js and "eval(" not in js
    assert "createTextNode" in js


def test_api_is_read_only(client):
    assert client.post("/api/events").status_code == 405
    assert client.delete("/api/findings/1").status_code == 405


def test_dashboard_filters_domain_hour_finding(client):
    r = client.get("/api/events", params={"domain": "wetransfer.com"}).json()
    assert r["total"] >= 2 and all("wetransfer.com" in e["url"] for e in r["events"])
    r = client.get("/api/events", params={"hour": 2, "tz": "UTC"}).json()
    assert r["total"] >= 6 and all(e["timestamp_utc"][11:13] == "02" for e in r["events"])
    # 02:xx UTC is 07:xx in Asia/Kolkata (+05:30 -> 07:40-07:46)
    ist = client.get("/api/events", params={"hour": 7, "tz": "Asia/Kolkata", "from": "2024-03-14T02:00:00Z",
                                            "to": "2024-03-14T02:20:00Z"}).json()
    assert ist["total"] >= 6
    f = client.get("/api/findings").json()[0]
    linked = client.get("/api/events", params={"finding": f["id"], "limit": 1000}).json()
    assert linked["total"] == f["event_count"] == len(f["event_ids"])
    assert f["first_time"] <= f["last_time"]
    assert client.get("/api/events", params={"hour": 24}).status_code == 422
    assert client.get("/api/events", params={"tz": "Mars/Base"}).status_code == 400


def test_chart_and_rules_metadata(client):
    rules = client.get("/api/rules").json()
    assert rules["off_hours"] == {"rule_id": "R003", "start": "00:00", "end": "05:00", "timezone": "UTC"}
    assert any(r["id"] == "R003" and "{count}" in r["reason_template"] for r in rules["rules"])
    c = client.get("/api/charts", params={"tz": "UTC"}).json()
    assert [h["off_hours"] for h in c["hours"]] == [h < 5 for h in range(24)]
    assert sum(h["count"] for h in c["hours"]) == c["total_events"]
    assert c["hours"][2]["findings"] >= 6 and c["hours"][2]["top_domain"]
    wt = next(d for d in c["domains"] if d["domain"] == "wetransfer.com")
    assert wt["findings"] >= 2 and wt["unique_urls"] >= 2 and wt["first_seen"] <= wt["last_seen"]
    assert c["domain_count"] >= len(c["domains"]) and c["total_visits"] >= sum(d["visits"] for d in c["domains"])
    # viewed in IST the UTC-defined window shifts to 05:30-10:30 local
    ist = client.get("/api/charts", params={"tz": "Asia/Kolkata"}).json()
    assert [h["hour"] for h in ist["hours"] if h["off_hours"]] == [5, 6, 7, 8, 9]


def test_csv_export_with_display_timezone(client):
    text = client.get("/api/export.csv", params={"tz": "Asia/Kolkata"}).text
    header, first = text.splitlines()[:2]
    assert header.endswith("datetime_local,local_timezone") and "+05:30,Asia/Kolkata" in first


def test_json_export(client):
    r = client.get("/api/export.json")
    assert r.headers["content-type"].startswith("application/json")
    data = r.json()
    assert data["disclaimer"] and data["events"] and data["findings"]
    assert {"evidence_files", "custody_log", "stats", "case"} <= data.keys()


def test_evidence_endpoint_and_reverify(client):
    e = client.get("/api/evidence").json()
    assert e["files"] and all(f["status"] == "ok" for f in e["files"])
    assert all(f["size_bytes"] and f["size_bytes"] > 0 for f in e["files"])
    assert e["custody_log"] and e["audit_log"] is not None
    r = client.post("/api/evidence/verify")
    assert r.status_code == 200
    reverified = r.json()
    assert reverified["all_ok"] is True and all(f["status"] == "ok" for f in reverified["files"])
