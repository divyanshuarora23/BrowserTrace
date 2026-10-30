from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from browsertrace.analysis.engine import (
    RuleError,
    domain_matches,
    keyword_matches,
    load_rules,
    parse_tz,
    rules_reference_markdown,
    run_rules,
)

DAY = datetime(2024, 3, 1, tzinfo=timezone.utc)
_next_id = iter(range(1, 10**6))


def ev(event_type="visit", url="https://example.com/", title="", hour=12, minute=0, day=0, detail="",
       browser="Chrome", profile="Default", visit_id=None, src="H"):
    ts = DAY + timedelta(days=day, hours=hour, minutes=minute)
    eid = next(_next_id)
    return {"event_id": eid, "timestamp_utc": ts.isoformat().replace("+00:00", "Z"), "event_type": event_type,
            "url": url, "title": title, "detail": detail, "browser": browser, "profile": profile,
            "source_file": src, "source_visit_id": visit_id if visit_id is not None else eid, "is_recovered": 0}


@pytest.fixture(scope="module")
def rules():
    return load_rules()


def only(rules, *ids):
    return [r for r in rules if r.id in ids]


def ids_of(findings):
    return sorted(f.rule_id for f in findings)


# ---- loading & validation ---------------------------------------------------------

def test_default_rules_load(rules):
    assert [r.id for r in rules] == [f"R00{i}" for i in range(1, 9)]
    doc = rules_reference_markdown(rules)
    assert "R005" in doc and "T1070.004" in doc


@pytest.mark.parametrize("body,msg", [
    ("rules: [{id: X, name: n, severity: Huge, type: burst, reason: r, count: 1, window_minutes: 1}]", "severity"),
    ("rules: [{id: X, name: n, severity: Low, type: nope, reason: r}]", "unknown type"),
    ("rules: [{id: X, name: n, severity: Low, type: domain_match, reason: r}]", "requires: domains"),
    ("rules: [{id: X, name: n, severity: Low, type: domain_match, reason: r, domains: [a], dommains: [b]}]",
     "unknown key"),
    ("rules: [{id: X, severity: Low, type: gap, reason: r}]", "missing required"),
    ("rules: [{id: X, name: n, severity: Low, type: time_window, reason: r, start: '25:00', end: '01:00'}]",
     "invalid time"),
    ("rules: [{id: X, name: n, severity: Low, type: burst, reason: r, count: 0, window_minutes: 1}]", "positive"),
    ("rules: [{id: X, name: n, severity: Low, type: sequence, reason: r, within_minutes: 1, first_rule: Z}]",
     "unknown first_rule"),
    ("rules: {}", "top-level"),
    ("rules: [", "invalid YAML"),
])
def test_validation_errors(tmp_path, body, msg):
    p = tmp_path / "r.yaml"
    p.write_text(body)
    with pytest.raises(RuleError, match=msg):
        load_rules(p)


def test_duplicate_ids(tmp_path):
    p = tmp_path / "r.yaml"
    rule = "{id: X, name: n, severity: Low, type: gap, reason: r}"
    p.write_text(f"rules: [{rule}, {rule}]")
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(p)


# ---- matching helpers ---------------------------------------------------------------

@pytest.mark.parametrize("url,entry,ok", [
    ("https://mega.nz/file/x", "mega.nz", True),
    ("https://www.mega.nz/", "mega.nz", True),
    ("https://omega.nz/", "mega.nz", False),
    ("https://mega.nz.evil.com/", "mega.nz", False),
    ("https://www.dropbox.com/upload?x", "dropbox.com/upload", True),
    ("https://www.dropbox.com/home", "dropbox.com/upload", False),
    ("not a url", "mega.nz", False),
])
def test_domain_matches(url, entry, ok):
    assert domain_matches(url, entry) is ok


@pytest.mark.parametrize("text,kw,ok", [
    ("how to clear browser history", "clear history", True),
    ("download ccleaner free", "cclean", True),
    ("history of clearwater", "clear history", True),  # documented limitation: word-prefix matching
    ("history channel", "clear history", False),
    ("weather tomorrow", "wipe", False),
])
def test_keyword_matches(text, kw, ok):
    assert keyword_matches(text, kw) is ok


# ---- each rule type: positive and negative ------------------------------------------

def test_domain_match_rule(rules):
    evs = [ev(url="https://www.mega.nz/x"), ev(url="https://omega.nz/"), ev(url="https://pastebin.com/a", minute=5),
           ev(url="https://pastebin.com/b", minute=6)]
    f = run_rules(evs, only(rules, "R001"))
    assert sorted(x.reason.split(" event")[0] for x in f) == ["1", "2"]  # one finding per domain, grouped
    assert all(x.severity == "Medium" for x in f)
    assert run_rules([ev(url="https://omega.nz/")], only(rules, "R001")) == []


def test_internal_and_embedded_pages_skipped(rules):
    evs = [ev(url="https://pastebin.com/", detail="internal page"), ev(url="https://pastebin.com/", detail="embedded resource")]
    assert run_rules(evs, only(rules, "R001")) == []


def test_extension_match_rule(rules):
    pos = ev("download", url="https://x/a", detail="target=C:\\D\\setup.EXE")
    neg = ev("download", url="https://x/report.pdf", detail="target=C:\\D\\report.pdf")
    f = run_rules([pos, neg], only(rules, "R002"))
    assert len(f) == 1 and "setup.EXE" in f[0].reason and f[0].event_ids == [pos["event_id"]]


def test_time_window_rule_sessions_and_tz(rules):
    evs = [ev(hour=1, minute=0), ev(hour=1, minute=10), ev(hour=4, minute=0), ev(hour=12)]
    f = run_rules(evs, only(rules, "R003"))
    assert len(f) == 2 and f[0].severity == "Low"  # two separate off-hours sessions
    assert run_rules([ev(hour=12)], only(rules, "R003")) == []
    # 20:00 UTC is 01:30 in Asia/Kolkata -> off-hours there
    assert len(run_rules([ev(hour=20)], only(rules, "R003"), tz_name="Asia/Kolkata")) == 1
    # custom window wrapping midnight
    assert len(run_rules([ev(hour=23)], only(rules, "R003"), off_hours="22:00-06:00")) == 1


def test_keyword_match_rule(rules):
    pos = ev("search", title="how to clear browser history", url="https://g/search?q=..")
    neg = ev("search", title="weather tomorrow")
    f = run_rules([pos, neg], only(rules, "R004"))
    assert len(f) == 1 and f[0].severity == "High" and f[0].event_ids == [pos["event_id"]]


def test_keyword_rule_on_downloads_url(rules):
    pos = ev("download", url="https://www.torproject.org/dist/torbrowser/13.0/tor-browser.exe", title="tor-browser.exe")
    neg = ev("download", url="https://example.com/report.pdf", title="report.pdf")
    f = run_rules([pos, neg], only(rules, "R007"))
    assert len(f) == 1 and f[0].event_ids == [pos["event_id"]]


def test_sequence_rule(rules):
    visit = ev(url="https://wetransfer.com/", minute=0)
    dl = ev("download", url="https://dl.wetransfer.com/f.zip", detail="target=C:\\f.zip", minute=7)
    late = ev("download", url="https://x/g.zip", detail="target=C:\\g.zip", minute=30)
    not_archive = ev("download", url="https://x/h.pdf", detail="target=C:\\h.pdf", minute=3)
    f = run_rules([visit, dl, late, not_archive], only(rules, "R001", "R005"))
    seq = [x for x in f if x.rule_id == "R005"]
    assert len(seq) == 1 and seq[0].event_ids == [visit["event_id"], dl["event_id"]]
    assert "7 min" in seq[0].reason
    # download BEFORE the visit doesn't count
    before = ev("download", url="https://x/f.zip", detail="target=C:\\f.zip", minute=0)
    after_visit = ev(url="https://wetransfer.com/", minute=2)
    assert [x for x in run_rules([before, after_visit], only(rules, "R001", "R005")) if x.rule_id == "R005"] == []


def _active_days(days, per_day=12, start_vid=1, **kw):
    out, vid = [], start_vid
    for d in days:
        for i in range(per_day):
            out.append(ev(day=d, hour=9 + i % 10, minute=i, visit_id=vid, **kw))
            vid += 1
    return out, vid


def test_gap_rule_time_gap(rules):
    before, vid = _active_days(range(0, 3))
    after, _ = _active_days(range(6, 9), start_vid=vid)
    f = run_rules(before + after, only(rules, "R006"))
    assert len(f) == 1 and "no history for" in f[0].reason
    # same data without the hole: no finding
    cont, _ = _active_days(range(0, 9))
    assert run_rules(cont, only(rules, "R006")) == []


def test_gap_rule_id_hole(rules):
    a, vid = _active_days(range(0, 3))
    b, _ = _active_days(range(3, 6), start_vid=vid + 100)
    f = run_rules(a + b, only(rules, "R006"))
    assert len(f) == 1 and "100 visit IDs missing" in f[0].reason
    # small holes (individual deleted entries) are below threshold
    c, _ = _active_days(range(3, 6), start_vid=vid + 5)
    assert run_rules(a + c, only(rules, "R006")) == []


def test_gap_rule_needs_activity_on_both_sides(rules):
    before = [ev(day=0, hour=10, visit_id=1), ev(day=0, hour=11, visit_id=2)]
    after, _ = _active_days(range(5, 8), start_vid=3)
    assert run_rules(before + after, only(rules, "R006")) == []


def test_burst_rule(rules):
    burst = [ev("download", url=f"https://x/{i}.pdf", detail=f"target=C:\\{i}.pdf", minute=i) for i in range(6)]
    calm = [ev("download", url=f"https://y/{i}.pdf", detail=f"target=C:\\y{i}.pdf", hour=15 + i) for i in range(6)]
    f = run_rules(burst + calm, only(rules, "R008"))
    assert len(f) == 1 and len(f[0].event_ids) == 6
    assert run_rules(burst[:5], only(rules, "R008")) == []  # exactly N is not "more than N"


def test_escalation_with_off_hours(rules):
    night = ev(url="https://pastebin.com/", hour=2)
    day = ev(url="https://mega.nz/", hour=14)
    f = {x.reason.split(" ")[3].rstrip(","): x for x in run_rules([night, day], only(rules, "R001", "R003"))
         if x.rule_id == "R001"}
    assert f["pastebin.com"].severity == "High" and "escalated from Medium to High" in f["pastebin.com"].reason
    assert f["mega.nz"].severity == "Medium" and "escalated" not in f["mega.nz"].reason


def test_findings_always_have_reason_and_events(rules):
    evs = [ev(url="https://pastebin.com/", hour=2), ev("search", title="shred files", hour=2)]
    for f in run_rules(evs, rules):
        assert f.reason and f.event_ids and "{" not in f.reason


def test_parse_tz():
    assert parse_tz("UTC").utcoffset(None) == timedelta(0)
    assert parse_tz("+05:30").utcoffset(None) == timedelta(hours=5, minutes=30)
    assert parse_tz("UTC-04:00").utcoffset(None) == timedelta(hours=-4)
    with pytest.raises(RuleError):
        parse_tz("Mars/Olympus")


def test_custom_rules_file(tmp_path):
    p = Path(tmp_path) / "r.yaml"
    p.write_text("rules:\n- {id: C1, name: Example, severity: High, attack: T0, type: domain_match,"
                 " domains: [example.com], reason: 'hit {domain} at {time}'}\n")
    f = run_rules([ev()], load_rules(p))
    assert len(f) == 1 and f[0].reason.startswith("hit example.com at 2024-03-01T12:00:00Z")
