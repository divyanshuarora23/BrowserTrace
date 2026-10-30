import os
from datetime import datetime, timedelta, timezone

from browsertrace.core.db import CaseDB
from browsertrace.core.schema import Event
from browsertrace.enrichment.chains import get_chain, resolve_chain_links
from browsertrace.enrichment.zone_identifier import (
    enrich_downloads,
    format_zone,
    parse_zone_identifier,
    read_zone_identifier,
)

T = datetime(2024, 1, 1, tzinfo=timezone.utc)


def _v(vid, frm, src="H", minute=0, browser="Chrome"):
    return Event(timestamp_utc=(T + timedelta(minutes=minute)).isoformat().replace("+00:00", "Z"),
                 browser=browser, browser_version="1", profile="P", event_type="visit", url=f"https://e/{vid}",
                 source_visit_id=vid, from_visit_id=frm, source_file=src, source_sha256="x",
                 source_record_id=f"visits:{vid}")


def _ids(db):
    return {(r["source_file"], r["source_visit_id"]): r["event_id"]
            for r in db.conn.execute("SELECT * FROM events")}


def test_chain_resolution_and_scope(tmp_path):
    with CaseDB(tmp_path / "c.db") as db:
        db.ingest_events([_v(1, None), _v(2, 1, minute=1), _v(3, 2, minute=2),
                          # same visit ids in another file must not cross-link
                          _v(1, None, src="OTHER"), _v(5, 2, src="OTHER", minute=3)])
        resolve_chain_links(db.conn)
        ids = _ids(db)
        chain = get_chain(db.conn, ids[("H", 3)])
        assert [e["source_visit_id"] for e in chain] == [1, 2, 3]
        other = get_chain(db.conn, ids[("OTHER", 5)])
        assert [e["source_visit_id"] for e in other] == [5]  # visit 2 doesn't exist in OTHER


def test_chain_cycle_and_depth_guard(tmp_path):
    with CaseDB(tmp_path / "c.db") as db:
        events = [_v(1, 3), _v(2, 1, minute=1), _v(3, 2, minute=2)]  # 1 -> 3 -> 2 -> 1 cycle
        events += [_v(100 + i, 100 + i - 1 if i else None, minute=10 + i) for i in range(80)]  # long chain
        db.ingest_events(events)
        resolve_chain_links(db.conn)
        ids = _ids(db)
        cyc = get_chain(db.conn, ids[("H", 3)])
        assert len(cyc) == 3 and len({e["event_id"] for e in cyc}) == 3
        long = get_chain(db.conn, ids[("H", 179)])
        assert len(long) == 51  # the event itself + 50 ancestors
        assert long[-1]["source_visit_id"] == 179


def test_zone_identifier_parsing():
    data = parse_zone_identifier("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://a/\r\nHostUrl=https://b/f.zip\r\n")
    assert data == {"ZoneId": "3", "ReferrerUrl": "https://a/", "HostUrl": "https://b/f.zip"}
    assert "ZoneId=3 (Internet)" in format_zone(data)
    assert format_zone({}) == ""


def test_zone_identifier_sidecar_and_rerooting(tmp_path):
    f = tmp_path / "Users" / "bob" / "Downloads" / "x.zip"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"PK")
    (f.parent / "x.zip.Zone.Identifier").write_text("[ZoneTransfer]\nZoneId=3\nHostUrl=https://h/x.zip\n")
    # Windows-style original path, re-rooted under the evidence folder
    assert read_zone_identifier("C:\\Users\\bob\\Downloads\\x.zip", [tmp_path])["ZoneId"] == "3"
    assert read_zone_identifier("C:\\nope\\y.zip", [tmp_path]) == {}
    assert read_zone_identifier("", [tmp_path]) == {}


def test_zone_identifier_ads_on_windows(tmp_path):
    if os.name != "nt":
        return
    f = tmp_path / "a.exe"
    f.write_bytes(b"MZ")
    try:
        with open(str(f) + ":Zone.Identifier", "w") as fh:
            fh.write("[ZoneTransfer]\nZoneId=3\n")
    except OSError:
        return  # not NTFS
    assert read_zone_identifier(str(f))["ZoneId"] == "3"


def test_enrich_downloads(tmp_path):
    f = tmp_path / "Users" / "bob" / "Downloads" / "x.zip"
    f.parent.mkdir(parents=True)
    (f.parent / "x.zip.Zone.Identifier").write_text("[ZoneTransfer]\nZoneId=3\n")
    ev = Event(timestamp_utc="2024-01-01T00:00:00Z", browser="Edge", browser_version="1", profile="P",
               event_type="download", url="https://h/x.zip", detail="target=C:\\Users\\bob\\Downloads\\x.zip",
               source_record_id="downloads:1")
    with CaseDB(tmp_path / "c.db") as db:
        db.ingest_events([ev])
        assert enrich_downloads(db.conn, [tmp_path]) == 1
        assert "MotW: ZoneId=3" in db.conn.execute("SELECT detail FROM events").fetchone()[0]
        assert enrich_downloads(db.conn, [tmp_path]) == 0  # idempotent
