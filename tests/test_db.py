import time
from datetime import datetime, timedelta, timezone

from browsertrace.core.db import CaseDB, count_events, query_events
from browsertrace.core.schema import Event


def _ev(i: int, ts: datetime, **kw) -> Event:
    base = dict(
        timestamp_utc=ts.isoformat().replace("+00:00", "Z"),
        browser="Chrome",
        browser_version="1",
        profile="Default",
        event_type="visit",
        url=f"https://site{i % 500}.example.com/page/{i}",
        title=f"Page {i}",
        source_visit_id=i,
        source_file="History",
        source_sha256="x",
        source_record_id=f"visits:{i}",
    )
    base.update(kw)
    return Event(**base)


def test_dedupe_sort_and_flags(tmp_path):
    t = datetime(2024, 1, 1, tzinfo=timezone.utc)
    events = [_ev(2, t + timedelta(minutes=1)), _ev(1, t), _ev(1, t),
              _ev(3, t + timedelta(days=3650))]
    with CaseDB(tmp_path / "c.db") as db:
        stats = db.ingest_events(events, collection_time_utc="2024-06-01T00:00:00Z")
        assert stats.inserted == 3 and stats.duplicates == 1
        assert stats.flagged_future == 1
        rows = db.query_events(limit=10)
        assert [r["source_visit_id"] for r in rows] == [1, 2, 3]
        assert "future timestamp" in rows[-1]["detail"]
        # re-ingesting the same events is idempotent
        assert db.ingest_events(events).inserted == 0


def test_filters(tmp_path):
    t = datetime(2024, 1, 1, tzinfo=timezone.utc)
    events = [_ev(i, t + timedelta(minutes=i)) for i in range(10)]
    events.append(_ev(99, t, browser="Firefox", is_synced=False, url="https://needle.example/", title="needle"))
    events.append(_ev(100, t, is_synced=True, event_type="download"))
    with CaseDB(tmp_path / "c.db") as db:
        db.ingest_events(events)
        c = db.conn
        assert count_events(c, browser="Firefox") == 1
        assert count_events(c, q="needle") == 1
        assert count_events(c, synced=True) == 1
        assert count_events(c, event_type="download") == 1
        assert count_events(c, ts_from="2024-01-01T00:05:00Z") == 5
        assert len(query_events(c, limit=3, offset=10)) == 2


def test_100k_ingest_and_query_timing(tmp_path):
    t = datetime(2023, 1, 1, tzinfo=timezone.utc)
    events = [_ev(i, t + timedelta(seconds=i * 7)) for i in range(100_000)]
    with CaseDB(tmp_path / "big.db") as db:
        start = time.perf_counter()
        stats = db.ingest_events(events)
        ingest_s = time.perf_counter() - start
        assert stats.inserted == 100_000
        assert ingest_s < 30, f"ingest took {ingest_s:.1f}s"

        start = time.perf_counter()
        page = query_events(db.conn, limit=200, offset=50_000)
        total = count_events(db.conn, q="site42.")
        filtered = query_events(db.conn, ts_from="2023-01-05T00:00:00Z", limit=200)
        query_s = time.perf_counter() - start
        assert len(page) == 200 and total > 0 and len(filtered) == 200
        assert query_s < 5, f"queries took {query_s:.2f}s"
