from pathlib import Path

import pytest

from browsertrace.core.audit import AuditLog
from browsertrace.parsers import chromium, firefox, get_parser
from browsertrace.parsers.base import ParserError, extract_search_term
from tests.conftest import make_chromium, make_firefox


def _by_type(events, t):
    return [e for e in events if e.event_type == t]


@pytest.mark.parametrize("legacy", [False, True])
def test_chromium_parser_schema_variants(tmp_path, legacy):
    db = make_chromium(tmp_path / "History", legacy=legacy)
    audit = AuditLog()
    events = chromium.parse(db, "Chrome", "Default", "abc", audit=audit)
    visits = _by_type(events, "visit")
    assert len(visits) == 5
    assert all(e.timestamp_utc.endswith("Z") for e in events)
    assert all(e.source_sha256 == "abc" and e.source_record_id for e in events)
    first = visits[0]
    assert first.timestamp_utc == "2024-05-01T10:00:00Z"
    assert first.transition == "typed [from_address_bar]"
    assert visits[1].from_visit_id == first.source_visit_id
    internal = [v for v in visits if v.url.startswith("chrome://")]
    assert "internal page" in internal[0].detail
    synced = [v for v in visits if v.is_synced]
    if legacy:
        assert synced == []
        assert any("originator_cache_guid missing" in e.detail for e in audit.entries)
    else:
        assert [v.url for v in synced] == ["https://news.example.org/"]
    searches = _by_type(events, "search")
    # URL-derived search and keyword_search_terms are de-duplicated into one event
    assert [s.title for s in searches] == ["sqlite wal format"]
    downloads = _by_type(events, "download")
    assert len(downloads) == 1
    assert downloads[0].title == "tool.exe"
    assert "target=C:\\Users\\x\\Downloads\\tool.exe" in downloads[0].detail
    if legacy:
        assert any("downloads_url_chains" in e.detail for e in audit.entries)
    else:
        assert downloads[0].url == "https://cdn.example.com/tool.exe"  # last URL of the chain


@pytest.mark.parametrize("legacy", [False, True])
def test_firefox_parser_schema_variants(tmp_path, legacy):
    db = make_firefox(tmp_path / "places.sqlite", legacy=legacy)
    audit = AuditLog()
    events = firefox.parse(db, "Firefox", "p1", "def", audit=audit)
    visits = _by_type(events, "visit")
    assert len(visits) == 5
    assert visits[0].timestamp_utc == "2024-05-01T10:00:00Z"
    assert visits[0].transition == "typed"
    embed = [v for v in visits if v.transition == "embed"]
    assert embed and "embedded resource" in embed[0].detail
    assert all(not e.is_synced for e in events)
    assert [s.title for s in _by_type(events, "search")] == ["firefox places schema"]
    downloads = _by_type(events, "download")
    assert len(downloads) == 1
    if legacy:
        assert "visit_type=7 only" in downloads[0].detail
    else:
        assert "target=C:/Users/x/Downloads/data.zip" in downloads[0].detail
        assert "bytes=999" in downloads[0].detail
        assert downloads[0].title == "data.zip"


def test_parser_rejects_non_sqlite(tmp_path):
    bad = tmp_path / "History"
    bad.write_bytes(b"this is not a database at all" * 100)
    with pytest.raises(ParserError):
        chromium.parse(bad, "Chrome", "Default", "x")


def test_parser_tolerates_unrelated_sqlite(tmp_path):
    import sqlite3

    db = tmp_path / "places.sqlite"
    sqlite3.connect(db).execute("CREATE TABLE something(x)").connection.commit()
    audit = AuditLog()
    assert firefox.parse(db, "Firefox", "p", "x", audit=audit) == []
    assert any(e.level == "warning" for e in audit.entries)


def test_parser_never_writes(tmp_path):
    db = make_chromium(tmp_path / "History")
    before = Path(db).read_bytes()
    chromium.parse(db, "Chrome", "Default", "x")
    assert Path(db).read_bytes() == before


def test_get_parser():
    assert get_parser("Edge") is chromium.parse
    assert get_parser("Firefox") is firefox.parse
    with pytest.raises(ValueError):
        get_parser("Netscape")


@pytest.mark.parametrize("url,expected", [
    ("https://www.google.com/search?q=hello+world", ("google", "hello world")),
    ("https://www.google.co.in/search?q=abc", ("google", "abc")),
    ("https://www.bing.com/search?q=x+y&form=QBLH", ("bing.com", "x y")),
    ("https://duckduckgo.com/?q=tor", ("duckduckgo.com", "tor")),
    ("https://search.yahoo.com/search?p=vpn", ("search.yahoo.com", "vpn")),
    ("https://search.brave.com/search?q=b", ("search.brave.com", "b")),
    ("https://yandex.ru/search/?text=y", ("yandex", "y")),
    ("https://www.baidu.com/s?wd=z", ("baidu.com", "z")),
    ("https://www.ecosia.org/search?q=trees", ("ecosia.org", "trees")),
    ("https://www.youtube.com/results?search_query=cats", ("youtube.com", "cats")),
    ("https://www.google.com/maps?q=paris", None),
    ("https://notgoogle.example/search?q=x", None),
    ("https://example.com/?q=x", None),
])
def test_search_term_extraction(url, expected):
    assert extract_search_term(url) == expected
