"""Synthetic evidence generator: fake Chrome, Edge and Firefox profiles.

Builds schema-faithful databases (real table and column names from current Chromium
``History`` and Firefox ``places.sqlite``) under a fake Windows user tree, and plants an
"insider data theft" scenario for a fictional employee, J. Doe:

* 2,000+ ordinary daytime browsing events across three browsers;
* 02:10 UTC  Firefox search "how to clear browser history";
* 02:12 UTC  Chrome visit to pastebin.com, 02:14 UTC wetransfer.com;
* 02:16 UTC  Edge download of ``project_files.zip`` from wetransfer (with a
  Zone.Identifier sidecar);
* one Chrome visit carrying ``originator_cache_guid`` (synced from another device);
* a Chrome deletion gap afterwards (missing visit IDs and ~3 days without history).

The default analysis timezone is UTC, so the planted 02:xx events fall inside the
default 00:00-05:00 off-hours window. Everything here is fake and deterministic (seeded).

The same builders are used by the test-suite fixtures (``legacy=True`` produces older
schema variants without ``originator_cache_guid`` / ``downloads_url_chains``).
"""

from __future__ import annotations

import json
import random
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote_plus

WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

INCIDENT_DAY = datetime(2024, 3, 14, tzinfo=timezone.utc)
USER = "jdoe"


def to_webkit(dt: datetime) -> int:
    return (dt - WEBKIT_EPOCH) // timedelta(microseconds=1)


def to_prtime(dt: datetime) -> int:
    return (dt - UNIX_EPOCH) // timedelta(microseconds=1)


# --------------------------------------------------------------------------------------
# Schemas (subset of real columns; names and types match current browser versions)
# --------------------------------------------------------------------------------------

CHROMIUM_SCHEMA = """
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR,
  visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL,
  last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER NOT NULL,
  visit_time INTEGER NOT NULL, from_visit INTEGER, external_referrer_url TEXT,
  transition INTEGER DEFAULT 0 NOT NULL, segment_id INTEGER,
  visit_duration INTEGER DEFAULT 0 NOT NULL,
  incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE NOT NULL, opener_visit INTEGER,
  originator_cache_guid TEXT, originator_visit_id INTEGER, originator_from_visit INTEGER,
  originator_opener_visit INTEGER, is_known_to_sync BOOLEAN DEFAULT FALSE NOT NULL,
  consider_for_ntp_most_visited BOOLEAN DEFAULT FALSE NOT NULL,
  visited_link_id INTEGER DEFAULT 0 NOT NULL, app_id TEXT);
CREATE TABLE keyword_search_terms(keyword_id INTEGER NOT NULL, url_id INTEGER NOT NULL,
  term LONGVARCHAR NOT NULL, normalized_term LONGVARCHAR NOT NULL);
CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR NOT NULL,
  current_path LONGVARCHAR NOT NULL, target_path LONGVARCHAR NOT NULL,
  start_time INTEGER NOT NULL, received_bytes INTEGER NOT NULL, total_bytes INTEGER NOT NULL,
  state INTEGER NOT NULL, danger_type INTEGER NOT NULL, interrupt_reason INTEGER NOT NULL,
  hash BLOB NOT NULL, end_time INTEGER NOT NULL, opened INTEGER NOT NULL,
  last_access_time INTEGER NOT NULL, transient INTEGER NOT NULL, referrer VARCHAR NOT NULL,
  site_url VARCHAR NOT NULL, embedder_download_data VARCHAR NOT NULL, tab_url VARCHAR NOT NULL,
  tab_referrer_url VARCHAR NOT NULL, http_method VARCHAR NOT NULL, by_ext_id VARCHAR NOT NULL,
  by_ext_name VARCHAR NOT NULL, by_web_app_id VARCHAR NOT NULL, etag VARCHAR NOT NULL,
  last_modified VARCHAR NOT NULL, mime_type VARCHAR(255) NOT NULL,
  original_mime_type VARCHAR(255) NOT NULL);
CREATE TABLE downloads_url_chains(id INTEGER NOT NULL, chain_index INTEGER NOT NULL,
  url LONGVARCHAR NOT NULL, PRIMARY KEY (id, chain_index));
"""

# Roughly Chrome ~30 era: no sync columns, no url chains, downloads.full_path + url.
CHROMIUM_LEGACY_SCHEMA = """
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
  visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL,
  last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL,
  favicon_id INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
  from_visit INTEGER, transition INTEGER DEFAULT 0 NOT NULL, segment_id INTEGER,
  is_indexed BOOLEAN, visit_duration INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE keyword_search_terms(keyword_id INTEGER NOT NULL, url_id INTEGER NOT NULL,
  lower_term LONGVARCHAR NOT NULL, term LONGVARCHAR NOT NULL);
CREATE TABLE downloads(id INTEGER PRIMARY KEY, full_path LONGVARCHAR NOT NULL,
  url LONGVARCHAR NOT NULL, start_time INTEGER NOT NULL, received_bytes INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL, state INTEGER NOT NULL, end_time INTEGER NOT NULL,
  opened INTEGER NOT NULL);
"""

FIREFOX_SCHEMA = """
CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
  rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL,
  typed INTEGER DEFAULT 0 NOT NULL, frecency INTEGER DEFAULT -1 NOT NULL,
  last_visit_date INTEGER, guid TEXT, foreign_count INTEGER DEFAULT 0 NOT NULL,
  url_hash INTEGER DEFAULT 0 NOT NULL, description TEXT, preview_image_url TEXT,
  site_name TEXT, origin_id INTEGER, recalc_frecency INTEGER NOT NULL DEFAULT 0,
  alt_frecency INTEGER, recalc_alt_frecency INTEGER NOT NULL DEFAULT 0);
CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER,
  visit_date INTEGER, visit_type INTEGER, session INTEGER, source INTEGER DEFAULT 0 NOT NULL,
  triggeringPlaceId INTEGER);
CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name VARCHAR(32) UNIQUE NOT NULL);
CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL,
  anno_attribute_id INTEGER, content LONGVARCHAR, flags INTEGER DEFAULT 0,
  expiration INTEGER DEFAULT 0, type INTEGER DEFAULT 0, dateAdded INTEGER DEFAULT 0,
  lastModified INTEGER DEFAULT 0);
"""

FIREFOX_LEGACY_SCHEMA = """
CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
  rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL,
  typed INTEGER DEFAULT 0 NOT NULL, frecency INTEGER DEFAULT -1 NOT NULL,
  last_visit_date INTEGER, guid TEXT);
CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER,
  visit_date INTEGER, visit_type INTEGER, session INTEGER);
"""

# Chromium transition values
T_LINK = 0
T_TYPED = 1 | 0x02000000 | 0x10000000 | 0x20000000  # typed [from_address_bar, chain_start, chain_end]
T_GENERATED = 5 | 0x10000000 | 0x20000000
T_LINK_CHAIN = 0 | 0x10000000 | 0x20000000
T_RELOAD = 8 | 0x10000000 | 0x20000000


# --------------------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------------------


@dataclass
class ChromiumBuilder:
    path: Path
    legacy: bool = False
    version: str = "122.0.6261.112"
    _url_ids: dict[str, int] = field(default_factory=dict)
    conn: sqlite3.Connection = field(init=False)

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.path.unlink()
        self.conn = sqlite3.connect(str(self.path))
        self.conn.executescript(CHROMIUM_LEGACY_SCHEMA if self.legacy else CHROMIUM_SCHEMA)
        self.conn.execute("INSERT INTO meta VALUES ('version', ?)", ("28" if self.legacy else "66",))
        self.conn.execute("INSERT INTO meta VALUES ('last_compatible_version', '16')")

    def url_id(self, url: str, title: str, when: datetime, typed: bool = False) -> int:
        wk = to_webkit(when)
        if url in self._url_ids:
            uid = self._url_ids[url]
            self.conn.execute(
                "UPDATE urls SET visit_count = visit_count + 1, typed_count = typed_count + ?, "
                "last_visit_time = MAX(last_visit_time, ?) WHERE id = ?",
                (int(typed), wk, uid),
            )
            return uid
        cur = self.conn.execute(
            "INSERT INTO urls (url, title, visit_count, typed_count, last_visit_time, hidden) "
            "VALUES (?, ?, 1, ?, ?, 0)",
            (url, title, int(typed), wk),
        )
        self._url_ids[url] = cur.lastrowid
        return cur.lastrowid

    def visit(
        self,
        url: str,
        title: str,
        when: datetime,
        transition: int = T_LINK_CHAIN,
        from_visit: int = 0,
        visit_id: int | None = None,
        originator_cache_guid: str = "",
    ) -> int:
        uid = self.url_id(url, title, when, typed=(transition & 0xFF) == 1)
        if self.legacy:
            cur = self.conn.execute(
                "INSERT INTO visits (id, url, visit_time, from_visit, transition, segment_id, "
                "is_indexed, visit_duration) VALUES (?, ?, ?, ?, ?, 0, 1, 0)",
                (visit_id, uid, to_webkit(when), from_visit, transition),
            )
        else:
            cur = self.conn.execute(
                "INSERT INTO visits (id, url, visit_time, from_visit, transition, segment_id, "
                "visit_duration, originator_cache_guid, is_known_to_sync) "
                "VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?)",
                (visit_id, uid, to_webkit(when), from_visit, transition, originator_cache_guid,
                 int(bool(originator_cache_guid))),
            )
        return cur.lastrowid

    def search(self, engine_url: str, term: str, when: datetime, keyword_id: int = 2) -> int:
        url = engine_url + quote_plus(term)
        vid = self.visit(url, f"{term} - Search", when, transition=T_GENERATED)
        uid = self._url_ids[url]
        if self.legacy:
            self.conn.execute(
                "INSERT INTO keyword_search_terms (keyword_id, url_id, lower_term, term) VALUES (?,?,?,?)",
                (keyword_id, uid, term.lower(), term),
            )
        else:
            self.conn.execute(
                "INSERT INTO keyword_search_terms (keyword_id, url_id, term, normalized_term) "
                "VALUES (?,?,?,?)",
                (keyword_id, uid, term, term.lower()),
            )
        return vid

    def download(
        self,
        url_chain: list[str],
        target_path: str,
        when: datetime,
        total_bytes: int,
        mime: str,
        referrer: str = "",
        tab_url: str = "",
        danger_type: int = 0,
    ) -> int:
        end = when + timedelta(seconds=20)
        if self.legacy:
            cur = self.conn.execute(
                "INSERT INTO downloads (full_path, url, start_time, received_bytes, total_bytes, "
                "state, end_time, opened) VALUES (?,?,?,?,?,1,?,0)",
                (target_path, url_chain[-1], to_webkit(when), total_bytes, total_bytes, to_webkit(end)),
            )
            return cur.lastrowid
        cur = self.conn.execute(
            "INSERT INTO downloads (guid, current_path, target_path, start_time, received_bytes, "
            "total_bytes, state, danger_type, interrupt_reason, hash, end_time, opened, "
            "last_access_time, transient, referrer, site_url, embedder_download_data, tab_url, "
            "tab_referrer_url, http_method, by_ext_id, by_ext_name, by_web_app_id, etag, "
            "last_modified, mime_type, original_mime_type) "
            "VALUES (?,?,?,?,?,?,1,?,0,x'',?,0,0,0,?,?,'',?,'','','','','','','',?,?)",
            (
                str(uuid.UUID(int=random.getrandbits(128))).upper(),
                target_path,
                target_path,
                to_webkit(when),
                total_bytes,
                total_bytes,
                danger_type,
                to_webkit(end),
                referrer,
                referrer,
                tab_url,
                mime,
                mime,
            ),
        )
        did = cur.lastrowid
        for i, u in enumerate(url_chain):
            self.conn.execute("INSERT INTO downloads_url_chains VALUES (?,?,?)", (did, i, u))
        return did

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()


@dataclass
class FirefoxBuilder:
    path: Path
    legacy: bool = False
    _place_ids: dict[str, int] = field(default_factory=dict)
    conn: sqlite3.Connection = field(init=False)

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.path.unlink()
        self.conn = sqlite3.connect(str(self.path))
        self.conn.executescript(FIREFOX_LEGACY_SCHEMA if self.legacy else FIREFOX_SCHEMA)
        if not self.legacy:
            self.conn.executemany(
                "INSERT INTO moz_anno_attributes (id, name) VALUES (?, ?)",
                [(1, "downloads/destinationFileURI"), (2, "downloads/metaData")],
            )

    def place_id(self, url: str, title: str, when: datetime) -> int:
        if url in self._place_ids:
            pid = self._place_ids[url]
            self.conn.execute(
                "UPDATE moz_places SET visit_count = visit_count + 1, last_visit_date = ? WHERE id = ?",
                (to_prtime(when), pid),
            )
            return pid
        host = url.split("/")[2] if "://" in url else ""
        cur = self.conn.execute(
            "INSERT INTO moz_places (url, title, rev_host, visit_count, last_visit_date, guid) "
            "VALUES (?, ?, ?, 1, ?, ?)",
            (url, title, host[::-1] + ".", to_prtime(when), uuid.UUID(int=random.getrandbits(128)).hex[:12]),
        )
        self._place_ids[url] = cur.lastrowid
        return cur.lastrowid

    def visit(self, url: str, title: str, when: datetime, visit_type: int = 1, from_visit: int = 0) -> int:
        pid = self.place_id(url, title, when)
        cur = self.conn.execute(
            "INSERT INTO moz_historyvisits (from_visit, place_id, visit_date, visit_type, session) "
            "VALUES (?, ?, ?, ?, 0)",
            (from_visit, pid, to_prtime(when), visit_type),
        )
        return cur.lastrowid

    def download(self, url: str, target_path: str, when: datetime, size: int) -> int:
        vid = self.visit(url, "", when, visit_type=7)
        if self.legacy:
            return vid
        pid = self._place_ids[url]
        uri = "file:///" + target_path.replace("\\", "/")
        end_ms = to_prtime(when + timedelta(seconds=15)) // 1000
        self.conn.execute(
            "INSERT INTO moz_annos (place_id, anno_attribute_id, content, flags, expiration, type, "
            "dateAdded, lastModified) VALUES (?, 1, ?, 0, 4, 3, ?, ?)",
            (pid, uri, to_prtime(when), to_prtime(when)),
        )
        self.conn.execute(
            "INSERT INTO moz_annos (place_id, anno_attribute_id, content, flags, expiration, type, "
            "dateAdded, lastModified) VALUES (?, 2, ?, 0, 4, 3, ?, ?)",
            (pid, json.dumps({"state": 1, "endTime": end_ms, "fileSize": size}), to_prtime(when),
             to_prtime(when)),
        )
        return vid

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()


# --------------------------------------------------------------------------------------
# The scenario
# --------------------------------------------------------------------------------------

NORMAL_SITES = [
    ("https://www.wikipedia.org/wiki/Forensic_science", "Forensic science - Wikipedia"),
    ("https://en.wikipedia.org/wiki/SQLite", "SQLite - Wikipedia"),
    ("https://en.wikipedia.org/wiki/Python_(programming_language)", "Python - Wikipedia"),
    ("https://www.bbc.com/news", "BBC News"),
    ("https://www.bbc.com/news/technology", "Technology - BBC News"),
    ("https://www.theguardian.com/international", "The Guardian"),
    ("https://github.com/", "GitHub"),
    ("https://github.com/python/cpython", "python/cpython"),
    ("https://stackoverflow.com/questions", "Newest Questions - Stack Overflow"),
    ("https://stackoverflow.com/questions/2887878", "Importing a CSV file into sqlite3"),
    ("https://docs.python.org/3/library/sqlite3.html", "sqlite3 — Python docs"),
    ("https://outlook.office.com/mail/", "Mail - J. Doe - Outlook"),
    ("https://teams.microsoft.com/", "Microsoft Teams"),
    ("https://www.linkedin.com/feed/", "Feed | LinkedIn"),
    ("https://www.youtube.com/", "YouTube"),
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "Quarterly all-hands recap - YouTube"),
    ("https://www.amazon.com/", "Amazon.com"),
    ("https://www.weather.com/", "Weather Forecast"),
    ("https://intranet.example-corp.com/", "Example Corp Intranet"),
    ("https://intranet.example-corp.com/hr/leave", "Leave requests - Intranet"),
    ("https://jira.example-corp.com/browse/PROJ-1432", "PROJ-1432 Fix export - Jira"),
    ("https://jira.example-corp.com/secure/Dashboard.jspa", "System Dashboard - Jira"),
    ("https://confluence.example-corp.com/display/ENG", "Engineering - Confluence"),
    ("https://www.reddit.com/r/programming/", "r/programming"),
    ("https://news.ycombinator.com/", "Hacker News"),
    ("https://www.nytimes.com/", "The New York Times"),
    ("https://maps.google.com/", "Google Maps"),
    ("https://calendar.google.com/calendar/r", "Google Calendar"),
    ("https://www.espn.com/", "ESPN"),
    ("https://www.imdb.com/", "IMDb"),
    ("https://developer.mozilla.org/en-US/docs/Web/JavaScript", "JavaScript | MDN"),
    ("https://www.w3schools.com/sql/", "SQL Tutorial"),
    ("https://www.coursera.org/", "Coursera"),
    ("https://www.booking.com/", "Booking.com"),
    ("https://www.investopedia.com/", "Investopedia"),
]

NORMAL_SEARCHES = [
    "python sqlite3 executemany example",
    "weather tomorrow",
    "quarterly report template",
    "best laptop bag",
    "jira jql examples",
    "how to export excel to csv",
    "pizza near me",
    "flight status AI 101",
    "regex email validation",
    "conference room booking outlook",
    "git rebase vs merge",
    "unit conversion inches to cm",
]

NORMAL_DOWNLOADS = [
    ("https://intranet.example-corp.com/files/expense_policy.pdf", "expense_policy.pdf", "application/pdf"),
    ("https://www.example-corp.com/brochure/product_sheet.pdf", "product_sheet.pdf", "application/pdf"),
    ("https://confluence.example-corp.com/download/meeting_notes.docx", "meeting_notes.docx",
     "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    ("https://upload.wikimedia.org/wikipedia/commons/a/a9/Example.jpg", "Example.jpg", "image/jpeg"),
]

PHONE_SYNC_GUID = "3c1f2a9e-77b4-4d1c-9a51-ad9c0e2b1f60"


def _day_times(rng: random.Random, day: datetime, n: int, start_h: int = 8, end_h: int = 21) -> list[datetime]:
    span = (end_h - start_h) * 3600
    secs = sorted(rng.randrange(span) for _ in range(n))
    return [day + timedelta(hours=start_h, seconds=s) for s in secs]


def _normal_chromium_day(
    rng: random.Random, b: ChromiumBuilder, day: datetime, n: int, search_url: str
) -> int:
    count = 0
    prev_vid = 0
    prev_t: datetime | None = None
    for t in _day_times(rng, day, n):
        # sessions: a visit within 3 min of the previous one usually follows a link from it
        linked = prev_t is not None and (t - prev_t) < timedelta(minutes=3) and rng.random() < 0.7
        r = rng.random()
        if r < 0.08:
            vid = b.search(search_url, rng.choice(NORMAL_SEARCHES), t)
        else:
            url, title = rng.choice(NORMAL_SITES)
            if linked:
                vid = b.visit(url, title, t, transition=T_LINK, from_visit=prev_vid)
            elif r < 0.35:
                vid = b.visit(url, title, t, transition=T_TYPED)
            else:
                vid = b.visit(url, title, t, transition=T_LINK_CHAIN)
        prev_vid, prev_t = vid, t
        count += 1
    return count


def _normal_firefox_day(rng: random.Random, b: FirefoxBuilder, day: datetime, n: int) -> int:
    count = 0
    prev_vid = 0
    prev_t: datetime | None = None
    for t in _day_times(rng, day, n):
        linked = prev_t is not None and (t - prev_t) < timedelta(minutes=3) and rng.random() < 0.7
        r = rng.random()
        if r < 0.08:
            term = rng.choice(NORMAL_SEARCHES)
            vid = b.visit(f"https://duckduckgo.com/?q={quote_plus(term)}", f"{term} at DuckDuckGo", t,
                          visit_type=2)
        elif r < 0.12:
            # embedded resource: should be tagged and not flood the timeline
            vid = b.visit("https://www.youtube.com/embed/abc123", "", t, visit_type=4, from_visit=prev_vid)
        else:
            url, title = rng.choice(NORMAL_SITES)
            vid = b.visit(url, title, t, visit_type=1 if linked else 2, from_visit=prev_vid if linked else 0)
        prev_vid, prev_t = vid, t
        count += 1
    return count


def build_scenario(out_dir: Path, seed: int = 1337) -> dict:
    """Create the full fake evidence tree under ``out_dir`` and return the expectations dict."""
    rng = random.Random(seed)
    random.seed(seed)  # builders draw GUIDs from the module RNG
    out_dir = Path(out_dir)
    home = out_dir / "Users" / USER
    local = home / "AppData" / "Local"
    roaming = home / "AppData" / "Roaming"

    chrome_ud = local / "Google" / "Chrome" / "User Data"
    edge_ud = local / "Microsoft" / "Edge" / "User Data"
    ff_profile = roaming / "Mozilla" / "Firefox" / "Profiles" / "x7k2m9qa.default-release"

    chrome = ChromiumBuilder(chrome_ud / "Default" / "History", version="122.0.6261.112")
    edge = ChromiumBuilder(edge_ud / "Profile 1" / "History", version="122.0.2365.80")
    firefox = FirefoxBuilder(ff_profile / "places.sqlite")
    (chrome_ud / "Last Version").write_text(chrome.version, encoding="utf-8")
    (edge_ud / "Last Version").write_text(edge.version, encoding="utf-8")
    (ff_profile / "compatibility.ini").write_text(
        "[Compatibility]\nLastVersion=123.0_20240311181342/20240311181342\nLastOSABI=WINNT_x86_64-msvc\n",
        encoding="utf-8",
    )

    days_before = [INCIDENT_DAY - timedelta(days=d) for d in range(6, 0, -1)]
    days_after = [INCIDENT_DAY + timedelta(days=d) for d in range(0, 6)]
    normal = 0

    # ---- before the incident: normal activity in all three browsers --------------------
    synced_planted = False
    for day in days_before:
        normal += _normal_chromium_day(rng, chrome, day, 70, "https://www.google.com/search?q=")
        normal += _normal_chromium_day(rng, edge, day, 55, "https://www.bing.com/search?q=")
        normal += _normal_firefox_day(rng, firefox, day, 68)
        if not synced_planted and day == days_before[2]:
            chrome.visit(
                "https://www.espn.com/cricket/scores",
                "Live cricket scores - ESPN",
                day + timedelta(hours=13, minutes=5),
                transition=T_LINK_CHAIN,
                originator_cache_guid=PHONE_SYNC_GUID,
            )
            synced_planted = True
    # A few ordinary daytime downloads, including a legitimate installer
    for i, (url, name, mime) in enumerate(NORMAL_DOWNLOADS):
        day = days_before[i]
        chrome.download([url], f"C:\\Users\\{USER}\\Downloads\\{name}", day + timedelta(hours=11, minutes=7 * i),
                        40_000 + i * 1234, mime, referrer=url.rsplit("/", 1)[0] + "/")
    firefox.download("https://intranet.example-corp.com/files/holiday_calendar.pdf",
                     f"C:\\Users\\{USER}\\Downloads\\holiday_calendar.pdf",
                     days_before[1] + timedelta(hours=15, minutes=2), 88_000)

    # ---- the incident (all UTC; inside the default 00:00-05:00 off-hours window) --------
    D = INCIDENT_DAY
    t_search = D + timedelta(hours=2, minutes=10)
    ff_search = firefox.visit(
        "https://www.google.com/search?q=how+to+clear+browser+history",
        "how to clear browser history - Google Search",
        t_search,
        visit_type=2,
    )
    t_paste = D + timedelta(hours=2, minutes=12)
    t_wt = D + timedelta(hours=2, minutes=14)
    v_paste = chrome.visit("https://pastebin.com/", "Pastebin.com - #1 paste tool since 2002!", t_paste,
                           transition=T_TYPED)
    v_wt = chrome.visit("https://wetransfer.com/", "WeTransfer | Send Large Files Fast", t_wt,
                        transition=T_TYPED)
    t_dl_page = D + timedelta(hours=2, minutes=15, seconds=30)
    t_dl = D + timedelta(hours=2, minutes=16)
    dl_page = "https://wetransfer.com/downloads/8f3a1c0d2e9b/7d1e0c"
    edge_v = edge.visit(dl_page, "WeTransfer - Download", t_dl_page, transition=T_TYPED)
    edge.download(
        [dl_page, "https://download.wetransfer.com/eu2/8f3a1c0d2e9b/project_files.zip"],
        f"C:\\Users\\{USER}\\Downloads\\project_files.zip",
        t_dl,
        48_213_377,
        "application/zip",
        referrer=dl_page,
        tab_url=dl_page,
    )
    downloads_dir = home / "Downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    (downloads_dir / "project_files.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    (downloads_dir / "project_files.zip.Zone.Identifier").write_text(
        "[ZoneTransfer]\nZoneId=3\nReferrerUrl=" + dl_page
        + "\nHostUrl=https://download.wetransfer.com/eu2/8f3a1c0d2e9b/project_files.zip\n",
        encoding="utf-8",
    )

    # ---- afterwards: Chrome history deleted for ~3 days (visit-ID hole + time gap) -----
    deleted_ids = 250
    last_chrome_visit = chrome.conn.execute("SELECT MAX(id) FROM visits").fetchone()[0]
    first_after_gap = last_chrome_visit + deleted_ids + 1
    resume = days_after[3]
    first = True
    for day in days_after:
        if day >= resume:
            if first:
                # reserve the id hole by inserting the first post-gap visit with an explicit id
                chrome.visit("https://outlook.office.com/mail/", "Mail - J. Doe - Outlook",
                             day + timedelta(hours=8, minutes=1), transition=T_TYPED, visit_id=first_after_gap)
                normal += 1
                first = False
            normal += _normal_chromium_day(rng, chrome, day, 70, "https://www.google.com/search?q=")
        if day != D:
            normal += _normal_chromium_day(rng, edge, day, 55, "https://www.bing.com/search?q=")
            normal += _normal_firefox_day(rng, firefox, day, 68)
        else:
            # incident day still has ordinary daytime work in Edge and Firefox
            normal += _normal_chromium_day(rng, edge, day, 40, "https://www.bing.com/search?q=")
            normal += _normal_firefox_day(rng, firefox, day, 40)

    for b in (chrome, edge, firefox):
        b.close()

    expected = {
        "scenario": "insider data theft",
        "subject": "J. Doe (fictional)",
        "timezone": "UTC",
        "off_hours": "00:00-05:00",
        "normal_events_generated": normal,
        "planted_events": [
            {"what": "search 'how to clear browser history'", "browser": "Firefox",
             "time_utc": t_search.isoformat().replace("+00:00", "Z"), "source_record_id": f"moz_historyvisits:{ff_search}"},
            {"what": "visit pastebin.com", "browser": "Chrome",
             "time_utc": t_paste.isoformat().replace("+00:00", "Z"), "source_record_id": f"visits:{v_paste}"},
            {"what": "visit wetransfer.com", "browser": "Chrome",
             "time_utc": t_wt.isoformat().replace("+00:00", "Z"), "source_record_id": f"visits:{v_wt}"},
            {"what": "visit wetransfer download page", "browser": "Edge",
             "time_utc": t_dl_page.isoformat().replace("+00:00", "Z"), "source_record_id": f"visits:{edge_v}"},
            {"what": "download project_files.zip", "browser": "Edge",
             "time_utc": t_dl.isoformat().replace("+00:00", "Z"), "source_record_id": "downloads:1"},
            {"what": "synced visit (originator_cache_guid set)", "browser": "Chrome",
             "url": "https://www.espn.com/cricket/scores"},
            {"what": f"deletion gap: Chrome visit ids {last_chrome_visit + 1}-{first_after_gap - 1} missing, "
                     f"no Chrome history until {resume.date().isoformat()}", "browser": "Chrome"},
        ],
        "expected_findings": [
            {"rule_id": "R001", "severity": "High", "match": "pastebin.com", "note": "Medium escalated by off-hours"},
            {"rule_id": "R001", "severity": "High", "match": "wetransfer.com", "note": "Medium escalated by off-hours"},
            {"rule_id": "R002", "severity": "High", "match": "project_files.zip", "note": "Medium escalated by off-hours"},
            {"rule_id": "R003", "severity": "Low", "match": ""},
            {"rule_id": "R004", "severity": "High", "match": "how to clear browser history"},
            {"rule_id": "R005", "severity": "High", "match": "project_files.zip"},
            {"rule_id": "R006", "severity": "High", "match": "Chrome"},
        ],
        "expected_synced_urls": ["https://www.espn.com/cricket/scores"],
        "max_unexpected_findings": 3,
    }
    (out_dir / "scenario_expected.json").write_text(json.dumps(expected, indent=2), encoding="utf-8")
    return expected
