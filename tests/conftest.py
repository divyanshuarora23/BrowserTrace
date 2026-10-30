from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from browsertrace.pipeline import analyze
from browsertrace.scenario import ChromiumBuilder, FirefoxBuilder, build_scenario

T0 = datetime(2024, 5, 1, 10, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="session")
def scenario(tmp_path_factory) -> dict:
    """The synthetic scenario, analyzed once per test session."""
    root = tmp_path_factory.mktemp("scenario")
    evidence = root / "evidence_source"
    expected = build_scenario(evidence)
    case_dir = root / "case"
    summary = analyze(evidence, case_dir, "TEST-001", "Pytest")
    return {"evidence": evidence, "case_dir": case_dir, "expected": expected, "summary": summary,
            "expected_file": json.loads((evidence / "scenario_expected.json").read_text())}


def make_chromium(path: Path, legacy: bool = False) -> Path:
    b = ChromiumBuilder(path, legacy=legacy)
    v1 = b.visit("https://example.com/", "Example", T0, transition=1 | 0x02000000)
    b.visit("https://example.com/page", "Page", T0 + timedelta(seconds=30), transition=0, from_visit=v1)
    if legacy:
        b.visit("https://news.example.org/", "News", T0 + timedelta(minutes=2))
    else:
        b.visit("https://news.example.org/", "News", T0 + timedelta(minutes=2),
                originator_cache_guid="phone-guid")
    b.visit("chrome://settings/", "Settings", T0 + timedelta(minutes=3))
    b.search("https://www.google.com/search?q=", "sqlite wal format", T0 + timedelta(minutes=4))
    b.download(["https://example.com/r", "https://cdn.example.com/tool.exe"], "C:\\Users\\x\\Downloads\\tool.exe",
               T0 + timedelta(minutes=5), 1234, "application/octet-stream", referrer="https://example.com/")
    b.close()
    return path


def make_firefox(path: Path, legacy: bool = False) -> Path:
    b = FirefoxBuilder(path, legacy=legacy)
    v1 = b.visit("https://example.com/", "Example", T0, visit_type=2)
    b.visit("https://example.com/page", "Page", T0 + timedelta(seconds=30), visit_type=1, from_visit=v1)
    b.visit("https://www.youtube.com/embed/x", "", T0 + timedelta(seconds=40), visit_type=4, from_visit=v1)
    b.visit("https://duckduckgo.com/?q=firefox+places+schema", "ddg", T0 + timedelta(minutes=1), visit_type=2)
    b.download("https://cdn.example.com/data.zip", "C:\\Users\\x\\Downloads\\data.zip", T0 + timedelta(minutes=2), 999)
    b.close()
    return path
