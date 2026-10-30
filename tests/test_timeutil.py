from datetime import datetime, timedelta, timezone

from browsertrace.core import timeutil


def test_webkit_known_value_matches_independent_computation():
    us = 13_300_000_000_000_000
    expected = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)
    got = timeutil.webkit_to_utc(us)
    assert got is not None
    assert datetime.fromisoformat(got.replace("Z", "+00:00")) == expected


def test_prtime_known_value_matches_independent_computation():
    us = 1_700_000_000_000_000  # ~2023-11-14
    expected = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)
    got = timeutil.prtime_to_utc(us)
    assert got is not None
    assert datetime.fromisoformat(got.replace("Z", "+00:00")) == expected


def test_webkit_zero_is_out_of_reasonable_range():
    # 1601-01-01 itself is far outside our sanity window -> None, not a crash.
    assert timeutil.webkit_to_utc(0) is None


def test_prtime_zero_is_out_of_reasonable_range():
    assert timeutil.prtime_to_utc(0) is None


def test_none_input():
    assert timeutil.webkit_to_utc(None) is None
    assert timeutil.prtime_to_utc(None) is None


def test_negative_input_handled_without_crash():
    assert timeutil.webkit_to_utc(-1) is None
    assert timeutil.prtime_to_utc(-99999999999999999) is None


def test_out_of_range_huge_value_does_not_crash():
    assert timeutil.webkit_to_utc(10**30) is None
    assert timeutil.prtime_to_utc(10**30) is None


def test_leap_year_boundary():
    # 2024-02-29T12:00:00Z, a leap day, round-tripped through PRTime.
    leap_day = datetime(2024, 2, 29, 12, 0, 0, tzinfo=timezone.utc)
    us = int((leap_day - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1_000_000)
    got = timeutil.prtime_to_utc(us)
    assert got is not None
    assert datetime.fromisoformat(got.replace("Z", "+00:00")) == leap_day


def test_non_numeric_input_returns_none():
    assert timeutil.webkit_to_utc("not-a-number") is None  # type: ignore[arg-type]


def test_now_utc_iso_round_trips():
    ts = timeutil.now_utc_iso()
    parsed = timeutil.parse_iso(ts)
    assert parsed.tzinfo is not None
