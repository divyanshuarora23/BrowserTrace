"""Timestamp conversion helpers.

Browsers store times in vendor-specific epochs. Everything downstream of this module
must only ever see UTC ISO-8601 strings — conversion happens here, at the parser
boundary, and nowhere else.

- Chromium ("WebKit" time): microseconds since 1601-01-01T00:00:00Z.
- Firefox ("PRTime"): microseconds since 1970-01-01T00:00:00Z.

Both converters are defensive: invalid, missing, negative-beyond-epoch, or
out-of-range values return ``None`` instead of raising, because a single corrupt or
anti-forensic-tampered timestamp must never crash a whole parse run.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Sanity bounds: nothing in this tool cares about dates outside roughly 1990..2200.
_MIN_REASONABLE = datetime(1990, 1, 1, tzinfo=timezone.utc)
_MAX_REASONABLE = datetime(2200, 1, 1, tzinfo=timezone.utc)


def _to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_from_epoch(epoch: datetime, microseconds: int | float | None) -> str | None:
    if microseconds is None:
        return None
    try:
        us = int(microseconds)
    except (TypeError, ValueError):
        return None
    try:
        dt = epoch + timedelta(microseconds=us)
    except OverflowError:
        return None
    if dt < _MIN_REASONABLE or dt > _MAX_REASONABLE:
        return None
    return _to_iso(dt)


def webkit_to_utc(us: int | float | None) -> str | None:
    """Convert a Chromium WebKit timestamp (microseconds since 1601-01-01 UTC) to UTC ISO-8601."""
    return _safe_from_epoch(_WEBKIT_EPOCH, us)


def prtime_to_utc(us: int | float | None) -> str | None:
    """Convert a Firefox PRTime timestamp (microseconds since 1970-01-01 UTC) to UTC ISO-8601."""
    return _safe_from_epoch(_UNIX_EPOCH, us)


def now_utc_iso() -> str:
    """The current time, UTC, in the same ISO-8601 format used everywhere else."""
    return _to_iso(datetime.now(timezone.utc))


def parse_iso(ts: str) -> datetime:
    """Parse one of our own UTC ISO-8601 strings back into an aware ``datetime``."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
