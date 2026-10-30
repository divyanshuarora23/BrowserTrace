"""Browser database parsers. Each exposes ``parse(db_path, browser, profile, sha256) -> list[Event]``."""

from __future__ import annotations

from collections.abc import Callable

from browsertrace.core.schema import Event

CHROMIUM_BROWSERS = {"Chrome", "Edge", "Brave", "Opera", "Chromium"}
FIREFOX_BROWSERS = {"Firefox"}


def get_parser(browser: str) -> Callable[..., list[Event]]:
    if browser in FIREFOX_BROWSERS:
        from browsertrace.parsers import firefox

        return firefox.parse
    if browser in CHROMIUM_BROWSERS:
        from browsertrace.parsers import chromium

        return chromium.parse
    raise ValueError(f"No parser for browser {browser!r} (known: Chrome, Edge, Brave, Opera, Firefox)")
