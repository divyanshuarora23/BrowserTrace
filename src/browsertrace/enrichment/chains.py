"""Navigation-chain resolution.

Browsers record *which visit led to which* (Chromium ``visits.from_visit``, Firefox
``moz_historyvisits.from_visit``). Those IDs are only meaningful inside the database
they came from, so resolution is scoped to the same browser + profile + evidence file.
"""

from __future__ import annotations

import sqlite3

MAX_CHAIN_DEPTH = 50

_VISIT_TYPES = ("visit", "deleted_visit")


def resolve_chain_links(conn: sqlite3.Connection) -> int:
    """Fill ``events.from_event_id`` from ``from_visit_id``. Returns rows linked."""
    conn.execute(
        """
        UPDATE events SET from_event_id = (
            SELECT p.event_id FROM events p
            WHERE p.source_file = events.source_file
              AND p.browser = events.browser
              AND p.profile = events.profile
              AND p.source_visit_id = events.from_visit_id
              AND p.event_type IN ('visit', 'deleted_visit')
              AND p.event_id != events.event_id
            ORDER BY p.event_id LIMIT 1
        )
        WHERE from_visit_id IS NOT NULL AND from_visit_id != 0
          AND event_type IN ('visit', 'deleted_visit')
        """
    )
    conn.commit()
    return conn.execute("SELECT COUNT(*) FROM events WHERE from_event_id IS NOT NULL").fetchone()[0]


def get_chain(conn: sqlite3.Connection, event_id: int, max_depth: int = MAX_CHAIN_DEPTH) -> list[dict]:
    """Return the navigation chain ending at ``event_id``, root first.

    Stops on a cycle (an event seen twice) or when ``max_depth`` ancestors were walked.
    """
    conn.row_factory = sqlite3.Row
    chain: list[dict] = []
    seen: set[int] = set()
    current: int | None = event_id
    while current is not None and current not in seen and len(chain) <= max_depth:
        row = conn.execute("SELECT * FROM events WHERE event_id = ?", (current,)).fetchone()
        if row is None:
            break
        seen.add(current)
        chain.append(dict(row))
        current = row["from_event_id"]
    chain.reverse()
    return chain
