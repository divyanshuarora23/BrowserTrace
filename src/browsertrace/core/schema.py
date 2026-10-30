"""The event schema: the contract every parser and downstream consumer agrees on."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any, Literal

EventType = Literal["visit", "download", "search", "deleted_visit"]


@dataclass
class Event:
    """A single, normalized browser-activity event.

    Every field that comes straight from a browser database keeps enough breadcrumbs
    (``source_file``, ``source_sha256``, ``source_record_id``) to trace the record back
    to the exact row it came from, in the exact evidence copy it was parsed from.
    """

    timestamp_utc: str
    browser: str
    browser_version: str
    profile: str
    event_type: str  # one of EventType, kept as str for forward/backward schema tolerance
    url: str = ""
    title: str = ""
    detail: str = ""
    transition: str = ""
    is_synced: bool = False
    source_visit_id: int | None = None
    from_visit_id: int | None = None
    from_event_id: int | None = None
    is_recovered: bool = False
    source_file: str = ""
    source_sha256: str = ""
    source_record_id: str = ""

    # Filled in later by the DB layer once the row has an identity.
    event_id: int | None = field(default=None, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)}


EVENT_FIELD_NAMES: tuple[str, ...] = tuple(f.name for f in fields(Event))
