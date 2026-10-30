"""Deleted-record recovery from SQLite WAL files — NOT IMPLEMENTED (documented stub).

Planned design (see docs/LIMITATIONS.md, "Future work"):

1. Parse the WAL header (magic 0x377f0682 / 0x377f0683, page size, salts, checksums).
2. Walk frames, keep only frames that belong to a committed transaction with valid
   checksums and matching salts.
3. Rebuild table-leaf cell content for ``visits``/``urls`` (Chromium) and
   ``moz_historyvisits``/``moz_places`` (Firefox).
4. Emit rows present in older frames but absent from the final database state as
   ``Event(is_recovered=True, event_type="deleted_visit")``, clearly marked partial.

Until this exists, history deletion is surfaced indirectly by rule R006 (gaps in the
visit-ID sequence and unexplained time gaps). The WAL sidecar *is* still copied and
hashed as evidence, so it can be examined later with dedicated tools.
"""

from __future__ import annotations

from pathlib import Path

from browsertrace.core.schema import Event

WAL_MAGIC = (0x377F0682, 0x377F0683)


def recover_from_wal(db_path: Path, wal_path: Path, browser: str, profile: str, sha256: str) -> list[Event]:
    raise NotImplementedError(
        "WAL recovery is not implemented in this version; deleted-history detection relies on rule R006."
    )
