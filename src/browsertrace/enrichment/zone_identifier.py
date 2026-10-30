"""Zone.Identifier (Mark-of-the-Web) enrichment for downloads.

On Windows/NTFS, a downloaded file usually carries an alternate data stream
``<file>:Zone.Identifier`` containing ``ZoneId``, ``ReferrerUrl`` and ``HostUrl``. When
the examined files are not on NTFS (e.g. exported evidence, or tests on Linux), we accept
a sidecar text file ``<file>.Zone.Identifier`` with the same content — this is also how
many forensic export tools preserve ADS content.

Everything here fails silently: a missing stream is normal, not an error.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

ZONE_NAMES = {
    "0": "Local machine",
    "1": "Local intranet",
    "2": "Trusted sites",
    "3": "Internet",
    "4": "Restricted sites",
}


def parse_zone_identifier(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key in ("ZoneId", "ReferrerUrl", "HostUrl"):
            out[key] = value.strip()
    return out


def _candidate_paths(target_path: str, evidence_roots: list[Path]) -> list[Path]:
    if not target_path:
        return []
    raw = target_path
    if raw.startswith("file:///"):
        raw = raw[len("file:///"):]
    candidates = [Path(raw)]
    # Re-root a Windows absolute path under each evidence root
    # (e.g. C:\Users\bob\Downloads\x.zip -> <root>/Users/bob/Downloads/x.zip).
    parts = raw.replace("\\", "/").split("/")
    if parts and parts[0].endswith(":"):
        parts = parts[1:]
    rel = Path(*[p for p in parts if p]) if parts else None
    for root in evidence_roots:
        if rel is not None:
            candidates.append(Path(root) / rel)
    return candidates


def read_zone_identifier(target_path: str, evidence_roots: list[Path] | None = None) -> dict[str, str]:
    for candidate in _candidate_paths(target_path, evidence_roots or []):
        streams = []
        if os.name == "nt":
            streams.append(str(candidate) + ":Zone.Identifier")
        streams.append(str(candidate) + ".Zone.Identifier")
        for stream in streams:
            try:
                with open(stream, encoding="utf-8", errors="replace") as fh:
                    data = parse_zone_identifier(fh.read())
                if data:
                    return data
            except OSError:
                continue
    return {}


def format_zone(data: dict[str, str]) -> str:
    if not data:
        return ""
    bits = []
    if "ZoneId" in data:
        bits.append(f"ZoneId={data['ZoneId']} ({ZONE_NAMES.get(data['ZoneId'], 'unknown')})")
    if "HostUrl" in data:
        bits.append(f"HostUrl={data['HostUrl']}")
    if "ReferrerUrl" in data:
        bits.append(f"ReferrerUrl={data['ReferrerUrl']}")
    return "MotW: " + ", ".join(bits)


def enrich_downloads(conn: sqlite3.Connection, evidence_roots: list[Path] | None = None) -> int:
    """Append Zone.Identifier info to download events' ``detail``. Returns count enriched."""
    enriched = 0
    rows = conn.execute(
        "SELECT event_id, detail FROM events WHERE event_type = 'download'"
    ).fetchall()
    for event_id, detail in rows:
        target = _extract_target(detail or "")
        if not target:
            continue
        zone = format_zone(read_zone_identifier(target, evidence_roots))
        if zone and zone not in (detail or ""):
            conn.execute(
                "UPDATE events SET detail = ? WHERE event_id = ?",
                ((detail + "; " if detail else "") + zone, event_id),
            )
            enriched += 1
    conn.commit()
    return enriched


def _extract_target(detail: str) -> str:
    for part in detail.split("; "):
        if part.startswith("target="):
            return part[len("target="):]
    return ""
