"""A tiny, dependency-free audit trail.

``AuditLog`` just accumulates structured entries in memory; the DB layer is responsible
for persisting them into the ``audit_log`` table. Keeping this separate means collectors
and parsers can log without needing a live database connection.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from browsertrace.core.timeutil import now_utc_iso


@dataclass
class AuditEntry:
    timestamp_utc: str
    action: str
    detail: str
    level: str = "info"  # info | warning | error


@dataclass
class AuditLog:
    entries: list[AuditEntry] = field(default_factory=list)

    def log(self, action: str, detail: str, level: str = "info") -> None:
        self.entries.append(AuditEntry(now_utc_iso(), action, detail, level))

    def warning(self, action: str, detail: str) -> None:
        self.log(action, detail, level="warning")

    def error(self, action: str, detail: str) -> None:
        self.log(action, detail, level="error")

    def extend(self, other: "AuditLog") -> None:
        self.entries.extend(other.entries)
