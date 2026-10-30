"""Forensically sound acquisition of browser databases into a case folder.

For each target:

1. SHA-256 the original (DB, and ``-wal`` / ``-shm`` sidecars if present).
2. Copy them into ``<case>/evidence/<browser>/<profile>/``.
3. SHA-256 the copies and compare. Sidecars of a *running* browser can legitimately
   change between hashing and copying, so the original is re-hashed after the copy and
   both values are recorded.
4. Record ``evidence_files`` + ``custody_log`` rows and audit every step.

Parsing never touches the evidence copy either: :func:`make_working_copy` makes a
scratch copy in ``<case>/work/`` that parsers open read-only, so the evidence copy
stays byte-identical and ``browsertrace verify`` keeps passing.
"""

from __future__ import annotations

import configparser
import hashlib
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from browsertrace.collector.discover import Target
from browsertrace.core.audit import AuditLog
from browsertrace.core.timeutil import now_utc_iso

SIDECAR_SUFFIXES = ("-wal", "-shm")
RETRIES = 3
RETRY_DELAY_S = 1.0
_SAFE = re.compile(r"[^A-Za-z0-9._ -]+")


class CollectionError(Exception):
    pass


@dataclass
class CollectedFile:
    original: Path
    copy: Path
    sha256_original: str
    sha256_copy: str
    sha256_original_after: str

    @property
    def verified(self) -> bool:
        return self.sha256_original == self.sha256_copy


@dataclass
class CollectedTarget:
    target: Target
    db: CollectedFile
    sidecars: list[CollectedFile] = field(default_factory=list)
    browser_version: str = "unknown"
    evidence_id: int | None = None

    @property
    def verified(self) -> bool:
        return self.db.verified


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _with_retries(fn, what: str, audit: AuditLog):
    last: Exception | None = None
    for attempt in range(1, RETRIES + 1):
        try:
            return fn()
        except PermissionError as exc:  # typical for a file locked by a running browser
            last = exc
            audit.warning("collect", f"{what}: locked/permission denied (attempt {attempt}/{RETRIES})")
            time.sleep(RETRY_DELAY_S)
    raise CollectionError(
        f"{what} is locked or not readable ({last}). Close the browser, or acquire the profile "
        "with a forensic imager / Volume Shadow Copy and point --evidence at that copy."
    )


def _safe_name(name: str) -> str:
    return _SAFE.sub("_", name).strip() or "unknown"


def _copy_one(src: Path, dest: Path, audit: AuditLog) -> CollectedFile:
    h_orig = _with_retries(lambda: sha256_file(src), f"hashing {src}", audit)
    _with_retries(lambda: shutil.copyfile(src, dest), f"copying {src}", audit)
    h_copy = sha256_file(dest)
    h_after = _with_retries(lambda: sha256_file(src), f"re-hashing {src}", audit)
    audit.log("copy", f"{src} -> {dest} sha256={h_copy}")
    if h_orig != h_copy:
        audit.warning(
            "verify",
            f"{src}: hash changed during acquisition (before={h_orig}, copy={h_copy}, after={h_after}); "
            "the file was probably being written by a running browser",
        )
    return CollectedFile(src, dest, h_orig, h_copy, h_after)


def detect_browser_version(target: Target) -> str:
    """Best effort. Chromium: ``User Data/Last Version``; Firefox: ``compatibility.ini``."""
    try:
        if target.browser == "Firefox":
            ini = target.path.parent / "compatibility.ini"
            if ini.is_file():
                cp = configparser.ConfigParser()
                cp.read(ini, encoding="utf-8")
                last = cp.get("Compatibility", "LastVersion", fallback="")
                if last:
                    return last.split("_")[0]
            return "unknown"
        for candidate in (target.path.parent.parent / "Last Version", target.path.parent / "Last Version"):
            if candidate.is_file():
                v = candidate.read_text(encoding="utf-8", errors="replace").strip()
                if v:
                    return v
    except OSError:
        pass
    return "unknown"


def collect_target(target: Target, case_dir: Path, audit: AuditLog) -> CollectedTarget:
    dest_dir = Path(case_dir) / "evidence" / _safe_name(target.browser) / _safe_name(target.profile)
    dest_dir.mkdir(parents=True, exist_ok=True)
    if not target.path.is_file():
        raise CollectionError(f"{target.path} does not exist or is not a file")
    audit.log("collect", f"acquiring {target.browser}/{target.profile} from {target.path}")
    db = _copy_one(target.path, dest_dir / target.path.name, audit)
    sidecars = []
    for suffix in SIDECAR_SUFFIXES:
        side = target.path.with_name(target.path.name + suffix)
        if side.is_file():
            sidecars.append(_copy_one(side, dest_dir / side.name, audit))
    version = detect_browser_version(target)
    return CollectedTarget(target, db, sidecars, version)


def _rel(path: Path, case_dir: Path) -> str:
    try:
        return Path(path).resolve().relative_to(Path(case_dir).resolve()).as_posix()
    except ValueError:
        return str(path)


def record_collection(db, ct: CollectedTarget, case_dir: Path) -> int:
    """Persist evidence_files + custody_log rows for one collected target.

    Copy paths are stored relative to the case folder so a case can be moved/archived.
    """
    note = ", ".join(f"{s.copy.name}" for s in ct.sidecars) or "no sidecars"
    evidence_id = db.record_evidence_file(
        browser=ct.target.browser,
        profile=ct.target.profile,
        original_path=str(ct.db.original),
        copy_path=_rel(ct.db.copy, case_dir),
        sha256_original=ct.db.sha256_original,
        sha256_copy=ct.db.sha256_copy,
        verified=int(ct.db.verified),
        browser_version=ct.browser_version,
        collected_utc=now_utc_iso(),
        note=f"sidecars: {note}",
    )
    for f in [ct.db, *ct.sidecars]:
        changed = f.sha256_original != f.sha256_original_after
        db.record_custody(
            original_path=str(f.original),
            copy_path=_rel(f.copy, case_dir),
            sha256_original=f.sha256_original,
            sha256_copy=f.sha256_copy,
            match=int(f.verified),
            note=(
                f"original changed during acquisition; after-copy hash {f.sha256_original_after}"
                if changed
                else "copied with shutil.copyfile; original opened for reading only"
            ),
        )
    ct.evidence_id = evidence_id
    return evidence_id


def make_working_copy(ct: CollectedTarget, case_dir: Path) -> Path:
    """Copy the evidence copy (+ sidecars) to ``<case>/work/`` for parsing."""
    work = Path(case_dir) / "work" / ct.db.copy.parent.relative_to(Path(case_dir) / "evidence")
    work.mkdir(parents=True, exist_ok=True)
    dest = work / ct.db.copy.name
    shutil.copyfile(ct.db.copy, dest)
    for s in ct.sidecars:
        shutil.copyfile(s.copy, work / s.copy.name)
    return dest


def verify_case_evidence(conn, case_dir: Path) -> list[dict]:
    """Re-hash every evidence copy and compare with the stored hash."""
    results = []
    for row in conn.execute("SELECT * FROM custody_log ORDER BY id").fetchall():
        row = dict(row)
        path = Path(row["copy_path"])
        if not path.is_absolute():
            path = Path(case_dir) / path
        if not path.is_file():
            status, current = "missing", ""
        else:
            current = sha256_file(path)
            status = "ok" if current == row["sha256_copy"] else "MODIFIED"
        results.append(
            {
                "copy_path": row["copy_path"],
                "stored_sha256": row["sha256_copy"],
                "current_sha256": current,
                "status": status,
            }
        )
    return results
