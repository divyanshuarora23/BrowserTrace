import sqlite3
from pathlib import Path

import pytest

from browsertrace.collector import collect as collect_mod
from browsertrace.collector.collect import (
    CollectionError,
    collect_target,
    record_collection,
    sha256_file,
    verify_case_evidence,
)
from browsertrace.collector.discover import DiscoveryError, discover, find_targets, target_for_file
from browsertrace.core.audit import AuditLog
from browsertrace.core.db import CaseDB
from browsertrace.pipeline import analyze
from tests.conftest import make_chromium, make_firefox


def _tree(root: Path) -> dict[str, Path]:
    u = root / "Users" / "bob" / "AppData"
    paths = {
        "chrome": u / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History",
        "chrome2": u / "Local" / "Google" / "Chrome" / "User Data" / "Profile 2" / "History",
        "edge": u / "Local" / "Microsoft" / "Edge" / "User Data" / "Default" / "History",
        "brave": u / "Local" / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "History",
        "opera": u / "Roaming" / "Opera Software" / "Opera Stable" / "History",
        "firefox": u / "Roaming" / "Mozilla" / "Firefox" / "Profiles" / "abcd.default-release" / "places.sqlite",
        # decoys that must not be picked up
        "decoy1": u / "Local" / "Google" / "Chrome" / "User Data" / "System Profile" / "History",
        "decoy2": u / "Local" / "Random" / "History",
    }
    for k, p in paths.items():
        if k == "firefox":
            make_firefox(p)
        else:
            make_chromium(p)
    return paths


def test_discovery_identifies_browsers_and_profiles(tmp_path):
    paths = _tree(tmp_path)
    found = {(t.browser, t.profile): t.path for t in discover(tmp_path)}
    assert found == {
        ("Chrome", "Default"): paths["chrome"],
        ("Chrome", "Profile 2"): paths["chrome2"],
        ("Edge", "Default"): paths["edge"],
        ("Brave", "Default"): paths["brave"],
        ("Opera", "Opera Stable"): paths["opera"],
        ("Firefox", "abcd.default-release"): paths["firefox"],
    }


def test_find_targets_filters_and_direct_file(tmp_path):
    paths = _tree(tmp_path)
    assert [t.profile for t in find_targets(tmp_path, browser="chrome")] == ["Default", "Profile 2"]
    t = target_for_file(paths["decoy2"], browser="Edge", profile="Work")
    assert (t.browser, t.profile) == ("Edge", "Work")
    with pytest.raises(DiscoveryError):
        target_for_file(tmp_path / "nothing")
    other = tmp_path / "copy.db"
    other.write_bytes(paths["chrome"].read_bytes())
    with pytest.raises(DiscoveryError):
        target_for_file(other)  # unknown file name, no --browser
    with pytest.raises(DiscoveryError):
        discover(tmp_path / "missing")


def test_collect_copies_db_and_wal_and_leaves_original_untouched(tmp_path):
    src = tmp_path / "src" / "Google" / "Chrome" / "User Data" / "Default" / "History"
    make_chromium(src)
    # put the DB into WAL mode with an un-checkpointed write so a -wal sidecar exists
    keep = sqlite3.connect(src)
    keep.execute("PRAGMA journal_mode=WAL")
    keep.execute("PRAGMA wal_autocheckpoint=0")
    keep.execute("INSERT INTO meta VALUES ('wal_test', '1')")
    keep.commit()
    wal = src.with_name("History-wal")
    assert wal.exists()
    hashes_before = {p.name: sha256_file(p) for p in src.parent.iterdir()}

    targets = find_targets(tmp_path / "src")
    case = tmp_path / "case"
    audit = AuditLog()
    ct = collect_target(targets[0], case, audit)
    assert ct.verified
    assert {s.copy.name for s in ct.sidecars} >= {"History-wal"}
    assert (case / "evidence" / "Chrome" / "Default" / "History-wal").is_file()
    with CaseDB(case / "case.db") as db:
        record_collection(db, ct, case)
        assert db.conn.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0] == 1 + len(ct.sidecars)
        assert all(r["status"] == "ok" for r in verify_case_evidence(db.conn, case))
    # Original DB and sidecars are byte-identical after collection (checked while the
    # "browser" connection is still open, so nothing has been checkpointed).
    assert {p.name: sha256_file(p) for p in src.parent.iterdir()} == hashes_before
    keep.close()


def test_full_run_does_not_modify_original(tmp_path):
    paths = _tree(tmp_path / "ev")
    before = {k: sha256_file(p) for k, p in paths.items()}
    summary = analyze(tmp_path / "ev", tmp_path / "case", "C1", "tester")
    after = {k: sha256_file(p) for k, p in paths.items()}
    assert before == after
    assert len(summary.targets) == 6
    assert not summary.failures


def test_missing_file_is_reported_not_fatal(tmp_path):
    paths = _tree(tmp_path / "ev")
    paths["edge"].unlink()
    from browsertrace.collector.discover import Target

    audit = AuditLog()
    with pytest.raises(CollectionError):
        collect_target(Target("Edge", "Default", paths["edge"]), tmp_path / "case", audit)


def test_locked_file_retries_then_fails_cleanly(tmp_path, monkeypatch):
    paths = _tree(tmp_path / "ev")
    monkeypatch.setattr(collect_mod, "RETRY_DELAY_S", 0)
    real = collect_mod.sha256_file

    def locked(path, *a, **k):
        if Path(path) == paths["edge"]:
            raise PermissionError("The process cannot access the file because it is being used by another process")
        return real(path, *a, **k)

    monkeypatch.setattr(collect_mod, "sha256_file", locked)
    summary = analyze(tmp_path / "ev", tmp_path / "case", "C1", "tester")
    assert len(summary.failures) == 1 and "locked" in summary.failures[0]
    assert len(summary.targets) == 5  # everything else still processed
    with CaseDB(tmp_path / "case" / "case.db") as db:
        levels = [r[0] for r in db.conn.execute("SELECT level FROM audit_log")]
    assert "error" in levels and levels.count("warning") >= collect_mod.RETRIES


def test_verify_detects_tampering(tmp_path):
    _tree(tmp_path / "ev")
    case = tmp_path / "case"
    analyze(tmp_path / "ev", case, "C1", "tester")
    copy = case / "evidence" / "Edge" / "Default" / "History"
    with open(copy, "ab") as fh:
        fh.write(b"tamper")
    with CaseDB(case / "case.db") as db:
        statuses = {r["copy_path"]: r["status"] for r in verify_case_evidence(db.conn, case)}
    assert statuses["evidence/Edge/Default/History"] == "MODIFIED"
    assert list(statuses.values()).count("ok") == 5
