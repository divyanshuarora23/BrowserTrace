import csv
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bt_validation_compare", ROOT / "validation" / "compare.py")
compare = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = compare  # dataclasses need the module registered
spec.loader.exec_module(compare)


def _write(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def test_template_when_no_reference(tmp_path):
    out = tmp_path / "V.md"
    assert compare.main(["--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "not yet measured" in text and "%" not in text


def test_comparison_numbers_are_computed(tmp_path):
    bt = tmp_path / "bt.csv"
    _write(bt, ["event_type", "browser", "url", "timestamp_utc"], [
        ["visit", "Chrome", "https://a.com/", "2024-03-14T02:12:00Z"],
        ["visit", "Chrome", "https://b.com/x", "2024-03-14T02:13:00Z"],
        ["visit", "Firefox", "https://c.com/", "2024-03-14T02:14:00Z"],
        ["search", "Chrome", "https://a.com/", "2024-03-14T02:12:00Z"],  # ignored: not a visit
    ])
    ref = tmp_path / "bhv.csv"
    # NirSoft export made on a machine in Asia/Kolkata (UTC+05:30), day-month-year format
    _write(ref, ["URL", "Title", "Visit Time", "Web Browser"], [
        ["https://a.com", "A", "14-03-2024 07:42:01", "Chrome"],
        ["https://b.com/x", "B", "14-03-2024 07:43:00", "Chrome"],
        ["https://d.com/", "D", "14-03-2024 07:50:00", "Firefox"],
        ["https://bad.com/", "bad", "not a date", "Chrome"],
    ])
    out = tmp_path / "V.md"
    compare.main(["--browsertrace", str(bt), "--reference", str(ref), "--reference-tz", "Asia/Kolkata",
                  "--out", str(out)])
    text = out.read_text(encoding="utf-8")
    assert "| Records in both | 2 |" in text
    assert "| Only in reference | 1 |" in text
    assert "| Only in BrowserTrace | 1 |" in text
    assert "0.500 / 1.000" in text
    assert "| Chrome | 2 | 2 | 100.0% |" in text and "| Firefox | 0 | 1 | 0.0% |" in text
    assert "1 rows with unparseable time skipped" in text
