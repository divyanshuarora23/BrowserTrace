"""Generate the synthetic "insider data theft" evidence tree.

Usage:  python tools/make_scenario.py OUT_DIR [--seed N]

The implementation lives in ``browsertrace.scenario`` so ``browsertrace demo`` and the
test-suite can use it too.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from browsertrace.scenario import build_scenario


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()
    expected = build_scenario(args.out_dir, seed=args.seed)
    print(json.dumps({k: expected[k] for k in ("scenario", "normal_events_generated")}, indent=2))
    print(f"Evidence tree written to {args.out_dir.resolve()}")


if __name__ == "__main__":
    main()
