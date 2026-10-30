"""Find browser history databases under an evidence root."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

CHROMIUM_VENDOR_MARKERS = (
    (("google", "chrome"), "Chrome"),
    (("microsoft", "edge"), "Edge"),
    (("bravesoftware",), "Brave"),
    (("opera software",), "Opera"),
    (("opera",), "Opera"),
)


@dataclass(frozen=True)
class Target:
    browser: str
    profile: str
    path: Path


class DiscoveryError(Exception):
    pass


def _lower_parts(path: Path) -> list[str]:
    return [p.lower() for p in path.parts]


def identify_chromium_browser(path: Path) -> str | None:
    parts = _lower_parts(path)
    for markers, name in CHROMIUM_VENDOR_MARKERS:
        n = len(markers)
        for i in range(len(parts) - n + 1):
            if tuple(parts[i : i + n]) == markers:
                return name
    return None


def _is_chromium_history(path: Path) -> tuple[str, str] | None:
    """Return (browser, profile) for .../User Data/{Default,Profile N}/History or Opera layouts."""
    if path.name != "History":
        return None
    profile_dir = path.parent
    browser = identify_chromium_browser(path)
    if profile_dir.parent.name.lower() == "user data" and (
        profile_dir.name == "Default" or profile_dir.name.startswith("Profile ")
    ):
        return (browser or "Chromium", profile_dir.name)
    # Opera keeps History directly in "Opera Software/Opera Stable" (or "Opera GX Stable").
    if profile_dir.parent.name.lower() == "opera software" and profile_dir.name.lower().startswith("opera"):
        return ("Opera", profile_dir.name)
    if (
        profile_dir.parent.parent.name.lower() == "opera software"
        and profile_dir.name == "Default"
    ):
        return ("Opera", f"{profile_dir.parent.name}/Default")
    return None


def _is_firefox_places(path: Path) -> tuple[str, str] | None:
    if path.name != "places.sqlite":
        return None
    parts = _lower_parts(path)
    # .../Mozilla/Firefox/Profiles/<profile>/places.sqlite
    if len(parts) >= 5 and parts[-3] == "profiles" and parts[-4] == "firefox" and parts[-5] == "mozilla":
        return ("Firefox", path.parent.name)
    return None


def discover(root: Path) -> list[Target]:
    """Walk ``root`` and return every recognised browser history database.

    Unreadable directories are skipped silently (a mounted drive is full of them).
    """
    root = Path(root)
    if not root.exists():
        raise DiscoveryError(f"evidence path does not exist: {root}")
    found: list[Target] = []
    for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda _e: None):
        for fname in filenames:
            if fname not in ("History", "places.sqlite"):
                continue
            p = Path(dirpath) / fname
            hit = _is_chromium_history(p) or _is_firefox_places(p)
            if hit:
                found.append(Target(hit[0], hit[1], p))
    found.sort(key=lambda t: (t.browser, t.profile, str(t.path)))
    return found


def target_for_file(path: Path, browser: str | None = None, profile: str | None = None) -> Target:
    """Build a target for a directly specified database file, with optional overrides."""
    path = Path(path)
    if not path.is_file():
        raise DiscoveryError(f"not a file: {path}")
    guess = _is_chromium_history(path) or _is_firefox_places(path)
    if browser is None:
        if guess:
            browser = guess[0]
        elif path.name == "places.sqlite":
            browser = "Firefox"
        elif path.name == "History":
            browser = identify_chromium_browser(path) or "Chromium"
        else:
            raise DiscoveryError(
                f"cannot tell which browser {path.name!r} belongs to; pass --browser (Chrome, Edge, Brave, Opera, Firefox)"
            )
    if profile is None:
        profile = guess[1] if guess else (path.parent.name or "unknown")
    return Target(browser, profile, path)


def find_targets(evidence: Path, browser: str | None = None, profile: str | None = None) -> list[Target]:
    evidence = Path(evidence)
    if evidence.is_file():
        return [target_for_file(evidence, browser, profile)]
    targets = discover(evidence)
    if browser:
        targets = [t for t in targets if t.browser.lower() == browser.lower()]
    if profile:
        targets = [t for t in targets if t.profile == profile]
    return targets
