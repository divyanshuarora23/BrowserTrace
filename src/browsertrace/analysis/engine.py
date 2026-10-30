"""YAML-driven rules engine.

Input: event dicts as stored in the case DB (each has ``event_id``). Output: findings,
each with a plain-language reason and the IDs of the events that triggered it.

Findings are leads for an examiner, not conclusions. The engine deliberately groups
matches (per domain, per off-hours session, per search term...) so one noisy behaviour
produces one finding instead of hundreds.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone, tzinfo
from importlib import resources
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from browsertrace.core.timeutil import parse_iso
from browsertrace.parsers.base import EMBED_FLAG, INTERNAL_FLAG

SEVERITIES = ("Low", "Medium", "High")
RULE_TYPES = {
    "domain_match": ({"domains"}, {"event_types"}),
    "keyword_match": ({"keywords"}, {"event_types", "fields"}),
    "extension_match": ({"extensions"}, {"event_types"}),
    "time_window": ({"start", "end"}, {"event_types", "session_gap_minutes"}),
    "sequence": (
        {"within_minutes"},
        {"first_rule", "first_domains", "then_event_types", "then_extensions"},
    ),
    "gap": (set(), {"gap_hours", "context_hours", "min_events_around", "min_missing_ids"}),
    "burst": ({"count", "window_minutes"}, {"event_types"}),
}
BASE_KEYS = {"id", "name", "severity", "attack", "type", "reason"}
MAX_LINKED_EVENTS = 500


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    attack: str
    type: str
    reason: str
    params: dict = field(default_factory=dict)


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    attack: str
    reason: str
    event_ids: list[int]
    first_time: str = ""


# ---------------------------------------------------------------------------- loading


def default_rules_path() -> Path:
    return Path(str(resources.files("browsertrace.analysis") / "rules" / "default.yaml"))


def load_rules(path: Path | None = None) -> list[Rule]:
    path = Path(path) if path else default_rules_path()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuleError(f"cannot read rules file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise RuleError(f"{path}: expected a top-level 'rules:' list")
    rules = [_validate(raw, i, path) for i, raw in enumerate(data["rules"])]
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError(f"{path}: duplicate rule id(s): {', '.join(sorted(dupes))}")
    for r in rules:
        ref = r.params.get("first_rule")
        if ref and ref not in ids:
            raise RuleError(f"{path}: rule {r.id} references unknown first_rule {ref!r}")
        if ref and next(x for x in rules if x.id == ref).type != "domain_match":
            raise RuleError(f"{path}: rule {r.id}: first_rule {ref!r} must be a domain_match rule")
    return rules


def _validate(raw, index: int, path: Path) -> Rule:
    where = f"{path}: rule #{index + 1}"
    if not isinstance(raw, dict):
        raise RuleError(f"{where}: must be a mapping")
    if "id" in raw:
        where = f"{path}: rule {raw['id']}"
    missing = {"id", "name", "severity", "type", "reason"} - raw.keys()
    if missing:
        raise RuleError(f"{where}: missing required key(s): {', '.join(sorted(missing))}")
    if raw["severity"] not in SEVERITIES:
        raise RuleError(f"{where}: severity must be one of {', '.join(SEVERITIES)}, got {raw['severity']!r}")
    rtype = raw["type"]
    if rtype not in RULE_TYPES:
        raise RuleError(f"{where}: unknown type {rtype!r}; supported: {', '.join(sorted(RULE_TYPES))}")
    required, optional = RULE_TYPES[rtype]
    params = {k: v for k, v in raw.items() if k not in BASE_KEYS}
    missing = required - params.keys()
    if missing:
        raise RuleError(f"{where}: type {rtype} requires: {', '.join(sorted(missing))}")
    unknown = params.keys() - required - optional
    if unknown:
        raise RuleError(f"{where}: unknown key(s) for type {rtype}: {', '.join(sorted(unknown))}")
    for key in ("domains", "keywords", "extensions", "event_types", "fields", "then_event_types",
                "then_extensions", "first_domains"):
        if key in params and (not isinstance(params[key], list) or not params[key]):
            raise RuleError(f"{where}: {key} must be a non-empty list")
    if rtype == "sequence" and not (params.get("first_rule") or params.get("first_domains")):
        raise RuleError(f"{where}: sequence needs first_rule or first_domains")
    if rtype == "time_window":
        for k in ("start", "end"):
            _parse_hhmm(str(params[k]), where)
    for k in ("within_minutes", "count", "window_minutes", "gap_hours", "context_hours",
              "min_events_around", "min_missing_ids", "session_gap_minutes"):
        if k in params and (not isinstance(params[k], (int, float)) or params[k] <= 0):
            raise RuleError(f"{where}: {k} must be a positive number")
    return Rule(
        id=str(raw["id"]),
        name=str(raw["name"]),
        severity=raw["severity"],
        attack=str(raw.get("attack", "none")),
        type=rtype,
        reason=str(raw["reason"]).strip(),
        params=params,
    )


def _parse_hhmm(s: str, where: str = "") -> time:
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", s.strip())
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        raise RuleError(f"{where}: invalid time {s!r}, expected HH:MM")
    return time(int(m.group(1)), int(m.group(2)))


def parse_off_hours(spec: str) -> tuple[str, str]:
    """``"00:00-05:00"`` -> ("00:00", "05:00"), validated."""
    parts = spec.split("-")
    if len(parts) != 2:
        raise RuleError(f"invalid off-hours {spec!r}, expected HH:MM-HH:MM")
    _parse_hhmm(parts[0], "--off-hours")
    _parse_hhmm(parts[1], "--off-hours")
    return parts[0].strip(), parts[1].strip()


def parse_tz(name: str | None) -> tzinfo:
    """IANA name (``Asia/Kolkata``), ``UTC``, or a fixed offset (``+05:30`` / ``UTC+05:30``)."""
    if not name or name.upper() in ("UTC", "Z"):
        return timezone.utc
    m = re.fullmatch(r"(?:UTC)?([+-])(\d{1,2}):?(\d{2})?", name.strip(), flags=re.I)
    if m:
        sign = 1 if m.group(1) == "+" else -1
        delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0))
        return timezone(sign * delta, name)
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise RuleError(f"unknown timezone {name!r} (use an IANA name like Asia/Kolkata, or +05:30)") from exc


# ---------------------------------------------------------------------------- helpers


class _SafeDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def _render(template: str, **values) -> str:
    return " ".join(template.format_map(_SafeDict(values)).split())


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def domain_matches(url: str, entry: str) -> bool:
    """Registrable-suffix match: ``mega.nz`` matches ``mega.nz`` and ``www.mega.nz`` but not ``omega.nz``.

    An entry may carry a path prefix (``dropbox.com/upload``).
    """
    entry = entry.lower().strip()
    domain, _, path = entry.partition("/")
    host = host_of(url)
    if not host or not (host == domain or host.endswith("." + domain)):
        return False
    if path:
        try:
            upath = urlsplit(url).path.lower()
        except ValueError:
            return False
        return upath.startswith("/" + path)
    return True


_TOKEN = re.compile(r"[a-z0-9]+")


def keyword_matches(text: str, keyword: str) -> bool:
    """Every word of ``keyword`` must prefix-match some word of ``text`` (order-insensitive).

    ``clear history`` matches "how to clear browser history"; ``cclean`` matches "ccleaner".
    """
    words = _TOKEN.findall(text.lower())
    if not words:
        return False
    return all(any(w.startswith(k) for w in words) for k in _TOKEN.findall(keyword.lower()))


def event_filename(ev: dict) -> str:
    detail = ev.get("detail") or ""
    for part in detail.split("; "):
        if part.startswith("target=") and len(part) > len("target="):
            return Path(part[len("target="):].replace("\\", "/")).name
    if ev.get("title") and ev.get("event_type") == "download":
        return ev["title"]
    try:
        return Path(urlsplit(ev.get("url") or "").path).name
    except ValueError:
        return ""


def _excluded(ev: dict) -> bool:
    detail = ev.get("detail") or ""
    return INTERNAL_FLAG in detail or EMBED_FLAG in detail or not ev.get("timestamp_utc")


def _fmt_delta(td: timedelta) -> str:
    secs = int(td.total_seconds())
    if secs < 120:
        return f"{secs} s"
    if secs < 7200:
        return f"{secs // 60} min"
    if secs < 172800:
        return f"{secs / 3600:.1f} h"
    return f"{secs / 86400:.1f} days"


@dataclass
class Context:
    tz: tzinfo
    tz_name: str
    off_hours: tuple[str, str] | None = None

    def fmt_time(self, ts: str) -> str:
        if self.tz is timezone.utc or not ts:
            return ts
        local = parse_iso(ts).astimezone(self.tz)
        return f"{ts} (local {local.strftime('%Y-%m-%d %H:%M')} {self.tz_name})"


# ---------------------------------------------------------------------------- evaluators


def _domain_match(rule: Rule, events: list[dict], ctx: Context) -> list[Finding]:
    types = set(rule.params.get("event_types", ["visit", "download"]))
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for ev in events:
        if ev["event_type"] not in types:
            continue
        for entry in rule.params["domains"]:
            if domain_matches(ev.get("url") or "", entry):
                day = parse_iso(ev["timestamp_utc"]).astimezone(ctx.tz).date()
                groups[(entry, day)].append(ev)
                break
    out = []
    for (entry, _day), evs in groups.items():
        first = evs[0]
        out.append(
            Finding(
                rule.id, rule.name, rule.severity, rule.attack,
                _render(rule.reason, domain=entry, url=first["url"], time=ctx.fmt_time(first["timestamp_utc"]),
                        count=len(evs)),
                [e["event_id"] for e in evs],
                first["timestamp_utc"],
            )
        )
    return out


def _keyword_match(rule: Rule, events: list[dict], ctx: Context) -> list[Finding]:
    types = set(rule.params.get("event_types", ["search"]))
    fields_ = rule.params.get("fields", ["title"])
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for ev in events:
        if ev["event_type"] not in types:
            continue
        text = " ".join(str(ev.get(f) or "") for f in fields_)
        for kw in rule.params["keywords"]:
            if keyword_matches(text, kw):
                label = (ev.get("title") or ev.get("url") or "").strip()
                groups[(kw, label.lower())].append(ev)
                break
    out = []
    for (kw, _label), evs in groups.items():
        first = evs[0]
        out.append(
            Finding(
                rule.id, rule.name, rule.severity, rule.attack,
                _render(rule.reason, keyword=kw, term=first.get("title") or first.get("url"),
                        url=first["url"], time=ctx.fmt_time(first["timestamp_utc"]), count=len(evs),
                        event_type=first["event_type"].capitalize()),
                [e["event_id"] for e in evs],
                first["timestamp_utc"],
            )
        )
    return out


def _extension_match(rule: Rule, events: list[dict], ctx: Context) -> list[Finding]:
    types = set(rule.params.get("event_types", ["download"]))
    exts = tuple(e.lower() for e in rule.params["extensions"])
    out = []
    for ev in events:
        if ev["event_type"] not in types:
            continue
        name = event_filename(ev)
        if name.lower().endswith(exts):
            out.append(
                Finding(
                    rule.id, rule.name, rule.severity, rule.attack,
                    _render(rule.reason, file=name, url=ev["url"], time=ctx.fmt_time(ev["timestamp_utc"]),
                            count=1),
                    [ev["event_id"]],
                    ev["timestamp_utc"],
                )
            )
    return out


def _in_window(local: datetime, start: time, end: time) -> bool:
    t = local.time()
    if start <= end:
        return start <= t < end
    return t >= start or t < end  # wraps midnight, e.g. 22:00-05:00


def _time_window(rule: Rule, events: list[dict], ctx: Context) -> list[Finding]:
    types = set(rule.params.get("event_types", ["visit", "search", "download"]))
    s_str, e_str = ctx.off_hours or (str(rule.params["start"]), str(rule.params["end"]))
    start, end = _parse_hhmm(s_str), _parse_hhmm(e_str)
    gap = timedelta(minutes=rule.params.get("session_gap_minutes", 30))
    hits = [
        ev for ev in events
        if ev["event_type"] in types and _in_window(parse_iso(ev["timestamp_utc"]).astimezone(ctx.tz), start, end)
    ]
    sessions: list[list[dict]] = []
    for ev in hits:
        if sessions and parse_iso(ev["timestamp_utc"]) - parse_iso(sessions[-1][-1]["timestamp_utc"]) <= gap:
            sessions[-1].append(ev)
        else:
            sessions.append([ev])
    out = []
    for s in sessions:
        out.append(
            Finding(
                rule.id, rule.name, rule.severity, rule.attack,
                _render(rule.reason, count=len(s), time=ctx.fmt_time(s[0]["timestamp_utc"]),
                        window=f"{s_str}-{e_str}", tz=ctx.tz_name),
                [e["event_id"] for e in s],
                s[0]["timestamp_utc"],
            )
        )
    return out


def _sequence(rule: Rule, events: list[dict], ctx: Context, rules_by_id: dict[str, Rule]) -> list[Finding]:
    domains = rule.params.get("first_domains") or rules_by_id[rule.params["first_rule"]].params["domains"]
    then_types = set(rule.params.get("then_event_types", ["download"]))
    then_exts = tuple(e.lower() for e in rule.params.get("then_extensions", []))
    window = timedelta(minutes=rule.params["within_minutes"])
    firsts: list[tuple[datetime, dict, str]] = []
    for ev in events:
        if ev["event_type"] != "visit":
            continue
        for d in domains:
            if domain_matches(ev.get("url") or "", d):
                firsts.append((parse_iso(ev["timestamp_utc"]), ev, d))
                break
    out = []
    for ev in events:
        if ev["event_type"] not in then_types:
            continue
        name = event_filename(ev)
        if then_exts and not name.lower().endswith(then_exts):
            continue
        t = parse_iso(ev["timestamp_utc"])
        prior = [(ft, fe, d) for ft, fe, d in firsts if timedelta(0) <= t - ft <= window]
        if not prior:
            continue
        ft, fe, d = prior[0]  # earliest qualifying visit
        doms = sorted({p[2] for p in prior})
        out.append(
            Finding(
                rule.id, rule.name, rule.severity, rule.attack,
                _render(rule.reason, domain=", ".join(doms), file=name, url=ev["url"], delta=_fmt_delta(t - ft),
                        time=ctx.fmt_time(ev["timestamp_utc"]), count=len(prior)),
                [p[1]["event_id"] for p in prior] + [ev["event_id"]],
                fe["timestamp_utc"],
            )
        )
    return out


def _gap(rule: Rule, events: list[dict], ctx: Context) -> list[Finding]:
    gap_h = rule.params.get("gap_hours", 48)
    ctx_h = rule.params.get("context_hours", 72)
    min_around = rule.params.get("min_events_around", 10)
    min_missing = rule.params.get("min_missing_ids", 20)
    by_source: dict[tuple, list[dict]] = defaultdict(list)
    for ev in events:
        if ev["event_type"] == "visit" and not ev.get("is_recovered"):
            by_source[(ev["browser"], ev["profile"], ev["source_file"])].append(ev)
    out = []
    for (browser, profile, _src), evs in by_source.items():
        pairs: dict[tuple[int, int], list[str]] = {}
        # 1) time gaps inside an otherwise active period
        times = [parse_iso(e["timestamp_utc"]) for e in evs]
        for i in range(1, len(evs)):
            delta = times[i] - times[i - 1]
            if delta <= timedelta(hours=gap_h):
                continue
            before = sum(1 for t in times[:i] if times[i - 1] - t <= timedelta(hours=ctx_h))
            after = sum(1 for t in times[i:] if t - times[i] <= timedelta(hours=ctx_h))
            if before >= min_around and after >= min_around:
                pairs.setdefault((i - 1, i), []).append(f"no history for {_fmt_delta(delta)}")
        # 2) holes in the visit-ID sequence
        with_ids = sorted(
            (i for i, e in enumerate(evs) if e.get("source_visit_id") is not None),
            key=lambda i: evs[i]["source_visit_id"],
        )
        for a, b in zip(with_ids, with_ids[1:]):
            missing = evs[b]["source_visit_id"] - evs[a]["source_visit_id"] - 1
            if missing >= min_missing:
                key = (a, b) if times[a] <= times[b] else (b, a)
                pairs.setdefault(key, []).append(
                    f"{missing} visit IDs missing ({evs[a]['source_visit_id'] + 1}-{evs[b]['source_visit_id'] - 1})"
                )
        for (a, b), reasons in sorted(pairs.items()):
            out.append(
                Finding(
                    rule.id, rule.name, rule.severity, rule.attack,
                    _render(rule.reason, browser=browser, profile=profile, gap_detail=" and ".join(reasons),
                            time=ctx.fmt_time(evs[a]["timestamp_utc"]), delta=_fmt_delta(times[b] - times[a]),
                            count=len(reasons)),
                    [evs[a]["event_id"], evs[b]["event_id"]],
                    evs[a]["timestamp_utc"],
                )
            )
    return out


def _burst(rule: Rule, events: list[dict], ctx: Context) -> list[Finding]:
    types = set(rule.params.get("event_types", ["download"]))
    n = int(rule.params["count"])
    window = timedelta(minutes=rule.params["window_minutes"])
    evs = [e for e in events if e["event_type"] in types]
    times = [parse_iso(e["timestamp_utc"]) for e in evs]
    out = []
    i = 0
    while i < len(evs):
        j = i
        while j + 1 < len(evs) and times[j + 1] - times[i] <= window:
            j += 1
        size = j - i + 1
        if size > n:
            out.append(
                Finding(
                    rule.id, rule.name, rule.severity, rule.attack,
                    _render(rule.reason, count=size, delta=_fmt_delta(times[j] - times[i]),
                            time=ctx.fmt_time(evs[i]["timestamp_utc"])),
                    [e["event_id"] for e in evs[i : j + 1]],
                    evs[i]["timestamp_utc"],
                )
            )
            i = j + 1
        else:
            i += 1
    return out


_EVALUATORS = {
    "domain_match": _domain_match,
    "keyword_match": _keyword_match,
    "extension_match": _extension_match,
    "time_window": _time_window,
    "gap": _gap,
    "burst": _burst,
}


# ---------------------------------------------------------------------------- driver


def run_rules(
    events: list[dict],
    rules: list[Rule],
    tz_name: str = "UTC",
    off_hours: str | None = None,
) -> list[Finding]:
    ctx = Context(tz=parse_tz(tz_name), tz_name=tz_name or "UTC",
                  off_hours=parse_off_hours(off_hours) if off_hours else None)
    usable = sorted((e for e in events if not _excluded(e)), key=lambda e: (e["timestamp_utc"], e["event_id"]))
    rules_by_id = {r.id: r for r in rules}
    findings: list[Finding] = []
    for rule in rules:
        if rule.type == "sequence":
            findings.extend(_sequence(rule, usable, ctx, rules_by_id))
        else:
            findings.extend(_EVALUATORS[rule.type](rule, usable, ctx))
    _escalate(findings, rules_by_id)
    for f in findings:
        f.event_ids = list(dict.fromkeys(f.event_ids))[:MAX_LINKED_EVENTS]
    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    findings.sort(key=lambda f: (order[f.severity], f.first_time, f.rule_id))
    return findings


def _escalate(findings: list[Finding], rules_by_id: dict[str, Rule]) -> None:
    """Raise a finding one severity level when its events also fall in the off-hours window."""
    off_ids: set[int] = set()
    window_rule_ids = {r.id for r in rules_by_id.values() if r.type == "time_window"}
    for f in findings:
        if f.rule_id in window_rule_ids:
            off_ids.update(f.event_ids)
    if not off_ids:
        return
    names = ", ".join(sorted(window_rule_ids))
    for f in findings:
        if f.rule_id in window_rule_ids or f.severity == "High":
            continue
        if off_ids.intersection(f.event_ids):
            new = SEVERITIES[SEVERITIES.index(f.severity) + 1]
            f.reason += f" Severity escalated from {f.severity} to {new} because it happened in the off-hours window ({names})."
            f.severity = new


def rules_reference_markdown(rules: list[Rule]) -> str:
    lines = [
        "# BrowserTrace rule reference",
        "",
        "Generated from the rules YAML. Findings are investigative leads, not proof.",
        "If an event matches an off-hours rule (time_window) and another rule, the other",
        "finding is raised one severity level (Low→Medium→High) and the reason says so.",
        "",
        "| ID | Name | Severity | ATT&CK | Type |",
        "|----|------|----------|--------|------|",
    ]
    for r in rules:
        lines.append(f"| {r.id} | {r.name} | {r.severity} | {r.attack} | {r.type} |")
    for r in rules:
        lines += ["", f"## {r.id} — {r.name}", "", f"- **Severity:** {r.severity}",
                  f"- **MITRE ATT&CK:** {r.attack}", f"- **Type:** `{r.type}`"]
        for k, v in r.params.items():
            val = ", ".join(map(str, v)) if isinstance(v, list) else v
            lines.append(f"- **{k}:** {val}")
        lines.append(f"- **Reason template:** {r.reason}")
    return "\n".join(lines) + "\n"
