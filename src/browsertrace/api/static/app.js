// BrowserTrace dashboard. No build step, no external network.
//
// SECURITY: URLs, titles, search terms and file names come from evidence and are
// attacker-controlled. Every value is rendered as a text node (via el()); no HTML
// string parsing is used anywhere, and the server sends a strict Content-Security-Policy.
"use strict";

const KNOWN_BROWSERS = ["Chrome", "Edge", "Firefox", "Brave", "Opera"];
const SEVERITIES = ["High", "Medium", "Low"];
const SEV_RANK = { High: 0, Medium: 1, Low: 2 };
const COLORS = {
  bar: "#2458d1", off: "rgba(36, 88, 209, 0.07)",
  domain: "#2458d1", others: "#9aa3b2",
  grid: "#dde1e7", tick: "#5b6372", label: "#16181d",
};
const BROWSER_DOTS = { Chrome: "#3b82f6", Edge: "#0ea35a", Firefox: "#e8730f", Brave: "#e0453a", Opera: "#9661f0" };
const SHORT_TITLES = {
  R001: "File-sharing site visited", R002: "Risky file downloaded", R003: "Off-hours activity",
  R004: "Anti-forensic search", R005: "Share-site visit, then archive download",
  R006: "History gap (possible clearing)", R007: "Anonymizer / VPN / Tor", R008: "Download burst",
};
const ATTACK_NAMES = {
  T1567: "Exfiltration Over Web Service", T1105: "Ingress Tool Transfer", T1070: "Indicator Removal",
  "T1070.004": "File Deletion", T1090: "Proxy", T1074: "Data Staged", T1213: "Data from Information Repositories",
};
const TZ_KEY = "browsertrace.tz";
const THEME_KEY = "browsertrace.theme";
const TZ_OPTIONS = ["UTC", "Asia/Kolkata"];

const state = {
  tz: "UTC", caseTz: "UTC",
  pageSize: 100, total: 0, grandTotal: 0,
  filters: {},            // q, browser, type, synced, from, to, hour, domain, finding
  findings: [], rules: {}, offHours: null,
  eventSeverity: new Map(), // event_id -> highest severity of linked findings
  sevFilter: "All", sort: "severity", selectedFinding: null, flashId: null,
  charts: { hours: null, domains: null }, chartData: null, topN: 15,
  tab: "overview", loadedTabs: new Set(),
};

// ---------------------------------------------------------------- DOM helpers
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}
const $ = (id) => document.getElementById(id);
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

async function api(path, params) {
  const qs = params ? `?${new URLSearchParams(params)}` : "";
  const r = await fetch(path + qs, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}

async function apiUpdate(path, body, method = "PUT") {
  const r = await fetch(path, {
    method,
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || `${path}: HTTP ${r.status}`);
  return data;
}

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = el("textarea", { class: "sr-only" }, text);
    document.body.append(ta); ta.select(); document.execCommand("copy"); ta.remove();
  }
  if (btn) { const old = btn.textContent; btn.textContent = "Copied"; setTimeout(() => { btn.textContent = old; }, 1200); }
}
function copyButton(text, label) {
  return el("button", { type: "button", class: "ghost small", "aria-label": label || "Copy to clipboard", title: "Copy",
    onclick: (e) => { e.stopPropagation(); copyText(text, e.currentTarget); } }, "Copy");
}

// ---------------------------------------------------------------- tabs / router
const TABS = ["overview", "findings", "timeline", "evidence", "report"];
function goToTab(name, { push = true } = {}) {
  if (!TABS.includes(name)) name = "overview";
  state.tab = name;
  for (const t of TABS) {
    const btn = document.querySelector(`.tab[data-tab="${t}"]`);
    const panel = $(`panel-${t}`);
    const active = t === name;
    if (btn) btn.setAttribute("aria-selected", String(active));
    if (panel) { panel.hidden = !active; panel.classList.toggle("active", active); }
  }
  if (push && location.hash.slice(1) !== name) location.hash = name;
  ensureTabLoaded(name);
}
function ensureTabLoaded(name) {
  if (state.loadedTabs.has(name)) return;
  state.loadedTabs.add(name);
  if (name === "evidence") loadEvidence().catch((err) => panelError("evidence-body", "evidence", err));
}

// ---------------------------------------------------------------- time / timezone
function tzLabel(tz) {
  if (tz === "UTC") return "UTC";
  if (tz === "Asia/Kolkata" || tz === "Asia/Calcutta") return "IST";
  try {
    const p = new Intl.DateTimeFormat("en-US", { timeZone: tz, timeZoneName: "short" }).formatToParts(new Date());
    return (p.find((x) => x.type === "timeZoneName") || {}).value || tz;
  } catch { return tz; }
}
const fmtCache = new Map();
function fmt(tz, opts) {
  const key = tz + JSON.stringify(opts);
  if (!fmtCache.has(key)) fmtCache.set(key, new Intl.DateTimeFormat("en-GB", { timeZone: tz, hourCycle: "h23", ...opts }));
  return fmtCache.get(key);
}
function toDate(iso) { const d = new Date(iso); return Number.isNaN(d.getTime()) ? null : d; }
function parts(iso, tz) {
  const d = toDate(iso);
  if (!d) return null;
  const o = {};
  for (const p of fmt(tz, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).formatToParts(d)) o[p.type] = p.value;
  return o;
}
function fmtFull(iso, tz = state.tz) {   // "08 Oct 2026, 11:29:26 IST"
  const p = parts(iso, tz);
  return p ? `${p.day} ${p.month} ${p.year}, ${p.hour}:${p.minute}:${p.second} ${tzLabel(tz)}` : "(invalid time)";
}
function fmtShort(iso, tz = state.tz) {   // "14 Mar 2024, 02:12 IST"
  const p = parts(iso, tz);
  return p ? `${Number(p.day)} ${p.month} ${p.year}, ${p.hour}:${p.minute} ${tzLabel(tz)}` : iso;
}
function fmtDay(iso, tz = state.tz) { const p = parts(iso, tz); return p ? `${Number(p.day)} ${p.month} ${p.year}` : ""; }
function fmtHM(iso, tz = state.tz) { const p = parts(iso, tz); return p ? `${p.hour}:${p.minute}` : ""; }
function fmtNum(n) { return (n ?? 0).toLocaleString("en-US"); }
function utcTitle(iso) { return iso ? `UTC: ${iso}` : ""; }

function tzOffsetMs(utcMs, tz) {
  const o = {};
  for (const p of fmt(tz, { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" })
    .formatToParts(new Date(utcMs))) o[p.type] = p.value;
  const asUtc = Date.UTC(+o.year, +o.month - 1, +o.day, +o.hour % 24, +o.minute, +o.second);
  return asUtc - Math.floor(utcMs / 1000) * 1000;
}
// "2024-03-14 07:42[:05]" interpreted in tz -> ISO UTC string, or null if invalid
function zonedInputToUtc(text, tz, endOfMinute) {
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?$/.exec(text.trim());
  if (!m) return null;
  const [y, mo, d, h = "0", mi = "0", s] = m.slice(1);
  const hasTime = m[4] !== undefined;
  if (+mo < 1 || +mo > 12 || +d < 1 || +d > 31 || +h > 23 || +mi > 59 || (s && +s > 59)) return null;
  let sec = s ? +s : 0;
  let hh = +h, mm = +mi;
  if (endOfMinute && !hasTime) { hh = 23; mm = 59; sec = 59; } else if (endOfMinute && !s) sec = 59;
  const guess = Date.UTC(+y, +mo - 1, +d, hh, mm, sec);
  let utc = guess - tzOffsetMs(guess, tz);
  const off2 = tzOffsetMs(utc, tz);
  utc = guess - off2;
  const iso = new Date(utc).toISOString().replace(".000Z", endOfMinute ? ".999999Z" : "Z");
  return iso;
}
function utcToInput(iso, tz) {
  const o = {};
  for (const p of fmt(tz, { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })
    .formatToParts(new Date(iso))) o[p.type] = p.value;
  return `${o.year}-${o.month}-${o.day} ${o.hour}:${o.minute}`;
}

// ---------------------------------------------------------------- URL helpers
function splitUrl(url) {
  try {
    const u = new URL(url);
    if (!u.host) return { dom: "", rest: url };
    return { dom: u.host.replace(/^www\./, ""), rest: `${u.pathname}${u.search}${u.hash}`.replace(/^\/$/, "") };
  } catch { return { dom: "", rest: url || "" }; }
}
function safeDecode(s) { try { return decodeURIComponent(s); } catch { return s; } }
function urlLine(url) {
  const { dom, rest } = splitUrl(url);
  return [dom ? el("b", { class: "dom" }, dom) : null, el("span", { class: "rest" }, dom ? rest : url)];
}

// ---------------------------------------------------------------- transitions (humanized)
const TRANSITION_CORE = {
  link: "Followed a link", typed: "Typed in the address bar", auto_bookmark: "Opened from a bookmark",
  auto_subframe: "Loaded a subframe automatically", manual_subframe: "Navigated in a subframe",
  generated: "Generated navigation", start_page: "Opened as start page", form_submit: "Submitted a form",
  reload: "Reloaded the page", keyword: "Searched via address bar keyword", keyword_generated: "Generated keyword search",
  bookmark: "Opened from a bookmark", embed: "Embedded content", redirect_permanent: "Permanent redirect",
  redirect_temporary: "Temporary redirect", download: "Download", framed_link: "Followed a link in a frame",
};
const TRANSITION_QUAL = {
  blocked: "blocked", forward_back: "via back/forward", from_address_bar: "from the address bar",
  home_page: "home page", from_api: "triggered by an extension or API", chain_start: "start of a redirect chain",
  chain_end: "end of a redirect chain", client_redirect: "client-side redirect", server_redirect: "server-side redirect",
};
function humanizeTransition(raw) {
  if (!raw) return "";
  const m = /^([a-z_]+)(?:\s*\[([^\]]*)\])?$/.exec(raw.trim());
  if (!m) return raw;
  const core = m[1];
  const quals = m[2] ? m[2].split(",").map((s) => s.trim()).filter(Boolean) : [];
  const label = TRANSITION_CORE[core] || (core.startsWith("unknown") ? "Unknown navigation type" : core);
  const extra = quals.map((q) => TRANSITION_QUAL[q] || q).filter((q) => !(core === "typed" && q === "from the address bar"));
  return extra.length ? `${label} (${extra.join(", ")})` : label;
}

// ---------------------------------------------------------------- header, theme, timezone
function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  const btn = $("theme-toggle");
  btn.textContent = theme === "dark" ? "Light" : "Dark";
  btn.setAttribute("aria-pressed", String(theme === "dark"));
}
function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem(THEME_KEY); } catch { /* unavailable */ }
  applyTheme(saved === "dark" ? "dark" : "light");
  $("theme-toggle").addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    applyTheme(next);
    try { localStorage.setItem(THEME_KEY, next); } catch { /* ignore */ }
    if (state.chartData) { renderHoursChart(); renderDomainsChart(); }
  });
}

async function loadCase() {
  const data = await api("/api/case");
  state.caseData = data;
  const c = data.case || {};
  state.caseTz = c.host_timezone || "UTC";
  $("brand-version").textContent = `v${data.tool_version}`;
  const info = $("case-info");
  clear(info);
  info.append(`Case ${c.case_id || "?"} · examiner ${c.examiner || "?"} · rules evaluated in ${state.caseTz} · `
    + `${data.evidence_files.length} evidence file(s)`);
  renderEvidenceBadge(data.verification || {}, data.evidence_files || []);

  let saved = null;
  try { saved = localStorage.getItem(TZ_KEY); } catch { /* storage unavailable */ }
  state.tz = TZ_OPTIONS.includes(saved) ? saved : (state.caseTz === "Asia/Kolkata" ? "Asia/Kolkata" : "UTC");
  renderTzSwitch();
  renderReportMeta(c, data);
}

function renderEvidenceBadge(v, files) {
  const btn = $("evidence-badge-btn");
  clear(btn);
  const ok = Boolean(v.all_ok);
  btn.append(el("span", { class: ok ? "ok" : "bad" }, `${ok ? "✓" : "✗"} ${files.length} evidence file${files.length === 1 ? "" : "s"} ${ok ? "verified" : "FAILED"}`));
  btn.onclick = (e) => {
    e.stopPropagation();
    const existing = $("evidence-popover");
    if (existing) { existing.remove(); btn.setAttribute("aria-expanded", "false"); return; }
    btn.setAttribute("aria-expanded", "true");
    const pop = el("div", { class: "evidence-popover", id: "evidence-popover" },
      el("ul", {}, ...(v.files || []).map((f) => el("li", {},
        el("div", {}, f.status === "ok" ? "✓ " : "✗ ", el("code", {}, f.copy_path)),
      ))));
    if (!(v.files || []).length) pop.append(el("p", { class: "empty" }, "No evidence files recorded."));
    $("evidence-badge").append(pop);
  };
  document.addEventListener("click", (e) => {
    const pop = $("evidence-popover");
    if (pop && !$("evidence-badge").contains(e.target)) { pop.remove(); btn.setAttribute("aria-expanded", "false"); }
  });
}

function renderTzSwitch() {
  const box = $("tz-switch");
  clear(box);
  for (const tz of TZ_OPTIONS) {
    box.append(el("button", { type: "button", "aria-pressed": tz === state.tz ? "true" : "false",
      title: tz, onclick: () => setTimezone(tz) }, tzLabel(tz)));
  }
  $("th-time").textContent = `Time (${tzLabel(state.tz)})`;
  $("export-csv").href = `/api/export.csv?${new URLSearchParams({ tz: state.tz })}`;
  $("export-csv").title = `CSV with UTC times plus a ${state.tz} column`;
  $("report-export-csv").href = $("export-csv").href;
}

async function setTimezone(tz) {
  if (tz === state.tz) return;
  state.tz = tz;
  try { localStorage.setItem(TZ_KEY, tz); } catch { /* ignore */ }
  if (state.filters.hour !== undefined) delete state.filters.hour; // hour-of-day differs per timezone
  syncInputsFromFilters();
  renderTzSwitch();
  renderFindingsList();
  renderFindingDetail();
  renderPriorityFindings();
  await Promise.all([loadCharts(), loadEvents()]);
}

function renderReportMeta(c, data) {
  const dl = $("report-case-meta");
  clear(dl);
  const rows = [
    ["Case ID", c.case_id], ["Examiner", c.examiner], ["Created (UTC)", c.created_utc],
    ["Tool version", data.tool_version], ["Host timezone", c.host_timezone],
    ["Evidence files", String(data.evidence_files.length)],
  ];
  for (const [k, v] of rows) dl.append(el("dt", {}, k), el("dd", {}, v || "—"));
}

// ---------------------------------------------------------------- overview stat cards
function browserIdLabel(name) {
  return el("span", { class: "b-id" }, el("span", { class: "dot", style: `background:${BROWSER_DOTS[name] || "#7a8699"}` }), name);
}

async function loadStats() {
  const s = await api("/api/stats");
  state.stats = s;
  state.grandTotal = s.total_events;
  const cards = $("cards");
  clear(cards);
  const browsers = Object.entries(s.by_browser).sort((a, b) => b[1] - a[1]);

  // 1. Events
  cards.append(el("div", { class: "card stat" },
    el("span", { class: "n" }, fmtNum(s.total_events)),
    el("span", { class: "l" }, "Events"),
    el("div", { class: "stat-rows" }, ...browsers.map(([b, n]) => el("div", { class: "row" }, browserIdLabel(b), el("b", {}, fmtNum(n)))))));

  // 2. Findings with severity breakdown
  const totalFindings = SEVERITIES.reduce((a, sev) => a + (s.by_severity[sev] || 0), 0);
  cards.append(el("div", { class: "card stat" },
    el("span", { class: "n" }, fmtNum(totalFindings)),
    el("span", { class: "l" }, "Findings"),
    el("div", { class: "stat-breakdown" }, ...SEVERITIES.map((sev) => el("button", { type: "button",
      onclick: () => { setSevFilter(sev); goToTab("findings"); } },
      el("span", { class: "dot", style: `background:var(--${sev.toLowerCase()})` }), `${sev} ${s.by_severity[sev] || 0}`)))));

  // 3. Browsers
  cards.append(el("div", { class: "card stat" },
    el("span", { class: "n" }, fmtNum(browsers.length)),
    el("span", { class: "l" }, browsers.length === 1 ? "Browser" : "Browsers"),
    el("div", { class: "stat-rows" }, ...browsers.map(([b, n]) => el("div", { class: "row" }, browserIdLabel(b),
      el("span", {}, `${Math.round((100 * n) / (s.total_events || 1))}%`))))));

  // 4. Time range
  const range = s.first_event_utc && s.last_event_utc
    ? `${fmtDay(s.first_event_utc)} – ${fmtDay(s.last_event_utc)}`
    : "—";
  cards.append(el("div", { class: "card stat" },
    el("span", { class: "n", style: "font-size:16px" }, range),
    el("span", { class: "l" }, "Time range"),
    el("div", { class: "stat-rows" },
      el("div", { class: "row" }, "Synced", el("b", {}, fmtNum(s.synced_events))),
      s.recovered_events ? el("div", { class: "row" }, "Recovered", el("b", {}, fmtNum(s.recovered_events))) : null)));

  const sel = $("f-browser");
  clear(sel); sel.append(el("option", { value: "" }, "All browsers"));
  for (const [b] of browsers) sel.append(el("option", { value: b }, b));
}

// ---------------------------------------------------------------- findings
async function loadFindings() {
  // rules metadata only improves the descriptions; never let it block the findings
  const [findings, rules] = await Promise.all([
    api("/api/findings"),
    api("/api/rules").catch((err) => { console.warn("rules metadata unavailable:", err); return { rules: [], off_hours: null }; }),
  ]);
  state.findings = findings;
  state.offHours = rules.off_hours;
  for (const r of rules.rules) state.rules[r.id] = r;
  state.eventSeverity = new Map();
  for (const f of findings) {
    for (const id of f.event_ids) {
      const cur = state.eventSeverity.get(id);
      if (!cur || SEV_RANK[f.severity] < SEV_RANK[cur]) state.eventSeverity.set(id, f.severity);
    }
  }
  renderSevChips();
  renderFindingsList();
  renderPriorityFindings();
}

function setSevFilter(sev) {
  state.sevFilter = sev;
  renderSevChips();
  renderFindingsList();
}

function renderSevChips() {
  const box = $("sev-chips");
  clear(box);
  for (const sev of ["All", ...SEVERITIES]) {
    const n = sev === "All" ? state.findings.length : state.findings.filter((f) => f.severity === sev).length;
    box.append(el("button", { type: "button", "aria-pressed": state.sevFilter === sev ? "true" : "false",
      onclick: () => setSevFilter(sev) }, `${sev} ${n}`));
  }
}

// Sentences of a rule's reason template that contain no placeholder are the same on every
// finding of that rule: show them once under "Why this matters" instead of repeating them.
function boilerplate(ruleId) {
  const t = (state.rules[ruleId] || {}).reason_template || "";
  return t.split(/(?<=\.)\s+/).map((s) => s.trim()).filter((s) => s && !s.includes("{"));
}
const ISO_RE = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z(?: \(local [^)]*\))?/g;
const URL_RE = /https?:\/\/[^\s)"'<>]+/g;
const ESCALATION_RE = /Severity escalated from (\w+) to (\w+) because it happened in the off-hours window \(([^)]*)\)\.?/;

function describe(f) {
  let text = f.reason.replace(/\s+/g, " ").trim();
  const why = boilerplate(f.rule_id);
  for (const s of why) text = text.replace(s, "").trim();
  let escalation = null;
  const em = ESCALATION_RE.exec(text);
  if (em) { escalation = { from: em[1], to: em[2] }; text = text.replace(em[0], "").trim(); }
  const urls = [...new Set(text.match(URL_RE) || [])].map((u) => u.replace(/[.,;]+$/, ""));
  text = text.replace(ISO_RE, (m) => fmtShort(m.slice(0, m.indexOf("Z") + 1)));
  text = text.replace(URL_RE, (u) => splitUrl(u.replace(/[.,;]+$/, "")).dom || u)
    .replace(/\(\s*\)/g, "").replace(/\s+([.,])/g, "$1").trim();
  return { text, why, urls, escalation };
}

function summaryLine(f) {
  const n = f.event_count;
  const ev = `${n} event${n === 1 ? "" : "s"}`;
  if (!f.first_time) return ev;
  const tzl = tzLabel(state.tz);
  if (n === 1 || f.first_time === f.last_time) return `${ev} at ${fmtHM(f.first_time)} ${tzl} on ${fmtDay(f.first_time)}`;
  if (fmtDay(f.first_time) === fmtDay(f.last_time)) {
    return `${ev} between ${fmtHM(f.first_time)} and ${fmtHM(f.last_time)} ${tzl} on ${fmtDay(f.first_time)}`;
  }
  return `${ev} from ${fmtDay(f.first_time)} ${fmtHM(f.first_time)} to ${fmtDay(f.last_time)} ${fmtHM(f.last_time)} ${tzl}`;
}

function attackLink(attack) {
  const parts2 = attack.split(".");
  const path = parts2.length > 1 ? `${parts2[0]}/${parts2[1]}` : parts2[0];
  return el("a", { class: "attack-link", href: `https://attack.mitre.org/techniques/${path}/`, target: "_blank", rel: "noopener noreferrer" },
    `${attack}${ATTACK_NAMES[attack] ? ` · ${ATTACK_NAMES[attack]}` : ""}`);
}

function renderFindingsList() {
  const box = $("findings");
  clear(box);
  let list = state.findings.filter((f) => state.sevFilter === "All" || f.severity === state.sevFilter);
  list = [...list].sort(state.sort === "time"
    ? (a, b) => (a.first_time || "").localeCompare(b.first_time || "") || a.id - b.id
    : (a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || (a.first_time || "").localeCompare(b.first_time || ""));
  if (!list.length) { box.append(el("p", { class: "empty-state" }, state.findings.length ? "No findings match this filter. Clear filter." : "No rule produced a finding.")); return; }

  const groups = new Map();
  for (const f of list) { if (!groups.has(f.rule_id)) groups.set(f.rule_id, []); groups.get(f.rule_id).push(f); }
  for (const [ruleId, items] of groups) {
    if (items.length === 1) { box.append(findingRow(items[0])); continue; }
    const sev = items.map((f) => f.severity).sort((a, b) => SEV_RANK[a] - SEV_RANK[b])[0];
    const containsSelected = items.some((f) => f.id === state.selectedFinding);
    const open = containsSelected;
    box.append(el("details", { class: "group", open },
      el("summary", { class: "f-row", style: "cursor:pointer" },
        el("span", { class: `sev-marker ${sev}` }), el("span", { class: "f-rule" }, ruleId),
        el("span", { class: "f-title" }, SHORT_TITLES[ruleId] || items[0].name),
        el("span", { class: "count-badge" }, `×${items.length}`)),
      ...items.map(findingRow)));
  }
}

function findingRow(f) {
  const title = SHORT_TITLES[f.rule_id] || f.name;
  const row = el("button", { type: "button", class: "f-row", "data-id": f.id,
    "aria-selected": state.selectedFinding === f.id ? "true" : "false",
    onclick: () => selectFinding(f.id) },
    el("span", { class: `sev-marker ${f.severity}` }),
    el("span", { class: "f-rule" }, f.rule_id),
    el("span", { class: "f-title" }, title),
    el("span", { class: "f-time" }, f.first_time ? fmtDay(f.first_time) : ""));
  return row;
}

function selectFinding(id) {
  state.selectedFinding = id;
  renderFindingsList();
  renderFindingDetail();
}

function renderPriorityFindings() {
  const box = $("priority-list");
  clear(box);
  const top = [...state.findings].sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]
    || (a.first_time || "").localeCompare(b.first_time || "")).slice(0, 5);
  if (!top.length) { box.append(el("p", { class: "empty" }, "No rule produced a finding.")); return; }
  for (const f of top) {
    box.append(el("button", { type: "button", class: "priority-row",
      onclick: () => { goToTab("findings"); selectFinding(f.id); } },
      el("span", { class: `sev-marker ${f.severity}` }),
      el("span", { class: "f-rule" }, f.rule_id),
      el("span", { class: "f-title" }, SHORT_TITLES[f.rule_id] || f.name),
      el("span", { class: "f-time" }, f.first_time ? fmtDay(f.first_time) : "")));
  }
}

function findingReviewEditor(f) {
  const reviewed = Boolean(f.reviewed_utc);
  const selectField = (label, name, values, current = "") => {
    const select = el("select", { name, required: true, "aria-label": label });
    select.append(el("option", { value: "", selected: !current }, `Select ${label.toLowerCase()}`));
    for (const value of values) select.append(el("option", { value, selected: value === current }, value));
    return el("label", { class: "field" }, label, select);
  };
  const status = el("p", { class: "review-status", "aria-live": "polite" },
    reviewed ? `Last saved ${f.reviewed_utc} UTC${f.reviewed_by ? ` by ${f.reviewed_by}` : ""}.` : "No analyst review saved.");
  const form = el("form", { class: "review-form", onsubmit: (e) => saveFindingReview(e, f, status) },
    selectField("Analyst risk level", "risk_level", ["Low", "Medium", "High", "Unclear"], f.risk_level || ""),
    selectField("Outcome", "outcome", ["Concerning", "Benign", "Needs more context"], f.outcome || ""),
    selectField("Confidence", "confidence", ["Low", "Medium", "High"], f.confidence || ""),
    el("label", { class: "field" }, "Reviewer (optional)",
      el("input", { name: "reviewed_by", maxlength: "120", value: f.reviewed_by || "", autocomplete: "name" })),
    el("label", { class: "field review-rationale" }, "Rationale",
      el("textarea", { name: "rationale", rows: "3", maxlength: "2000", required: true,
        placeholder: "Why does this risk level fit the linked evidence?" }, f.rationale || "")),
    el("div", { class: "review-actions" }, el("button", { type: "submit", class: "primary review-save" }, reviewed ? "Update review" : "Save review"), status));
  return el("details", { class: "review-editor", open: reviewed },
    el("summary", {}, reviewed ? `Analyst review: ${f.risk_level} · ${f.outcome}` : "Add analyst review"),
    el("p", { class: "review-guidance" },
      "Working guide: Low = isolated or contextual signal; Medium = a specific signal or related signals with context missing; " +
      "High = multiple independent, time-linked signals. Off-hours activity alone is not High. Use Unclear when evidence is insufficient."),
    form);
}

async function saveFindingReview(event, f, status) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  status.textContent = "Saving review…";
  try {
    const body = Object.fromEntries(new FormData(form).entries());
    const saved = await apiUpdate(`/api/findings/${f.id}/review`, body);
    Object.assign(f, saved);
    renderFindingDetail();
  } catch (err) {
    status.textContent = `Could not save review: ${err.message}`;
    button.disabled = false;
  }
}

function renderFindingDetail() {
  const box = $("finding-detail");
  clear(box);
  const f = state.findings.find((x) => x.id === state.selectedFinding);
  if (!f) { box.append(el("p", { class: "empty-state" }, "Select a finding from the list to see its details.")); return; }
  const { text, why, urls, escalation } = describe(f);
  const title = SHORT_TITLES[f.rule_id] || f.name;
  const hasAttack = f.attack && f.attack.toLowerCase() !== "none";

  box.append(
    el("div", { class: "detail-head" },
      el("span", { class: `pill pill-${f.severity}` }, f.severity),
      el("span", { class: "f-rule" }, f.rule_id),
      el("h2", {}, title)),
    el("p", { class: "f-summary" }, summaryLine(f)),
    escalation ? el("p", { class: "escalation-note" }, `Escalated from ${escalation.from}: off-hours activity.`) : null,
    el("div", { class: "detail-section" }, el("span", { class: "detail-label" }, "Reason"), el("p", {}, text)),
    why.length ? el("div", { class: "detail-section" }, el("span", { class: "detail-label" }, "Why this matters"),
      el("p", {}, why.join(" "))) : null,
    hasAttack ? el("div", { class: "detail-section" }, el("span", { class: "detail-label" }, "ATT&CK technique"), attackLink(f.attack)) : null,
    urls.length ? el("div", { class: "detail-section" }, el("span", { class: "detail-label" }, "Linked URLs"),
      ...urls.map((u) => el("div", { class: "ev-line" }, el("span", { class: "ev-text", title: u }, ...urlLine(u)), copyButton(u, "Copy URL")))) : null,
    el("div", { class: "detail-section" }, el("span", { class: "detail-label" }, `Linked events (${f.event_count})`),
      el("table", { class: "linked-events" },
        el("thead", {}, el("tr", {}, el("th", {}, "Time"), el("th", {}, "Type"), el("th", {}, "URL / term"))),
        el("tbody", {}, ...(f.events || []).slice(0, 20).map((e) => el("tr", {},
          el("td", {}, fmtShort(e.timestamp_utc)), el("td", {}, e.event_type),
          el("td", {}, e.url ? urlLine(e.url) : e.title || ""))))),
      el("button", { type: "button", class: "primary", style: "margin-top:8px", onclick: () => jumpToFinding(f) },
        `Show in timeline (${f.event_count} event${f.event_count === 1 ? "" : "s"})`)),
    findingReviewEditor(f));
}

async function jumpToFinding(f) {
  state.filters = { finding: f.id };
  state.offset = 0;
  syncInputsFromFilters();
  state.flashId = f.event_ids[0];
  goToTab("timeline");
  await loadEvents();
  $("timeline-panel").scrollIntoView({ block: "start" });
}

// ---------------------------------------------------------------- filters, chips
let searchDebounce = null;
function readFilters() {
  const f = {};
  const keep = ["hour", "domain", "finding"];
  for (const k of keep) if (state.filters[k] !== undefined) f[k] = state.filters[k];
  const q = $("f-q").value.trim(); if (q) f.q = q;
  const b = $("f-browser").value; if (b) f.browser = b;
  const t = $("f-type").value; if (t) f.type = t;
  const s = $("f-synced").value; if (s) f.synced = s;
  let ok = true;
  for (const [id, key, end] of [["f-from", "from", false], ["f-to", "to", true]]) {
    const input = $(id);
    const v = input.value.trim();
    input.classList.remove("invalid");
    if (!v) continue;
    const iso = zonedInputToUtc(v, state.tz, end);
    if (iso) f[key] = iso; else { input.classList.add("invalid"); ok = false; }
  }
  return ok ? f : null;
}
function syncInputsFromFilters() {
  const f = state.filters;
  $("f-q").value = f.q || ""; $("f-browser").value = f.browser || ""; $("f-type").value = f.type || "";
  $("f-synced").value = f.synced || "";
  $("f-from").value = f.from ? utcToInput(f.from, state.tz) : "";
  $("f-to").value = f.to ? utcToInput(f.to, state.tz) : "";
}

function hourLabel(h) { const hh = String(h).padStart(2, "0"); return `${hh}:00–${hh}:59 ${tzLabel(state.tz)}`; }

function renderChips() {
  const box = $("active-chips");
  clear(box);
  const f = state.filters;
  const chip = (label, key) => el("span", { class: "fchip" }, label,
    el("button", { type: "button", class: "fchip-x", "aria-label": `Remove filter ${label}`, onclick: () => removeFilter(key) }, "×"));
  const chips = [];
  if (f.finding !== undefined) {
    const fd = state.findings.find((x) => x.id === f.finding);
    chips.push(el("span", { class: "fchip" }, `Showing ${fd ? fd.rule_id : "finding"}'s ${state.total} linked event${state.total === 1 ? "" : "s"}`,
      el("button", { type: "button", class: "fchip-x", "aria-label": "Clear linked events filter", onclick: () => removeFilter("finding") }, "Clear ×")));
  }
  if (f.hour !== undefined) chips.push(chip(`Hour: ${hourLabel(f.hour)}`, "hour"));
  if (f.domain) chips.push(chip(`Domain: ${f.domain}`, "domain"));
  if (f.q) chips.push(chip(`Text: "${f.q}"`, "q"));
  if (f.browser) chips.push(chip(`Browser: ${f.browser}`, "browser"));
  if (f.type) chips.push(chip(`Type: ${f.type}`, "type"));
  if (f.synced) chips.push(chip(f.synced === "true" ? "Synced only" : "Local only", "synced"));
  if (f.from) chips.push(chip(`From ${fmtShort(f.from)}`, "from"));
  if (f.to) chips.push(chip(`To ${fmtShort(f.to)}`, "to"));
  if (chips.length) {
    box.append(...chips);
    if (chips.length > 1) box.append(el("button", { type: "button", class: "link-btn", onclick: resetAll }, "Clear all"));
  }
}
function removeFilter(key) {
  delete state.filters[key];
  state.offset = 0;
  syncInputsFromFilters();
  loadEvents().catch(showError);
}
function resetAll() {
  state.filters = {}; state.offset = 0;
  for (const id of ["f-from", "f-to"]) $(id).classList.remove("invalid");
  syncInputsFromFilters();
  loadEvents().catch(showError);
}
function applyFilter(key, value) {
  // a chart click starts a new exploration: it replaces "linked events of finding X"
  delete state.filters.finding;
  state.filters[key] = value;
  state.offset = 0;
  goToTab("timeline");
  loadEvents().then(() => $("timeline-panel").scrollIntoView({ block: "start" })).catch(showError);
}

// ---------------------------------------------------------------- timeline
function eventParams() {
  return { ...state.filters, limit: state.pageSize, offset: state.offset, tz: state.tz };
}

async function loadEvents() {
  const data = await api("/api/events", eventParams());
  state.total = data.total;
  const body = $("timeline-body");
  clear(body);
  let flashRow = null;
  for (const e of data.events) {
    const sev = state.eventSeverity.get(e.event_id);
    const linkedHere = state.filters.finding !== undefined;
    const tags = [];
    if (e.is_synced) tags.push(el("span", { class: "tag", title: "Made on another device signed into the same account" }, "Synced"));
    if (e.is_recovered) tags.push(el("span", { class: "tag", title: "Recovered record — partial" }, "Recovered"));
    const titleText = e.title || (e.event_type === "visit" ? "(no title)" : "");
    const humanTransition = humanizeTransition(e.transition);
    const row = el("tr", { class: [sev ? `sev-row-${sev}` : "", linkedHere ? "hl" : ""].join(" ").trim() || null,
      "data-id": e.event_id, tabindex: "0", "aria-label": `${e.event_type} ${fmtFull(e.timestamp_utc)} ${e.url}`,
      onclick: () => openEvent(e.event_id), onkeydown: (ev) => { if (ev.key === "Enter") openEvent(e.event_id); } },
      el("td", { class: "time", title: utcTitle(e.timestamp_utc) }, e.timestamp_utc ? fmtFull(e.timestamp_utc) : "(invalid)",
        sev ? el("span", { class: "sub-line", title: "Linked to a finding" }, `${sev} finding`) : null),
      el("td", {}, browserIdLabel(e.browser), el("span", { class: "sub-line", title: e.profile }, e.profile)),
      el("td", {}, el("span", { class: "one-line" }, e.event_type.replace("_", " ")), ...tags,
        humanTransition ? el("span", { class: "sub-line", title: e.transition }, humanTransition) : null),
      el("td", { title: [e.title, e.detail].filter(Boolean).join("\n") },
        el("span", { class: "one-line" }, titleText),
        e.detail ? el("span", { class: "sub-line" }, e.detail) : null),
      el("td", { class: "url-cell", title: e.url }, el("span", { class: "one-line" }, ...urlLine(e.url))),
      el("td", {}, el("button", { type: "button", class: "ghost small", "aria-label": `Details for event ${e.event_id}`,
        onclick: (ev) => { ev.stopPropagation(); openEvent(e.event_id); } }, "Details")));
    if (e.event_id === state.flashId) { row.classList.add("flash"); flashRow = row; }
    body.append(row);
  }
  if (!data.events.length) body.append(el("tr", { class: "empty-row" }, el("td", { colspan: "6" }, "No events match these filters.")));
  renderPagers();
  renderChips();
  if (flashRow) requestAnimationFrame(() => flashRow.scrollIntoView({ block: "center" }));
  state.flashId = null;
}

function renderPagers() {
  const pages = Math.max(1, Math.ceil(state.total / state.pageSize));
  const page = Math.floor(state.offset / state.pageSize) + 1;
  const first = state.total ? state.offset + 1 : 0;
  const last = Math.min(state.offset + state.pageSize, state.total);
  const filtered = Object.keys(state.filters).length > 0;
  for (const [id, withSize] of [["pager-top", true], ["pager-bottom", false]]) {
    const box = $(id);
    clear(box);
    const info = filtered
      ? `Showing ${first.toLocaleString()}–${last.toLocaleString()} of ${state.total.toLocaleString()} matching events (${state.grandTotal.toLocaleString()} total)`
      : `Showing ${first.toLocaleString()}–${last.toLocaleString()} of ${state.total.toLocaleString()} events`;
    const size = el("select", { "aria-label": "Rows per page", onchange: (e) => { state.pageSize = +e.target.value; state.offset = 0; loadEvents().catch(showError); } },
      ...[50, 100, 200].map((n) => el("option", { value: n, selected: n === state.pageSize }, `${n} per page`)));
    box.append(el("span", {}, info), el("span", { class: "pager-nav" },
      withSize ? size : null,
      el("button", { type: "button", class: "ghost small", disabled: page <= 1, "aria-label": "Previous page",
        onclick: () => { state.offset = Math.max(0, state.offset - state.pageSize); loadEvents().then(() => id === "pager-bottom" && $("timeline-panel").scrollIntoView({ block: "start" })).catch(showError); } }, "‹ Prev"),
      el("span", {}, `Page ${page} of ${pages}`),
      el("button", { type: "button", class: "ghost small", disabled: page >= pages, "aria-label": "Next page",
        onclick: () => { state.offset += state.pageSize; loadEvents().then(() => id === "pager-bottom" && $("timeline-panel").scrollIntoView({ block: "start" })).catch(showError); } }, "Next ›")));
  }
}

// ---------------------------------------------------------------- drawer
function openDrawer(title, content) {
  $("drawer-title").textContent = title;
  const body = $("drawer-body");
  clear(body);
  body.append(content);
  $("drawer").hidden = false;
  $("drawer-close").focus();
}
function closeDrawer() { $("drawer").hidden = true; }

function kv(pairs) {
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of pairs) dl.append(el("dt", {}, k), el("dd", {}, v === null || v === undefined || v === "" ? "—" : v));
  return dl;
}

async function openEvent(id) {
  const data = await api(`/api/event/${id}`);
  const e = data.event;
  const decoded = safeDecode(e.url || "");
  const content = el("div", {});
  content.append(el("h3", {}, "Event"), kv([
    ["Time (local)", el("span", { title: utcTitle(e.timestamp_utc) }, e.timestamp_utc ? fmtFull(e.timestamp_utc) : "(invalid)")],
    ["Time (UTC)", el("code", {}, e.timestamp_utc)],
    ["Browser", el("span", {}, browserIdLabel(e.browser), " ", e.browser_version || "", " · ", e.profile)],
    ["Type", e.event_type],
  ]));
  content.append(el("h3", {}, "URL"),
    el("div", { class: "copy-row" }, el("div", { class: "url-box mono" }, decoded || "—"), e.url ? copyButton(e.url, "Copy URL") : null));
  let params = [];
  try { params = [...new URL(e.url).searchParams.entries()]; } catch { /* not a URL */ }
  if (params.length) {
    content.append(el("h3", {}, `Query parameters (${params.length})`),
      el("table", { class: "params" }, el("tbody", {}, ...params.map(([k, v]) => el("tr", {}, el("th", { scope: "row" }, k), el("td", { class: "mono" }, v))))));
  }
  content.append(el("h3", {}, "Title"), el("p", {}, e.title || "—"));
  content.append(el("h3", {}, "Transition"), kv([
    ["Human-readable", humanizeTransition(e.transition) || "—"], ["Raw value", el("code", {}, e.transition || "—")],
  ]));
  content.append(el("h3", {}, "Flags"), kv([
    ["Synced", e.is_synced ? "yes — made on another device" : "no"], ["Recovered", e.is_recovered ? "yes (partial)" : "no"],
    ["Visit id / from", `${e.source_visit_id ?? "—"} / ${e.from_visit_id ?? "—"}`],
  ]));
  if (e.event_type === "visit") {
    const chainBox = el("div", {});
    content.append(el("h3", {}, "Navigation chain"), chainBox);
    chainBox.append(el("button", { type: "button", class: "ghost", onclick: () => loadChain(id, chainBox) }, "Show how the user got here"));
  }
  const raw = JSON.stringify(e, null, 2);
  const src = data.source;
  content.append(el("h3", {}, "Source record"), kv([
    ["File", el("code", {}, src.file || "—")], ["Record ID", el("code", {}, e.source_record_id || "—")],
    ["SHA-256", el("div", { class: "copy-row" }, el("code", {}, src.sha256 || "—"), src.sha256 ? copyButton(src.sha256, "Copy SHA-256") : null)],
    ["Evidence copy", el("code", {}, src.evidence_copy || "—")],
    ["Verify with", src.query ? el("div", { class: "copy-row" }, el("code", {}, src.query), copyButton(src.query, "Copy SQL query")) : "—"],
  ]), el("details", {}, el("summary", {}, "Raw stored record (JSON)"),
    el("div", { class: "copy-row" }, el("pre", { class: "url-box mono" }, raw), copyButton(raw, "Copy raw record"))));
  content.append(el("h3", {}, "Linked findings"), data.findings.length
    ? el("ul", { style: "margin:0;padding-left:16px" }, ...data.findings.map((f) => el("li", {},
      el("span", { class: `pill pill-${f.severity}` }, f.severity),
      ` ${f.rule_id} ${SHORT_TITLES[f.rule_id] || f.name}`,
      f.risk_level ? el("span", { class: "sub-line" }, `Analyst review: ${f.risk_level} · ${f.outcome} · confidence ${f.confidence}`) : null)))
    : el("p", { class: "empty" }, "Not linked to any finding."));
  openDrawer(`Event ${e.event_id}`, content);
}

async function loadChain(id, box) {
  const data = await api(`/api/chain/${id}`);
  clear(box);
  box.append(el("p", { class: "empty" }, `${data.chain.length} step(s), oldest first.`),
    ...data.chain.map((e) => el("div", { class: `chain-step ${e.event_id === id ? "current" : ""}` },
      el("div", {}, el("code", { title: utcTitle(e.timestamp_utc) }, fmtFull(e.timestamp_utc)), " · ", humanizeTransition(e.transition) || e.event_type),
      el("div", {}, e.title || "(no title)"), el("div", { class: "ev-text" }, ...urlLine(e.url)))));
}

// ---------------------------------------------------------------- charts
function offHoursBandPlugin() {
  return {
    id: "offHoursBand",
    beforeDatasetsDraw(chart) {
      const hours = state.chartData && state.chartData.hours;
      if (!hours) return;
      const { ctx, chartArea, scales } = chart;
      if (!chartArea) return;
      ctx.save();
      ctx.fillStyle = COLORS.off;
      for (let i = 0; i < hours.length; i++) {
        if (!hours[i].off_hours) continue;
        const x = scales.x.getPixelForValue(i);
        const half = (scales.x.width / hours.length) / 2;
        ctx.fillRect(x - half, chartArea.top, half * 2, chartArea.height);
      }
      ctx.restore();
    },
  };
}

function legend(boxId, items) {
  const box = $(boxId);
  clear(box);
  for (const [color, label] of items) {
    const sw = el("span", { class: "sw", "aria-hidden": "true" });
    sw.style.background = color; // CSSOM, allowed by the CSP
    box.append(el("span", {}, sw, label));
  }
}

function themeColor(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

async function loadCharts() {
  if (typeof Chart === "undefined") return;
  state.chartData = await api("/api/charts", { tz: state.tz });
  renderHoursChart();
  renderDomainsChart();
}

function renderHoursChart() {
  const d = state.chartData;
  const tzl = tzLabel(d.timezone);
  const hours = d.hours;
  const counts = hours.map((h) => h.count);
  const total = d.total_events || 1;
  const grid = themeColor("--border"), tick = themeColor("--text-muted"), bar = themeColor("--accent");
  Chart.defaults.color = tick;
  Chart.defaults.font.family = "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif";
  Chart.defaults.font.size = 12;
  const w = d.off_hours;
  $("hours-sub").textContent = `${total.toLocaleString()} events by hour of day, ${tzl}, all days combined`;
  legend("hours-legend", w ? [[COLORS.off.replace("0.07", "0.4"), `Off-hours window (${w.start}–${w.end} ${tzLabel(w.timezone)})`]] : []);

  if (state.charts.hours) state.charts.hours.destroy();
  state.charts.hours = new Chart($("hours-chart"), {
    type: "bar",
    data: { labels: hours.map((h) => String(h.hour).padStart(2, "0")),
      datasets: [{ label: "Events", data: counts, backgroundColor: bar, borderRadius: 3, maxBarThickness: 28 }] },
    options: {
      maintainAspectRatio: false, animation: false,
      scales: {
        x: { grid: { display: false }, ticks: { color: tick } },
        y: { beginAtZero: true, grid: { color: grid }, ticks: { precision: 0, color: tick } },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          displayColors: false,
          callbacks: {
            title: (items) => hourLabel(items[0].dataIndex),
            label: (item) => {
              const h = hours[item.dataIndex];
              const lines = [`${h.count.toLocaleString()} events (${((100 * h.count) / total).toFixed(1)}%)`];
              if (h.top_domain) lines.push(`Top domain: ${h.top_domain}`);
              if (h.off_hours) lines.push("Inside off-hours window");
              return lines;
            },
            footer: () => "Click to filter the timeline",
          },
        },
      },
      onClick: (_evt, elements) => { if (elements.length) applyFilter("hour", elements[0].index); },
      onHover: (evt, elements) => { evt.native.target.style.cursor = elements.length ? "pointer" : "default"; },
    },
    plugins: [offHoursBandPlugin()],
  });
}

function truncate(s, n) { return s.length > n ? `${s.slice(0, n - 1)}…` : s; }
function labelChars() { const w = $("domains-box").clientWidth; return w < 420 ? 14 : w < 640 ? 20 : 26; }

function renderDomainsChart() {
  const d = state.chartData;
  const n = state.topN;
  const top = d.domains.slice(0, n);
  const shown = top.reduce((a, x) => a + x.visits, 0);
  const othersVisits = d.total_visits - shown;
  const othersCount = Math.max(0, d.domain_count - top.length);
  const rows = top.map((x) => ({ ...x, others: false }));
  if (othersVisits > 0) rows.push({ domain: `Others (${othersCount} domains)`, visits: othersVisits, others: true });
  const total = d.total_visits || 1;
  const grid = themeColor("--border"), tick = themeColor("--text-muted"), bar = themeColor("--accent"), others = themeColor("--text-muted");
  $("domains-sub").textContent = `${d.total_visits.toLocaleString()} history visit events (searches/downloads excluded), top ${top.length} of ${d.domain_count} domains`;
  legend("domains-legend", []);

  if (state.charts.domains) state.charts.domains.destroy();
  state.charts.domains = new Chart($("domains-chart"), {
    type: "bar",
    data: { labels: rows.map((r) => r.domain),
      datasets: [{ label: "Visits", data: rows.map((r) => r.visits), borderRadius: 3, barThickness: 16,
        backgroundColor: rows.map((r) => (r.others ? others : bar)) }] },
    options: {
      indexAxis: "y", maintainAspectRatio: false, animation: false,
      scales: {
        y: { grid: { display: false }, ticks: { autoSkip: false, color: tick, callback: (v, i) => truncate(rows[i].domain, labelChars()) } },
        x: { beginAtZero: true, grid: { color: grid }, ticks: { precision: 0, color: tick } },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          displayColors: false,
          callbacks: {
            title: (items) => rows[items[0].dataIndex].domain,
            label: (item) => {
              const r = rows[item.dataIndex];
              const lines = [`${r.visits.toLocaleString()} visits (${((100 * r.visits) / total).toFixed(1)}%)`];
              if (r.others) return lines;
              lines.push(`Unique URLs: ${r.unique_urls.toLocaleString()}`, `Linked findings: ${r.findings}`);
              return lines;
            },
            footer: (items) => (rows[items[0].dataIndex].others ? "" : "Click to filter the timeline"),
          },
        },
      },
      onClick: (_evt, elements) => {
        if (!elements.length) return;
        const r = rows[elements[0].index];
        if (!r.others) applyFilter("domain", r.domain);
      },
      onHover: (evt, elements) => { evt.native.target.style.cursor = elements.length && !rows[elements[0].index].others ? "pointer" : "default"; },
    },
  });
}

// ---------------------------------------------------------------- evidence tab
async function loadEvidence() {
  const data = await api("/api/evidence");
  const body = $("evidence-body");
  clear(body);
  for (const f of data.files) {
    body.append(el("tr", {},
      el("td", {}, browserIdLabel(f.browser)), el("td", {}, f.profile || "—"),
      el("td", { class: "mono" }, f.original_path || "—"),
      el("td", {}, f.size_bytes != null ? `${(f.size_bytes / 1024).toFixed(1)} KB` : "—"),
      el("td", { class: "mono" }, f.sha256_original || "—"), el("td", { class: "mono" }, f.sha256_copy || "—"),
      el("td", {}, el("span", { class: f.status === "ok" ? "status-ok" : "status-bad" }, f.status === "ok" ? "Verified" : f.status))));
  }
  if (!data.files.length) body.append(el("tr", {}, el("td", { colspan: "7", class: "empty" }, "No evidence files recorded.")));

  const custodyBody = $("custody-body");
  clear(custodyBody);
  for (const c of data.custody_log) {
    custodyBody.append(el("tr", {},
      el("td", {}, c.timestamp_utc || "—"), el("td", { class: "mono" }, c.original_path || "—"),
      el("td", { class: "mono" }, c.copy_path || "—"),
      el("td", {}, el("span", { class: c.match ? "status-ok" : "status-bad" }, c.match ? "Match" : "No match")),
      el("td", {}, c.note || "—")));
  }
  if (!data.custody_log.length) custodyBody.append(el("tr", {}, el("td", { colspan: "5", class: "empty" }, "No custody log entries.")));

  const auditBody = $("audit-body");
  clear(auditBody);
  for (const a of data.audit_log) {
    auditBody.append(el("tr", {}, el("td", {}, a.timestamp_utc || "—"), el("td", {}, a.level || "—"),
      el("td", {}, a.action || "—"), el("td", {}, a.detail || "—")));
  }
  if (!data.audit_log.length) auditBody.append(el("tr", {}, el("td", { colspan: "4", class: "empty" }, "No audit log entries.")));
}

async function verifyAgain() {
  const btn = $("verify-again");
  btn.disabled = true;
  btn.textContent = "Verifying…";
  try {
    await apiUpdate("/api/evidence/verify", undefined, "POST");
    await loadEvidence();
    const data = await api("/api/case");
    renderEvidenceBadge(data.verification || {}, data.evidence_files || []);
  } catch (err) {
    console.error(err);
  } finally {
    btn.disabled = false;
    btn.textContent = "Verify again";
  }
}

// ---------------------------------------------------------------- wiring
function wire() {
  for (const btn of document.querySelectorAll(".tab[data-tab]")) {
    btn.addEventListener("click", () => goToTab(btn.dataset.tab));
  }
  window.addEventListener("hashchange", () => goToTab(location.hash.slice(1), { push: false }));

  $("priority-view-all").addEventListener("click", () => goToTab("findings"));

  $("filters").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const f = readFilters();
    if (!f) return;
    delete f.finding;
    state.filters = f;
    state.offset = 0;
    loadEvents().catch(showError);
  });
  $("f-q").addEventListener("input", () => {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(() => $("filters").requestSubmit(), 250);
  });
  $("f-reset").addEventListener("click", resetAll);
  $("sort").addEventListener("change", (e) => { state.sort = e.target.value; renderFindingsList(); });

  $("kebab-btn").addEventListener("click", (e) => {
    e.stopPropagation();
    const menu = $("kebab-menu");
    const open = menu.hidden;
    menu.hidden = !open;
    $("kebab-btn").setAttribute("aria-expanded", String(open));
  });
  document.addEventListener("click", (e) => {
    if (!$("kebab-menu").hidden && !e.target.closest(".toolbar-kebab")) { $("kebab-menu").hidden = true; $("kebab-btn").setAttribute("aria-expanded", "false"); }
  });

  $("verify-again").addEventListener("click", verifyAgain);
  for (const btn of document.querySelectorAll("#evidence-subtabs .tab[data-subtab]")) {
    btn.addEventListener("click", () => {
      for (const b of document.querySelectorAll("#evidence-subtabs .tab")) b.setAttribute("aria-selected", String(b === btn));
      $("evidence-sub-custody").hidden = btn.dataset.subtab !== "custody";
      $("evidence-sub-audit").hidden = btn.dataset.subtab !== "audit";
    });
  }

  $("drawer-close").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  const toTop = $("to-top");
  window.addEventListener("scroll", () => { toTop.hidden = window.scrollY < 600; }, { passive: true });
  toTop.addEventListener("click", () => window.scrollTo({ top: 0 }));
  const setHeights = () => {
    document.documentElement.style.setProperty("--toolbar-h", `${($("toolbar") || {}).offsetHeight || 0}px`);
    document.documentElement.style.setProperty("--topbar-h", `${($("topbar") || {}).offsetHeight || 0}px`);
  };
  new ResizeObserver(setHeights).observe($("topbar"));
  setHeights();
  let resizeTimer = null;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { if (state.chartData) renderDomainsChart(); }, 200);
  });
}

function showError(err) {
  console.error(err);
  const body = $("timeline-body");
  clear(body);
  body.append(el("tr", { class: "empty-row" }, el("td", { colspan: "6" }, `Error: ${err.message}`)));
}

function panelError(boxId, what, err) {
  console.error(err);
  const box = $(boxId);
  if (!box) return;
  clear(box);
  box.append(el("p", { class: "empty" }, `Could not load ${what}: ${err.message}. `
    + "If you just updated BrowserTrace, restart 'browsertrace serve' and reload."));
}

window.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  wire();
  goToTab(location.hash.slice(1) || "overview", { push: false });
  try { await loadCase(); } catch (err) { panelError("case-info", "case details", err); }
  await Promise.all([
    loadStats().catch((err) => panelError("cards", "summary", err)),
    loadFindings().catch((err) => panelError("findings", "findings", err)),
  ]);
  await Promise.all([
    loadEvents().catch(showError),
    loadCharts().catch((err) => { panelError("hours-legend", "charts", err); }),
  ]);
});
