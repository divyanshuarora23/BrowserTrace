# Limitations

BrowserTrace is a triage tool. It surfaces **investigative leads**, not proof. Every finding
must be checked against the source record it links to, and against other evidence.

## Scope
- **Browsers:** Chromium family (Chrome, Edge, Brave, Opera) `History`, and Firefox `places.sqlite`.
  Other browsers, mobile browsers and browser extensions' own storage are not parsed.
- **Artifacts:** visits, downloads, and searches only. Cookies, passwords, autofill, cache,
  sessions/tabs, bookmarks, favicons, Top Sites and `Web Data` are not examined (passwords,
  cookie values and autofill are deliberately excluded).
- **Execution correlation is out of scope:** a download is not proof the file was opened or run.
  Prefetch, Amcache, ShimCache, SRUM and Jump Lists are not correlated (future work).

## Deleted history
- **WAL/free-page recovery is not implemented.** `parsers/recovery.py` is a documented stub.
  The `-wal`/`-shm` sidecars *are* collected and hashed so they can be examined with other tools.
- History clearing is only **inferred** by rule R006 (time gaps inside active periods and holes in
  the visit-ID sequence). Both have innocent explanations (holidays, another browser used,
  individual entries deleted for privacy, sync or import quirks). Chromium's automatic expiry of
  history older than ~90 days removes the *oldest* records, so the start of history is not evidence
  of clearing. Clearing "all time" or the most recent period leaves no hole, so R006 cannot detect it.

## Timestamps
- All times are converted to UTC. Off-hours rules use `--tz` (default **UTC**); passing the wrong
  timezone shifts R003 results.
- Chromium `keyword_search_terms` has no timestamp of its own; BrowserTrace uses the URL's
  `last_visit_time` and marks the event "timestamp approximate". URL-derived searches use the exact
  visit time.
- Firefox downloads stored in annotations get their start time from the matching `visit_type=7`
  visit, or from the annotation's `dateAdded` when no such visit exists.
- System clock manipulation on the examined machine is not detected beyond flagging timestamps
  later than the collection time.

## Sync
- Chromium visits with a non-empty `visits.originator_cache_guid` are labelled SYNCED (made on
  another device). Older Chromium versions lack this column; then sync origin is unknown.
- Firefox records no equivalent, so **synced Firefox visits cannot be distinguished** and are
  always reported as local.

## Rules
- Domain, keyword and extension lists are short and English-centric. Keyword matching is
  word-prefix based (e.g. "clear history" also matches "history of clearwater").
- Searches are derived only for listed engines (Google, Bing, DuckDuckGo, Yahoo, Brave, Yandex,
  Baidu, Ecosia, YouTube) and from Chromium `keyword_search_terms`.
- Severity escalation (off-hours + another rule) is a prioritisation heuristic.

## Acquisition
- Files locked by a running browser are retried, then reported. Acquire from a forensic image or a
  Volume Shadow Copy instead of a live, running profile where possible.
- If a browser writes to the database while it is being copied, the original and copy hashes differ;
  both hashes are recorded and the evidence is flagged "not verified".
- Zone.Identifier (Mark-of-the-Web) is only read if the downloaded file still exists in the evidence
  tree (NTFS ADS on Windows, or a `<file>.Zone.Identifier` sidecar exported by imaging tools).

## Validation
- Accuracy has **not yet been measured** against reference tools (NirSoft BrowsingHistoryView,
  Hindsight). See `docs/VALIDATION.md` and `validation/compare.py`.
- The synthetic scenario uses real table/column names but is generated data; passing on it does not
  prove correctness on every real browser version.
