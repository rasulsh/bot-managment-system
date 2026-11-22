# Phase 5 — admin panel

Setup is also summarised in the [README](../README.md#26-installation-by-environment) (developers) and [panel tour](../README.md#14-first-login-and-a-tour-of-the-panel) (operators).

Everything the first four phases built is operated from a terminal: `jq` over
JSONL, `ctl.py` for overrides, an editor for `guard/config.php`, `replay.py`
before every threshold change. That works, and it is why the panel adds **no new
detection surface and no new decision authority**. It is a window onto data that
already exists and a controlled writer for settings that already exist.

The panel is **optional**. Delete `panel/` and the guard and analyzer behave
exactly as before; the overlay file simply stops being written and the guard
falls back to `guard/config.php`. Pure PHP 8.0+, no Composer, no vendor
directory, no build step, no CDN — it runs on a server with no outbound network
access at all.

## Two rules it is built around

**It never writes PHP and never runs a shell command.** Settings changed in the
panel are written as **JSON** to `guard/config.local.json`, never as PHP source:
a panel that rewrites executable config from form input is a code-injection hole
in a security tool. Analyzer actions are queued in Redis and drained by
`analyzer/worker.py`, which maps a job type to a Python function called
in-process. No `exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`
or backticks appear anywhere in `panel/` — `scripts/panel-selftest.php` fails the
build if one ever does.

**Everything it displays is attacker-controlled.** User agents, paths, referers
and query strings in the logs were written by the bots this system fights. Every
value rendered anywhere goes through `gp_e()`. A stored XSS in the admin panel of
a bot guard would be handing an attacker the console.

## Install the panel

```bash
php panel/setpass.php          # the only terminal command the panel needs
```

It prompts for a username and password, refuses passwords under 12 characters,
generates a session secret distinct from the guard's, and writes
`panel/panel.config.php` at mode 0600. Re-run it to rotate credentials. Then:

> **Installs created before the credential file carried a direct-access guard:**
> the generated file now begins with
> `if (!defined('GP_BOOT')) { http_response_code(404); exit; }`, the same line
> every other file under `panel/` has. An older `panel.config.php` keeps working
> and is unaffected — to pick the guard up, either re-run `setpass.php` or add
> that one line by hand above the `return`.

1. **Add the panel to `exempt_paths` in `guard/config.php`:**

   ```php
   'exempt_paths' => array('/bot-guard/panel/'),   // your panel's URI prefix
   ```

   Being challenged or blocked out of your own admin panel by your own bot guard
   is a real and stupid failure mode. The panel carries its own auth, CSRF and
   login rate limit, so exempting it costs nothing. There is no guard code for
   this on purpose — it is a config line you set.

2. **Add two cron entries** next to the existing analyzer ones:

   ```
   */15 * * * * bash /full/path/bot-guard/scripts/analyzer-cron.sh snapshot >/dev/null 2>&1
   *    * * * * bash /full/path/bot-guard/scripts/analyzer-cron.sh worker   >/dev/null 2>&1
   ```

   `snapshot` writes `analyzer/snapshot.json`, which is the only thing the
   dashboard reads — a busy site's dashboard opens as fast as a quiet one's.
   `worker` drains the job queue; without it the panel's action buttons queue
   jobs that nobody runs. Both take the same `flock` as the other modes.

3. Serve `panel/` over HTTPS. The session cookie sets `Secure` on HTTPS,
   `HttpOnly` and `SameSite=Strict` always, with `Path` scoped to the panel
   directory.

How to expose the panel on a URL (symlink, permissions, web server settings,
troubleshooting): [13-PANEL-WEB-ACCESS.md](13-PANEL-WEB-ACCESS.md).

`panel/.htaccess` denies everything except `index.php` and the CSS/font assets,
and denies `panel.config.php` and `audit.jsonl` explicitly. If your server
ignores `.htaccess`, put `panel/` outside the document root and alias only
`index.php` and `assets/`.

## Security model

| control | behaviour |
|---|---|
| **No setup wizard** | If `panel/panel.config.php` is absent or malformed, **every panel route returns a bare 404** — no hint that a panel exists. A first-run setup screen reachable by whoever finds the URL first is how admin panels get taken over; one install-time command is the correct trade. |
| **Session** | Signed cookie `gp_sess` = `user.issued_at.hmac`, verified with `hash_equals`, sliding renewal at half of `session_ttl` (default 12 h). Tampering with any part invalidates it. |
| **CSRF** | Per-session token in a hidden field on every state-changing POST, verified with `hash_equals`. GET routes never change state. |
| **Login rate limit** | 5 attempts per 15 minutes per IP (`gp:login:{ip}`), plus a second global counter across all addresses (`gp:login:user`) at four times that, so an attempt spread over many IPs is caught too. Wrong user and wrong password give an identical message and an identical response time. Messages are drawn inside the login card (`role="alert"`); after a failed login the typed username is kept (never the password) and the password field takes focus. A locked-out visitor sees a separate message with the minutes left to wait, which is the same whether or not the username exists. |
| **Redis down** | The limiter falls back to a **file counter**, not to no limit. This is the one place in the whole system that deliberately does **not** fail open. |
| **IP allowlist** | Optional `ip_allowlist` in `panel/panel.config.php`: IPv4 and IPv6 addresses or CIDR ranges. Empty means no restriction (default, so upgrades lock nobody out); a non-empty list with no valid entry refuses everyone (fail closed). It is checked before any route, login included. `X-Forwarded-For` is read only when the connection comes from an address in `trusted_proxies`, walking from the right past trusted hops. The same address feeds the login rate limit and the audit trail. |
| **Search engines** | `X-Robots-Tag: noindex, nofollow, noarchive, nosnippet` on every response (PHP, and `.htaccess` for assets and server errors) plus a robots meta tag. No `robots.txt`, on purpose. |
| **Audit trail** | Every accepted config change, override, job and login — success *and* failure — appends one JSONL line to `panel/audit.jsonl` with timestamp, actor, key, old value, new value and client IP. Append-only; the panel offers no delete. An untraceable config change in a security tool is unacceptable. |

Nothing sensitive is committed: `panel/panel.config.php`, `panel/audit.jsonl`,
`guard/config.local.json` and `analyzer/snapshot.json` are all git-ignored, and
`scripts/config-dump.php` strips the panel credentials from its output.

## The config overlay and its precedence

```
shipped defaults  →  guard/config.php  →  guard/config.local.json
```

The overlay is a flat JSON object written only by the panel, atomically (temp
file in the same directory, `chmod 0640`, then `rename()`), so a half-written
overlay is never observable by the guard.

- Missing file: ignored silently.
- Unreadable, malformed, or non-object JSON: ignored silently. The guard
  continues on `guard/config.php`. **Never fatal, never a warning that could
  reach output.**
- Only whitelisted keys are read; anything else in the file is discarded. A key
  with the wrong type or an out-of-range value is discarded **individually**, not
  the whole file.

Validation lives in `gv_overlay_validate()` in `guard/guard.php`, not in
`panel/`, and both sides call it. The panel is optional and deleting it must
change nothing — so what the panel accepts on write has to be the same code the
guard runs on read, permanently.

**Whitelist:** `gv_overlay_whitelist()` in `guard/guard.php` is the complete list, with
the type and range of every key (the **Config file** page prints it too). It covers
enforcement, signals and weights, every rate limit, the challenge (`pow_bits`, `gate_post`,
`bind_ip`, `token_ttl`, `nonce_ttl`), the challenge page text
(`strings.*`), holdout and outcome capture, exemptions and the honeypot,
`exempt_params_paths`, `cdn_ranges`, `known_bots`, `preview_bots`, `bot_suffixes`, and the
analyzer's operational settings (`analyzer.*`).

Editing `guard/config.php` by hand still works and is still authoritative for
anything not in the overlay. To go back to the file, use **reset to file** in the
settings view — it removes the key from the overlay rather than writing the old
value back.

## Where each setting lives

| Category | Where | Keys |
|---|---|---|
| **A. Install and secrets** | `guard/config.php`, over SSH | `secret`, `holdout_salt`, `redis.*` (host, port, socket, username, password, db, prefix, timeout, breaker_ttl), `log_dir`, `cookie_name`, `challenge.test_key`, `challenge.trust_headers` (rollback switch that weakens the challenge); the panel login (`setpass.php`); analyzer paths and `php_bin` (`GV_ANALYZER_CONFIG`) |
| **B. Operation** | Panel: **Settings** or **Config file** | everything on the whitelist above |

Category A is what the guard needs before it can read anything else (Redis, the log
directory), or a secret whose change breaks every token or reshuffles the holdout. The
**Settings** page shows their state at the bottom (set / not set, endpoint), never a
secret value.

Precedence, guard: shipped defaults → `guard/config.php` → `guard/config.local.json`.
Precedence, analyzer: `analyzer/config.py` defaults → `GV_ANALYZER_CONFIG` file → panel
(`analyzer.*` keys, read through `scripts/config-dump.php`).

When a change takes effect: the guard reads the overlay on every request (no cache; the
file is JSON, so OPcache does not hold an old copy). The analyzer reads it at the start of
every run. The settings form writes only the keys you changed; a value that comes from
`guard/config.php` stays there.

## The config file editor

**Config file** in the menu edits `guard/config.local.json` as text, with JSON syntax
highlighting and a live syntax check in the browser. The browser check is a convenience;
the server decides. Nothing is written unless the whole file passes:

- strict JSON, one object, no duplicate keys (a parser that reports line and column,
  because `json_decode()` only says "Syntax error");
- every key on the whitelist and every value accepted by `gv_overlay_validate()`;
- the file has not changed since the editor opened it (another tab, the settings form).

Every error is listed with its line and a sentence that says what is wrong; clicking it
selects the line. On success the previous version is copied to `guard/config-backups/`
(newest 20 kept; also on every settings save and reset), the new text is written to a
temp file and renamed into place, and each changed key goes to the audit trail as
`config_file`. A backup can be opened in the editor and saved like any other edit.

The editor is a textarea over a highlighted `<pre>` (about 80 lines of inline JS, no
library). CodeMirror or Monaco would add 150 KB+ of vendored code to a panel that has no
build step and no CDN, for one small JSON file. Without JavaScript the page is a plain
textarea and the server check still applies. It edits JSON only: `guard/config.php` stays
read-only for the panel, because a web form that writes PHP is code execution for anyone
who steals the session.

## What deliberately has no UI

| setting | why |
|---|---|
| `secret`, `holdout_salt`, `redis`, `log_dir`, `cookie_name`, `challenge.test_key`, `challenge.trust_headers` | Not on the whitelist and there is no form for them (category A above). Rotating `secret` invalidates every issued token at once; changing `holdout_salt` silently reshuffles the control group and invalidates the comparison the holdout exists to provide. Both are `openssl rand` + an editor, once. |
| Panel username, password, session secret | `setpass.php` only. A panel that can rewrite its own credentials from a session is one XSS away from a permanent backdoor. |
| Reputation weights (`analyzer/reputation.py`), `DECISION_SPAN`, model internals | Code, not configuration. Changing them changes what every historical score meant, and the honest way to do that is a diff, a replay and a deploy. |
| Log deletion, audit deletion | Append-only by design. Rotation is `scripts/guard-logrotate.sh`. |
| Arbitrary jobs | The queue accepts exactly ten named types — `verify`, `nightly`, `train`, `train_clf`, `replay_full`, `promote_ml`, `promote_clf`, `snapshot`, `geo_compile`, `iplist_compile` (`gp_job_types()` in `panel/jobs.php`, `HANDLERS` in `analyzer/worker.py`). Queued training always writes to `--candidate`, so a job fired from a browser can never make the guard more permissive while nobody is watching. |

## What the panel does

- **Dashboard** — kill-switch state, every toggle, Redis reachability, and the
  last successful `run_verify` / `run_nightly` / `snapshot` / `worker` times with
  a stale warning. KPI cards, inline-SVG charts generated in PHP, and the
  kill-switch control itself behind a confirm step.
- **Log explorer** — the replacement for `grep` and `jq`. Filters on date, `act`,
  `sh`, `hold`, `ovr`, `tok`, device, IP, path substring, reason, response status
  and score ranges; reverse-streamed with a hard cap of 200 rows per page. It
  never loads a whole log file into memory, and CSV export of the current filter.
- **Identity drill-down** — every `gv:` verdict for one device or IP on one page:
  the `ctl.py show` output that answers "why was this customer blocked?".
- **Overrides** — the `ctl.py allow` / `deny` five-second fix, with the same TTL
  ceiling of 30 days and the same rule that allow is ungated and deny respects
  `enforce.block`.
- **Replay** — `replay.py` against real history before a threshold change, run
  natively in PHP through the guard's own `gv_effective_score()` and
  `gv_decide()`, so the preview and the live decision cannot drift.
- **Models** — bundle status, staleness, classifier precision, and the buttons
  that queue training and promotion.
- **Rules** — block / challenge / log by User-Agent or path (see
  [02-ARCHITECTURE.md](02-ARCHITECTURE.md#access-rules) for precedence). Create, edit,
  duplicate, enable/disable, delete (confirmed), reorder (renumbers 10, 20, ...). Every change
  is audited with before/after. Non-blocking warnings before saving: pattern also matches a
  `known_bots`/`preview_bots` entry, matches current real browsers (a fixed sample list in
  `panel/rules.php`), is a `contains` under 4 chars, overlaps an exempt path. A **Test** box
  shows which rule would match a UA/path (and what happens) without changing anything.
  **Install starter set** adds 16 disabled monitor rules (python-requests, python-urllib,
  aiohttp, httpx, Go-http-client, curl/, Wget, Scrapy, HeadlessChrome, PhantomJS, node-fetch,
  axios/, okhttp, Java/, libwww-perl, empty UA). **Quick block** on a log or identity row opens
  a pre-filled monitor rule (exact UA; a UA cut at 120 chars becomes a prefix rule). Hits come
  from the snapshot (log-derived), never from Redis counters. The create/edit/quick-block form
  shows an **impact preview**: what the rule would have matched in the recent logs (requests,
  distinct IPs and devices, top 5 paths, requests that carried a valid token) with the scanned
  time range, using the log explorer's scan caps; red when more than 50 devices or any tokened
  request match. **Preview impact** re-runs it on the form as typed; switching a rule from
  monitor to enforce (or creating one in enforce) requires seeing it and ticking the
  acknowledgement. Regexes are refused on save if they hit the backtrack limit or take more than 1 ms
  for a single match on the stress and real-browser test strings (`regex_slow`). If `guard/rules.json` is
  invalid the page says so and refuses writes until it is fixed or the invalid part discarded.
- **GeoIP** — the active databases (source file, build date, age, IPv4 / IPv6 range counts), the source files in
  `geo/`, upload (checked against `upload_max_filesize` / `post_max_size`; a bigger file: copy it to `geo/` over
  SFTP), **Compile now** (queues the `geo_compile` job; the worker cron runs it), the last compile result with
  its errors and the **ignored geoip.dat tags**, one-click **rollback** to the previous compiled file, delete of
  a source file, and a **lookup tester** (address -> country / ASN, and which rule would act on that client, with
  optional UA, path and "verified crawler"). Everything is audited (`geo_upload`, `geo_delete`, `geo_rollback`,
  the job). Warnings (also on the dashboard): a database older than 45 days, a rule that needs a database that is
  not installed, a damaged compiled file. Rules gain **Country** and **ASN** conditions (include / exclude);
  the form says that an unknown country never matches. Extra rule warnings: block / challenge by country
  without `skip_verified_bots` (Googlebot and Bingbot crawl from US addresses), "not IR -> block" (blocks
  Iranian visitors on a VPN or foreign proxy: try `challenge` or `monitor` first), a country code that is not in
  the active database. The Rules **Test** box takes an optional client IP. The impact preview works for
  country / ASN conditions: when the log rows carry no `cc` / `asn` yet (Settings -> GeoIP -> log country is off)
  it says so and resolves the logged addresses in the current database, or says it cannot evaluate when there is
  no database - it never shows a bare zero. The Logs page filters by country (`cc`) and ASN (`asn`) and the CSV
  export has both columns.
- **IP lists** — named allow / block lists of addresses and CIDRs, kept as files and compiled into one range file per type
  that the guard searches without Redis (see [02-ARCHITECTURE.md](02-ARCHITECTURE.md#ip-allow--block-lists)). The single-address
  overrides on the Overrides page stay as they are. Tabs: **Lists** (table with type, mode, enabled, entry and address counts,
  hits 24 h / 7 d and last hit from the snapshot; filters name / type / mode / status, each include or exclude, as chips; enable /
  disable, switch monitor / enforce, edit, export, delete), **Editor** (name, type, mode, enabled, note; paste text or upload a
  file; the size is checked against `upload_max_filesize` / `post_max_size` and a bigger file is to be copied to `lists/` over SFTP),
  **Entries** (the entries of one list, filter by text and family, include or exclude, the first 200), **Lookup tester** (an
  address -> which list holds it, the effective decision in the guard's order, and the matching source entry) and **Compile**
  (the compiled files with build time and range counts, rollback to `.prev`, *Compile now*, *use the worker job*, the last compile
  result and its errors). Accepted text: plain text, one IPv4 / IPv6 address or CIDR per line, `#` comments, blank lines, CRLF, an
  optional CSV first column. **Saving checks every line**: invalid lines are listed by line number and *nothing is saved* until
  the operator ticks "save the valid lines only"; a block entry wider than /8 (IPv4) or /32 (IPv6), and any entry that covers
  private, loopback, link-local space, the server's own address or the operator's own address, is refused (listed with the
  reason) unless "I know what I'm doing" is ticked; `0.0.0.0/0` and `::/0` are refused even then. The **compile applies the same caps**
  to every file, also one copied over SFTP: allow entries wider than /16 (IPv4) or /32 (IPv6), block entries wider than /8 or /32 and block
  entries covering private, loopback, link-local space or the server's own addresses are dropped unless the list is forced, `0/0` always;
  the Compile tab and the Entries tab show what was dropped (per reason, with samples) and the lines that are not an address. Overlapping
  ranges are merged and the addresses counted. Every change is
  audited (`iplist`, before / after) and compiles at once (or queues the job).
  Warnings on the page: an address in both an allow and a block list (the allow list wins; the overlapping ranges are listed),
  an allow entry wider than /16 (/32 for IPv6), an allow entry in the carrier-grade NAT range `100.64.0.0/10` or inside a mobile
  operator AS, a block entry that covers a verified crawler seen in the recent logs, and a list changed but not yet compiled.
- **CAPTCHA** (Settings tab and a rule action) — Settings -> **CAPTCHA**: the GD status ("CAPTCHA unavailable (GD not installed)" when it is missing),
  a **live preview image** drawn with the values typed in the form (*Update preview*; nothing is saved), the level, every individual value, the per-IP budget,
  the proof-of-work switch, the escalation score, CAPTCHA instead of the device 429, and the **weight of each headless signal**, each with a tooltip.
  The CAPTCHA page texts are in the Strings tab. Rules get the action **Image CAPTCHA**; the form warns when GD is missing, and the **impact preview** shows
  how many of the matching requests would get a CAPTCHA (HTML, gated, no CAPTCHA-level token, not exempt, not allowed, not a verified crawler). Sample images:
  ![level 1](img/captcha-level-1.png) ![level 3](img/captcha-level-3.png) ![level 5](img/captcha-level-5.png).
- **Overrides and Identity** — a deny override for an address (or a device seen on an address) inside an *enforced* IP allow list has no
  effect, because the allow list is checked first: the page shows a warning with a link to the list, and so does the flash right after the deny
  is created.
- **Audit** — the append-only trail, searchable (filters: event, user, text; each include or exclude).
- **Jobs** also has a **File permissions** card: group- or world-writable files and directories, cron scripts without the execute bit and secret files readable by everybody, each with the exact commands (cached one hour, **Scan again**, recomputed after an update). The same findings are dashboard alerts.
- **Update** — install a newer version from the GitHub ZIP, review it, apply it with your password, roll it back. See [Update from a ZIP](#update-from-a-zip).

## Dashboard, job health and alerts

The dashboard is ordered by importance. Anything that decides an alert is read **live** (a file stat or a small read, one
cheap Redis command), never from the snapshot, because the snapshot job is one of the things that can die.

1. **Needs attention** (only when something is wrong; critical red, warning amber, each with an Open link): web exposure;
   Redis down; rows logged in degraded mode in the last 15 minutes; new `guard-errors.log` lines; a background job failing,
   late, or "did nothing useful", or a required job that never ran; panel jobs stuck in the queue (older than 5 minutes);
   free disk below `log_min_free_mb`; logs over the cap; no snapshot or a stale one; analyzer and panel time zones differ;
   **PR 1:** `rules.json` invalid, `rules.cache.php` older than `rules.json` (the guard then reads the JSON on every request);
   **PR 2:** a GeoIP database missing or corrupt while a geo rule is enabled (critical), older than 45 days (warning);
   **PR 6:** a CAPTCHA rule, escalation or the CAPTCHA device budget is enabled but GD is not installed (warning, opens Settings);
   **PR 5:** a compiled IP list file missing or corrupt while its list is enabled (critical), the last IP list compile failed or its
   worker job failed (critical), entries dropped by the safety caps (warning; **critical** when an allow list lost an entry wider than /8),
   lists changed more than 10 minutes ago and still not compiled (warning);
   `secret` or `holdout_salt` still the placeholder; Redis not on `maxmemory-policy noeviction` (read with `CONFIG GET`, unknown
   when forbidden); crontab entries missing (critical), disabled, pointing at another install, running too rarely, or
   `GV_PYTHON` missing or invalid (warnings).
2. **Protection state:** the kill switch (prominent), each enforce toggle, enabled rules by mode and action, and a global summary:
   *monitor only* (also when `secret` is the placeholder, which forces it), *partly enforcing*, *enforcing*.
3. **Last 24 hours:** requests, allowed, blocked (403), rate-limited (429), challenged, challenge success rate, rule hits, (plus a CAPTCHA row when there was CAPTCHA activity: shown, solved, failed attempts, expired, solve rate, median solve time; a rate near 100 % with very short times looks like a solving service)
   honeypot hits and degraded rows, each against the 24 hours before (from the snapshot).
4. **Top lists** (each entry opens the Logs page with the matching filter): rules by hits, reasons, addresses, devices and
   User-Agents being acted on, countries (needs *log country*), paths hit by blocked clients.
5. **Details** (collapsible): the job table, data pipeline, log storage, system status, signals, models, coverage and charts.

A **Cron setup** card shows when a required job has never run or the crontab check found a problem: the exact lines to add for
what is missing, built from this install's real directory and starting with the `GV_PYTHON=` line, and the command to open the
editor (`crontab -e`).

**Jobs page.** The crontab check runs `scripts/cron-check.sh` through `proc_open` (argv array, stderr to `/dev/null`, 3 s read limit,
SIGTERM then SIGKILL after 1 s for a child that hangs); the result is cached in `analyzer/.cron-check-live.json` for 5 minutes, so the dashboard
and the Jobs page never start a process per view, and **Check again** (CSRF, audit-logged, once per 30 s for everyone) refreshes it. If the live check cannot run,
the copy the cron wrapper writes is shown. A table per job (state, last success, last failure, next expected run, first line of the last error; the
expected interval is editable in Settings -> Analyzer), the crontab check, the queue (length and age of the oldest job) and the
jobs started from the panel (they now record exit code, duration, warnings and the result of a training run). A job's detail
shows the captured error text (secrets redacted, shown escaped), the last runs from `logs/jobs.log`, and **Mark this error as
seen** (audit-logged: it silences the alert for that failure; a newer failure raises it again). `proc_open` is used in exactly
one place, with an argv array, to run `scripts/cron-check.sh`.

## Layout, tabs, tooltips and filters

* **Width.** The content is up to 1680 px wide (fluid below that); card grids use 1 column on a phone, 2 from
  1024 px and 3 from 1500 px; tables scroll inside their card, never the page.
* **Tabs.** Settings has one tab per group (enforcement ... analyzer, GeoIP). The Rules form has Conditions /
  Action / Advanced, the GeoIP page Databases / Sources and upload / Lookup tester. One form, one Save button:
  a rejected save opens the tab that holds the first error and puts an error count on every tab with errors.
  The active tab is kept in the URL hash (`#set-limits`, `#rule-action`). Without JavaScript every section is
  shown, stacked. Keyboard: arrow keys, Home and End (`role="tablist"`).
* **Tooltips.** A `?` next to every setting, rule field, GeoIP field and filter. The text (lang.php key
  `tip_<name>`) says what the field does, a safe value, and the risk of a wrong one. It opens on hover, on keyboard
  focus and on tap; Esc or a tap elsewhere closes it; it is moved back inside the screen at an edge
  (`aria-describedby`, `role="tooltip"`). panel-selftest fails if a field has no text.
* **Include / exclude filters.** Every list with filters (Logs, Rules, Overrides, Identity, Audit, GeoIP sources)
  has an operator next to each field: choice fields (action, token, status, reason, country, ASN, ...) are
  **is / is not** and take several values separated by commas (OR inside a field); text fields (path, User-Agent,
  search) are **contains / does not contain**; identity fields (address, device) are **is / is not** and an
  address also accepts a CIDR (IPv4 or IPv6); score ranges keep no operator. Fields are AND-ed. The query string
  keeps the field names and adds `<key>_op=not` (absent = include), so older links keep working, and paging, the
  CSV export and *Share link* keep the operators. Active filters show as removable chips above the table, an
  exclude one marked "is not" / "does not contain". An exclude filter can scan more lines before it finds rows; the
  existing "scan limit reached" notice appears when a cap is hit.
* **Empty values: unknown versus known.** What an empty value *means* decides how a filter treats it.
  * **Unknown** (the information does not exist): country and ASN (no lookup ran, or none found; ASN 0), the outcome
    status (`capture_outcomes` off or no outcome line), the bot verdict (`botv`, no bot claim). Like the rule engine's
    unknown country, a row **without** the value matches **neither "is" nor "is not"**: "country is not IR" lists
    only rows whose country is known and is not IR, so counts are not inflated by rows that were never looked up.
  * **Known empty** (the empty value is a fact): reasons (a row with no reasons has none), the device id (no device =
    a token-less client), the operator override (none was set), and, on the Rules table, a rule with no country /
    ASN condition. These are plain include / exclude and an empty value equals no real value, so "reason is not
    UA_EMPTY", "device is not X" and "override is not deny" **include** those rows.
  * **`(none)`** (offered in the datalist, explained in the tooltip, valid on all of these fields) means "empty":
    **is (none)** lists those rows, **is not (none)** lists the rows that have a value, and it can be mixed into the
    comma list (`cc=IR,(none)` = Iran or unknown; `reason=(none),UA_SCRIPT` = no reason or UA_SCRIPT).
  * Fields every row always has (action, address, path, User-Agent, token, shadow, holdout) are plain include /
    exclude and need no `(none)`.
  `(none)` survives paging, the CSV export link and *Share link*.

## Update from a ZIP

Admin page **Update** (`?r=update`). It applies the GitHub ZIP of this repository (Code, Download ZIP, or a release ZIP) and
can undo it. The installed version is the `VERSION` file at the repository root (shown in the footer of every page and on this
page); `CHANGELOG.md` lists what changed, newest first.

| Step | What happens | Changes the install? |
|---|---|---|
| Upload (POST, CSRF) | The ZIP is read, every entry validated, every PHP file parse-checked (`token_get_all` with `TOKEN_PARSE`), the plan computed. Audit: `update_upload` or `update_refused`. | No (staged in `updates/pending/`, discarded after an hour) |
| Review | From and to version, added / changed / removed / protected files, the changelog between the two versions, warnings (downgrade, same version, `.git`, `requirements.txt`, cron scripts, first ZIP update). | No |
| Apply (POST, CSRF, **password again**) | Manifest + backups, recovery scripts, `guard.off`, atomic file swap, OPcache invalidation, then the health check in a fresh request. Audit: `update_apply`, `update_verified` or `update_failed`. | Yes |
| Roll back (POST, CSRF, browser confirm) | Restores the backup of that update and of every newer one. Audit: `update_rollback`. | Yes |

A wrong password counts as a failed login (the same limiter) and writes `reauth_failed`. A downgrade, the same version and a `.git`
directory each need an explicit tick before **Apply**.

**Never overwritten, never deleted.** The list lives in one file, `panel/update-protected.txt` (the updater reads it; the copy
inside the ZIP is read too and a file protected by either is skipped). On top of it, every pattern of the installed and the shipped
`.gitignore` protects a file. `.htaccess` and `.gitkeep` files inside the data directories stay updatable.

```
guard/config.php
guard/config.local.json*
guard/config-backups/
guard/rules.json*
guard/rules.cache.php*
panel/panel.config.php
panel/users.json*
panel/audit.jsonl
panel/jobs-seen.json*
panel/.ratelimit/
panel/*.log
guard.off
lists/*
geo/*
logs/*
analyzer/model.joblib*
analyzer/clf.joblib*
analyzer/*.candidate
analyzer/*.csv
analyzer/snapshot.json*
analyzer/ground-truth.txt
analyzer/reports/
analyzer/.jobstatus-*
analyzer/.jobstate-*
analyzer/.cron-check*
analyzer/.perm-check*
analyzer/.lastrun-*
analyzer/.laststats-*
analyzer/.rule-hits.json
analyzer/.venv/
analyzer/venv/
.venv/
venv/
__pycache__/
*.pyc
.git/
updates/
```

**Limits.** ZIP up to 30 MB (and what PHP allows: the smaller of `upload_max_filesize` and `post_max_size`, shown on the page), at most
3000 files, 10 MB per file, 100 MB unpacked. Allowed top-level folders: `guard`, `panel`, `analyzer`, `scripts`, `docs`, `geo`, `lists`,
`logs`, `updates`; allowed types: `php py sh md txt json css js woff2 ttf png tpl` and the names `.htaccess .gitkeep .gitignore VERSION LICENSE`.
Refused: `..`, absolute paths, backslashes, drive letters, symbolic links, encrypted or ZIP64 entries, duplicate paths, `.git/`.

**The health check.** `updates/verify.php` (written from the *old* code before the files change) loads the new guard and panel in a fresh
request and runs one synthetic request in dry-run mode (no log row). Failure, including a fatal error that kills the request, rolls the
update back automatically; the result page says so. If the browser closes before the check finishes, the page shows a red banner with
**Run the check now** and the dashboard raises a critical alert (the guard may still be off).

**Recovery when the panel is broken.** After a good check the result page shows a **recovery token once**: valid 24 hours, single use,
stored only as a hash in `updates/recovery.json`. Web: `<panel-address>/recover.php?token=<token>` (an empty 404 without a valid token).
Shell: `php <install-dir>/updates/rollback.php` (`--list` shows the updates, a stamp rolls back that update and all newer ones).
Both use the same script, `updates/rollback.php`, written from the old code before the update, with no dependency on the new code.

**File modes.** The updater never relies on the modes in the ZIP: directories it creates are 0755, files 0644, `scripts/*.sh` 0755, nothing is group- or world-writable (the manifest counts the corrections). Files that did not change are corrected as well; the code directories lose group / world write; `logs/`, `lists/`, `geo/` and `updates/` keep their mode. Protected files are never touched. The result page runs the permission check (below).

**After the update.** When `analyzer/requirements.txt` changed the panel queues the worker job `pip_sync`
(`<python> -m pip install -r analyzer/requirements.txt`, 10 minute limit, output in the job log; a failure raises a dashboard warning).
The page prints the exact SSH command as well. The crontab check runs and any missing line is listed.

**Web access.** `updates/` is denied like `guard/` (`updates/.htaccess`, listed in `scripts/exposure-check.sh`); the only web path into it is
`panel/recover.php`, which needs a token. See [13-PANEL-WEB-ACCESS.md](13-PANEL-WEB-ACCESS.md).

## Testing

```bash
php scripts/panel-selftest.php     # exit 0 on success
```

It covers overlay precedence and the never-fatal rules, that `secret` and
`holdout_salt` are unreachable through the overlay, every whitelist bound, the
atomic write and audit append, the bounded tail reader, session signing and
expiry and tampering, CSRF, the login rate limit with Redis up *and* down, stored
XSS (asserted by parsing the rendered HTML with `DOMDocument` and counting what a
browser would actually execute, not by matching a regex), and a token-level scan
proving no shell function, backtick or `eval` exists under `panel/`.

## Themes

The sidebar and login page have a Light / Dark / Automatic switcher. The choice is kept in the browser (`localStorage`, key `gp_theme`) and applied before first paint, so there is no flash. Automatic follows the system setting. All colours are CSS variables defined once in `panel/assets/app.src.css`; the self-test checks the contrast of every text/background pair in both themes (4.5:1 for text, 3:1 for control borders). The switcher needs JavaScript; without it the panel follows the system setting.

## Why the panel is still exposed by symlink

Replacing the symlink with an `.htaccess` rewrite was tested on Apache 2.4 with mod_php. A per-directory `RewriteRule` cannot target a path outside the document root: Apache prepends the docroot, so the panel answers 404. `Alias` would work but needs the server or vhost config, which shared hosting does not give you. A small PHP stub in the docroot that `require`s the real panel would work, but it adds a second entry point that must repeat every guard (allowlist, headers, direct-access rules). Not worth the extra attack surface, so the symlink stays. OpenLiteSpeed was not tested.
