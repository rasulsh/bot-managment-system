# Changelog

Newest first. Each entry is one version, written as `## <version>` (the same string as the `VERSION` file).
The Update page of the panel shows the entries between the installed version and the one in the ZIP.
Older history and upgrade steps: [docs/10-UPGRADE-NOTES.md](docs/10-UPGRADE-NOTES.md).

## 2026.11.36

- **Dashboard v2** (`?r=dashboard`): rebuilt on one 12-column grid with equal-height cards and three explicit layouts (desktop 1440-1680, tablet, 390 px phone; spans per card in [docs/15-DASHBOARD.md](docs/15-DASHBOARD.md)). Top to bottom: a **status strip** (protection mode, kill switch with its button, open alerts by level, job health, snapshot age, version) with the alert list collapsible below; **six equal KPI tiles** (requests, allowed, challenged with solve rate, blocked, rate-limited, **would act if enforced** = monitor-only hits), each with its change against the previous 24 h and a 24 h sparkline, each linking to **Logs** with the matching filter; **requests per hour** (24 h, toggle 7 d) stacked by outcome with a line for distinct addresses; **rollout readiness** (every enabled rule and IP list in monitor mode: hits 24 h / 7 d, addresses, devices, share of hits with a valid token, and a "ready to enforce?" hint); the **challenge and CAPTCHA funnel** (served, solved, passed, failed, median solve time, per level); **top lists in tabs** (IPs, devices, User-Agents, paths, countries, ASNs with requests, share, an outcome mix bar and a quick action); a compact **System** section (jobs, Redis and guard, storage, models with the classifier label progress, GeoIP and feeds, permissions) and a collapsed **More**.
- Charts are server-rendered inline SVG (no library, no JavaScript needed to read them) with axis labels, units, a legend only where there is more than one series, and the outcome colours of Logs / Live in light and dark. Empty states say what is missing and how to fix it.
- **Snapshot additions** (`dash` block, computed by `analyzer/snapshot.py`, not by the page): 24 and 168 hourly buckets by outcome with distinct addresses, per-rule and per-list readiness numbers, the funnel by level, top lists with the outcome mix; `kpi.cur.would_act`. The snapshot job now reads 9 days of logs instead of 3. A snapshot from the previous version still renders (the report cards say the next snapshot run adds them).
- The Demo role keeps only aggregate tiles and the main chart (hourly counts), no identities. Quick actions can now return to the dashboard.

## 2026.11.35

- **Fix: old CSS after an update.** Every asset URL the panel emits is versioned: `assets/app.css?v=<VERSION>-<8 hex of the file's contents>` through ONE helper (`gp_asset_url()`, computed once per request); the fonts moved from `app.css` into `views/layout.php` so their URLs are versioned too. `panel/assets/.htaccess` caches a versioned asset for a year on Apache (`public, max-age=31536000, immutable`) and makes an unversioned request revalidate; OpenLiteSpeed keeps its own static-file expiry (7 days by default, it ignores `.htaccess` there); nginx equivalent in README §2.6. HTML stays `no-store`, and every panel response now also sends `X-LiteSpeed-Cache-Control: no-cache` so LSCache cannot keep a panel page. The guard's challenge and CAPTCHA pages are self-contained (no static asset). panel-selftest fails on any unversioned asset reference; the webservers job checks the headers on Apache and OpenLiteSpeed.
- One Ctrl+Shift+R is still needed once, in a browser that cached the OLD `app.css`, after this update.

## 2026.11.34

- **Live requests page** (`?r=live`, Monitoring operators and administrators): the current daily log read as a tail from a byte-offset cursor (`panel/live.php`), polled as JSON (`?r=live&poll=1`, a GET, never cached, no Redis, no writes). A line still being written waits for its newline, the cursor crosses midnight and skips days without traffic, caps per poll are 500 rows and 1 MiB, **Live** (last 1 / 5 / 15 / 60 minutes, then follow) or a **fixed start / end** window (binary search on the time stamps); refresh 2 / 5 / 10 / 30 s or paused, paused while the pointer is over the table and stopped while the tab is hidden; 200 / 500 / 1000 rows kept.
- All Logs filters with include / exclude plus quick toggles (blocked, challenged, CAPTCHA, rate limited, monitor-only would-act, allowed, verified crawlers); rows coloured by outcome with full reason names (PR F); a strip with requests per second, counts per outcome, distinct addresses and devices and an inline-SVG per-second chart; **Top right now** (press to filter); a details drawer (all fields, the rule or list that matched, the identity history, the quick actions of *Temporary blocks & allows* for the address and the device); **Watch** an address or device; CSV export of the rows on screen. Client-written text is only ever put on the page as text.

## 2026.11.33

- **Behaviour change: overrides always act.** A deny override no longer waits for `enforce.block`: allow, deny, challenge and CAPTCHA overrides act immediately, also in monitor mode and for a client in the holdout, like a rule in enforce mode. Only the kill switch (`guard.off`) stops them. A deny override now logs `OVR_DENY`. The Temporary blocks & allows page says "Overrides act immediately, also in monitor mode." Existing deny overrides that never acted will start blocking at once (docs/10).
- **IP list expiry within a minute.** The compile stores the earliest future `# expires=` time as `next_expiry` in `lists/lists-status.json`; the every-minute `worker` recompiles when it has passed (one small file read when nothing is pending). The nightly check stays as a safety net.

## 2026.11.32

- **Temporary blocks & allows.** The Overrides page is renamed (route unchanged) with an intro, presets 5 min / 15 min / 30 min / 1 h / 6 h / 24 h / 7 d / 30 d plus a custom number of minutes (max 30 days), the time left and the exact expiry per entry, and extend / shorten / remove.
- **New override kind: Challenge / CAPTCHA** (`gv:chal:<ip|device>`, `1` / `c`): the client is shown the check page / the image CAPTCHA until it holds a token (a CAPTCHA-level one for CAPTCHA). Precedence allow > deny > CAPTCHA > challenge; a rule that blocks still blocks, a CAPTCHA wins over a rule's plain challenge, a verified crawler keeps its pass, an enforced allow list is checked first. Read in the existing Redis pipeline (no extra round trip); logged as `OVR_CHALLENGE` / `OVR_CAPTCHA` with `ovr` = `challenge` / `captcha`; replay skips such rows. `ctl.py challenge|captcha`.
- Warning on the form and in the result for a carrier-grade NAT (`100.64.0.0/10`) or known mobile-network address.
- **Quick actions** (Block 15 min, Challenge 1 h, CAPTCHA 1 h, Allow 1 h, Custom...) on every log row and the Identity page, for the address and the device; admin only, CSRF, audited, they return to the page.
- **IP lists:** optional per-entry expiry `203.0.113.7  # expires=2026-11-30` (or `T14:30`); expired entries are ignored by the compile (panel and Python) and their lines removed; the nightly job recompiles when one has expired; a malformed `expires=` refuses the line.

## 2026.11.31

- **Reason codes in words.** New registry `panel/reasons.php` (data only): every reason code the guard, analyzer and panel emit has a full name, a one-sentence explanation, a category and a colour; `SH_` is rendered as a "monitor only" marker. Logs, Identity and the dashboard show badges with the full name, the code in small monospace and the explanation as a tooltip; a rule or list id is resolved to its name and links to it. The log rows keep their short codes (nothing is renamed).
- The Logs Reason / Action / Token / Crawler / Monitor / Holdout filters list full names (value = code); the log detail spells out `act`, `tok`, `ovr`, `botv`, `sh`, `hold`, `cap`; the CSV export keeps its columns and adds `rs_names`.
- `docs/14-REASON-CODES.md` is generated by `scripts/gen-reason-docs.php` (CI checks it is up to date); `panel-selftest` scans the guard, analyzer and panel source for emitted codes and fails on one missing from the registry.
- **GeoIP page:** a file over `geo.upload_max_mb` (new setting, default 32) is refused in the browser with the "copy it over SFTP" hint, instead of the web server's own 413 page; the page names the web server limit (LiteSpeed Max Request Body Size) and says the City database is not needed. After an upload: "press Compile now", and a banner (also a dashboard warning) while a source file is not compiled.
- UI: the source table keeps a readable File column at 390 px; tooltips are positioned against the viewport and never clipped by a scrolling container; the filter operator and value box share one height and the pick button sits inside the box.

## 2026.11.30

- **File modes.** Cron's umask 002 made `model.joblib`, the job status / state / marker files and the lock holder group-writable. Every wrapper now sets `umask 022`, Python writers create files 0644 explicitly (`analyzer/fsmode.py`), and each job corrects the files it owns on its next run. Logs keep their own modes.
- **File permissions scan** covers the same set every time (all files except `.venv`, `.git`, `logs/`, dotfiles and analyzer data included), reports an unreadable directory or a truncated scan as incomplete (own alert) instead of "No permission problems found", and a 0664 file under `analyzer/` is always reported.
- **Nightly:** a classifier skipped for lack of labels is an informational note (`GV_JOB_INFO`, shown as Notes), not "did nothing useful", when the rest of nightly did its work. The Models page and the dashboard details show the label progress (`0 / 50 positives`, honeypot hits / refuted crawler claims / operator ground truth) with a link to the new docs section "Classifier labels: how each source is set up".

## 2026.11.29

- **Fix: `nightly` never ran.** It started in the same second as the every-minute `worker`, both used `analyzer/.write.lock`, and `nightly` (`flock -n`) lost almost every night. `nightly`, `train` and `train-clf` now **wait** for the lock (`flock -w`, `GV_LOCK_WAIT` seconds, default 900); a run that still cannot get it is recorded as "skipped (lock busy after N s)" with the holder named.
- The worker takes the write lock itself, only around a job that writes models or verdicts and only while it runs (`GV_WORKER_LOCK_WAIT`, default 45 s; the job goes back on the queue when the lock stays busy). An empty queue or a read-only job takes none.
- Job health: a required job whose only runs were lock skips is **skipped by lock**, not "never ran (check the crontab)"; the alert says so and names the other job holding the lock. `cron-check.sh` accepts `sleep N;` prefixes and `PATH=` / `SHELL=` / `MAILTO=` lines (tests added).
- **Running a job by hand from SSH works:** the wrapper picks the Python as `GV_PYTHON` from the environment, else `GV_PYTHON` read from the user's crontab (same parser as `cron-check.sh`), else `<install-dir>/.venv/bin/python`, else `python3`, and records it as `"python": "... (source: crontab)"` in the job status; a non-CLI `php` falls back to `/usr/local/bin/php`. README troubleshooting row added.
- UI: the dashboard *Cron setup* card no longer renders an empty code box; *File permissions* and the IP feeds table no longer show "20,780 days ago" for a zero or double-subtracted timestamp.

## 2026.11.28

- **IP range feeds** (IP lists -> Feeds tab): a provider's IPv4 ranges fetched from an HTTPS URL into ONE destination, either a managed allow list or the trusted CDN ranges (`cdn_ranges_feed`, merged with the manual `cdn_ranges`). Presets: Google common crawlers and UptimeRobot -> allow list, ArvanCloud and Cloudflare -> CDN ranges, with strong warnings against putting a CDN in an allow list.
- Plain text, Google JSON and any JSON are auto-detected; IPv6 and `0.0.0.0/0` are dropped. HTTPS only, 3 redirects, 5 MB, timeouts, SSRF guard (every resolved address must be public). A failed fetch keeps the last good entries (dashboard warning after 2 failures), an update removing more than half of them is held for confirmation, entries wider than /16 in an allow list are held by the compile cap until accepted for that feed.
- New cron mode `analyzer-cron.sh feeds` (PHP only, own job status, `cron-check.sh` recommends it only when an enabled feed has a schedule), `scripts/feeds-sync.php`, setting `analyzer.interval_feeds`.

## 2026.11.27

- **Login lockout resistance, completed:** a known device (valid `gp_kd` cookie for the submitted user name) is now also exempt from the **panel-wide** sign-in limit, so 20 wrong passwords from a few addresses can no longer lock every administrator out of their own browser. The per-IP limit still applies to it, and its own failures still count against its address and the panel-wide counter.
- The Users page shows the current panel-wide, per-user-name and per-address lockouts next to the unlock form; the dashboard raises a warning while the panel-wide limit is reached.

## 2026.11.26

- **Messages in context:** the result of every panel action (save settings, Check again, rule / list save, override, kill switch, users, update ...) is drawn in its own section next to the button, the redirect ends in `#msg-<section>`, and the page scrolls to it and focuses it; a message with no section on the page falls back to the top. The kill switch reports what it did.
- **IP lists:** Allow = blue (`gp-btn-info`), Block = red, in buttons and badges on every page including the Logs reasons `IPL_ALLOW` / `IPL_BLOCK`, the dashboard and the tester; AA contrast checked in both themes.
- **Pick list instead of `<datalist>`** on every choice filter (checkboxes, free text, keyboard, Esc, touch, themes; plain text box without JavaScript).
- **Logs:** new filters *Method* and *IP list at request time* / *IP list name*, with include / exclude, chips, paging, CSV and share link.
- **Jobs / dashboard:** the web server's PHP card (OPcache, GD, ZipArchive) and a warning for `opcache.validate_timestamps = 0`.
- **Login lockout resistance:** a known-device cookie (HMAC, bound to the user and `session_version`, 90 days) exempts the per-username limit only; *Clear a login lockout* on the Users page and `panel/setpass.php --unlock-user|--unlock-ip|--unlock-all` (audited).
- **Cron PHP binary:** `php -q`, CGI header stripping, binary order `php_bin` -> `GV_PHP` -> `php`, SAPI warnings, a `php` check in `cron-check.sh`, a `PATH=` line in every crontab template, and a clear "Redis settings not confirmed (PHP bridge failed)" message.

## 2026.11.25

- **Hotfix: the update health check was blocked by `panel/.htaccess`.** `recover.php` was allowed by the `FilesMatch` block but not by the `RewriteRule` allow-list, so mod_rewrite answered the web server's 403, the update stayed "Waiting for the check" and the guard stayed off. Fixed; an install that is stuck can be repaired with one `sed` line (docs/10-UPGRADE-NOTES.md).
- The check no longer depends on one web path: **Run the check now** runs it inside the panel request; `php updates/verify.php <stamp>` from the shell. An update waiting more than 2 minutes raises a critical alert (the guard is OFF, with the command).
- `exposure-check.sh` requires `recover.php` to answer the application's own bare 404. New `scripts/update-web-e2e.sh` runs the full update flow on real Apache and OpenLiteSpeed in CI.

## 2026.11.24

- **Several panel users, three roles:** Administrator, Monitoring operator (every report except secrets and user management; changes nothing) and Demo (aggregate numbers only). New pages **Users** and **My account**; the updater is administrator only.
- One deny-by-default permission map checked on the server for every GET and POST (HTTP 403 and an audit line on denial). The Demo page is built from a separate, data-minimised view model.
- `panel/users.json` (migrated automatically from `panel/panel.config.php`, nobody changes a password). Disabling a user, a role change and a password reset end their sessions at once. Per-username login limit. `panel/setpass.php` recovers admin access.

## 2026.11.23

- **Updater sets file modes explicitly:** directories 0755, files 0644, every `scripts/*.sh` 0755, nothing group- or world-writable (GitHub ZIPs carry no reliable modes). Unchanged files are corrected too, so the first update repairs an install that was copied with 666 modes. The updater's own workspace is private (0600 / 0644).
- **The crontab goes through bash everywhere** (`bash /path/scripts/analyzer-cron.sh verify`): README, docs, the dashboard "Cron setup" card, `cron-check.sh` output. `cron-check.sh` accepts both forms and reports a direct entry whose script is not executable as an ERROR ("not executable — cron will fail silently", with the fix) and exits 1.
- **File permission health check** (dashboard alerts and a card on the Jobs page): group/world-writable files and directories, cron scripts without the execute bit, secret files readable by everybody, with the exact `chmod` / `find` commands. Cached for one hour, recomputed after an update.

## 2026.11.22

- New admin page **Update**: upload the GitHub ZIP of the repository, review what changes, apply it with your password,
  roll back with one click or from the shell. Protected install files (configuration, rules, lists, logs, models) are never touched.
- `VERSION` file and this changelog; the version is shown in the panel footer.
- New worker job `pip_sync` (installs `analyzer/requirements.txt` after an update that changed it).
- `panel/recover.php` and `updates/` (recovery and health-check scripts the updater writes).
