# Changelog

Newest first. Each entry is one version, written as `## <version>` (the same string as the `VERSION` file).
The Update page of the panel shows the entries between the installed version and the one in the ZIP.
Older history and upgrade steps: [docs/10-UPGRADE-NOTES.md](docs/10-UPGRADE-NOTES.md).

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
