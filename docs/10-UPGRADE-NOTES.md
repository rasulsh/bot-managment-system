# Upgrade notes

What changed in each release and what to do about it. Newest first.

## Live requests (2026.11.34)

* **New page: Live requests** (side menu, for Monitoring operators and administrators; the Demo role cannot open it). It tails the current daily log from a byte-offset cursor and polls every 2 / 5 / 10 / 30 seconds (paused while the pointer is over the table or the tab is hidden): it reads only new bytes, uses no Redis and writes nothing. The same filters as Logs, quick toggles, a fixed start / end window, a per-second chart, Top right now, a details drawer with the quick actions of *Temporary blocks & allows* (administrators), Watch and CSV export. Needs `logs/` readable by the panel, like the Logs page.
* **Limits.** At most 500 rows and 1 MiB per poll (the page asks again at once while more is waiting); a window is at most two days; the response-status filter only sees outcomes that arrive in the same poll; a day's file that has been compressed by log rotation is not read (only uncompressed `guard-YYYYMMDD.jsonl`).
* Nothing to do on upgrade. `app.css` is rebuilt.

**Rollback.** Update page *Roll back* or `php updates/rollback.php`; nothing else reads or depends on the page.

## Overrides always act; list expiry within a minute (2026.11.33)

* **Behaviour change.** An operator **deny** override used to follow `enforce.block`: on an install in monitor mode it was only logged. Now every override is an explicit operator action and acts **immediately, also in monitor mode and for a client in the holdout** (like a rule in enforce mode): deny answers 403, challenge shows the check page, CAPTCHA the image test. Only the kill switch (`guard.off`) stops them. **Check the Temporary blocks & allows page after upgrading: a deny override that was set earlier and never acted will start blocking at once.** The log reason is `OVR_DENY` (no `SH_` form); the page says "Overrides act immediately, also in monitor mode."
* **IP list expiry without waiting for the nightly job.** The compile stores the earliest future `# expires=` time as `next_expiry` in `lists/lists-status.json`; the `worker` job (every minute) reads that file (one small read, nothing else when no expiry is pending) and recompiles when the time has passed, so an expired entry stops matching within about a minute. Needs the `worker` cron entry (already required). A list edited by hand over SFTP is picked up at the next compile (any panel save, the nightly job).

**Rollback.** Update page *Roll back* or `php updates/rollback.php`; an older guard gates a deny override on `enforce.block` again, and `next_expiry` is ignored.

## Temporary blocks & allows (2026.11.32)

* **New:** the Overrides page is now **Temporary blocks & allows** (route unchanged): presets from 5 minutes, a custom number of minutes, the time left and the exact expiry, extend / shorten / remove, and a new kind **Challenge** / **CAPTCHA** (`gv:chal:<id>`, value `1` / `c`). Precedence allow > deny > CAPTCHA > challenge; it needs no enforce switch. The guard reads the two new keys in its existing Redis pipeline (no round trip added). An older guard ignores the `gv:chal:` keys, so a rollback only loses the challenges.
* **Quick actions** on every log row and the Identity page; a warning for carrier-grade NAT and known mobile-network addresses.
* **IP lists:** `# expires=2026-11-30` after an entry; the compile ignores and removes expired entries, and the worker recompiles within about a minute (nightly is the safety net). Lines with a malformed `expires=` are refused (they show as invalid lines).
* `ctl.py challenge` / `captcha`; log rows decided by such an override carry `ovr` = `challenge` / `captcha` and are skipped by replay.
* Nothing to do on upgrade.

**Rollback.** Update page *Roll back* or `php updates/rollback.php`; entries with `# expires=` are then plain comments (the entry never expires), so remove those lines first if that matters.

## Readable reason codes, GeoIP page fixes (2026.11.31)

* **Reason codes in words.** The log rows are unchanged (short codes stay: `SH_RULE:<id>`, `IPL_BLOCK:<id>`, `UA_SCRIPT`, ...). The panel now shows the full name, the code, a tooltip
  and a "monitor only" marker for `SH_` codes on Logs, Identity and the dashboard; the Logs Reason, Action, Token, Crawler, Monitor and Holdout pick lists show names. The CSV export gains a
  last column `rs_names`; the existing columns are unchanged. [14-REASON-CODES.md](14-REASON-CODES.md) is generated from `panel/reasons.php`.
* **GeoIP.** New setting `geo.upload_max_mb` (default 32): the page refuses a larger file in the browser instead of reaching the web server's own 413 page. After an upload the page says "press Compile now"
  and warns (also on the dashboard) while a source file is not compiled. The source table no longer squeezes the File column; tooltips are never clipped by a scrolling table; the filter operator and
  value box share one height with the pick button inside the box. `app.css` is rebuilt. Nothing to do on upgrade.

**Rollback.** Update page *Roll back* or `php updates/rollback.php`; an older panel ignores `geo.upload_max_mb` in `config.local.json` (the overlay is validated per key, an unknown key is dropped on the next save).

## File modes of job output, permission scan, classifier labels (2026.11.30)

* **Modes.** On a host whose cron runs with umask 002 the analyzer's files (`analyzer/model.joblib`, `.jobstatus-*.json`, `.jobstate-*`, `.lastrun-*`, `.write.lock.holder`) were group-writable. All wrappers now use
  `umask 022`, Python creates files 0644 explicitly, and every job corrects the files it owns on its next run. Nothing to do; the File permissions check goes quiet after the next nightly / worker run.
* **File permissions scan.** It scans the same set every time (everything except `.venv`, `.git`, `logs/`; dotfiles and analyzer data files included), no longer skips a directory named `venv`, and an unreadable
  directory or a truncated scan is reported as an incomplete scan instead of "No permission problems found".
* **Nightly "did nothing useful".** A classifier that only waits for labels is now an informational note, with the progress (`0 / 50 positives`, per source) on the Models page and the dashboard details.
  How to produce labels: [08-ANALYZER-PHASES.md, Classifier labels](08-ANALYZER-PHASES.md#classifier-labels-how-each-source-is-set-up). Job status files gain a `notes` array.

**Rollback.** Update page *Roll back* or `php updates/rollback.php`; older code ignores the `notes` field and the `clf_labels` entry of the snapshot.

## Job lock waits: nightly never ran (2026.11.29)

**Symptom.** `nightly` (and `train` / `train-clf`) never ran: at 04:17 cron starts `nightly` and `worker` in the same second, both used `analyzer/.write.lock`, the worker won and `nightly`
(which used `flock -n`) was skipped ("another nightly run holds the lock"). With the worker on `* * * * *` that happened almost every night. The dashboard said "never ran (check the crontab)".

**Fix.** `nightly`, `train` and `train-clf` wait for the lock (`flock -w`, `GV_LOCK_WAIT` seconds, default 900); the worker takes the lock itself only while it runs a job that writes models or
verdicts (an empty queue or a read-only job takes none) and puts the job back on the queue if the lock stays busy for 45 s. A run that still cannot get the lock is recorded as *skipped (lock busy
after N s)* and shown as **skipped by lock**, with the holder named. **What to do:** update; if you added a `sleep N;` in front of your entries as a workaround you may remove it (the check accepts both).
To keep the old behaviour for one mode put `GV_LOCK_WAIT=0` in front of it. Also fixed: the dashboard *Cron setup* card no longer shows an empty code box, *File permissions* no longer says
"20,780 days ago", and the IP feeds table showed the same wrong age for its last run.

**Also in this release: running a job by hand.** `bash scripts/analyzer-cron.sh nightly` from an SSH shell used to fall back to the bare `python3` (no packages) and record a failed preflight. The Python is now
`GV_PYTHON` from the environment, else `GV_PYTHON` read from your crontab, else `<install-dir>/.venv/bin/python`, else `python3`; the choice is recorded as `"python": "... (source: ...)"` in the status file. A non-CLI `php` falls back to `/usr/local/bin/php`.

**Rollback.** Update page *Roll back* or `php updates/rollback.php`. The status files gain `lock_holder` and a longer `python` text that older code ignores.

## IP range feeds (2026.11.28)

**New.** IP lists -> **Feeds**: provider IPv4 ranges (Google common crawlers, UptimeRobot, ArvanCloud, Cloudflare presets or your own URL) kept up to date into a managed allow list
or into the trusted CDN ranges. New cron mode `analyzer-cron.sh feeds` (recommended only when an enabled feed has a daily / weekly schedule; add
`27 3 * * * bash <install-dir>/scripts/analyzer-cron.sh feeds >/dev/null 2>&1`). New overlay key `cdn_ranges_feed`, new setting `analyzer.interval_feeds`, new files
`lists/feeds.json`, `lists/feed-<id>.txt`, `panel/feeds.php`, `scripts/feeds-sync.php`, `scripts/feeds-cron.sh`.

**Nothing to do on upgrade**: with no feed configured nothing changes. **Read the CDN warning before adding a CDN feed**: ArvanCloud and Cloudflare ranges belong in *Trusted CDN
ranges*, never in an allow list, and only if the site is behind that CDN.

**Rollback.** Update page *Roll back* or `php updates/rollback.php`. The older code ignores `lists/feeds.json` and `cdn_ranges_feed` (an unknown overlay key is dropped when the old panel next
saves settings, so CDN ranges a feed wrote stop being trusted: re-add them to `cdn_ranges` by hand if the site is behind that CDN). The managed `feed-<id>` lists stay as ordinary allow lists:
delete them if you no longer want them.

## Panel round 3: messages in context, IP list colours, pick lists, Logs filters, lockout resistance, cron PHP (2026.11.26)

**Nothing to do for a normal upgrade** (no configuration change; the Update page is enough). What is new:

* **Results appear where the button is.** Saving settings, *Check again*, saving a rule or a list, an override and the kill switch show their message in the same
  section and bring it into view. The kill switch now says what it did. Old links keep working.
* **IP lists:** *Allow* is blue, *Block* is red everywhere (buttons, badges, Logs reasons, dashboard, tester).
* **Pick lists** replace the browser datalist on every choice filter (checkboxes, free text still allowed, no-JavaScript fallback is the plain text box).
* **Logs:** new filters *Method* and *IP list at request time* / *IP list name* (from the `IPL_ALLOW` / `IPL_BLOCK` reasons).
* **Jobs page:** *The web server's PHP* card; a dashboard warning when `opcache.validate_timestamps = 0`.
* **A person who knows the password can no longer be locked out of their own browser** by someone hammering their username (known-device cookie `gp_kd`,
  90 days; exempt from the per-username and the panel-wide limit, the per-IP limit still applies). The Users page lists the current lockouts and the dashboard warns while the panel-wide limit is reached. *Clear a login lockout*: Users page (admin) or `php panel/setpass.php --unlock-user|--unlock-ip|--unlock-all`.
* **Cron and the PHP binary (fixes "verify: Redis unavailable" on cPanel):** the analyzer runs `php -q`, strips CGI headers, picks the binary from `php_bin`, then
  `GV_PHP`, then `php`, and warns when it is not the command-line build. **Add `PATH=/usr/local/bin:/usr/bin:/bin` as the first line of your crontab** (the
  dashboard Cron setup card and `cron-check.sh` print it) or set `GV_PHP=/usr/local/bin/php`. The wording distinguishes "Redis settings not confirmed (the PHP
  bridge failed)" from "Redis unavailable".

**Rollback.** Use the Update page (*Roll back*) or `php updates/rollback.php`. Nothing in this release writes a new data format; a `gp_kd` cookie is ignored by the
older code, `login_unlock` audit lines are shown as an unknown event by it.

## Hotfix: the update health check was blocked by `panel/.htaccess` (stuck "Waiting for the check")

**Symptom.** After a ZIP update on LiteSpeed / Apache the browser lands on the web server's own 403 page for
`/<panel>/recover.php?a=verify&ts=...&k=...`, the update stays **Waiting for the check**, and the guard stays switched off (`guard.off` exists).

**Cause.** `panel/.htaccess` has two independent mechanisms. The `FilesMatch` block allowed `recover.php`, but the second one, the `RewriteRule`
allow-list (`^(|index\.php|assets/...)$ - [L]` followed by `RewriteRule ^ - [F,L]`), did not, so mod_rewrite answered 403. The files were updated correctly;
only the web path of the check was blocked.

**Fixed in this release.**

* `panel/.htaccess` lists `recover.php` in the RewriteRule allow-list too; every other `.htaccess` of the repository is deny-all (checked, no other mismatch), and a
  self-test fails when the two lists differ.
* The check no longer depends on one web path: **Run the check now** on the Update page is a POST to the panel itself that runs the same verify code inside the
  authenticated request (no `recover.php` needed); `php <install-dir>/updates/verify.php <stamp>` works from the shell.
* An update that waits for its check for **more than 2 minutes** raises a **critical** alert on the Update page and the dashboard: it says the guard is OFF (when
  `guard.off` exists) and shows the exact shell command.
* `scripts/exposure-check.sh` now requires `recover.php` **without a token** to answer the application's own bare 404 (text/plain, empty body): a server 403 fails the
  check (it used to pass any non-200). New `scripts/update-web-e2e.sh` runs the whole update flow (upload, apply, check through `recover.php`, token, in-panel check,
  automatic rollback of a broken update, shell check and rollback) against **real Apache and OpenLiteSpeed** in the CI `webservers` job, in every layout (docroot, symlink,
  alias). `update-e2e.sh` (PHP's built-in server) cannot see `.htaccess`, which is why CI missed this.

**An install that is stuck right now** (an update applied, the page says *Waiting for the check*, `guard.off` exists, or the browser showed a 403 for `recover.php`):

1. Fix the rewrite rule on the server, as the user that owns the install (this is the only line that changes):

   ```bash
   sed -i 's#RewriteRule ^(|index\\.php|assets#RewriteRule ^(|index\\.php|recover\\.php|assets#' <install-dir>/panel/.htaccess
   grep -n 'recover' <install-dir>/panel/.htaccess      # both the FilesMatch line and the RewriteRule line must name recover
   ```

   OpenLiteSpeed reads `.htaccess` at start: restart it (`/usr/local/lsws/bin/lswsctrl restart`). LiteSpeed Enterprise and Apache read it on the next request.
2. Finish the check, any one of these: open **Update** and press **Run the check now** (this release; older versions show the same button as a link to
   `recover.php`, which works after step 1), or on the shell `php <install-dir>/updates/verify.php <stamp>` (the stamp is on the Update page, or the newest directory
   name in `<install-dir>/updates/`). The script was written before the update and exists on every stuck install.
3. A good check removes `guard.off` (only if the updater created it) and the update turns green. Verify: `bash scripts/exposure-check.sh <url> <panel-path>` must
   show `recover.php ... 404 ok (the application's own bare 404)`. If the check fails it rolls the update back by itself.
4. If you cannot do any of this: `php <install-dir>/updates/rollback.php` restores the previous version, and `rm <install-dir>/guard.off` switches the guard on
   again (only if it exists and you do not want it off).

**Rollback.** Restore the previous files (the fix is one rewrite rule, the Update page button and a shell-visible alert).

## Users and roles (panel)

**New**

* **Several panel users with three roles**: Administrator, Monitoring operator (every report except secrets and user management; changes nothing) and Demo (aggregate numbers only,
  from a separate server-side view model). New pages **Users** (administrators) and **My account** (everybody); the top bar shows the user and role. The updater is administrator only.
* **One deny-by-default permission map** (`panel/acl.php`) checked in the router for GET and POST before any handler; a denial is HTTP 403 and an `acl_denied` audit line.
* **User store** `panel/users.json` (git-ignored, protected from updates, mode 0600, atomic writes under a lock). Fails closed when damaged.
* Per-username login limit (10 per 15 minutes) next to the per-address and global limits; a disabled user gets the generic failure.
* `panel/setpass.php` is now also the recovery tool: create or reset an administrator and re-enable it, move a damaged store aside, optionally log out every session.
* New files: `panel/users.php`, `panel/acl.php`, `panel/demo.php`, `panel/views/{users,account,demo,forbidden}.php`. Changed: `panel/auth.php`, `panel/index.php`, `panel/setpass.php`,
  `panel/views/layout.php`, `panel/.htaccess` is unchanged. `scripts/exposure-check.sh` also checks `/panel/users.json`; `scripts/secret-values.php` redacts every account's password hash in job logs.

**Migration (automatic).** On the first request after the upgrade `users.json` is created from `panel/panel.config.php`: that single user becomes an enabled administrator with the same
password hash (the name is lowercased; it may be shorter, longer or use other characters than the rule for new names and still signs in). **Nobody has to change a password.** Open
sessions stay valid (session version 0 signs exactly as before). `panel.config.php` keeps the install settings (`ip_allowlist`, `trusted_proxies`, session secret). If the panel
directory is not writable the migrated administrator still works from memory and the Users page says users cannot be changed until `panel/` is writable (or use `setpass.php`).

**Upgrade**

1. Update from the panel (or copy the files). `users.json` appears on the first request. Make sure it is not web-reachable: `bash scripts/exposure-check.sh <url> <panel>`; on nginx add
   `location = /gv-admin/users.json { return 404; }`.
2. Create the other accounts under **Users**. Give colleagues who only watch the **Monitoring operator** role.
3. If nobody can sign in: `php panel/setpass.php` (README, "Recover admin access").

**Rollback.** Restore the previous files. The previous code reads `panel/panel.config.php` only, so the first account signs in with the password **it had before the upgrade** (run
`php panel/setpass.php` with the same username afterwards if you changed it under *My account*); the other accounts do not exist for the old code. `users.json` can stay; a later
upgrade picks it up again.

## File modes, crontab through bash, permission health check

**Why.** On a live server the files had mode 666 and the cron scripts had no execute bit, so every crontab line that called a script directly
failed silently for days, while the crontab check reported the entries as present. A GitHub ZIP carries no reliable Unix modes (and
`ZipArchive` does not apply them), so an update would have recreated the problem.

**Changed**

* **Updater modes:** every file the updater writes gets an explicit mode: directories it creates 0755, files 0644, `scripts/*.sh` 0755, never group- or
  world-writable. Files the ZIP delivers but that did not change are corrected too, and code directories (`guard`, `panel`, `analyzer`, `scripts`,
  `docs`) lose group / world write; data directories (`logs`, `lists`, `geo`, `updates`) keep the mode you gave them. Protected files (`guard/config.php`,
  `panel/panel.config.php`, `guard/config.local.json`, `panel/users.json`) are never touched. A rollback restores the old bytes without group / world write
  and keeps scripts executable. The Update result page shows how many modes were corrected and the permission findings.
* **Crontab through bash.** The recommended lines are now `*/10 * * * * bash <install-dir>/scripts/analyzer-cron.sh verify >/dev/null 2>&1`
  (README, docs/03, the dashboard card, `cron-check.sh`), so they never depend on the execute bit. **Existing direct lines keep working** as long as the
  scripts are executable; change them when convenient. `analyzer-cron.sh` also runs `cron-check.sh` through bash.
* **`cron-check.sh`** accepts both forms. A direct entry whose script exists but is not executable is an ERROR for every job (required or not): "not executable —
  cron will fail silently", with `chmod 755 <script>` or the bash form; exit code 1; state `not_executable` in `--json` and a critical dashboard alert.
* **Permission health check** (new `panel/perms.php`): dashboard alerts and a card on the **Jobs** page for files or directories writable by group or others
  (`.venv`, `.git`, `logs` skipped), cron scripts without the execute bit, and secret files readable by everybody (world-readable; group-readable is not
  flagged because `0640` is normal when the web server runs under another group), each with the exact commands. The scan is cached in `analyzer/.perm-check.json`
  for one hour and recomputed after an update or with **Scan again**. Group-writable files are sometimes intended (PHP under another account): ignore that finding,
  never a readable secret.

**Upgrade**

1. Update from the panel (or copy the files). If the install was copied with 666 modes, the first update from the panel repairs the scripts and files it delivers; or run
   the commands the Jobs page shows now: `chmod 755 <install-dir>/scripts/*.sh`, `chmod 600 <install-dir>/guard/config.php <install-dir>/panel/panel.config.php`.
2. Edit the crontab (`crontab -e`): put `bash ` before each script path. Check with `bash scripts/cron-check.sh`.
3. Nothing to migrate. `analyzer/.perm-check.json` is a cache (gitignored, protected from updates).

**Rollback.** Restore the previous files. Crontab lines with `bash` keep working with the old code.

## In-panel updater (ZIP), VERSION and CHANGELOG

**New**

* **Update page** (admin): upload the GitHub ZIP, review the plan, apply with your password, roll back with one click. Files:
  `panel/update.php`, `panel/views/update.php`, `panel/update-protected.txt`, `panel/update-rollback.tpl`, `panel/update-verify.tpl`,
  `panel/recover.php`, `updates/` (workspace, web-denied). Full description in [09-ADMIN-PANEL.md](09-ADMIN-PANEL.md#update-from-a-zip).
* **`VERSION`** (repository root, date style, e.g. `2026.11.22`) and **`CHANGELOG.md`**. The panel footer and the Update page show the version.
  CI fails a pull request that changes code without bumping `VERSION` and adding the changelog entry (`scripts/version-check.sh`).
* Worker job **`pip_sync`**: `pip install -r analyzer/requirements.txt` with the worker's interpreter, after an update that changed it.
* `guard/guard.php`: the constant `GV_DRY_RUN` (never defined by the guard itself) makes `gv_run()` skip the log row and the outcome capture;
  only the updater's health check uses it.
* Panel: `gp_reauth()` (password asked again before an update; a wrong one counts as a failed login), dashboard alerts `update_unverified`,
  `update_rollback_failed`, `update_pip_failed`, new audit events `update_upload`, `update_refused`, `update_apply`, `update_verified`,
  `update_failed`, `update_rollback`, `reauth_failed`.
* `panel/.htaccess` also serves `recover.php`; `scripts/exposure-check.sh` checks `updates/*`, `VERSION`, `CHANGELOG.md` and `panel/recover.php`.

**Upgrade**

1. Copy this release over the install **by hand once** (the Update page is part of it). Keep `guard/config.php`, `guard/config.local.json`,
   `guard/rules.json`, `lists/`, `geo/`, `panel/panel.config.php` as always. Make sure PHP can write the project (see
   [13-PANEL-WEB-ACCESS.md](13-PANEL-WEB-ACCESS.md), the permissions table).
2. Web server: `updates/` must not be reachable. Apache / LiteSpeed / OpenLiteSpeed read the shipped `updates/.htaccess`; **nginx** needs
   `location ^~ /updates/ { return 404; }` (README §2.6). `panel/recover.php` must stay reachable inside the panel directory.
3. `bash scripts/exposure-check.sh <url> <panel>`; reload PHP (OPcache).
4. From now on update from the panel. The first update has no file list from the previous one, so files removed upstream stay in place (once).

**Rollback of this release.** Restore the previous files (the updater is new code: no data format changes, nothing to migrate). `updates/`
can be deleted; `VERSION` and `CHANGELOG.md` are harmless to keep.

## Login page error message

* The "Wrong username or password." message was drawn by the shared layout, outside the centred login card. It is now inside the card, between the brand
  block and the form, as an alert. The username is kept after a failed login, the password field takes focus, and a rate-limited visitor sees how many
  minutes to wait (`login_locked` now contains `%d`). The IP-blocked page and the bare 404 are plain pages with no flash, so they needed no change.
* `panel/assets/app.css` is rebuilt (one new rule, `.gp-login-msg`). No data, config or Redis change. Roll back by deploying the previous files.

## Image CAPTCHA and headless-browser signals

**New**

* **A self-hosted image CAPTCHA** (PHP GD, no external service) with five difficulty levels, used by a new rule action **Image CAPTCHA**, by an optional
  escalation of headless-looking browsers, and optionally instead of the hourly / daily device 429. See
  [02-ARCHITECTURE.md](02-ARCHITECTURE.md#image-captcha-and-the-headless-signals). New files: `guard/captcha.php`, `guard/captcha-font.ttf` (+ its licence).
  GD is the only extension this project allows and it is **optional**: without it every captcha action is the proof-of-work challenge, and the dashboard
  warns while a CAPTCHA is configured.
* **Never shown to** an enforced allow-list address, an operator allow override, a verified crawler, an exempt path or a non-HTML request; a block-listed
  address gets 403 (decided long before). A captcha rule skips a verified crawler even with `skip_verified_bots` off.
* **Token levels.** A solved CAPTCHA issues a **level c** token (`device.issued.c.signature`); every token issued before this release is **level p** and stays
  valid (a captcha rule still asks for a CAPTCHA, the normal challenge accepts both). `gv_tok_check()` is unchanged for callers.
* **Settings -> CAPTCHA**: level 1-5 and every individual value (length, alphabet, distortion, noise, overlap, time limit), attempts per image, the
  per-IP CAPTCHA budget (default 10 pages per 15 minutes, checked in the existing single pipeline: a client over it gets a 429 with **no Redis work**), the
  proof-of-work switch (default on), the escalation score, CAPTCHA instead of the device 429 (default off), the **weight of every headless signal**, a **live
  preview image**, and the GD status; the CAPTCHA page texts are in the Strings tab (`strings.cap_*`, Persian defaults in the shipped `config.php`).
* Visitors: Persian / Arabic-Indic digits are normalised, answers are case-insensitive, look-alike characters are never used, a numeric keyboard opens for
  digit answers, "New image" is a reload (counted against the per-IP budget).
* **Headless signals** (`X-GV-S`): the challenge script sends yes / no answers and one number (webdriver, HeadlessChrome UA, UA-data mismatch, no languages,
  no `window.chrome`, no plugins, software WebGL, 0x0 screen, notification permission mismatch, time to submit, input events on the CAPTCHA page); the server
  scores them with a pure function and logs `hs` / `hf` (short keys, no raw fingerprint). A browser the script cannot read is neutral.
* **Dashboard**: a CAPTCHA row (shown, solved, failed attempts, expired, solve rate, median solve time, each against the previous 24 h) and an alert when GD is
  missing while a captcha rule, escalation or the CAPTCHA device budget is enabled. The impact preview of a captcha rule shows how many matching requests would
  get a CAPTCHA.
* New log keys (only when they apply): `cap`, `ct`, `tl`, `hs`, `hf`; reasons `CAPT_BUDGET`, `CAPT_ESC`, `SH_CAPT_ESC`, `CAPT_DEGRADED`; Redis keys `cpi:<ip>`, `ca:<id>`, `cesc:<md5>`. The
  snapshot's KPIs gain `captcha_*`. The challenge page script now also sends the signals and treats a 202 as "reload".
* **Review changes (escalation and Redis down).** (1) **Escalation no longer depends on the client keeping a cookie.** An enforced escalation also sets the
  Redis flag `cesc:<md5(ip net|UA hash)>` (600 s), written in the handshake's own pipeline (no extra round trip); while it exists a navigation request from
  that ip + UA without a level-c token gets the CAPTCHA, cookie or not, and a proof-of-work handshake from it is answered 202 (reload into the CAPTCHA) instead of a
  level-p token. The cookie stays as the second signal (it works with Redis down). A level-c token deletes the key. Monitor mode is unchanged (`SH_CAPT_ESC` only).
  (2) **Answer guessing while Redis is down.** A CAPTCHA served while Redis is not alive is issued with `pow_bits = max(configured, 20)` (reason `CAPT_DEGRADED`).
  **Extension to the brief, please review:** the proof of work is bound to the nonce only, so one solved counter would serve every guess; therefore a CAPTCHA nonce
  with 20 or more bits has a proof **bound to the typed answer** (`nonce:answer:counter`), solved by the page on submit, so every guess really costs CPU.
  Below 20 bits nothing changes (background solving). `scripts/pow-solve.php` takes the answer as an optional second argument. The remaining window and the native-solver
  residual are in [06-KNOWN-LIMITS.md](06-KNOWN-LIMITS.md). The bits stay at 20 (22 costs real mobile users seconds per submit and does not stop a multi-core attacker); instead a CAPTCHA served while Redis is down also gets an **answer of at least 6 characters** (same charset, time limit as configured), so enumerating it costs ~1000 s of native CPU for digits (3x10^5 s+ for letters + digits) against a 60-180 s limit.
* CI installs GD; `scripts/captcha-solve.php` (test tooling), `rules-e2e.sh` sections M / K2, `browser-test.js` scenarios, `bench-gv-run.php --cap-gen`.

**Compatibility.** Nothing changes until a captcha rule is enabled, `captcha.escalate_score` is above 0 or `captcha.device_budget` is on (all off by default).
Existing tokens, rules, lists and logs are untouched. Rolling back: a level c cookie is invalid for the old code (the visitor gets the challenge once).

**Upgrade steps (existing install `<install-dir>`, monitor mode)**

1. Deploy. Check GD: `php -m | grep -i gd` in the **web server's** PHP (the panel's Settings -> CAPTCHA says so too). Install it if you want the image (otherwise nothing breaks).
   Run `scripts/exposure-check.sh` (it now probes the font and `guard/captcha.php`).
2. Open Settings -> CAPTCHA, look at the preview at levels 1, 2 and 3, keep **level 2**.
3. Create a rule with the action **Image CAPTCHA** in `monitor` mode (for example on `HeadlessChrome`, `python-requests` or the `<empty>` UA), read the **impact
   preview** and the `SH_RULE:` rows. Switch it to `enforce` only after that, and watch the dashboard CAPTCHA row for a day (solve rate, median time, failed).
4. (Escalation) Redis keeps the escalation flag for 10 minutes; nothing to migrate. After deploying, `redis-cli --scan --pattern 'gv:cesc:*'` lists escalated clients.
   Optional: read `hs` / `hf` on the log rows of real visitors for a few days, then set `captcha.escalate_score` to 60 (it only acts while `enforce.challenge` is on;
   in monitor mode it logs `SH_CAPT_ESC`). Leave `captcha.device_budget` off until the device budgets look right.

**Rollback.** Disable or delete the rule; set `captcha.escalate_score` to 0; or switch the kill switch (`guard.off`). Removing GD makes every captcha action the
proof-of-work challenge.

**Cost** (`bash scripts/bench-gv-run.sh`; PHP 8.3 with OPcache, `gv_run` on a request that does NOT get a CAPTCHA, Redis `noeviction`, a fresh request each time,
median of 15 runs of 6000 requests in rotating order, same machine):

| | p50 | p99 |
|---|---|---|
| master | 251 us | 548 us |
| this branch, no captcha rule, escalation off (the default) | 241 us | 515 us |
| this branch, escalation ENFORCED (`escalate_score` 60 + `enforce.challenge`): the request also reads `cesc` and the CAPTCHA budget | 256 us | 495 us |
| this branch, a captcha rule that MATCHES the client, which holds a CAPTCHA-level token (so it is not asked) | 250 us | 584 us |

(Re-run for the review changes on a slower machine than the first run, hence the higher absolute numbers; the master row is the baseline of THIS run. Median of 15 rounds
of 6000 requests, four variants in rotating order, Redis on a local socket with `noeviction`.)

Budget: a request that does not get a CAPTCHA stays within +20 us p50 of master: met (+5 us in the worst case above, escalation enforced; the default configuration is within noise of master). Escalation adds two `GET`s to the existing pipeline only for token-less or level-p navigation requests while it is enabled, never a round trip. A
request that no captcha rule matches pays one extra array test; one that may need a CAPTCHA pays one more GET in the existing pipeline and one `is_file` for the font.
(The first version of this release built the 25 captcha defaults with function calls on every request and cost +12 us p50 on every request; they are a literal now.)

CAPTCHA page generation (`php scripts/bench-gv-run.php --cap-gen`, in-process: the answer, the PNG and the whole HTML page, 400 pages per level, GD 2.3 + FreeType,
median of 3 runs):

| level | p50 (image) | p99 (image) | p50 (whole page) | p99 (whole page) | page size |
|---|---|---|---|---|---|
| 1 (4 digits, light) | 1.4 ms | 2.1 ms | 1.4 ms | 2.2 ms | 16 KB |
| 2 (5 digits, light) | 1.6 ms | 2.4 ms | 1.7 ms | 2.4 ms | 16 KB |
| 3 (5 digits, medium) | 1.8 ms | 2.1 ms | 1.9 ms | 2.1 ms | 19 KB |
| 4 (6 letters+digits, heavy) | 2.2 ms | 3.7 ms | 2.2 ms | 3.7 ms | 22 KB |
| 5 (7 letters+digits, heaviest) | 2.4 ms | 3.3 ms | 2.5 ms | 3.4 ms | 23 KB |

Only a client that is actually shown a CAPTCHA pays this (and the per-IP budget limits how often).

**Known and not changed:** see [06-KNOWN-LIMITS.md](06-KNOWN-LIMITS.md#image-captcha-and-headless-signals).

## IP allow / block lists (files)

**New**

* New panel page **IP lists**: named **allow** and **block** lists of IPv4 / IPv6 addresses and CIDRs, each with a mode (`enforce` /
  `monitor`), an enabled flag and a note; paste text or upload a file. They complement the single-address overrides (Redis), which stay
  as they are. See [09-ADMIN-PANEL.md](09-ADMIN-PANEL.md#what-the-panel-does) and
  [02-ARCHITECTURE.md](02-ARCHITECTURE.md#ip-allow--block-lists).
* New `guard/iplist.php`, the `lists/` directory (web-protected, probed by `scripts/exposure-check.sh`), `panel/iplists.php`,
  `analyzer/iplist.py` and the worker job `iplist_compile`. The compiled files (`lists/allow.bin`, `lists/block.bin`) use the range
  format of the GeoIP files (kind 3) and the same binary-search lookup; the search got a faster tail (the last 128 records in one read)
  and unbuffered reads, which also speeds up the GeoIP lookup. **No Redis command, no DNS, no file write in the request path**; the lists
  are opened only while an enabled list of that type has entries.
* **Precedence:** kill switch and exempt paths (unchanged) -> **allow list** (like an operator allow override: skips rules, scoring,
  counters, challenge; decided before any Redis connection) -> **block list** (403, before the known-bot pass, no holdout, not gated by
  `enforce.block`; the list's own mode decides) -> everything else as before. An address in both lists is allowed, and the panel warns.
* New log reasons `IPL_ALLOW:<id>` / `IPL_BLOCK:<id>` (`SH_IPL_*` in monitor); the snapshot gains `iplists` (hits per list, 24 h / 7 d / last).
  A list hit that returns early writes the usual single log row (`allow_override` / `403`).
* Saving checks every line: invalid lines are reported by line number and nothing is saved until the operator accepts the valid ones;
  entries over the safety caps (see the review changes below) are refused unless "I know what I'm doing" is ticked, and the compile applies the same caps.
* New dashboard alerts: a compiled list file missing or corrupt while its list is enabled (critical), a failed compile or compile job
  (critical), lists changed and not compiled for more than 10 minutes (warning). The dashboard's protection card counts enabled lists.
* The IP lists page has tabs (Lists / Editor / Entries / Lookup tester / Compile), a tooltip on every field and include / exclude
  filters on its tables. New env knobs for tests: `GV_LISTS_DIR`, `GV_AUDIT`.

**Compatibility.** Nothing changes until a list exists: with no `lists/*.bin` the guard makes two failed `open()` calls per request
(about 1-4 us) and goes on. Existing overrides, rules, GeoIP and the logs are untouched. `scripts/geo-fixture.php` (test tooling) now
packs kind 3 with 2-byte values.

**Upgrade steps (existing install `<install-dir>`, monitor mode)**

1. Deploy the files. Make sure `lists/` is writable by the web user (the panel creates it if the project directory allows) and keep
   `lists/.htaccess`; run `bash scripts/exposure-check.sh` (it probes `lists/` too). No new Python package, no new cron entry: small
   lists compile inside the panel request; for a list of more than 512 KiB the existing `worker` cron runs `iplist_compile`.
2. Create the first list as **block**, mode **monitor**, from a short list you trust (for example the addresses of a scraper you already
   saw in the logs). Read the `SH_IPL_BLOCK:<id>` rows in Logs (reason filter), try addresses in the **Lookup tester**, and read the
   page warnings (conflicts with allow lists, verified crawlers, wide entries).
3. Only then switch the list to **enforce** (one click on the Lists tab). Keep allow lists short and specific: they skip everything.
4. Watch the dashboard for the list alerts for a day.

**Rollback.** Disable or delete the list (the guard stops using it as soon as the compile finishes, a second or two); **Roll back** on the
Compile tab restores `*.bin.prev`; or delete `lists/block.bin` / `lists/allow.bin` (the lists are then simply not applied, and the
dashboard says so). The kill switch (`guard.off`) bypasses all lists.

**Cost** (`bash scripts/bench-gv-run.sh`; PHP 8.3 with OPcache, `gv_run` on an allowed request that no list matches, Redis `noeviction`,
a fresh request each time so the files are re-opened on every request, median of 15 runs of 6000 requests in rotating order, same machine):

| | p50 | p99 |
|---|---|---|
| master (no `iplist.php`) | 265 us | 489 us |
| this branch, no list (two failed `open()` calls) | 277 us | 508 us |
| this branch, a **block** file of 100 000 IPv4 + 10 000 IPv6 ranges | 269 us | 594 us |
| this branch, an **allow and a block** file of 100 000 + 10 000 ranges each (worst case, both searched) | 310 us | 567 us |

The list lookup alone (`php scripts/bench-gv-run.php --list-lookup [--list-types=block]`, random IPv4 / IPv6 addresses, a fresh request each
time: reset, open, header check, search; median of 9 runs of 10 000 lookups):

| | lookup p50 | lookup p99 | files already open p50 / p99 |
|---|---|---|---|
| no list file at all | 6 us | 18 us | - |
| a block file, 100 000 + 10 000 ranges | **15 us** | 39 us | 8 / 27 us |
| an allow and a block file, 100 000 + 10 000 each | **21 us** | 61 us | 17 / 47 us |

Budget: at most 50 us p50 for the lookup with 100k IPv4 + 10k IPv6 entries: met (15 us for one file, 21 us with two). The whole-`gv_run` rows
sit within the run-to-run noise of this shared machine (+/- 15 us p50, much more at p99); the lookup rows are the reliable ones. The
benchmark process used to keep the generated test table (tens of MB) alive next to the timed loop, which inflated every number
by 30-100 us; it is freed now (this also applies to the GeoIP rows of the previous release). A request that a list **hits** costs less than
one it does not: it returns at step 3a, before any Redis connection (0 Redis commands, checked in `rules-e2e.sh`).

**Review changes (same release)**

* **The compile enforces the safety caps, not only the form.** `analyzer/iplist.py` (the worker, and files copied over SFTP) and the panel's compile share
  one rule set (`gp_ipl_refusal()` / `refusal()`, kept in byte-parity by a test): `0.0.0.0/0` and `::/0` are **always** dropped, even with "force"; allow entries
  wider than /16 (IPv4) or /32 (IPv6) are dropped; block entries wider than /8 or /32 are dropped; block entries covering private, loopback, link-local space
  or the server's own addresses are dropped. `force` (panel only, audit-logged) keeps all but `0/0`. Dropped entries and bad lines are counted per list and reason
  in `lists/lists-status.json` (shape changed: `wide` became `dropped` / `dropped_n` / `dropped_huge` / `dropped_samples`, plus `invalid_samples`), shown on the
  Compile and Entries tabs, with a dashboard warning, and a **critical** alert when an allow list lost an entry wider than /8. `lists/lists.json` gains `own` (the server's
  own addresses, written by the panel). **Check after upgrading:** an existing *allow* list with an entry wider than /16 (or a block list with private ranges) now loses it at the next compile
  unless it is saved with the force box ticked; the Compile tab lists what was dropped.
* **The enforced block list is decided before the challenge handshake** (step 1b of `gv_run`), so a block-listed address cannot drive handshake `POST`s (nonce claim,
  counters, a Redis round trip): 403, zero Redis commands. Exempt paths and an enforced allow list still win; a monitor block list leaves the handshake unchanged.
  The allow list stays after the handshake step.
* **Deny override under an enforced allow list:** the Overrides and Identity pages (and the flash after creating the deny) now warn that the deny has no effect, with a link to the list.

**Known and not changed:** see [06-KNOWN-LIMITS.md](06-KNOWN-LIMITS.md#ip-lists).

## Dashboard redesign and background job health

**New**

* The dashboard is reordered: critical alerts, protection state, last-24 h KPIs against the previous 24 h, top lists linking to the
  Logs filters, then collapsible details. See [09-ADMIN-PANEL.md](09-ADMIN-PANEL.md#dashboard-job-health-and-alerts). It also surfaces the
  alerts of earlier releases: rules file invalid, rules cache stale, GeoIP database missing / corrupt while a geo rule is enabled,
  GeoIP database older than 45 days.
* **Every** cron mode and `guard-logrotate.sh` now record `analyzer/.jobstatus-<mode>.json`, `logs/jobs.log` and (on failure)
  `logs/jobs-errors.log` (see [03-SETUP.md](03-SETUP.md#every-background-job-how-often-and-what-breaks-without-it)). A Python that cannot import the packages is a recorded
  failure (exit 3) instead of a silent success. A run skipped by the lock is counted. Jobs that did nothing useful (no input, Redis
  down, no model, nothing trained) are `warning`s. Training runs record their result; log rotation records its fields and reasons.
* New `scripts/cron-check.sh` (crontab report; `--json`), `scripts/jobstatus-selftest.sh`, `scripts/lib-jobstatus.sh`, `scripts/secret-values.php`.
* The Jobs page shows job health, the crontab check, the queue, error details and "mark as seen". Expected intervals are Settings -> Analyzer
  (`analyzer.interval_*`).
* The snapshot gains `kpi`, `top` and `tz`; its "last 24 h" is now a rolling window of timestamps (it used to be today's file).
* `guard-logrotate.sh` also rotates the job logs and deletes the oldest archives when free disk space is below `log_min_free_mb`.
* The worker records exit code, duration, warnings and the result in the status of each panel job.

**Review changes (same release)**

* **The free-disk floor is report-only by default.** The first version of this release deleted archives when the disk was low; the disk is shared with the
  whole server, so that is now opt-in: new settings `log_floor_delete` (default **off**) and `log_floor_keep_days` (default 7, minimum 1) under Settings -> Log storage.
  With it off, a low disk is only reported (logrotate status *warning*, `jobs.log`, dashboard alert). With it on, only archives older than the keep days are eligible, the
  oldest first, at most **10 files per run** (the limit being hit is recorded). The size cap and retention are unchanged. `df` and the guard's `disk_free_space()` see the
  filesystem, not the cPanel / CloudLinux user quota; where `quota` exists its usage is recorded in the logrotate status and shown on the dashboard
  ([06-KNOWN-LIMITS.md](06-KNOWN-LIMITS.md#background-jobs-dashboard-alerts-and-the-crontab-check)).
* **The crontab check is cached and cannot block.** The live result is cached in `analyzer/.cron-check-live.json` for 5 minutes; the Jobs page has **Check again** (CSRF,
  audit-logged, once per 30 s). The child's stderr goes to `/dev/null`, and a child that hangs is killed (SIGTERM, then SIGKILL after 1 s) so `proc_close` cannot wait for ever.
  New ignored file: `analyzer/.cron-check-live.json` (and `.cron-check-refresh`).

**Upgrade steps** (`<install-dir>`, monitor mode)

1. Deploy the files. No config change, no new extension, no new cron entry is required.
2. Run `bash scripts/cron-check.sh` over SSH and fix what it reports (add missing entries, add a `GV_PYTHON=` line if the packages live in a
   virtualenv). Until each job has run once with the new wrapper, the dashboard uses the old `.lastrun-*` heartbeat where there is one and
   says "never ran" otherwise; the **Cron setup** card shows the exact lines.
3. Open the dashboard. Fix what is critical first. Mark a known, understood failure as seen on the Jobs page.
4. If the analyzer and the panel show different time zones, set `date.timezone` (PHP) and `TZ` (crontab) to the same zone.
5. Optional: adjust the expected intervals in Settings -> Analyzer if your crontab differs from the documented one.

**Rollback**: redeploy the previous release. The new files (`.jobstatus-*`, `.jobstate-*`, `.cron-check.json`, `logs/jobs*.log`,
`panel/jobs-seen.json`) are ignored by git and harmless to leave; delete them if you like.

**Cost**: none on the request path. Each cron run adds a few small file writes and, at most every 10 minutes, one run of `cron-check.sh`.
The dashboard performs a few small live reads (status files, the log tails, one `LLEN`/`LINDEX`/`CONFIG GET` each); the crontab check
spawns one bash + python process (3 s limit).

## Panel layout: width, tabs, tooltips, include / exclude filters

**New** (panel only; the guard, the log format and Redis are untouched)

* Content width up to 1680 px, card grids (1 / 2 / 3 columns), tables scroll inside their card.
* Tabs on Settings (one per group), the Rules form (Conditions / Action / Advanced) and the GeoIP page; a rejected save
  opens the tab with the first error and badges every tab with errors; the tab is kept in the URL hash.
* A `?` tooltip with real help text (what it does, a safe value, the risk) on every setting, rule field, GeoIP field and filter.
* Every filtered list (Logs, Rules, Overrides, Identity, Audit, GeoIP sources) has include / exclude operators
  (`<key>_op=not`), multi-value choice fields, CIDR on addresses, removable chips, and keeps them across paging, CSV
  export and a new *Share link*. New Logs filters: User-Agent and the PR 1/2 fields country and ASN; Rules filters by
  country, ASN and UA; Audit filters by event and user.
* `panel/assets/app.css` is rebuilt (`npx tailwindcss@3 -c panel/assets/tailwind.config.js -i panel/assets/app.src.css -o panel/assets/app.css --minify`).
* New test: `scripts/panel-layout-test.sh` (browser, 1600 px / 390 px), also run by `panel-smoke.sh` and in CI.

**Empty values.** The panel distinguishes *unknown* from *known empty*. Country, ASN, outcome status and bot verdict are
**unknown** when empty (no lookup, not captured, no bot claim): a row without the value matches neither "is" nor "is not",
like an unknown country in a rule. Reasons, device id (a token-less client), operator override and a rule with no country /
ASN condition are **known empty**: plain include / exclude, so "reason is not UA_EMPTY", "device is not X" and
"override is not deny" include those rows. The value `(none)` selects empty rows on all of these fields (`is (none)`,
`is not (none)`, or mixed into a list). A saved "is not" link on country, ASN, status or bot verdict now lists fewer rows
than before; links on reasons, device and override behave as they always did.

**Compatibility.** Every existing link keeps working (a bare `act=403` is "is 403"). `gp_log_match()` still accepts the old
scalar filters. `gp_audit_read()` still accepts a search string.

**Upgrade steps** (`<install-dir>`, monitor mode): deploy the files. Nothing to configure, no cron change, no new
extension. Hard-reload the browser once so it loads the new `app.css`.

**Rollback**: redeploy the previous release; nothing was written to the data files.

**Cost**: none on the request path (panel only). Exclude filters on Logs scan more lines to find rows, bounded by the existing
scan caps.

## GeoIP: country and ASN conditions for access rules

**New**

* Rules gain a **Country** and an **ASN** condition (include / exclude), next to the User-Agent and path
  conditions. They work in `monitor` and `enforce` exactly like any rule and follow the same precedence
  ([02-ARCHITECTURE.md](02-ARCHITECTURE.md#geoip-country--asn-conditions)).
* `guard/geo.php` and the `geo/` directory (web-protected). Sources: MaxMind DB `.mmdb` (GeoLite2, DB-IP Lite,
  IPinfo Lite) and V2Ray/Xray `geoip.dat` (2-letter country tags only; other tags are listed as ignored). They are
  compiled **offline** by `analyzer/geo.py` into `geo/country.bin` / `geo/asn.bin`; the guard binary-searches those
  files with `fopen` / `fseek` / `fread`. No PHP extension, no `.mmdb` parsing in PHP, no Redis, no DNS.
* New panel page **GeoIP** (databases, upload, compile, rollback, lookup tester), a GeoIP group in Settings
  (`geo.log`), country / ASN filters and CSV columns in Logs, an optional client IP in the Rules test box, and an
  impact preview that works for country / ASN conditions. A database older than 45 days warns on the dashboard.
* New worker job type `geo_compile` (panel **Compile now**) and cron mode `scripts/analyzer-cron.sh geo`.
* New optional Python package `maxminddb` (in `analyzer/requirements.txt`; without it `.mmdb` files are reported
  as unreadable and a `geoip.dat` still compiles).
* Log rows gain `cc` / `asn` **only when a lookup ran** (a rule needed it, or `geo.log` is on). An unknown
  country is logged as `""`. A row without the key was not looked up. Existing readers ignore unknown keys.
* **An unknown country or ASN matches neither include nor exclude.** "Block everything except IR" never blocks
  a visitor that could not be placed.

**Compatibility.** `guard/rules.json` files and `guard/rules.cache.php` written by the previous release keep working
unchanged (a rule without `country` / `asn` has none). Nothing reads `geo/` unless a rule needs it or `geo.log` is on.

**Upgrade steps (existing install `<install-dir>`, monitor mode)**

1. Deploy the files. `pip install -r analyzer/requirements.txt` in the analyzer's virtualenv (adds `maxminddb`).
   Make sure `geo/` is writable by the web user if you want to upload from the panel; otherwise copy files with SFTP.
   Run `bash scripts/exposure-check.sh` (it now probes `geo/` too).
2. Put a database in `geo/` (panel **GeoIP** -> upload, or SFTP): a country `.mmdb` (and optionally an ASN
   `.mmdb`), or a `geoip.dat`. Press **Compile now** (needs the `worker` cron) or run
   `scripts/analyzer-cron.sh geo`. Check the active database, then try an address in the **Lookup tester**.
   Optional: `geo/known.json` with a few addresses that must resolve a given way before a new table is swapped in.
3. Add the monthly cron line from [03-SETUP.md](03-SETUP.md) (only if you use geo rules).
4. Optional: Settings -> GeoIP -> **log country**, so Logs can filter by country and the impact preview reads real
   data. Costs one small file search per request.
5. Create the first country rule in `monitor` mode, read its hits and the impact preview, then `challenge`, and only
   then `block`. Leave **Skip verified crawlers** ticked. Do not start with "not IR -> block".

**Rollback.** Disable or delete the rule; or roll the database back (**Roll back** on the GeoIP page restores
`*.bin.prev`); or delete `geo/country.bin` (country rules then simply never match). The kill switch bypasses all rules.

**Cost** (`scripts/bench-gv-run.sh`, PHP 8.3 with OPcache, `gv_run` on an allowed request, 150 000 IPv4 + 20 000 IPv6
ranges in the country file, median of 15 interleaved runs of 4000 requests, same machine, Redis `noeviction`; a fresh
request each time, so the file is re-opened on every request):

| | p50 | p99 |
|---|---|---|
| master, no rules | 205 us | 388 us |
| this branch, no rules (nothing reads `geo/`) | 205 us | 431 us |
| master, 200 UA rules x 5 values | 284 us | 527 us |
| this branch, 200 UA rules x 5 values | 299 us | 623 us |
| this branch, `geo.log` on (lookup on every request, no rules) | 226 us | 450 us |
| this branch, 200 country rules (the lookup runs once) | 255 us | 488 us |
| this branch, 200 UA + country rules (the UA misses, the lookup still runs) | 250 us | 493 us |

200 country rules cost +50 us p50 over master with no rules; the lookup is about 20 us of that, so the 200-rule loop
itself is about 30 us (budget 100 us). `--geo-rules=200 --match` measures the loop alone: 20.5 us p50 / 41 us p99, with
the country already known. The lookup alone (`--lookup`): warm file 8-12 us p50, 36-52 us p99; a fresh request
(open + header check + search) 11-17 us p50, 35-57 us p99 (target: p99 well under 200 us). With 200 UA-only rules the
loop got about 15 us slower (two more `isset()` per rule); the p99 columns are noisy on a shared machine.

## Access rules (User-Agent / path)

**New**

* `guard/rules.php` and `guard/rules.json` (written only by the panel): block, challenge or log
  a client by User-Agent (`exact`, `contains`, `prefix`, `regex`, `<empty>`) and/or path prefix,
  each with `include`/`exclude`, a priority, an expiry, and a `monitor` or `enforce` mode.
  See [02-ARCHITECTURE.md](02-ARCHITECTURE.md#access-rules) and [09-ADMIN-PANEL.md](09-ADMIN-PANEL.md).
* `guard/rules.cache.php` (generated, see Cost below).
* New panel page **Rules** (test box, starter set, "Quick block" on log and identity rows).
* Log reasons `RULE:<id>` / `SH_RULE:<id>`; the snapshot gains `rules` (hits per rule, 24 h / 7 d).
* Without `guard/rules.json` nothing changes: no file read beyond one `is_file()`.

**Upgrade steps (existing install, monitor mode)**

1. Deploy the files. No config change, no new cron job, no new extension. Run
   `bash scripts/exposure-check.sh` (it now also probes `guard/rules.json`).
2. Open **Rules**, press **Install starter set** (16 rules, all disabled, monitor mode).
3. Enable the ones you care about, still in monitor mode, and read the hits (Logs filter
   `reason = SH_RULE:<id>`, or the Hits column after the next snapshot run).
4. Switch a rule to `enforce` only after its monitor hits look right. Rule actions do not
   depend on `enforce.block` / `enforce.challenge`: the rule's own mode decides.

**Rollback**: disable or delete the rule in the panel, or delete `guard/rules.json`
(takes effect on the next request). The kill switch (`guard.off`) also bypasses all rules.

**Cost** (`scripts/bench-gv-run.sh`, PHP 8.3 with OPcache, p50 of `gv_run`, allowed request, interleaved
runs on the same machine): master ~0.18 ms; no rules unchanged; 20 rules +0.015 ms; 200 rules x 5 values
+0.09 ms; 200 rules x 50 values +0.15 ms. This relies on the generated `guard/rules.cache.php`: it is written by
the panel on every save and included by the guard (OPcache-friendly). If it is missing or older than
`rules.json` the guard reads the JSON instead (about 1 ms for 200 rules) and logs `rules cache stale`;
saving in the panel rebuilds it. The file is gitignored and covered by `exposure-check.sh`.

**Also**: with Redis down a known-bot UA skips `skip_verified_bots` rules (row reason `RULE_SKIP_DEGRADED`),
matching the existing outage policy for the bot pass. Rules can be previewed against recent logs before saving.

## Log storage limits

**New**

* `log_skip_paths`: path prefixes that are never logged (add `/gv-admin/` so the panel stops
  filling the log). `exempt_paths` still skips the checks and still logs `exempt`.
* `log_retention_days` (default 60) and `log_max_mb` (default 0 = off), applied by
  `guard-logrotate.sh`, which now reads them and `log_dir` from the effective config.
* `log_min_free_mb` (default 200): below this free disk space the guard pauses request logging.
* Dashboard card **Log storage**: sizes, free disk, last rotation, warnings.

**What to do**

* Make sure the `guard-logrotate.sh` cron job exists (the new card says so if it does not).
* If cron cannot find `php`, set `GV_PHP=/full/path/to/php` in the crontab.

## Settings managed in the panel

**New**

* **Settings** now covers every operational setting: tokens and challenge (`token_ttl`, `nonce_ttl`,
  `challenge.bind_ip`), the challenge page text (`strings.*`),
  `exempt_params_paths`, `cdn_ranges`, `bot_suffixes`, and the analyzer (`analyzer.*`). Only install
  settings and secrets stay in `guard/config.php` ([09-ADMIN-PANEL.md](09-ADMIN-PANEL.md#where-each-setting-lives)).
* **Config file** page: edit `guard/config.local.json` as JSON with highlighting and validation.
  Invalid files are never written.
* Every overlay write backs up the previous file to `guard/config-backups/` (newest 20).

**Behaviour that changed**

* The settings form writes only the keys you changed. A value that came from `guard/config.php` is
  no longer copied into the overlay, and no longer blocks a save when it is outside the panel's range.
* Analyzer precedence: defaults → `GV_ANALYZER_CONFIG` → panel. A key set in both the analyzer file
  and the panel now takes the panel value.
* PHP must be able to create `guard/config-backups/` (it already writes `guard/config.local.json`).

## Admin panel in English

**Behaviour that changed**

* **The panel is English and left-to-right.** Every page, the menu, the login page and the messages.
  The visitor-facing challenge page is unchanged (its text is `strings` in `guard/config.php`).
* **Every number uses Latin digits (0-9)**, grouped by thousands where it is read (`12,345`),
  ungrouped in the log explorer so it can be copied into a filter. Percentages use `%`.
* **Log details redesigned.** Each field is a row: label, raw log key (`ua`, `q`, ...), value. Long
  values wrap without breaking the layout and very long ones collapse behind "Show full value". The
  query string is also shown as a decoded parameter table. Raw request data is shown as received.
* **Settings: number fields had `min="0" max="0"`**, so a browser refused to submit the form. Fixed.
* The panel font is the system font; Vazirmatn stays as the fallback for Persian text in log data.

## Panel reachable at its directory URL

**Behaviour that changed**

* **`/gv-admin/` (the directory URL) now opens the panel on Apache.** `panel/.htaccess` granted
  only `index.php`, so Apache 2.4 answered 403 for the directory itself and only
  `/gv-admin/index.php` worked. Copy the new `panel/.htaccess` over the old one.
* `scripts/exposure-check.sh` checks both `/gv-admin/` and `/gv-admin/index.php`.

**New**

* [13-PANEL-WEB-ACCESS.md](13-PANEL-WEB-ACCESS.md): exposing the panel with a symlink, permissions,
  Apache/LiteSpeed settings, checks and troubleshooting.

## Admin panel: themes, IP allowlist, pipeline status

**Behaviour that changed**

* **`ip_allowlist` now takes IPv4 and IPv6 addresses and CIDR ranges.** Empty or absent still means
  no IP restriction. A non-empty list with no valid entry, or a value that is not a list, now
  refuses everyone (it used to be ignored). Check the file after upgrading.
* **New `trusted_proxies`.** `X-Forwarded-For` is read only when the connection comes from one of
  these addresses. Behind your own proxy or CDN, add its address, or the panel sees the proxy as
  the client (login rate limit and audit trail included). Re-running `setpass.php` keeps both lists.
* **Every panel response sends `X-Robots-Tag: noindex, nofollow, noarchive, nosnippet`.** Do not add the
  panel path to `robots.txt`.
* **Logs page: the "Response status" filter works.** It returned nothing before.

**New**

* Light, dark and automatic themes, chosen in the panel header and remembered per browser.
* Dashboard card **Data pipeline**: whether the guard is logging, and when the last request was seen.
* `scripts/e2e-pipeline.sh`, an end-to-end test, and [11-TESTING-PIPELINE.md](11-TESTING-PIPELINE.md).
* Persian wording fixes in the panel (for example "تأثیر قوانین").

**What to do**

* `chmod +x scripts/*.sh` if your copy lost the execute bit, otherwise cron jobs fail silently.
* Review `ip_allowlist` and, behind a proxy, set `trusted_proxies` in `panel/panel.config.php`.

## Review-hardening release

A full review with concurrent testing found the problems below. Behaviour changes are listed
first; everything is covered by tests.

**Behaviour that changed**

* **A rule in shadow no longer cancels the rules below it.** With `enforce.ratelimit` off and
  `enforce.challenge` on, a token-less client that went over a limit was served unchallenged
  for the rest of the window; with `enforce.block` off the worst-scoring clients skipped the
  challenge. Now the first rule that matches *and is enforced* is served. The row carries the
  served action and names the shadowed one in `rs` (`SH_429`, `SH_403`).
* **`exempt_params` only count on the front controller** (`exempt_params_paths`, default `/`
  and `/index.php`). `?route=payment/x` appended to a product URL used to exempt it from
  everything. A path with a dot segment, a doubled slash or an encoded slash/dot is never
  exempt by prefix either. If your callbacks arrive on another path, add it to
  `exempt_params_paths` or use `exempt_paths`.
* **HEAD is gated like GET.** Uptime monitors that use HEAD need an exemption or an allow.
* **POST is shadow-gated.** Most applications render a page for a POST as well, which made
  POST the next way round the challenge. Token-less POSTs are now logged as
  `act=challenge, sh=1`; set `challenge.gate_post` to enforce, after checking
  `jq -r 'select(.m=="POST" and .act=="challenge")|.p+"?"+.q' logs/guard-*.jsonl | sort | uniq -c | sort -rn | head -30`.
* **Unverified crawler claims share one budget** (`limits.bot_unverified`) and an operator deny
  now beats the crawler pass. Run `analyzer-cron.sh verify`.
* **IPv6 clients are counted per /64**, and every address is stored in one canonical spelling
  (an IPv4-mapped address as its IPv4 address), in the guard, the panel and the verifier.
* **Defaults:** `limits.mint` 60 → 300, `limits.preview` 60 → 20, `challenge.pow_bits` maximum
  24 → 22 in the panel.
* **The breaker needs two timeouts within ten seconds** before it switches Redis off for
  `breaker_ttl`; one slow reply used to open a site-wide gap. A refused connection still arms
  it at once. Its marker falls back to the system temp directory when `logs/` is not writable.
* **Monitor mode refuses nothing:** a bad handshake nonce is logged (`nonce_bad`, `sh=1`) and
  the request runs.

**Fixed without a behaviour change you need to act on**

* `Cookie: _gv[]=x` raised a PHP warning; a stale `_gv` cookie in front of a valid one caused
  an endless challenge loop.
* A Redis that answers but refuses writes (read-only replica, out of memory, loading) left
  every counter at 0 with no sign of it: rows are now `rd=1` and `guard-errors.log` says
  `redis_cmd_error`.
* A reply line without an end could exhaust PHP's memory (uncatchable); a breaker marker dated
  in the future kept Redis off; a log that cannot be written now reports `log_write_failed`.
* `config.php` values are sanity-checked: a limit or lifetime that is not a positive whole
  number falls back to its default, `'false'`/`'off'` read as off, an empty secret forces
  monitor mode.
* The panel refuses settings that switch the guard or the shop off in one click (`/` as an
  exempt path or honeypot, a bot fragment like `mozilla`), saves under a lock and writes only
  the keys that changed, bounds audit rows, counts login attempts atomically, lists deny
  overrides first and completely, and neutralises spreadsheet formulas in the CSV export.
* `guard-logrotate.sh` no longer compresses a file that is still being written, never
  overwrites an archive, skips anything that is not a regular file and exits non-zero on
  failure. `GV_LOG_DIR` points it at a non-default directory.
* Analyzer: a DNS failure right after a successful health check can no longer mark a real
  crawler as fake; verification looks at the busiest claimants first; a wrong-typed log field
  no longer kills every job; models are written atomically; rounding matches PHP exactly;
  all writing cron modes share one lock; reputation expires in 14 days.
* `scripts/accesslog_report.py`: see [05-ACCESS-LOG-REPORT.md](05-ACCESS-LOG-REPORT.md) (served-only counting,
  per-client machine signals, `--date`, format and truncation warnings).

**Known and not changed:** see [06-KNOWN-LIMITS.md](06-KNOWN-LIMITS.md).

## Slow-scraper release

* **The challenge no longer depends on request headers.** Before, only a GET with
  `Accept: text/html` and no `X-Requested-With` was challenged, so any HTTP library
  with default headers was served without a token. Now every non-exempt GET needs one.
  **Before enabling `enforce.challenge`, list every server-to-server GET** (feeds, price
  APIs, payment callbacks made by GET, cron URLs, uptime monitors) in `exempt_paths` /
  `exempt_params`. In monitor mode they show up as `act=challenge, sh=1, nav=0` rows:
  `jq -r 'select(.act=="challenge" and .nav==0)|.p' logs/guard-*.jsonl | sort | uniq -c | sort -rn | head -30`.
  `challenge.trust_headers = true` is the rollback.
* **Log schema 5:** new fields `gate` (1 = this request needed a token), `cdh` and `cdd`
  (the hourly and daily device counters), new act `allow_preview`. Replay reads `gate`
  and falls back to `nav` on older rows, so existing logs keep replaying.
* **New limits** `device_hour` (400), `device_day` (1500), `preview` (60) and the
  `preview_bots` list are all panel-tunable. The device budgets enforce under
  `enforce.ratelimit`; read the `DEV_HOUR` / `DEV_DAY` shadow rows first, and exempt the
  shop's admin path, where staff legitimately make thousands of requests a day.
* **`known_bots` grew and `preview_bots` is new.** Both lists come from `config.php`
  (or the panel), not from built-in defaults: an existing `config.php` keeps the bots it
  names and has no preview fetchers until you copy the two lists from the shipped
  `guard/config.php`.
* **New tool:** `scripts/accesslog_report.py`, see
  [`05-ACCESS-LOG-REPORT.md`](05-ACCESS-LOG-REPORT.md).

## Production-readiness release

* **Nothing to do by default.** Defaults keep key names, token cookies and behaviour; the
  new `redis` keys, `limits.mint` (60), `challenge.pow_bits` (16) and `bind_ip` (true) have
  safe defaults. PHP 8.0+ is now required (older PHP: guard silently off + note in
  `logs/guard-errors.log`). Python 3.9+.
* **Challenge:** nonce format changed; a visitor mid-challenge during the deploy gets one
  automatic retry. `_gv` tokens stay valid. `pow_bits` can be tuned in the panel.
* **Changing `redis.prefix`** orphans existing counters, verdicts and overrides (they expire
  by TTL). Re-add overrides; the analyzer rebuilds verdicts on its next runs. Raw
  `redis-cli` commands must use the prefixed names.
* **Ops:** run `scripts/exposure-check.sh`; `guard-logrotate.sh` now also rotates
  `guard-errors.log`; no new cron jobs.
