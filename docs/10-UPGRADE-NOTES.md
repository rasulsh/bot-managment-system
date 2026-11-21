# Upgrade notes

What changed in each release and what to do about it. Newest first.

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

**Compatibility.** Every existing link keeps working (a bare `act=403` is "is 403"). `gp_log_match()` still accepts the old
scalar filters. `gp_audit_read()` still accepts a search string.

**Upgrade steps** (`/home/cloud/bot-guard`, monitor mode): deploy the files. Nothing to configure, no cron change, no new
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

**Upgrade steps (existing install `/home/cloud/bot-guard`, monitor mode)**

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
