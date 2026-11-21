# Configuration and operations reference

Every setting of `guard/config.php`, notes per platform, the honeypot, and the
day-to-day commands. For the first install see the Quick Start in the
[README](../README.md); for a step-by-step guide see [03-SETUP.md](03-SETUP.md).

## Requirements and install notes

PHP 8.0+ (no Composer, no extensions, no external dependencies). On older PHP
`prepend.php` returns at once, the host app runs unguarded and one line goes to
`logs/guard-errors.log`. Python 3.9+ for the analyzer. Redis is optional (any
version from 5; AUTH, ACL users, a db number, a unix socket and a key prefix are
all optional).

Keep the directory **outside the web root** (see [03-SETUP.md](03-SETUP.md),
"Layout": the panel is exposed by a symlink or an Alias). The shipped `.htaccess`
files deny everything by default as a safety net, and
`scripts/exposure-check.sh <BASE_URL> [panel-path|none]` verifies it over HTTP.

`auto_prepend_file` is preferred over `require` in a front controller: it runs
before any application code or page cache layer and needs zero host-app changes.

## Configuration table (`guard/config.php`)

**Where each setting lives.** Only these stay in `guard/config.php`, because the guard
needs them before it can start or because they are secrets: `secret`, `holdout_salt`,
`redis` (all of it), `log_dir`, `cookie_name`, `challenge.test_key`, and `challenge.trust_headers` (a rollback switch that weakens the challenge). Every other key below
can be changed in the admin panel (**Settings**, or **Config file** for the raw JSON). A
panel value overrides the file value key by key; **Reset to file value** removes it again.
See [09-ADMIN-PANEL.md](09-ADMIN-PANEL.md#where-each-setting-lives).

| key | meaning |
|-----|---------|
| `secret` | HMAC key for tokens and nonces. While it equals `CHANGE_ME` every enforce toggle is forced off (monitor only). |
| `cookie_name` | Token cookie name. |
| `token_ttl` | Token lifetime in seconds (default 7 days). |
| `nonce_ttl` | Challenge nonce lifetime in seconds. |
| `enforce.block` | Serve 403 on hard-score GETs. Stage 1. |
| `enforce.challenge` | Serve the JS challenge to every token-less GET or HEAD, whatever headers it sends. Stage 2. |
| `enforce.ratelimit` | Serve 429 over the limits. Stage 3. |
| `hard_block_score` | Score at or above which a GET is a block candidate. |
| `limits.window` | Fixed counter window in seconds. |
| `limits.mint` | Tokens minted per IP (IPv6: per /64) per window (default 300; a carrier address is shared by many new visitors). Over it: 429 with `enforce.ratelimit`, logged `mint_limited` with `sh=1` otherwise. An allow-listed IP is never refused. |
| `challenge.pow_bits` | Proof-of-work difficulty of the challenge, 0-24 in `guard/config.php` (default 16, 0 = off). Panel-tunable, but the panel accepts 0-22 only. |
| `challenge.bind_ip` | Bind a nonce to the IP it was issued to (default true). |
| `challenge.trust_headers` | Default false. `true` restores the old rule (only a GET that asks for HTML is challenged), which any client walks past by not sending `Accept: text/html`. A rollback switch, file-only. |
| `limits.device` / `ip_ua` / `ip` / `bot` | Requests per window per device token, per IP+UA pair, per IP, per known bot. The IP limit is deliberately generous. |
| `limits.device_hour` / `device_day` | Requests per device token per hour (400) and per day (1500), fixed windows. They catch the client that paces itself under `limits.device` and keeps changing address: the count follows the token, not the IP. Over either: 429 with `enforce.ratelimit`, otherwise logged with `sh=1` and `DEV_HOUR` / `DEV_DAY` in `rs`. Exempt your admin path before enforcing. |
| `limits.preview` | Requests per `preview_bots` name per window, **site-wide** (default 20). |
| `limits.bot_unverified` | Requests per `known_bots` name per window, **site-wide**, from addresses the verifier has not confirmed (default 300). Past it an unverified claim is handled like any client. A verified crawler (`botok`) is outside it, so `analyzer-cron.sh verify` must be running. |
| `challenge.gate_post` | Default false: a token-less POST is served and logged as a shadow challenge (`act=challenge, sh=1, m=POST`). True: it is challenged like a GET. Turn it on once the shadow rows show only endpoints you have exempted. |
| `exempt_params_paths` | The exact paths on which `exempt_params` count (default `/` and `/index.php`). On any other path the parameter is something the client added and exempts nothing. |
| `honeypot_path` | Hidden path that must 404 today. A hit marks the IP for 7 days. |
| `exempt_paths` | URI prefixes the guard skips entirely. |
| `exempt_params` | `param => array of value prefixes` the guard skips, e.g. `'route' => array('payment/')`. |
| `known_bots` | Lowercase UA substrings allowed through under their own bucket. Ships with the Google and Bing crawler families (Googlebot, AdsBot, Mediapartners, InspectionTool, StoreBot, GoogleOther, Bingbot, AdIdxBot, BingPreview). Each needs a `bot_suffixes` entry so the claim is verified by reverse DNS out of band. |
| `preview_bots` | Lowercase UA substrings of link-preview fetchers (Telegram, WhatsApp, Facebook, X, LinkedIn). They cannot solve a challenge and cannot be verified, so they pass only inside `limits.preview`, a budget shared by every address using that name; past it they are handled like any other client. No Redis, no pass. Logged as `allow_preview`. |
| `cdn_ranges` | IPv4 CIDRs. `X-Forwarded-For` is trusted only when `REMOTE_ADDR` is inside one, and then only its last entry. |
| `redis` | One block shared by guard, panel and analyzer: `host`, `port`, `socket` (unix path, wins over host/port), `username`, `password` (empty = no AUTH sent), `db` (0 = no SELECT), `prefix` (key namespace, `[A-Za-z0-9_.:-]{0,32}`, empty = legacy key names), `timeout` (0.05 s), `breaker_ttl` (seconds to skip Redis after a failure, 0 = off). File-only: never in the panel overlay, never displayed, stripped from `config-dump.php`. |
| `log_dir` | JSONL destination. |
| `strings` | `lang`, `dir`, `title`, `sub`, `noscript`, `failed`, `retry` — the only user-facing text; translate here, the code stays English. |
| `signals.reputation` | Phase 2. Add `gv:rep:{dev}` to the score. Default off (shadow). |
| `signals.ml` | Phase 2. Add the scaled `gv:ml:{dev}` anomaly level to the score. Default off (shadow). |
| `ml_weight` | Phase 2. Multiplier turning an anomaly level of 0..100 into a score contribution. Default 0.4. |
| `bot_suffixes` | Phase 2. Reverse-DNS suffixes per known bot. Consumed by the Python verifier; kept here as one source of truth. |
| `analyzer.interval_verify`, `_worker`, `_snapshot`, `_nightly`, `_logrotate`, `_train`, `_train_clf`, `_geo`, `_report` | Expected run interval of each background job in minutes (defaults 10, 1, 15, 1440, 1440, 10080, 10080, 43200, 10080). Read by the panel's job health only: a job is late after twice its interval. Settings -> Analyzer. |
| `geo.log` | Default false. Add the country (`cc`) and, when `geo/asn.bin` exists, the AS number (`asn`) to every log row. Without it the lookup only runs for a rule that needs it. Settings -> GeoIP. |
| `capture_outcomes` | Phase 4. Record what the application did with each allowed request as a second tiny log line. Default off. |

## Access rules file (`guard/rules.json`)

Not part of `config.php`: written by the panel (Rules page), read by the guard on every request.
`GV_RULES` (environment) points the guard at another file (tests). Missing, empty or invalid = no rules.

| Field | Meaning |
|---|---|
| `id` | Short generated id (`^[a-z0-9][a-z0-9-]{2,15}$`), used in logs as `RULE:<id>`. |
| `name`, `note` | Text, 80 / 300 chars. |
| `enabled` | Bool. |
| `mode` | `enforce` or `monitor` (monitor only logs `SH_RULE:<id>`). |
| `action` | `block` (403), `challenge`, or `log`. |
| `priority` | 1-100000, lowest first, first match wins. |
| `skip_verified_bots` | Default true: a verified crawler is not touched. |
| `ua` | `{op: include|exclude, type: exact|contains|prefix|regex, values: [...]}` or null. `<empty>` = missing/blank UA. |
| `path` | `{op, type: "prefix", values: ["/x", ...]}` on the raw path, or null. |
| `expires_at` | Unix time, 0 = never. |
| `pow_bits` | 0 (global) or 12-22 for this rule's challenge. |
| `country` | `{op, type: "code", values: ["IR", "US", ...]}` ISO 3166 alpha-2, upper case, or null. Needs `geo/country.bin`. |
| `asn` | `{op, type: "number", values: ["13335", ...]}` AS numbers as decimal strings (1-4294967295, no `AS` prefix), or null. Needs `geo/asn.bin`. |

`guard/rules.cache.php` is generated by the panel from this file on every save (enabled rules only, compiled patterns); do not edit it, it is gitignored and web-protected like the rest of `guard/`.

At least one of `ua` / `path` / `country` / `asn`. An unknown country or ASN matches neither `include` nor `exclude`. Limits: 200 rules, 50 values per condition, 300 chars per value.
Conditions of one rule are AND-ed.

## Job status files (written by the cron wrappers)

| File | Meaning |
|---|---|
| `analyzer/.jobstatus-<mode>.json` | Latest state of a job: status, last start / end / success / failure, exit code, duration, skipped-by-lock count, last error, warnings, result. Modes: `verify nightly train train-clf snapshot worker report geo logrotate`. |
| `analyzer/.jobstate-<mode>` | Numbers that survive runs (last success / failure, skip count, runs, failures). |
| `analyzer/.cron-check.json` | The last crontab check (`scripts/cron-check.sh --json`), refreshed by every cron run at most every 10 minutes. |
| `logs/jobs.log`, `logs/jobs-errors.log` | One JSON line per run; the captured stderr (64 KiB cap, redacted) of a failed run. Rotated and expired like the guard logs. |
| `panel/jobs-seen.json` | Failures an operator marked as seen (panel-written). |

Environment (tests and unusual installs): `GV_JOBSTATUS_DIR` (status files, default `analyzer/`), `GV_JOBLOG_DIR` (default the
configured `log_dir`), `GV_LOCK_DIR` (lock files, default `analyzer/`), `GV_MIN_FREE_MB` (logrotate's disk floor override).

## GeoIP files (`geo/`)

Web-protected like `guard/`. `GV_GEO_DIR` (environment) points the guard and the analyzer at another directory (tests).

| File | Written by | Meaning |
|---|---|---|
| `*.mmdb`, `*.dat` | you (panel upload or SFTP) | Sources: MaxMind DB (GeoLite2 / DB-IP Lite / IPinfo Lite) and V2Ray/Xray `geoip.dat`. |
| `country.bin`, `asn.bin` | `analyzer/geo.py` | Compiled range files the guard searches. `.prev` = the file they replaced (rollback). |
| `geo-status.json` | `analyzer/geo.py` | Last compile: sources, used / unused, ignored `geoip.dat` tags, errors, country list. Read by the panel. |
| `known.json` | you (optional) | `{"country": {"1.1.1.1": "AU"}, "asn": {"1.1.1.1": 13335}}`: addresses that must resolve this way, or the new table is not swapped in. |

Compile: panel -> GeoIP -> **Compile now** (job `geo_compile`) or `scripts/analyzer-cron.sh geo`. Environment knobs for the compile:
`GV_GEO_MIN_RANGES` (default 1000, the smallest table that is accepted; for tests).

## Image CAPTCHA (`captcha.*`, `strings.cap_*`)

All keys are panel-tunable (Settings -> CAPTCHA, overlay keys). A level 1-5 preset sets the values below; every value can be overridden
(`auto` / `0` = take it from the level). The panel validates every value and refuses an out-of-range one (never clamps).

| Key | Default | Meaning |
|---|---|---|
| `captcha.level` | 2 | Preset: 1 = 4 digits, low distortion, few lines, no overlap, 180 s; 2 = 5 digits, low, few, no, 150 s; 3 = 5 digits, medium, medium, slight, 120 s; 4 = 6 letters+digits, high, many, yes, 90 s; 5 = 7 letters+digits, high, many, yes, 60 s. |
| `captcha.length` | 0 | 3-8 characters; 0 = the level's. |
| `captcha.charset` | auto | `digits`, `alnum` (capitals and digits without look-alikes) or `auto`. Answers are case-insensitive; Persian / Arabic-Indic digits are accepted. |
| `captcha.warp` / `noise` / `overlap` | auto | `low` / `medium` / `high`, `few` / `medium` / `many`, `no` / `slight` / `yes`, or `auto`. |
| `captcha.time_limit` | 0 | 20-900 s; 0 = the level's. Part of the signed nonce. |
| `captcha.max_attempts` | 3 | Answers one image accepts (counted in Redis). |
| `captcha.ip_budget` / `ip_window` | 10 / 900 | CAPTCHA pages per address (IPv6 /64) per window (s). Over it: 429 and no Redis work. |
| `captcha.require_pow` | true | The proof of work (`challenge.pow_bits`, or the rule's `pow_bits`) is still required with the CAPTCHA. |
| `captcha.escalate_score` | 0 | 0 = off. A proof of work whose headless score reaches it gets a CAPTCHA instead of a token (only while `enforce.challenge` is on). |
| `captcha.device_budget` | false | CAPTCHA instead of the hourly / daily device 429; a CAPTCHA-level token is waived from those two budgets. |
| `captcha.w_webdriver` 40, `w_ua_headless` 40, `w_ua_mismatch` 25, `w_no_languages` 15, `w_no_chrome` 20, `w_no_plugins` 10, `w_webgl_soft` 15, `w_screen_zero` 20, `w_notification` 15, `w_too_fast` 20, `w_no_input` 20, `w_ua_spoof` 25 | | Weight (0-100) of each headless signal; 0 switches it off. |
| `strings.cap_title`, `cap_sub`, `cap_label`, `cap_submit`, `cap_new`, `cap_wrong`, `cap_failed`, `cap_expired` | English / Persian defaults | The CAPTCHA page texts (escaped, any language, RTL follows `strings.dir`). |

Rule action: `captcha` (rules cache like the others). Files: `guard/captcha-font.ttf` + `guard/captcha-font.LICENSE.txt` (DejaVu Sans Mono Bold, free
Bitstream Vera / public-domain licence). Test knob: `GV_CAPTCHA_NO_GD=1` makes the guard behave as if GD were missing.

Redis keys (prefixed): `cpi:<ip net>` pages per window, `ca:<nonce id>` attempts at a nonce, `nonce:<id>` the usual single-use claim.
Log row keys (only when they apply): `cap` = `show | ok | wrong | fail | exp | inv | esc`, `ct` seconds a solved CAPTCHA took, `tl` = `c` for a request that
carried a CAPTCHA-level token, `hs` the headless score, `hf` the letters of the signals that fired. Reasons: `CAPT_BUDGET`, `CAPT_ESC`, `SH_CAPT_ESC`.
Token cookie: `device.issued.signature` (level p) or `device.issued.c.signature` (level c). Escalation flag cookie: `<cookie_name>c` (signed expiry).

## IP list files (`lists/`)

Web-protected like `guard/` and `geo/` (`lists/.htaccess`; `scripts/exposure-check.sh` probes it). `GV_LISTS_DIR` (environment)
points the guard, the panel and the analyzer at another directory (tests). No overlay key: everything the operator changes
is a list on the IP lists page.

| File | Written by | Meaning |
|---|---|---|
| `lists.json` | the panel | `own` (the server's own addresses the panel saw, 16 at most: block entries covering them are dropped by the compile) and the lists: `id` (log name, `[a-z0-9-]`, 24 at most), `idx` (the number in the compiled value, never reused), `name`, `type` (`allow` / `block`), `enabled`, `mode` (`enforce` / `monitor`), `force`, `note`, audit fields. 50 lists at most. |
| `<id>.txt` | the panel (or SFTP) | The source of one list: one IPv4 / IPv6 address or CIDR per line. `#` starts a comment, blank lines, CRLF and a BOM are fine, a CSV reads its first column. The panel stores the accepted entries in canonical form. 16 MiB and 300 000 lines at most per list. |
| `allow.bin`, `block.bin` | the panel (small) or `analyzer/iplist.py` (job `iplist_compile`) | Compiled range files (kind 3) from every enabled list of that type. Deleted when no enabled list of the type has entries. `.prev` = the file replaced (rollback). |
| `lists-status.json` | the compiler | Last compile: time, who ran it (`php` / `python`), `ok`, errors, per type the build time / range counts / sha256 / list ids, per list the counts (`entries` kept, `v4` / `v6` ranges, `addresses` (IPv4), `invalid` lines with `invalid_samples`, `dropped` per reason `all` / `allow_wide` / `wide` / `protected`, `dropped_n`, `dropped_huge` (allow entries wider than /8) and `dropped_samples`, 10 samples at most each). |
| `.pending-<token>.txt` | the panel | A text waiting for the operator's confirmation of invalid lines; removed on save or after a day. |
| `.compile.lock`, `.meta.lock` | the panel / the compiler | Locks. |

Safety caps applied by every compile (panel and worker): `0.0.0.0/0` / `::/0` always dropped; allow wider than /16 or /32 dropped; block wider
than /8 or /32 dropped; block covering private / loopback / link-local space or `own` dropped. `force` keeps all but `0/0`.

Log reasons: `IPL_ALLOW:<id>`, `IPL_BLOCK:<id>`, and `SH_IPL_ALLOW:<id>` / `SH_IPL_BLOCK:<id>` for a monitor list.
Job type: `iplist_compile` (no parameters). Audit event: `iplist` (create, edit, toggle, delete, rollback, with before / after).

## Platform notes

- **WordPress**: `auto_prepend_file` recommended. Typical exemptions:
  `/wp-cron.php`, `/xmlrpc.php`, and `/wp-json/` when headless clients exist.
  `admin-ajax.php` POSTs are safe by default: a POST is only challenged when `challenge.gate_post` is on.
- **OpenCart**: `auto_prepend_file`, or the top of the catalog `index.php`.
  Typical exemptions via query param: `'route' => array('payment/', 'api/')`.

**Before enabling `enforce.challenge`, exempt every server-to-server endpoint** —
payment gateway callbacks, webhooks, cron URLs, feeds and REST endpoints. Every
GET (and HEAD) is challenged, whatever `Accept` or `X-Requested-With` it
carries: those headers are chosen by the client, so they cannot decide who is
let through. A POST is only challenged when `challenge.gate_post` is on. A
browser's own XHR and `fetch()` calls carry the token cookie and are unaffected;
a server-to-server GET has no cookie and must be exempted.

## Honeypot

Two one-line additions to the host site. In `robots.txt`:

```
Disallow: /old-archive
```

And in the site template:

```html
<a href="/old-archive" style="position:absolute;left:-9999px" tabindex="-1" rel="nofollow" aria-hidden="true">archive</a>
```

Real users never see it; a client that follows it is labelled for 7 days.

## Log rotation

`scripts/guard-logrotate.sh` compresses finished days (gzip, roughly a tenth of the size),
deletes archives older than `log_retention_days` (default 60) and, when `log_max_mb` is
set, deletes the oldest archives until all log files fit under it. It reads these from the
effective config (`guard/config.php` plus the panel), so changes in **Settings → Log
storage** apply on its next run. Install it once (as the account user):

```
10 3 * * * /full/path/bot-guard/scripts/guard-logrotate.sh >/dev/null 2>&1
```

If `php` is not on cron's PATH, put `GV_PHP=/full/path/to/php` at the top of the crontab;
without PHP the script uses the defaults (60 days, no cap). Each run writes
`logs/.last-rotate`; the dashboard card **Log storage** warns when rotation never ran or
is more than two days old.

| Setting | Default | Effect |
|---|---|---|
| `log_skip_paths` | none | Path prefixes never written to the log (e.g. `/gv-admin/`). The guard still checks them; `exempt_paths` is what skips the checks, and those requests are still logged as `exempt`. |
| `log_retention_days` | 60 | Archives older than this are deleted (1-3650). |
| `log_max_mb` | 0 (off) | Total size cap for all `guard-*` files. Oldest archives go first; today's file is never deleted, and a run where it alone is over the cap says so. |
| `log_floor_delete` | Default false. Lets `scripts/guard-logrotate.sh` delete the oldest archives when free disk space is below `log_min_free_mb`. Off: the condition is only reported. Settings -> Log storage. |
| `log_floor_keep_days` | Default 7, minimum 1. Archives newer than this are never deleted for the disk floor; at most 10 files are deleted per run. Only matters when `log_floor_delete` is on. |
| `log_min_free_mb` | 200 | Below this much free space on the log disk the guard stops writing request logs (the site keeps answering) and writes `disk_low` to `guard-errors.log` (at most once a minute). 0 = off. It sees the file system, not a cPanel quota: use `log_max_mb` for a quota. |

Rough size: a decision line is 450-650 bytes, an outcome line about 80. One million PHP
requests a day is about 0.6 GB for the live day and 60-90 MB per compressed day.

## KPIs

```bash
# 1. Challenge success rate — token_issued vs challenge. Target >= ~95%.
jq -r 'select(.act=="challenge" or .act=="token_issued")|.act' logs/guard-*.jsonl | sort | uniq -c

# 2. Top scored IPs and UA hashes.
jq -r 'select(.sc>=30)|[.sc,.ip,.uah]|@tsv' logs/guard-*.jsonl | sort -k2 | uniq -c -f1 | sort -rn | head -20

# 3. Shadow-action distribution — what enforcement would have done.
jq -r 'select(.sh==1)|.act' logs/guard-*.jsonl | sort | uniq -c | sort -rn
```

To try the guard locally, see "Try it locally" in the [README](../README.md).
The rollout order is in [ROLLOUT.md](../ROLLOUT.md).
