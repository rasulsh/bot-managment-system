# Upgrade notes

What changed in each release and what to do about it. Newest first.

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
