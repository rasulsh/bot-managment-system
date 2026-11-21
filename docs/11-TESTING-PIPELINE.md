# Testing the data pipeline end to end

"I visited the site and nothing shows in the panel." This page explains where the
data goes, why it may not arrive, and how to prove each stage works.

## The pipeline

| # | Stage | Who | Where the evidence is |
|---|---|---|---|
| 1 | PHP loads the guard (`auto_prepend_file`) | PHP, on every PHP request | a new line in the log (stage 2) |
| 2 | One JSON line per request (plus one outcome line after the page is built) | `guard/log.php` | `logs/guard-YYYYMMDD.jsonl` |
| 3 | Counters and verdicts | Redis | `redis-cli -n <db> keys 'gv:*'` (names depend on your prefix) |
| 4 | Dashboard numbers | `scripts/analyzer-cron.sh snapshot`, every 15 min | `analyzer/snapshot.json` |
| 5 | Panel pages | `panel/` | **Logs** reads stage 2 live; **Dashboard** reads stage 4 only |

Two consequences people trip over:

- **Dashboard numbers lag by up to 15 minutes and are zero until the `snapshot` cron has run once.** The **Logs** page has no such delay.
- A request that never reaches PHP is never logged. That is by design (see below).

## Why your own visits may not appear

Check in this order. The dashboard card **Data pipeline** (and the hint on an empty **Logs** page) shows the verdict for the first four.

1. **Guard not loaded.** `auto_prepend_file` is missing, wrong, or a `.user.ini` change is still cached (PHP waits up to 5 minutes, `user_ini.cache_ttl`). `.user.ini` only applies to PHP files in that directory and below.
2. **Page served from a cache without running PHP** (LiteSpeed Cache, a CDN, a full-page cache plugin). Anonymous visits to cached pages are invisible to the guard; logged-in and uncached URLs are not. Test with a URL that is never cached, e.g. `/?gvtest=1234`.
3. **Log directory missing or not writable** by the PHP user. Look at `logs/guard-errors.log` for `log_write_failed`.
4. **Kill switch on** (`guard.off` exists): the guard returns before logging.
5. **Looking at the wrong day.** The Logs page shows today's file by default. PHP names the file with its own `date.timezone`; the analyzer uses the system time zone of the cron user. Keep both on the same zone.
6. **Dashboard too early**: see above; run `scripts/analyzer-cron.sh snapshot` by hand.
7. **Your visits come from an address you did not expect.** Behind a CDN or proxy the guard sees the proxy's address unless `cdn_ranges` lists it (the panel has its own `trusted_proxies`, see docs/09). Filter the Logs page by path instead of address.

## Manual test on the real server

Run these on the server, in the guard directory (`cd /home/youruser/bot-guard`).

1. Make a request that cannot come from a cache and mark it:
   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' -A 'Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0' 'https://YOUR-SITE/?gvtest=step1'
   ```
2. Check it was logged (wait up to 5 minutes after any `.user.ini` change):
   ```bash
   grep gvtest logs/guard-$(date +%Y%m%d).jsonl | tail -3
   ```
   One line expected. If there is none, the cause is stage 1, 2 or 3 above. Nothing else is worth checking before this works.
3. Repeat from another machine or network (a phone on mobile data) with `?gvtest=step3`. The `ip` field must show that machine's address, not yours.
4. Open the site in 3 browser tabs at once, reload each. Expect one line per request, all with the same `dev` value once the browser holds a token (`tok` is `v`).
5. Open the panel, **Logs**, type `gvtest` in the path filter. The same rows appear within a second.
6. Build the dashboard numbers now instead of waiting:
   ```bash
   scripts/analyzer-cron.sh snapshot
   ```
   Reload the **Dashboard**: *requests* must be at least the number of lines in today's file.

## Automated test (no server needed)

```bash
bash scripts/e2e-pipeline.sh
```

It starts a private PHP server, Redis and log directory, and sends real traffic:

- 5 different client addresses (separate `127.0.0.x` source addresses), 3 requests each
- one browser with 6 parallel tabs sharing a cookie, plus a second browser with its own cookie, checking one token and one device id per browser
- 200 requests, 20 at a time, from 10 addresses, checking no line is lost or torn
- HEAD, an exempt path, and an application 404 with its outcome
- the analyzer snapshot, then the panel's own readers (paging, address, path, status and action filters), comparing counts at every stage

It needs `php`, `curl`, `python3` and `redis-server`. Expected last line: `PASS 35  FAIL 0`.

It cannot test: a real cache or CDN in front of PHP, real browsers, IPv6 on your network, or your server's `auto_prepend_file`. Those need the manual test above.

## Panel layout (tabs, tooltips, include / exclude filters)

```bash
php scripts/panel-selftest.php        # filter parser / matchers (every operator), chips, tabs markup, tooltip texts for every field, CSS
bash scripts/panel-layout-test.sh     # real browser (Playwright): every page at 1600 px and 390 px, tabs, tooltips, chips
bash scripts/panel-smoke.sh <url> <panel-path> <user> <pass>   # also runs the layout test when node + playwright exist
```

`panel-layout-test.sh` copies the repository to a temp directory, installs a login there, writes sample log and audit
rows, serves it with PHP's built-in server and runs `scripts/panel-layout-test.js`: no horizontal page scroll at either
width, the wide layout really uses the screen, no console error, CSP violation or request to another origin, tabs by
click / arrow keys / hash, a rejected Settings or Rules save opening the tab with the error, tooltips (tap, Esc, outside
tap, not cut off), filter chips. It needs `node` and `playwright` with Chromium and skips cleanly without them; CI runs it
in the `http` job. Pass a directory to keep screenshots. Nothing is written into the working tree.

## Access rules

```bash
php scripts/guard-selftest.php        # engine: every condition, op, <empty>, regex errors, precedence helpers
bash scripts/rules-e2e.sh             # HTTP: block/challenge/log/monitor + the whole precedence chain
bash scripts/bench-gv-run.sh          # gv_run p50/p99 with 0 / 20 / 200 rules (run on both branches)
```

GeoIP has its own sections in the same suites: `guard-selftest.php` (lookup edge cases on generated range files:
first / last range, gaps, IPv4-mapped IPv6, corrupt / truncated / missing files, unknown-country semantics,
validation, cache), `panel-selftest.php` (upload, rollback, staleness, warnings, tester, impact preview),
`analyzer/selftest.py` (range merging, `geoip.dat`, a generated `.mmdb`, atomic swap, sanity failures, and a check
that PHP and Python resolve the same addresses from the same file) and `rules-e2e.sh` (country rules over HTTP,
precedence, an unplaced visitor, a broken database, and "country rule + Googlebot UA + Redis down"). The
fixtures are generated in temp directories; nothing binary is committed.
`bash scripts/bench-gv-run.sh` also prints the geo rows (`--geo-log`, `--geo-rules=200`, `--geo-rules=200 --geo-ua`,
`--lookup`); `php scripts/bench-gv-run.php --geo-rules=200 --match` times the rule loop alone.

`rules-e2e.sh` needs `php`, `python3`, `curl`, `redis-server`; it creates and removes `guard.off` in the project root.
