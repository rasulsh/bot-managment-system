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

`guard/rules.cache.php` is generated by the panel from this file on every save (enabled rules only, compiled patterns); do not edit it, it is gitignored and web-protected like the rest of `guard/`.

At least one of `ua` / `path`. Limits: 200 rules, 50 values per condition, 300 chars per value.
Conditions of one rule are AND-ed.

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
