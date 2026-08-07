# Bot Guard — Phase 1

A drop-in request guard for any PHP application. One `require` (or one
`auto_prepend_file` line) in front of WordPress, OpenCart, Laravel or plain PHP:
every top-level HTML navigation from a client that cannot run JavaScript and
keep a cookie is challenged, every request is written to a JSONL log, and an
instant kill switch is one `touch` away. Redis is **optional** — without it the
guard runs in degraded mode where rate limiting and honeypot history are off but
logging, static scoring and the whole token/challenge handshake keep working
(both are stateless by design). Every path fails open: a Throwable, a missing
Redis or an unwritable log directory results in a silent allow. The guard may
fail; the site may not. IP is treated as a weak signal throughout (CGNAT, mobile
carriers and shared VPN egress are normal), so the guard never hard-blocks on IP
alone and always prefers a challenge over a block.

## Requirements

PHP 7.4+ (no Composer, no extensions, no external dependencies). Redis optional.

## Install

Copy this directory anywhere outside the web root, then pick one entry point.

- `.user.ini` (PHP-FPM / LiteSpeed / CGI): `auto_prepend_file=/full/path/bot-guard/prepend.php`
- `.htaccess` (mod_php / lsapi): `php_value auto_prepend_file /full/path/bot-guard/prepend.php`
- global `php.ini`: `auto_prepend_file = /full/path/bot-guard/prepend.php`
- fallback — first line of the host front controller: `require '/full/path/bot-guard/prepend.php';`

`auto_prepend_file` is preferred: it runs before any application code or page
cache layer and needs zero host-app changes. Then set a real secret in
`guard/config.php`: `openssl rand -hex 32`. Never commit it.

## Configuration (`guard/config.php`)

| key | meaning |
|-----|---------|
| `secret` | HMAC key for tokens and nonces. While it equals `CHANGE_ME` every enforce toggle is forced off (monitor only). |
| `cookie_name` | Token cookie name. |
| `token_ttl` | Token lifetime in seconds (default 7 days). |
| `nonce_ttl` | Challenge nonce lifetime in seconds. |
| `enforce.block` | Serve 403 on hard-score navigations. Stage 1. |
| `enforce.challenge` | Serve the JS challenge to token-less navigations. Stage 2. |
| `enforce.ratelimit` | Serve 429 over the limits. Stage 3. |
| `hard_block_score` | Score at or above which a navigation is a block candidate. |
| `limits.window` | Fixed counter window in seconds. |
| `limits.device` / `ip_ua` / `ip` / `bot` | Requests per window per device token, per IP+UA pair, per IP, per known bot. The IP limit is deliberately generous. |
| `honeypot_path` | Hidden path that must 404 today. A hit marks the IP for 7 days. |
| `exempt_paths` | URI prefixes the guard skips entirely. |
| `exempt_params` | `param => array of value prefixes` the guard skips, e.g. `'route' => array('payment/')`. |
| `known_bots` | Lowercase UA substrings allowed through under their own bucket. |
| `cdn_ranges` | IPv4 CIDRs. `X-Forwarded-For` is trusted only when `REMOTE_ADDR` is inside one, and then only its last entry. |
| `redis` | `host`, `port`, `timeout` (0.05 s: fail fast, never stall a page). |
| `log_dir` | JSONL destination. |
| `strings` | `lang`, `dir`, `title`, `sub`, `noscript` — the only user-facing text; translate here, the code stays English. |

## Platform notes

- **WordPress**: `auto_prepend_file` recommended. Typical exemptions:
  `/wp-cron.php`, `/xmlrpc.php`, and `/wp-json/` when headless clients exist.
  `admin-ajax.php` POSTs are already safe under the non-navigation rule.
- **OpenCart**: `auto_prepend_file`, or the top of the catalog `index.php`.
  Typical exemptions via query param: `'route' => array('payment/', 'api/')`.

**Before enabling `enforce.challenge`, exempt every server-to-server endpoint** —
payment gateway callbacks, webhooks, cron URLs, feeds and REST endpoints. The
non-navigation rule already means POST, XHR and non-HTML clients are never
challenged or blocked by the challenge rule, but exemptions are the explicit
guarantee.

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

## Rollout

1. Set a real `secret`. 2. Run 14 days in monitor mode and read the logs.
3. Enable `enforce.block`. 4. After a few quiet days enable `enforce.challenge`.
5. Tune `limits` from the observed counters. 6. Enable `enforce.ratelimit` last.

Kill switch — takes effect on the very next request, no restart:

```bash
touch /full/path/bot-guard/guard.off      # off;  rm guard.off to re-arm
```

Log rotation (compresses finished days, drops archives after 60 days):

```
10 3 * * * /full/path/bot-guard/scripts/guard-logrotate.sh >/dev/null 2>&1
```

## KPIs

```bash
# 1. Challenge success rate — token_issued vs challenge. Target >= ~95%.
jq -r 'select(.act=="challenge" or .act=="token_issued")|.act' logs/guard-*.jsonl | sort | uniq -c

# 2. Top scored IPs and UA hashes.
jq -r 'select(.sc>=30)|[.sc,.ip,.uah]|@tsv' logs/guard-*.jsonl | sort -k2 | uniq -c -f1 | sort -rn | head -20

# 3. Shadow-action distribution — what enforcement would have done.
jq -r 'select(.sh==1)|.act' logs/guard-*.jsonl | sort | uniq -c | sort -rn
```

## Local testing

```bash
php scripts/guard-selftest.php                     # unit self-test, exit 0 on success
php -S 127.0.0.1:8080 scripts/dev-router.php &     # full guard in front of a stub page
bash scripts/guard-test.sh http://127.0.0.1:8080   # HTTP matrix
```

The dev router uses `scripts/config.dev.php`: a public secret, all enforce
toggles on and tiny limits. **It is test-only and must never be deployed.**
Without Redis the matrix shows degraded behaviour (`rd=1` in the logs, no 429 in
case 8) — that is the expected result, not a failure.
