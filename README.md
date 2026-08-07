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
| `signals.reputation` | Phase 2. Add `gv:rep:{dev}` to the score. Default off (shadow). |
| `signals.ml` | Phase 2. Add the scaled `gv:ml:{dev}` anomaly level to the score. Default off (shadow). |
| `ml_weight` | Phase 2. Multiplier turning an anomaly level of 0..100 into a score contribution. Default 0.4. |
| `bot_suffixes` | Phase 2. Reverse-DNS suffixes per known bot. Consumed by the Python verifier; kept here as one source of truth. |

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

---

# Phase 2 — offline analyzer

Phase 2 adds an **out-of-band Python analyzer** (`analyzer/`) that reads these
same JSONL logs, writes verdicts into Redis, and stops there. It never sees a
live request, never blocks and never challenges — the in-band PHP guard remains
the only component that touches traffic. The guard reads the verdicts as cheap
Redis GETs and folds them into the score it already computes.

Everything Phase 2 adds is **shadow-first**: the verdicts are always logged, but
only change a decision once you switch a `signals` toggle on. See
`analyzer/README.md` for the analyzer's own operator guide.

## Requirements

Python 3.8+ and `python3 -m pip install -r analyzer/requirements.txt` (redis,
scikit-learn, numpy). Redis must be reachable by both the PHP guard and the
analyzer — it is the only channel between them. Without Redis both sides simply
degrade: the guard runs as in Phase 1, the analyzer computes and reports without
storing.

## Verdict contract

All keys are written by Python and read by PHP. All are optional — absence means
no signal — and all carry a TTL, so a stopped analyzer cannot pin a stale
verdict forever.

| key | writer | value | TTL | effect in the guard |
|-----|--------|-------|-----|---------------------|
| `gv:botok:{ip}` | `run_verify` | `"1"` | 86400 | The UA-claimed bot is forward-confirmed. Logged as `botv=ok`; the known-bot pass stands. |
| `gv:botbad:{ip}` | `run_verify` | `"1"` | 86400 | The UA claims a known bot but reverse DNS failed. Logged as `botv=bad`; **revokes** the pass and adds `BOT_FAKE` (+35). |
| `gv:rep:{dev}` | `run_nightly` | signed int, clamped [-50, 80] | 2592000 | Behavioural reputation. Logged as `rep`; added to the score when `signals.reputation` is on. |
| `gv:ml:{dev}` | `run_nightly` | int 0..100 | 86400 | Isolation Forest anomaly level. Logged as `ml`; `round(ml * ml_weight)` is added when `signals.ml` is on. |

Positive reputation is suspicious, negative is trustworthy — the same sign
convention the static score uses. `botok`/`botbad` are per IP because bots do
not carry the cookie; `rep`/`ml` are per device because they describe a browsing
identity.

`BOT_FAKE` is deliberately **not** gated by any toggle: it is part of the static
score, because a revoked bot claim is a hard signal. It still does not block on
its own (+35 is below the default `hard_block_score`) — an impersonator is
scored like any other client, not summarily blocked.

## Cron

```
*/10 * * * * /full/path/bot-guard/scripts/analyzer-cron.sh verify  >/dev/null 2>&1
17 4   * * * /full/path/bot-guard/scripts/analyzer-cron.sh nightly >/dev/null 2>&1
41 5   * * 0 /full/path/bot-guard/scripts/analyzer-cron.sh train   >/dev/null 2>&1
```

Each mode takes its own `flock`, so overlapping firings skip cleanly rather than
writing partial verdicts.

## New log fields

`botv` (`ok` / `bad` / empty), `rep`, `ml` (`-1` means no verdict), and `esc` —
the effective score. `sc` remains the pure static score, so `esc` next to `sc`
shows exactly what the new signals contributed.

```bash
# Distribution of bot verification verdicts.
jq -r 'select(.bot!="")|.botv' logs/guard-*.jsonl | sort | uniq -c | sort -rn

# Requests where the Phase 2 signals actually moved the score.
jq -c 'select(.esc != .sc)|{ip,dev,sc,esc,rep,ml,act,sh}' logs/guard-*.jsonl

# Top devices by anomaly level.
jq -r 'select(.ml>=0)|[.ml,.dev]|@tsv' logs/guard-*.jsonl | sort -rnu | head -20
```

## Keep the two configs in sync

`known_bots` and `bot_suffixes` live in **both** `guard/config.php` and
`analyzer/config.py`. They are one contract seen from two sides: the analyzer
decides which addresses are impersonators, the guard honours the verdict. If
they drift, the guard keeps passing a UA the analyzer never checks.

## Evaluating the signals

To generate labelled bot traffic, point a headless browser or HTTP client you
control at a **staging copy** of the site, let it browse, then run the nightly
job and confirm those device ids come back with a high `ml` and a positive
`rep`. Compare against your own real browsing session on the same staging copy.

## Phase 2 rollout

1. Install the requirements and wire both cron jobs. Leave
   `signals.reputation` and `signals.ml` **off**.
2. Run about two weeks. `botv`, `rep`, `ml` and `esc` appear in every log line
   while `esc` still equals `sc` — nothing can change a decision yet.
3. Read the logs. Check that devices you believe are human carry a negative
   `rep`, and that `esc` would only have moved requests you are happy to move.
4. Enable `signals.reputation`. Watch the `403` and `challenge` rates.
5. Later, enable `signals.ml`, and tune `ml_weight` (and the reputation weights
   in `analyzer/reputation.py`) from what the logs show.

Bot verification needs no toggle and is safe from day one — it only ever
replaces a blind pass with a checked one.

---

# Phase 3 — measure, tune, then classify

Phase 3 adds no new detection surface. It makes the first two phases
**measurable**: a control group that produces unbiased outcome data, a replay
tool that answers "what would this change have done?" against real history, a
report that turns the KPIs into one command, a fast escape hatch for false
positives — and only then a supervised classifier, trained on labels that do
not come from the guard's own decisions.

## Holdout control group

```php
'holdout_pct'  => 0,                 // 1-2 is the right place to start
'holdout_salt' => 'CHANGE_ME_TOO',   // any stable string
```

A deterministic slice of identities is scored and logged exactly as usual, but
never actually challenged or blocked. Those requests carry `hold=1` and the
intended action with `sh=1`, so the report can compare the enforced population
against a population nothing was done to.

**What it costs:** those requests are genuinely unprotected. At 1% that is one
visitor in a hundred, which is why the value is clamped at 5 — it is a
measurement sample, not a bypass.

**What it buys:** the only unbiased outcome data the system has. Every other
label is contaminated by enforcement — `challenge_unsolved` means "we
challenged it and it did not answer", which says as much about the guard as
about the client. The holdout is also the only way to estimate **false
negatives** at all: whatever the holdout shows and the enforced population does
not is what enforcement is hiding from you.

Rate limiting (`429`) is never held out. It is resource protection, not
classification, and the holdout must not become a way to hammer the site.

**Identity limitation:** a holdout identity is never challenged, so it never
receives a token, so it has no stable `dev` and falls back to `ip|uah`. Holdout
data is therefore **sound in aggregate only** — the nightly job deliberately
writes no per-device reputation or classifier verdict from holdout sessions.

Changing `holdout_salt` reshuffles who is in the holdout, so change it rarely.

## Operator overrides

```bash
python3 analyzer/ctl.py show  <device_id|ip>     # run this FIRST
python3 analyzer/ctl.py allow <device_id> --ttl 3600
python3 analyzer/ctl.py deny  <device_id|ip> --ttl 86400
python3 analyzer/ctl.py list  [--kind allow|deny]
python3 analyzer/ctl.py clear <device_id|ip>
```

When someone reports being blocked, `ctl.py show` is the first response: it
prints every `gv:` verdict for that identity — reputation, anomaly level,
classifier level, bot verification, honeypot history and any override — which
usually explains what happened without reading a log line. The device id is the
leading field of the `_gv` cookie.

**Allow is ungated, deny is not.** A permissive override can only ever make the
guard less strict, so it is safe in any mode and takes effect on the customer's
very next request — it is the five-second fix. A restrictive override is an
enforcement action, so it respects `enforce.block` like everything else;
otherwise monitor mode would no longer mean what you were promised. Allow wins
over deny. Every override carries a TTL, and TTLs above 30 days are refused: an
override that never expires is a config change in disguise.

## New config keys

| key | meaning |
|-----|---------|
| `holdout_pct` | Percent of identities measured but never enforced against. 0 = off, clamped at 5. |
| `holdout_salt` | Stable string that fixes holdout membership. Changing it reshuffles the sample. |
| `signals.clf` | Add the scaled `gv:clf:{dev}` classifier level to the score. Default off (shadow). |
| `clf_weight` | Multiplier turning a classifier level of 0..100 into a score contribution. Default 0.5. |

## New log fields

`clf` (classifier level, `-1` = no verdict), `hold` (1 = in the holdout) and
`ovr` (`allow` / `deny` / empty). A new action, `allow_override`, appears when a
permissive override short-circuits the request.

## Phase 3 rollout

1. **Enable the holdout first** — `holdout_pct = 1` and a real `holdout_salt` —
   and let it fill for a couple of weeks. Everything downstream reads better
   with a control group in the data.
2. **Never touch a threshold without replaying it.** `analyzer/replay.py` tells
   you exactly what a change would have done to traffic you already have.
3. **Run the report weekly.** It is what turns "enable the next toggle" from a
   leap into a decision.
4. **Enable `signals.clf` last**, and only after the classifier's precision on
   held-out data is above target — `run_nightly.py --train-clf` prints it on
   every training run, and says so in words when the target was not reached.

Bot verification and the holdout need no toggle. Everything else stays
shadow-first.
