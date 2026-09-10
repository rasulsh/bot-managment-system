# Bot Guard — Setup Guide

This is the exact installation and configuration process. It assumes the target
is typical shared or managed PHP hosting (cPanel / LiteSpeed / Apache). Adapt
paths to your host.

The golden rule: **install in monitor mode, run for two weeks, then enforce one
step at a time.** Do not skip the monitor period.

---

## Prerequisites

- **PHP 7.x or 8.x** with the standard library. No PHP extensions are required for
  the guard — the Redis client is a raw socket implementation. `apcu` is
  recommended (used for an optional config-overlay cache; see the performance
  notes) but not required.
- **Redis** reachable from PHP (default `127.0.0.1:6379`). The guard works without
  it, but in a degraded mode that can only ever allow — Redis is what makes rate
  limiting and offline verdicts function.
- **Python 3.8+** for the analyzer, with `redis`, `scikit-learn`, and `numpy`
  (see `analyzer/requirements.txt`). The analyzer degrades gracefully if
  scikit-learn is missing (it just does no ML that run), but you want it for the
  full system.
- **Cron** (or any scheduler) to run the analyzer jobs.
- Shell access for the one-time install steps. After install, everything is driven
  from the panel and cron.

---

## Step 0 — Place the files

Put the repository somewhere **outside** your web root if at all possible, or in a
subdirectory that your `.htaccess` files protect (the repo ships `.htaccess` deny
rules for `guard/`, `logs/`, `scripts/`, and all of `panel/` except `index.php`
and static assets). A common layout:

```
/home/youruser/bot-guard/        <- the repository, outside public_html
/home/youruser/public_html/      <- your site's web root (the host app)
```

Ensure the `logs/` directory is writable by the PHP user:

```bash
mkdir -p /home/youruser/bot-guard/logs
chmod 0775 /home/youruser/bot-guard/logs
```

---

## Step 1 — Create the guard config

Copy the shipped config and edit it (or edit it in place). The file is
`guard/config.php`. The two things you must change:

```bash
cd /home/youruser/bot-guard
# generate a real secret:
openssl rand -hex 32
```

Open `guard/config.php` and set:

- **`secret`** — paste the value from `openssl rand -hex 32`. **This is the master
  switch.** While `secret` is still the placeholder `CHANGE_ME`, every enforcement
  toggle is forced off no matter what else the config says — that is the built-in
  guarantee that an unconfigured install cannot affect a live site. Setting a real
  secret is what makes enforcement *possible* (not active — you turn that on later).
- **`holdout_salt`** — any stable random string (a second `openssl rand -hex 32` is
  fine). Changing it later reshuffles which visitors are in the holdout, so pick it
  once.

Leave **everything else at its defaults for now.** In particular, leave all
`enforce` toggles `false` and all `signals` toggles `false`. That is monitor mode,
and it is where you start.

Also set, appropriate to your site:

- **`honeypot_path`** — a URL that returns 404 on your site today and that no human
  would ever visit (e.g. `/old-archive`). You will link to it invisibly later
  (see the Honeypot section below). It must currently 404.
- **`strings`** — the interstitial's language and text. It ships in Persian/RTL;
  change `lang`, `dir`, and the messages if your audience is different.
- **`cdn_ranges`** — leave empty unless you are behind a CDN. If you are, this is
  the list of the CDN's IPv4 ranges; only then will the guard trust
  `X-Forwarded-For` to find the real client IP. (Note: CIDR matching is IPv4 only
  — see the code review if you are on an IPv6 CDN.)
- **`exempt_paths`** — URI prefixes the guard must never touch: payment callbacks,
  cron endpoints, health checks, webhooks. For a CMS, add its admin and API paths
  here (examples in the CMS Integration doc).

---

## Step 2 — Wire the guard into the request path

The guard runs via `prepend.php` as PHP's `auto_prepend_file`. Point PHP at it.

**cPanel (MultiPHP INI Editor), or `.user.ini` in your web root, or `php.ini`:**

```ini
auto_prepend_file = "/home/youruser/bot-guard/prepend.php"
```

If you use `.user.ini`, place it in your web root; changes take effect after the
FastCGI TTL (a few minutes) or a PHP restart.

**Verify it is loaded** without enforcing anything: load your site normally. It
should behave exactly as before (you are in monitor mode). Then check that a log
file appeared:

```bash
ls -la /home/youruser/bot-guard/logs/
tail -1 /home/youruser/bot-guard/logs/guard-*.jsonl
```

You should see one JSON line per request, each with `"act":"allow"` (or `exempt`)
and `"sh":1` on any it would have acted on (the `sh:1` means "shadow" — it would
have done this, but monitor mode allowed it).

If nothing appears, the prepend is not loading. Confirm the `auto_prepend_file`
path is absolute and correct and that PHP restarted.

---

## Step 3 — Install the analyzer

```bash
cd /home/youruser/bot-guard
python3 -m venv .venv            # optional but recommended
. .venv/bin/activate
pip install -r analyzer/requirements.txt
```

Confirm it runs against your (currently small) logs:

```bash
python3 analyzer/run_nightly.py --dry-run
```

`--dry-run` computes everything and reports but writes no verdicts. You want to see
it read your rows and sessions without error. It is normal this early for it to say
there is too little data to train a model.

The analyzer's own settings live in `analyzer/config.py` and can be overridden via
a JSON or Python file pointed to by `GV_ANALYZER_CONFIG`. The default `log_dir`
and `redis` match the guard's; you only need to override if you moved things.

---

## Step 4 — Schedule the analyzer (cron)

Use the wrapper `scripts/analyzer-cron.sh`, which takes a `flock` per mode so
overlapping firings skip cleanly. A complete crontab (adjust the absolute path):

```cron
# reverse-DNS bot verification, frequent
*/10 * * * * /home/youruser/bot-guard/scripts/analyzer-cron.sh verify    >/dev/null 2>&1
# nightly behavioural scoring + anomaly levels
17 4   * * * /home/youruser/bot-guard/scripts/analyzer-cron.sh nightly   >/dev/null 2>&1
# weekly candidate retrain (trains a candidate; promote it explicitly to go live)
41 5   * * 0 /home/youruser/bot-guard/scripts/analyzer-cron.sh train     >/dev/null 2>&1
11 6   * * 0 /home/youruser/bot-guard/scripts/analyzer-cron.sh train-clf >/dev/null 2>&1
# dashboard snapshot for the panel (do NOT forget this one)
*/15 * * * * /home/youruser/bot-guard/scripts/analyzer-cron.sh snapshot  >/dev/null 2>&1
# panel job queue worker (do NOT forget this one either)
*    * * * * /home/youruser/bot-guard/scripts/analyzer-cron.sh worker    >/dev/null 2>&1
# daily log rotation (gzip finished days, delete old archives)
10 3   * * * /home/youruser/bot-guard/scripts/guard-logrotate.sh         >/dev/null 2>&1
# optional weekly report by email
30 7   * * 1 /home/youruser/bot-guard/scripts/analyzer-cron.sh report | mail -s "Bot Guard weekly" you@example.com
```

The `snapshot` and `worker` lines are the two most-forgotten and the two whose
absence is hardest to diagnose: without `snapshot`, the panel dashboard is stale;
without `worker`, panel-triggered jobs sit queued forever.

---

## Step 5 — Install the admin panel (optional but recommended)

The panel is optional — the guard and analyzer work without it. To install it, set
credentials from the command line (there is no web setup wizard by design):

```bash
php /home/youruser/bot-guard/panel/setpass.php
```

It prompts for a username and a password (minimum 12 characters, because this
panel can change enforcement for the whole site) and writes
`panel/panel.config.php` (mode 0600) containing a password hash and a session
secret. Until this command has been run, every panel route returns a bare 404.

Then, per the tool's own post-install advice:

1. **Add the panel's URL path to `exempt_paths`** in `guard/config.php`, so your
   own bot guard cannot challenge you out of your own admin panel.
2. Make sure the `snapshot` and `worker` cron lines from Step 4 are present.
3. Open `panel/index.php` in a browser and sign in.

Optionally lock the panel to your own IP range: edit `panel.config.php` and set
`ip_allowlist` to a list of IPv4 CIDRs (e.g. `array('203.0.113.0/24')`); empty
disables it.

---

## Step 6 — Set up the honeypot

Pick the `honeypot_path` you configured (e.g. `/old-archive`) and add an invisible
link to it somewhere on your site — typically in the footer, hidden from humans:

```html
<a href="/old-archive" rel="nofollow" aria-hidden="true"
   style="position:absolute;left:-9999px">archive</a>
```

Also add it to your `robots.txt` as disallowed, so honest crawlers stay away and
only misbehaving ones follow it:

```
User-agent: *
Disallow: /old-archive
```

Any client that fetches this path gets a 404 and is flagged — a strong,
guard-independent bot signal that also becomes a training label. Confirm the path
genuinely 404s on your site (the guard serves the 404 itself, but the path must not
collide with a real page).

---

## Step 7 — The monitor period (about 2 weeks)

Do nothing else. Let the guard log, let the analyzer score, and watch:

- The **dashboard**: decision mix (how much traffic *would* be challenged/blocked),
  score histograms, and — once you have some — the challenge success funnel.
- The **logs**: spot-check the requests the guard *would* have challenged (`act` of
  `challenge`/`403` with `sh:1`). Confirm they look like bots. Spot-check high-score
  allowed requests and confirm they look like customers.
- The **report** (weekly email or `report` mode): the KPIs in one place.

You are looking for confidence that enforcement will hit bots and not customers.
If a legitimate crawler or an odd-but-real client is scoring high, tune the
weights or add an exemption *now*, while nothing is enforced.

---

## Step 8 — Enable the offline signals (shadow first)

Before enforcing, turn on the offline signals so they show up in the effective
score in the logs — still without changing any outcome (because enforcement is
still off). In the panel Settings (or `guard/config.php`), set `signals.reputation`
(and later `signals.ml`, `signals.clf`) to `true`. Watch the effective-score
column (`esc`) diverge from the static score (`sc`) in the logs and confirm the
divergence is in the right direction (bots up, customers not). Use **replay** in
the panel to preview any threshold change against real history before applying it.

For the classifier specifically: do not enable `signals.clf` until a training run
reports it reached its target precision on held-out data. The training output says
so explicitly and warns if it did not.

---

## Step 9 — Enable enforcement, one mechanism at a time

Now, and only now, turn on enforcement — one toggle, then wait days, then the next:

1. **`enforce.block`** — start blocking the clearest cases (very high effective
   score on a navigation, refuted bot impersonators, deny overrides). Keep a
   holdout: set `holdout_pct` to a few percent so a small unenforced slice keeps
   telling you what you would be missing.
2. **`enforce.challenge`** — start serving the JS/cookie interstitial to token-less
   navigations. Watch the challenge success funnel: if the challenge→token rate
   falls below ~95%, real users are burning on it — investigate before continuing.
3. **`enforce.ratelimit`** — start returning 429 to clients over the rate ceilings.
   The limits ship deliberately generous (CGNAT reality); tighten them only with
   replay evidence.

After each toggle, watch the dashboard and the identity page. When a customer
reports being blocked, open their identity page, see which signal caught them, and
if they are real, set an `allow` override (`ctl.py allow <id> --ttl 3600` or the
panel) — it takes effect on their next request.

---

## Configuration reference (`guard/config.php`)

| Key | Meaning | Safe default |
|---|---|---|
| `secret` | HMAC master secret; **while `CHANGE_ME`, all enforcement is forced off** | set to `openssl rand -hex 32` |
| `cookie_name` | the guard's token cookie name | `_gv` |
| `token_ttl` | how long a solved-challenge token lasts | `604800` (7 days) |
| `nonce_ttl` | how long a challenge nonce is valid | `120` |
| `enforce.block` / `.challenge` / `.ratelimit` | the three enforcement switches | all `false` (monitor) |
| `signals.reputation` / `.ml` / `.clf` | whether each offline signal adds to the score | all `false` (shadow) |
| `ml_weight` / `clf_weight` | how much the 0–100 model level contributes | `0.4` / `0.5` |
| `hard_block_score` | effective score at/above which a navigation is blocked | `60` |
| `holdout_pct` | percent of visitors measured but never enforced against (0–5) | `0` (off; use a few during rollout) |
| `holdout_salt` | stable salt fixing holdout membership | set once |
| `capture_outcomes` | record status/size of allowed requests (Phase 4) | `false` until you want outcome signals |
| `limits.window` / `.device` / `.ip_ua` / `.ip` / `.bot` | fixed-window rate counters | shipped generous |
| `honeypot_path` | the invisible 404 trap path | `/old-archive` (change per site) |
| `exempt_paths` | URI prefixes the guard never touches | add payment/cron/webhook/admin paths |
| `exempt_params` | query param → value-prefix exemptions | e.g. `route => ['payment/','api/']` |
| `known_bots` | lowercase UA substrings given the fast pass | `['googlebot','bingbot']` |
| `cdn_ranges` | IPv4 CIDRs whose XFF is trusted | empty unless behind a CDN |
| `redis` | host / port / timeout | `127.0.0.1:6379`, 0.05s |
| `log_dir` | where JSONL is written | `../logs` |
| `strings` | interstitial language and text | Persian/RTL by default |

---

## Local testing without a host platform

To exercise the whole flow on your own machine, the repo ships a dev router:

```bash
php -S 127.0.0.1:8080 scripts/dev-router.php
```

Every request passes through the full guard (using the test-only
`scripts/config.dev.php`, which has enforcement on and tiny limits so cases trip
quickly). There are test endpoints under `/t/` for 404, 500, large bodies, custom
headers, and fatal errors, used by the self-tests to verify outcome capture. Never
deploy `config.dev.php` — its secret is public.

The self-tests (`scripts/guard-selftest.php`, `scripts/panel-selftest.php`,
`analyzer/selftest.py`, `scripts/guard-test.sh`, `scripts/decision-parity.php`)
are the reference for expected behaviour and the parity between the PHP and Python
decision logic.
