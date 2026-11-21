# Bot Guard — Setup Guide

This is the exact installation and configuration process. It assumes the target
is typical shared or managed PHP hosting (cPanel / LiteSpeed / Apache). Adapt
paths to your host.

The golden rule: **install in monitor mode, run for two weeks, then enforce one
step at a time.** Do not skip the monitor period.

---

## Prerequisites

- **PHP 8.0 or newer**. No PHP extensions are required for the guard — the Redis
  client is a raw socket implementation. (The overlay is read from disk on every
  request; there is no APCu cache.)
- **Redis** reachable from PHP (default `127.0.0.1:6379`). The guard works without
  it, but in a degraded mode that can only ever allow — Redis is what makes rate
  limiting and offline verdicts function.
- **Python 3.9+** for the analyzer, with `redis`, `scikit-learn`, and `numpy`
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

### Layout (supported)

Keep the repository outside the document root and expose only the panel:

```bash
# repository outside the docroot, guard wired by auto_prepend_file
/home/USER/bot-guard/                      # repo
# panel under a name you choose, by symlink (create it as the web user so
# SymLinksIfOwnerMatch accepts it)
ln -s /home/USER/bot-guard/panel /home/USER/public_html/gv-admin
```

Apache alternative (LiteSpeed Enterprise reads the same config):

```apache
Alias /gv-admin /home/USER/bot-guard/panel
<Directory /home/USER/bot-guard/panel>
	AllowOverride All
	Options FollowSymLinks
	Require all granted
</Directory>
```

Notes verified on Apache 2.4 and OpenLiteSpeed 1.9: `.htaccess` needs `AllowOverride All`
(or `AuthConfig Limit FileInfo`; a partial set gives a 500, which fails closed). The
rewrite fallback needs `FollowSymLinks`/`SymLinksIfOwnerMatch`. OpenLiteSpeed ignores
`Require`/`Order` in `.htaccess` and relies on the rewrite rule. With `AllowOverride None`
nothing protects an in-docroot install - another reason to use this layout. The panel
cookie path becomes `/gv-admin/`; add that prefix to `exempt_paths`. Then verify:

```bash
bash scripts/exposure-check.sh https://example.com /gv-admin
```

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

You should see one JSON line per request. A line with `"sh":1` (for example
`"act":"challenge"`) means "shadow": the guard would have done this, but monitor
mode let the request through. The site answers as usual.

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

Use the wrapper `scripts/analyzer-cron.sh`, which takes a `flock` so overlapping
firings skip cleanly (the modes that write models or verdicts share one lock). If
you installed the Python packages in `.venv` as above, add this line at the top of
the crontab, or the jobs run the system `python3`, find no packages and store
nothing while exiting 0:

```cron
GV_PYTHON=/home/youruser/bot-guard/.venv/bin/python
```
 A complete crontab (adjust the absolute path):

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
# only when you use country / ASN rules: recompile the GeoIP databases monthly (see docs/09-ADMIN-PANEL.md, GeoIP)
23 3   1 * * /home/youruser/bot-guard/scripts/analyzer-cron.sh geo       >/dev/null 2>&1
```

The `geo` line only recompiles what is already in `geo/`: download a fresh database yourself (GeoLite2,
DB-IP Lite, IPinfo Lite, or a `geoip.dat`) into `geo/` first. Reading a `.mmdb` needs the `maxminddb` package
(in `analyzer/requirements.txt`; the analyzer still runs without it and only reports the `.mmdb` file as unreadable).

The `snapshot` and `worker` lines are the two most-forgotten and the two whose
absence is hardest to diagnose: without `snapshot`, the panel dashboard is stale;
without `worker`, panel-triggered jobs sit queued forever.

### Every background job, how often, and what breaks without it

| Job (cron mode) | Interval | Required | If it does not run |
|---|---|---|---|
| `verify` | 10 min | yes | Real crawlers never leave the shared `limits.bot_unverified` budget; fake crawlers are not refuted. |
| `worker` | 1 min | yes | Jobs started from the panel (compile GeoIP or IP lists, train, promote, replay) wait in the queue for ever. Small IP lists compile inside the panel request and do not need it. |
| `snapshot` | 15 min | yes | The dashboard numbers (24 h KPIs, top lists, charts) freeze; the dashboard keeps looking normal. |
| `nightly` | 24 h | yes | Reputations and anomaly levels expire (14 d / 24 h) and stop being refreshed; scoring gets weaker. |
| `guard-logrotate.sh` | 24 h | yes | Logs are never compressed or deleted: the disk fills, then the guard stops logging at the floor. |
| `train`, `train-clf` | 7 d | recommended | The model and the classifier age; no new candidate to promote. |
| `geo` | 30 d | only with GeoIP rules | Country / ASN rules run on an ageing database (the panel warns at 45 days). |
| `report` | 7 d | optional | No periodic report. |

The expected interval of each job is editable in Settings > Analyzer; a job is **late** after twice that.

### Is it really running? Job status, error logs and the crontab check

* **Status per job.** Every run of `analyzer-cron.sh` (any mode) and `guard-logrotate.sh` records, in
  `analyzer/.jobstatus-<mode>.json` (read live by the panel): last start, end, success and failure, exit code, duration,
  how many firings were skipped because the lock was busy, the last error lines, warnings and a result (a training run
  records whether a candidate was written, the sample counts and metrics; log rotation records files gzipped and
  deleted, bytes freed and why: retention, `log_max_mb`, or the free-disk floor `log_min_free_mb`). A trap records a crash
  or a signal too. States: **ok**, **warning** (it exited 0 but said it did nothing useful: no input rows, Redis unreachable,
  no model, nothing trained), **late**, **failing**, **never ran**.
* **Error logs.** Each run adds one JSON line to `logs/jobs.log`; a failure also leaves its captured stderr (the last 64 KiB)
  in `logs/jobs-errors.log`. The wrapper captures stderr itself, so nothing is lost although cron sends output to
  `/dev/null`. Both files are rotated and expired by `guard-logrotate.sh`. The Redis password, `secret`, `holdout_salt`
  and the panel's credentials are redacted before anything is written.
* **A wrong `GV_PYTHON`.** The wrapper first checks that the chosen Python can import what the mode needs (`redis`; plus
  `numpy` and `sklearn` for `nightly`, `train`, `train-clf`). If not, the run exits non-zero with the fix in the message and is
  recorded as a failure. It no longer "succeeds" having stored nothing.
* **Crontab check.** `bash scripts/cron-check.sh` (English output; exit 0 = all required entries present and right, 1 =
  something required is missing or wrong, 2 = the crontab could not be read) reads the crontab (`/usr/bin/crontab.cagefs -l`
  on CloudLinux / CageFS, then `crontab -l`) and reports, per job: missing, **disabled** (commented out), **wrong path**
  (another install directory), **runs too rarely** for its interval, duplicates; and a missing or invalid `GV_PYTHON=` line.
  `--json` prints the same as JSON. The panel runs it itself (argv array, no shell, 3 s timeout) when `proc_open` is allowed;
  otherwise it shows `analyzer/.cron-check.json`, which every cron run refreshes (at most every 10 minutes); the live result is cached for 5 minutes (Jobs page: Check again); otherwise it falls
  back to the heartbeats above and says "run scripts/cron-check.sh over SSH". It sees the crontab of the user the panel
  runs as.

### Time zones

Three clocks name the daily files and decide "today", and they can differ: the guard names `logs/guard-YYYYMMDD.jsonl` by
**PHP's** time zone (`date.timezone`), `guard-logrotate.sh` and the Python analyzer use the **system** time zone of the cron
user, and the panel shows times in **PHP's** zone. When PHP and the system disagree, a day's file can be rotated while it is
still being written to (the rotation therefore never touches a file written in the last hour). The dashboard's "last 24 h"
is a rolling window of **timestamps** (epoch seconds), not "today's file", so it does not depend on any of them; the page
header shows the panel's and the analyzer host's zone, and an alert appears when their offsets differ. Fix a mismatch by
setting `date.timezone` in the PHP configuration (and `TZ` in the crontab) to the same zone.

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
3. Expose the panel with the symlink from "Layout (supported)" above, open
   `https://example.com/gv-admin/` and sign in. Step by step, with permissions and
   troubleshooting: [13-PANEL-WEB-ACCESS.md](13-PANEL-WEB-ACCESS.md).

Optionally lock the panel to your own IP addresses: edit `panel/panel.config.php`
and set `ip_allowlist` to single IPv4/IPv6 addresses or CIDR ranges, for example
`array('203.0.113.7', '198.51.100.0/24', '2001:db8::/32')`.

- An empty list means no IP restriction (the login still applies). The panel shows
  a notice on the dashboard while the list is empty.
- A non-empty list in which no entry is valid locks everyone out, on purpose: a typo
  must never switch the restriction off. Fix the file to get back in.
- If the panel is behind your own reverse proxy, load balancer or CDN, add that
  proxy's address to `trusted_proxies`. Only a request that arrives from a trusted
  proxy may name the client in `X-Forwarded-For`; otherwise the header is ignored.
  Leave `trusted_proxies` empty when there is no proxy.
- The same client address is used for the allowlist, the login rate limit and the
  audit trail. Re-running `setpass.php` keeps both lists.

Every panel response carries `X-Robots-Tag: noindex, nofollow, noarchive, nosnippet`
and a robots meta tag. Do **not** add the panel path to `robots.txt`: it would
publish the path, and crawlers that obey it would never see the noindex header.

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
| `hard_block_score` | effective score at/above which a GET is blocked | `60` |
| `holdout_pct` | percent of visitors measured but never enforced against (0–5) | `0` (off; use a few during rollout) |
| `holdout_salt` | stable salt fixing holdout membership | set once |
| `capture_outcomes` | record status/size of allowed requests (Phase 4) | `false` until you want outcome signals |
| `limits.window` / `.device` / `.ip_ua` / `.ip` / `.bot` | fixed-window rate counters | shipped generous |
| `limits.device_hour` / `.device_day` | per-device budgets over an hour and a day, for slow clients on changing addresses | `400` / `1500`; exempt the admin path first |
| `limits.preview` / `preview_bots` | site-wide budget per link-preview fetcher name | `20`; Telegram, WhatsApp, Facebook, X, LinkedIn |
| `challenge.trust_headers` | `true` = old rule, challenge only GETs that ask for HTML (bypassable) | `false` |
| `honeypot_path` | the invisible 404 trap path | `/old-archive` (change per site) |
| `exempt_paths` | URI prefixes the guard never touches | add payment/cron/webhook/admin paths |
| `exempt_params` | query param → value-prefix exemptions | e.g. `route => ['payment/','api/']` |
| `known_bots` | lowercase UA substrings given the fast pass | Google and Bing crawler families |
| `cdn_ranges` | IPv4 CIDRs whose XFF is trusted | empty unless behind a CDN |
| `redis` | host, port, socket, username, password, db, prefix, timeout, breaker_ttl | `127.0.0.1:6379`, no auth, db 0, no prefix, 0.05s, 5s |
| `limits.mint` / `challenge.pow_bits` / `challenge.bind_ip` | token minting cap, proof-of-work bits, nonce IP binding | 60 / 16 / true |
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
