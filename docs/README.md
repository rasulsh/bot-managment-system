# Bot Guard

A self-hosted bot and scraper defense system for PHP websites. It scores every
request in front of your application, and — once you turn it on — challenges,
rate-limits, or blocks automated traffic while leaving real visitors untouched.

It is built to be **safe by default**: out of the box it only watches and logs,
enforcing nothing, and it fails open on every error so it can never take your
site down. You turn up enforcement gradually, one mechanism at a time, after you
have watched it and trust it.

---

## Table of contents

- [What it is](#what-it-is)
- [How it works at a glance](#how-it-works-at-a-glance)
- [Design principles](#design-principles)
- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [The rollout, in one paragraph](#the-rollout-in-one-paragraph)
- [Configuration](#configuration)
- [The admin panel](#the-admin-panel)
- [Operating it](#operating-it)
- [Testing](#testing)
- [Documentation](#documentation)
- [Requirements](#requirements)

---

## What it is

Three cooperating parts, communicating only through Redis and daily log files:

- **The guard** (`guard/`, `prepend.php`) — PHP that runs on every request, in the
  request path. It scores the request, reads a few cheap Redis keys, and decides:
  allow, challenge, rate-limit, or block. It never does DNS, never runs a machine-
  learning model, never scans logs — all of that is done out of band and left in
  Redis as small integers for the guard to read. Any error → the request is
  allowed and your app runs normally.
- **The analyzer** (`analyzer/`) — Python that runs on cron. It reads the guard's
  logs, verifies bot claims with reverse DNS, computes a transparent behavioural
  reputation per visitor, trains and runs two ML models (an anomaly detector and a
  supervised classifier), and writes verdicts back to Redis. It never touches the
  request path.
- **The panel** (`panel/`) — an optional Persian/RTL web console for one operator:
  traffic dashboards, a log explorer, per-visitor override controls, a "what would
  this config change have done" replay, and analyzer job controls. It writes config
  as validated JSON; it never writes PHP and never runs a shell command.

## How it works at a glance

```
Request ─▶ PHP ─▶ prepend.php ─▶ guard ─┬─ allow ─────▶ your app runs (0 bytes from the guard)
                                         ├─ exempt ────▶ your app runs
                                         ├─ challenge ─▶ JS/cookie interstitial (a script can't solve it)
                                         ├─ 429 ───────▶ rate limited
                                         ├─ 403 ───────▶ blocked
                                         └─ any error ─▶ fail open, your app runs

   guard  ──writes──▶  logs/guard-YYYYMMDD.jsonl  ──reads──▶  analyzer (cron)
   guard  ──reads───▶  Redis verdicts  ◀──writes──  analyzer
   panel  ──reads───▶  logs + snapshot + Redis,  ──writes──▶  config.local.json + job queue
```

A normal visitor sees nothing (their first HTML page load flashes a sub-second
"please wait" interstitial that sets a week-long cookie; every page after is
invisible). A scraper accumulates a score and a bad reputation and — once
enforcement is on — gets challenged, throttled, or blocked. A verified good crawler
(confirmed by reverse DNS out of band) gets a fast pass and is never challenged.

## Design principles

Everything here follows from one belief: **blocking a paying customer costs far
more than missing a scraped page.**

- **Monitor first.** Ships in monitor mode — scores and logs everything, enforces
  nothing. While `secret` is still `CHANGE_ME`, enforcement is *forced* off no
  matter what the config says. An unconfigured install cannot affect a live site.
- **Fail open, always.** Every Redis error, every exception, every missing file
  degrades to "allow." A Redis outage can only make the guard more permissive,
  never break the site.
- **Nothing slow in the request path.** No DNS, no model scoring, no log scanning
  in-band. The analyzer does the expensive work on cron and leaves a cheap integer
  in Redis.
- **The response is never buffered.** Outcome capture reads the declared
  `Content-Length` at shutdown — streaming and downloads are untouched.
- **Shadow before enforce.** Every new signal is off by default and visible in the
  logs before it can change a decision. You always see what a change *would* do
  before it does it (in the logs, and interactively via replay).
- **A holdout control group.** A small, deterministic, unenforced slice of traffic
  is kept as a control, so the system can estimate what it is *missing* — the one
  thing enforcement otherwise hides.
- **The panel writes no code and runs no commands.** Config is validated JSON;
  analyzer actions are typed queue jobs run in-process. For a security tool, that
  closes the two classic self-inflicted holes.

## Repository layout

```
prepend.php              Entry point: set as PHP auto_prepend_file. Fail-open loader.
guard/
  guard.php              All request-path decision logic (scoring, decision, config).
  redis.php              Minimal raw-socket Redis (RESP) client — no PHP extension needed.
  challenge.php          HMAC token/nonce + the JS/cookie interstitial.
  log.php                JSONL logger (one line per request).
  outcome.php            Shutdown-time response-outcome capture (status + declared size).
  config.php             Per-deployment configuration (copy/edit this).
analyzer/
  run_verify.py          Cron: forward-confirmed reverse DNS for bot claims.
  run_nightly.py         Cron: sessions → features → reputation → ML/classifier levels.
  snapshot.py            Cron: fold recent logs into snapshot.json for the panel.
  report.py              Period KPI report (text + self-contained HTML).
  worker.py              Cron: drain the panel's job queue (in-process, no shell).
  ctl.py                 Operator CLI: show/allow/deny/clear a visitor, promote a model.
  replay.py              Counterfactual replay of a config change against real logs.
  reputation.py          Transparent additive reputation formula.
  model.py               Isolation Forest anomaly detector (offline only).
  classifier.py          Gradient-boosted bot classifier, tuned for precision (offline).
  features.py            Per-session feature extraction (from logged fields only).
  labels.py              Training-label derivation + the anti-circularity guard.
  logs.py / outcomes.py  Log reading, sessionization, decision/outcome join.
  decision.py            Python mirror of the guard's decision (parity-tested).
  bridge.py              Reads the guard's live thresholds via config-dump.php.
  promote.py             Safe candidate→live model promotion.
panel/
  index.php              Front controller (explicit route table, no dynamic includes).
  auth.php               Login, sessions, CSRF, the one fail-closed rate limiter.
  data.php               Bounded, reverse-streaming log/Redis reads; SVG charts.
  config_io.php          Validated JSON overlay writes + append-only audit trail.
  jobs.php / replay.php  Job queue producer; native-PHP threshold replay.
  setpass.php            One-time CLI credential install (no web setup wizard).
  views/                 Dashboard, logs, identity, overrides, replay, settings, ...
scripts/
  analyzer-cron.sh       flock wrapper for all analyzer cron modes.
  guard-logrotate.sh     Daily gzip + retention for the JSONL logs.
  config-dump.php        Emit the guard's effective config as JSON (for the analyzer).
  dev-router.php         Local dev server that runs the full guard (test only).
  *-selftest.*           Self-tests, including PHP↔Python decision parity.
logs/                    Daily JSONL output (gitignored).
```

## Quick start

```bash
# 1. Place the repo outside your web root, make logs/ writable.
mkdir -p logs && chmod 0775 logs

# 2. Set a real secret (this is the master switch; enforcement stays off).
openssl rand -hex 32        # paste into guard/config.php -> 'secret'
#                             also set a random 'holdout_salt'

# 3. Wire the guard in (php.ini / .user.ini / cPanel):
#    auto_prepend_file = "/full/path/bot-guard/prepend.php"

# 4. Confirm monitor mode works: load your site, then:
tail -1 logs/guard-*.jsonl   # one JSON line per request, act:"allow", sh:1 on shadowed actions

# 5. Install + schedule the analyzer:
pip install -r analyzer/requirements.txt
python3 analyzer/run_nightly.py --dry-run
#    add the cron lines from docs/03-SETUP.md (don't forget snapshot + worker)

# 6. (Optional) install the panel:
php panel/setpass.php        # then add the panel path to exempt_paths, sign in
```

Full, exact steps — including the crontab, the honeypot, and CMS exemptions — are
in [`docs/03-SETUP.md`](docs/03-SETUP.md).

## The rollout, in one paragraph

Install in **monitor mode** (steps above) and leave it for **~2 weeks**, watching
the dashboard and spot-checking logs to confirm the guard would catch bots and not
customers. Then enable the offline **signals** (reputation, then ML, then
classifier) in *shadow* — they show up in the effective score in the logs without
changing any outcome yet. Then enable **enforcement one mechanism at a time**:
`enforce.block`, then `enforce.challenge`, then `enforce.ratelimit`, each with a
few-percent **holdout** kept as a control, waiting days between steps and watching
for false positives. When a real customer is caught, open their **identity** page,
see which signal did it, and set an **allow** override — it takes effect on their
next request. The step-by-step operational checklist is in
[`ROLLOUT.md`](ROLLOUT.md).

## Configuration

All request-path configuration is in `guard/config.php`. The essentials:

| Key | What it does |
|---|---|
| `secret` | HMAC master secret. **While `CHANGE_ME`, all enforcement is forced off.** Set it to `openssl rand -hex 32`. |
| `enforce.{block,challenge,ratelimit}` | The three enforcement switches. All `false` = monitor mode. |
| `signals.{reputation,ml,clf}` | Whether each offline verdict adds to the score. All `false` = shadow. |
| `hard_block_score` | Effective score at/above which a GET is blocked (default 60). |
| `holdout_pct` | Percent measured but never enforced against (0–5). Use a few during rollout. |
| `honeypot_path` | An invisible path that 404s today; fetching it flags a bot. |
| `exempt_paths` / `exempt_params` | Paths/params the guard never touches (payments, cron, APIs, admin). |
| `known_bots` | Lowercase UA substrings given the fast pass (verified out of band). |
| `cdn_ranges` | IPv4 CIDRs whose `X-Forwarded-For` is trusted (set only if behind a CDN). |
| `limits.*` | Fixed-window rate counters (ship deliberately generous for CGNAT), plus hourly and daily per-device budgets for slow clients on changing addresses. |
| `preview_bots` | Link-preview fetchers; pass inside one small site-wide budget per name. |

The full table with defaults is in [`docs/03-SETUP.md`](docs/03-SETUP.md). The
panel can edit most of these live (writing a validated JSON overlay in
`guard/config.local.json` that layers over `config.php`); the `secret`,
`holdout_salt`, and panel credentials deliberately have no UI and no overlay path.

## The admin panel

Optional, but the easiest way to run the system. Install credentials from the CLI
(there is no web setup wizard — until you run this, every panel route is a bare
404):

```bash
php panel/setpass.php
```

Then add the panel's path to `exempt_paths` (so the guard does not challenge you
out of your own console), ensure the `snapshot` and `worker` cron lines are
present, and sign in at `panel/index.php`. The panel gives you: a **dashboard**
(traffic, decision mix, score histograms, challenge funnel, holdout comparison), a
bounded **log explorer** with CSV export, an **identity** page (every verdict for
one visitor — open this first when someone reports being blocked), **override**
controls (`allow`/`deny` with a mandatory TTL), interactive **replay** (move a
slider, see the effect on real recent traffic instantly), **settings** with a
before/after diff, **model/job** controls, and an append-only **audit** trail.

## Operating it

- **Someone reports being blocked.** Open their identity page (or
  `python3 analyzer/ctl.py show <device_id|ip>`). It shows every signal that
  touched them. If they are real: `ctl.py allow <id> --ttl 3600` (or the panel) —
  effective on their next request, ungated by any enforce toggle.
- **You want to try a stricter threshold.** Use replay (panel or
  `analyzer/replay.py --set hard_block_score=50`). It recomputes decisions over
  real logs and shows exactly how many bots you would newly catch and — the number
  that decides it — how many *humans* you would newly restrict. It writes nothing.
- **The dashboard looks stale.** Check the `snapshot` cron is running (its age is
  shown in the panel). Check the `worker` cron if a job is stuck "queued."
- **You changed the feature set / are migrating a model.** Train to a candidate
  (`run_nightly.py --train --candidate`), then promote explicitly
  (`ctl.py promote-model ml|clf`). The classifier candidate is refused if its
  held-out precision is below target. The live model keeps working until you
  promote.

## Testing

```bash
php scripts/guard-selftest.php        # request-path decision logic
php scripts/panel-selftest.php        # panel auth, config I/O, log reading
python3 analyzer/selftest.py          # analyzer pipeline
php scripts/decision-parity.php       # PHP↔Python decision agreement
bash scripts/guard-test.sh            # end-to-end against the dev router

# exercise the full flow locally, no host platform needed:
php -S 127.0.0.1:8080 scripts/dev-router.php
```

The decision logic lives in both PHP (`gv_effective_score`, `gv_decide`) and
Python (`analyzer/decision.py`); the parity test fails until they agree exactly
(including PHP's round-half-away-from-zero). Do not change one without the other.

## Documentation

- [`docs/01-OVERVIEW.md`](docs/01-OVERVIEW.md) — what the tool is and why.
- [`docs/02-ARCHITECTURE.md`](docs/02-ARCHITECTURE.md) — how the three parts fit
  together and what happens on a single request.
- [`docs/03-SETUP.md`](docs/03-SETUP.md) — exact install and configuration steps.
- [`docs/04-CMS-INTEGRATION.md`](docs/04-CMS-INTEGRATION.md) — bolting the guard
  onto any PHP CMS, with per-platform exemption lists.
- [`ROLLOUT.md`](ROLLOUT.md) — the operational, day-by-day rollout checklist.
- [`analyzer/README.md`](analyzer/README.md) — analyzer internals in depth.
- [`docs/05-ACCESS-LOG-REPORT.md`](docs/05-ACCESS-LOG-REPORT.md) — the daily
  access-log report that finds slow scrapers on changing addresses.
- [`docs/06-KNOWN-LIMITS.md`](docs/06-KNOWN-LIMITS.md) — what the guard cannot do,
  what degraded mode switches off, and what Redis and the server must provide.

## Requirements

- **PHP 8.0+** for the guard and panel. No PHP extensions required (the Redis
  client is a raw socket).
- **Redis** reachable from PHP (default `127.0.0.1:6379`). The guard runs without
  it, degraded to allow-only.
- **Python 3.8+** with `redis`, `scikit-learn`, `numpy` for the analyzer (it
  degrades gracefully without scikit-learn — just no ML that run).
- **Cron** for the analyzer, and a **local filesystem** for the log directory.
