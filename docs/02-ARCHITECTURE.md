# Bot Guard — Architecture & Workflow

## The three parts and what connects them

```
                          ┌──────────────────────────────────────────┐
                          │                 REDIS                    │
                          │  gv:rep:{dev}   gv:ml:{dev}  gv:clf:{dev} │
   reads (fast, in-band)  │  gv:botok/botbad:{ip}   gv:hp:{ip}       │  writes (out of band)
        ┌─────────────────┤  gv:allow/deny:{id}     counters        ├─────────────────┐
        │                 │  gp:jobs (panel job queue)               │                 │
        │                 └──────────────────────────────────────────┘                 │
        │                                    ▲                                          │
        ▼                                    │ writes verdicts                          ▼
┌───────────────┐   appends    ┌─────────────┴──────────┐   reads     ┌──────────────────────┐
│  THE GUARD    │─────────────▶│   DAILY JSONL LOGS      │────────────▶│    THE ANALYZER      │
│  (PHP, in     │  one line    │  logs/guard-YYYYMMDD    │   cron      │  (Python, cron)      │
│  request path)│  per request │  .jsonl                 │             │  reverse DNS, rep,   │
└───────┬───────┘              └─────────────┬───────────┘             │  ML, classifier,     │
        │                                    │ reads                   │  snapshot, report    │
        │ host app runs                      ▼                         └──────────┬───────────┘
        ▼                       ┌────────────────────────┐                        │ writes
┌───────────────┐              │      THE PANEL          │◀───────────────────────┘ snapshot.json
│  HOST APP     │              │  (PHP web console)      │   reads logs + snapshot + Redis
│  (CMS/store)  │              └────────────────────────┘   writes config.local.json + jobs
└───────────────┘
```

Two channels, and only two:

- **Redis** carries small, cheap, expiring verdict keys. The guard reads them
  in-band; the analyzer and panel write them out of band. Everything in Redis has
  a TTL, so a stopped analyzer cannot pin a stale verdict forever — verdicts
  simply age out and the guard falls back to its static scoring.
- **JSONL logs** are the guard's output and the analyzer's input. One line per
  request (a "decision line"), plus optionally a tiny second line per allowed
  request (an "outcome line"), correlated by a random request id.

Nothing else couples the three parts. The panel can be deleted and the guard and
analyzer keep working. Redis can be down and the guard keeps working (in a
degraded mode that only ever *allows*). The analyzer can be stopped and the guard
keeps working on its static scoring.

---

## Part 1 — The guard (request path)

Files: `prepend.php` (entry point), `guard/guard.php` (all decision logic),
`guard/redis.php` (Redis client), `guard/challenge.php` (token + interstitial),
`guard/log.php` (JSONL logger), `guard/outcome.php` (shutdown capture),
`guard/config.php` (per-deployment config).

### How it is loaded

`prepend.php` is intended to be set as PHP's `auto_prepend_file`, so it runs
before the host application on every request. It is deliberately tiny and
defensive: it bails out immediately for CLI runs, bails out if a `guard.off` kill
file exists, defines a boot constant, and then `require`s the guard inside a
`try/catch` that swallows every `Throwable`. If anything in the guard fails, the
host application runs as if the guard were not there. This is the fail-open
guarantee, established at the very first line.

### What happens on one request (`gv_run()`)

The guard reads the superglobals in exactly one place (`gv_facts()`) and passes an
explicit facts array everywhere else, so the scoring, CIDR matching and IP
resolution are pure and testable. The flow, in order, with the first matching
branch winning:

1. **Facts.** Extract everything the guard needs from the request: client IP
   (resolving `X-Forwarded-For` only when `REMOTE_ADDR` is inside a configured CDN
   range, and then only its last hop), method, path, query, user agent, a handful
   of headers, header count, HTTPS-ness, and the guard's own cookie.

2. **Challenge handshake intercept.** If this is the `POST` that the interstitial
   page makes back to itself carrying a valid nonce, mint a signed token, set it
   as a cookie, log `token_issued`, and return `204`. This runs before exemptions
   so the handshake can always complete.

3. **Exemptions.** If the path prefix or a configured query parameter is exempt
   (e.g. payment callbacks, cron endpoints, webhooks), log `exempt`, arm outcome
   capture, and return — the host app runs untouched.

4. **Redis connect.** One connection. If it fails, the guard enters degraded mode:
   all counters and verdict reads are skipped, and the request can only ever be
   allowed. A Redis outage is never a bypass in the dangerous direction — it can
   only make the guard *more* permissive.

5. **Known bots.** If the user agent matches a configured known-bot substring,
   read the out-of-band reverse-DNS verdict for this IP. If it was refuted (`bad`),
   revoke the free pass and fall through into normal scoring with a penalty. If it
   is ok or simply unknown, give the fast pass (subject to a generous bot rate
   ceiling) and return. No DNS is ever done in-band — the analyzer did it earlier.

6. **Honeypot.** If the path is the configured honeypot path (a URL no human would
   visit, linked invisibly), record an IP flag, log `404_hp`, and serve a 404.
   This is labelling data and fires regardless of the enforce toggles.

7. **Token, offline verdicts, overrides.** Verify the cookie into a device id.
   Then, if there is a device id and Redis is up, read the three offline verdicts
   (reputation, anomaly level, classifier level). Then read operator overrides — an
   `allow` override short-circuits everything below with zero output; a `deny`
   override is recorded and enforced later.

8. **Static score.** Compute the Phase 1 score from the facts (empty UA, script
   UA, missing Accept-Language on a navigation, missing Sec-Fetch on a modern
   browser, too few headers, honeypot history). Add a penalty if step 5 refuted a
   bot claim.

9. **Rate counters.** Increment the per-device, per-IP+UA, and per-IP fixed-window
   counters (skipped entirely in degraded mode). Any counter over its limit sets an
   "over" flag.

10. **Decision.** Fold the offline verdicts into the static score to get an
    *effective* score (each signal contributes only if its toggle is on — otherwise
    the effective score equals the static score exactly, so signals are visible in
    logs long before they change anything). Then decide, first match wins: deny
    override → block; effective score over the hard block threshold on a navigation
    → block; over a rate limit → 429; a navigation with no valid token → challenge;
    otherwise allow.

11. **Act.** Log exactly one line. If the decision is "allow," arm outcome capture
    and return with zero output. Otherwise consult the enforce toggle for that
    action: if enforcement is off (monitor mode) or this request is in the holdout
    slice, log what *would* have happened, allow, and let the app run. If
    enforcement is on, emit the block / 429 / challenge response and exit.

### The challenge

`guard/challenge.php` issues stateless, HMAC-signed tokens and nonces — they carry
their own timestamp and signature, so no server-side storage is needed and the
handshake works identically with or without Redis. The interstitial is a single
inline HTML document with no external assets: it waits a fraction of a second,
`fetch()`es a `POST` back to the same URL carrying the nonce, and reloads when the
guard answers `204`. A real browser sails through; a script that does not run
JavaScript never completes it. The token is deliberately **not** bound to the
client IP, so CGNAT and mobile carrier IP rotation do not re-challenge real users
on every network change.

### Outcome capture

`guard/outcome.php` is the only guard code that runs *after* the host application,
via a shutdown callback. It is held to a strict rule: it emits no bytes, sends no
header, sets no cookie, never buffers, and swallows every error. It appends one
tiny line recording the final HTTP status and the *declared* `Content-Length`
(never buffering the body to measure it — streaming and downloads stay untouched).
This is how the analyzer later learns that an allowed session walked into 404s or
pulled a catalogue's worth of bytes.

---

## Part 2 — The analyzer (out of band)

Files: `analyzer/*.py`. Entry points: `run_verify.py`, `run_nightly.py`,
`snapshot.py`, `report.py`, `worker.py`, `ctl.py`, `replay.py`.

The analyzer never runs in the request path and never blocks, challenges, or
serves a request. It reads logs and Redis, computes verdicts, and writes small
integers back to Redis for the guard. Every write carries a TTL.

### The pipeline

- **Read & sessionize** (`logs.py`, `outcomes.py`). Read the last N days of JSONL,
  joining each request's decision line to its outcome line file by file (kept per
  file, not per window, so memory stays flat). Group rows into sessions per
  identity — the stable device id when the visitor has a token, else IP+UA-hash as
  a fallback — splitting on an idle gap.

- **Features** (`features.py`). For each session, compute a fixed-order numeric
  vector from fields the guard already logged: request count, duration, timing gap
  mean/std/min, navigation ratio, path-uniqueness ratio, mean score, and the
  ratios of script-UA / few-header / no-Accept-Language reasons — plus, from the
  outcome lines, the 404 ratio, other-4xx ratio, 5xx ratio, mean bytes, and how
  much of the session even had an outcome recorded. The feature order is a
  contract between training and scoring; it is only ever appended to.

- **Bot verification** (`botverify.py`, `run_verify.py`). For every IP that
  claimed to be a known bot, do forward-confirmed reverse DNS (PTR the IP, check
  the hostname ends in a registered suffix like `.googlebot.com`, then forward-
  resolve that hostname back to the same IP). Write `gv:botok:{ip}` or
  `gv:botbad:{ip}`. This is the DNS the guard refuses to do in-band. Runs often
  (≈ every 10 minutes), rate-limited so it never hammers DNS.

- **Reputation** (`reputation.py`). A transparent additive formula — not a black
  box. Positive weights for evidence of automation (honeypot hit, unsolved
  challenge, metronomic timing, high rate, script UA, cold jumps into detail pages,
  and the outcome-based signals: 404-walking, bulk byte extraction, driving the app
  into 5xx). Negative weights for evidence of a real person (solved the handshake
  and browsed plausibly; wide path spread with human-like irregular timing). The
  sum is clamped and written to `gv:rep:{dev}`. Every weight is a named constant an
  operator can tune.

- **Models** (`model.py`, `classifier.py`). Two models on the same features. An
  Isolation Forest learns what "normal" looks like from confident-human sessions
  only (training on everything would teach it that scraping is normal) and emits an
  anomaly level 0–100 to `gv:ml:{dev}`. A gradient-boosted classifier learns a
  boundary between labelled bot and human sessions and emits a bot-likelihood 0–100
  to `gv:clf:{dev}`. The classifier's threshold is chosen for **precision, not
  accuracy** — the lowest threshold that still reaches a target precision on
  held-out data — because a false positive is a lost customer. Both models are
  scored offline; the guard reads only the resulting integer.

- **Labels** (`labels.py`). The training labels are derived only from evidence the
  guard did **not** itself produce: a honeypot hit, a reverse-DNS refutation, or an
  operator-supplied ground-truth file for positives; strong evidence of a real
  person for negatives. Crucially, "was served a challenge and never solved it" is
  *refused* as a label — it is the guard's own decision fed back as truth, and a
  model trained on it would just reproduce the existing rules (and inherit their
  false positives). It stays a bounded reputation input, never a label.

- **Snapshot & report** (`snapshot.py`, `report.py`). The snapshot folds recent
  logs into one small JSON the panel dashboard reads (so the dashboard's cost is
  one small file read, not a log scan). The report renders KPIs as a self-contained
  HTML file with no JavaScript, for mailing or archiving.

### Safe model migration

`promote.py` and the candidate-path machinery exist because extending the feature
set makes every existing model stale, which would silently stop verdicts being
written and make the system quietly more permissive. So training during a
migration writes to a *candidate* path, the live model keeps working, and
promotion is an explicit, checked act (the classifier candidate is refused if its
held-out precision is below target). The nightly job prints a loud warning if a
live model has gone stale.

---

## Part 3 — The panel (operator console)

Files: `panel/*.php`, `panel/views/*.php`.

A single-operator web console, in Persian/RTL. It reads the logs, the analyzer
snapshot, and Redis; it writes configuration (as validated JSON) and analyzer job
requests. It is built around two rules:

1. **It never writes executable code.** Configuration changes are written to
   `guard/config.local.json` as a flat, validated JSON overlay — never PHP. A panel
   that rewrote PHP from form input would be a code-injection hole in a security
   tool. Validation is not reimplemented in the panel: the *same* function the
   guard uses to read a key is the one the panel uses to accept it on write, so
   they can never drift.

2. **It never builds a shell command.** Analyzer actions (retrain, replay,
   promote, snapshot) are dispatched as typed JSON envelopes onto a Redis list; a
   Python worker drains that list and calls the corresponding function in-process.
   Nothing constructs or executes a command line from operator input.

### What the panel does

- **Dashboard** — traffic, decision mix, score histograms, the challenge success
  funnel, signal coverage, and the holdout-vs-enforced comparison, all from the
  snapshot.
- **Logs** — a reverse-streaming log explorer with typed, bounded filters and CSV
  export. No panel function ever loads a whole log file into memory; every query
  reads from the end of the file under a byte and line budget and reports if it hit
  the cap.
- **Identity** — every verdict touching one visitor (reputation, anomaly,
  classifier, bot verification, honeypot history, overrides). This is the first
  page to open when a customer reports being blocked.
- **Overrides** — set a per-visitor `allow` (takes effect on their next request,
  ungated by any enforce toggle — the five-second rescue) or `deny`. Every override
  carries a mandatory TTL; one without an expiry is a config change in disguise.
- **Replay** — move the threshold sliders and instantly see what the change would
  have done to real recent traffic, computed natively in PHP (the decision
  functions are parity-tested against the Python mirror, so PHP reproduces the
  candidate decision exactly, with no round trip). Apply the values, or enqueue a
  full replay that re-derives reputation.
- **Settings** — edit the config overlay with a before/after diff shown prior to
  saving; nothing is written unless every field validates.
- **Models / Jobs** — inspect model status and trigger analyzer jobs (which the
  worker runs).
- **Audit** — an append-only trail of every config change and override, so "the
  false-positive rate jumped on Tuesday" can be tied to "hard_block_score was
  lowered on Tuesday."

### Panel security posture

There is no web setup wizard — until credentials are installed from the command
line (`panel/setpass.php`), every panel route returns a bare 404, so nothing hints
that a panel exists. Login rate limiting is the one component in the whole system
that does **not** fail open: if Redis is down it falls back to a file counter,
because a rate limiter that disappears when Redis hiccups is not a rate limiter.
Sessions and CSRF tokens are HMAC-signed and stateless. Wrong username and wrong
password produce an identical message, status, and response time, so the login
form cannot be used to enumerate the operator's username.

---

## The decision, in one place, mirrored in two languages

The effective-score fold and the decision rule exist in PHP (`gv_effective_score`,
`gv_decide` in `guard/guard.php`) and are mirrored in Python
(`analyzer/decision.py`) so the analyzer's replay can reproduce the guard's
decision exactly. Keeping the same logic in two languages is a maintenance hazard,
so it is defended by a parity test (`scripts/decision-parity.php` plus assertions
in the self-tests) that fails until both implementations agree, down to PHP's
round-half-away-from-zero behaviour. Do not add behaviour to one without the
other.

---

## Data lifetimes

- **Decision & outcome log lines** — one daily file, gzipped by the logrotate
  cron after the day ends, deleted after a retention window (default 60 days).
- **Redis verdicts** — every key has a TTL (reputation ~30 days, ML/classifier/bot
  ~1 day, overrides operator-chosen up to 30 days, honeypot ~7 days). A stopped
  analyzer means verdicts age out and the guard falls back to static scoring.
- **The snapshot** — rewritten every ~15 minutes by cron; its age is shown in the
  panel, so a stale snapshot is itself an alert that the analyzer has stopped.
