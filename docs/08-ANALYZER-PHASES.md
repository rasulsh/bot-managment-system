# Analyzer and later phases (Phases 2 to 4)

The offline analyzer, the holdout and overrides, and response outcome capture.
Phase 1 (the guard) is in the [README](../README.md) and
[07-CONFIG-REFERENCE.md](07-CONFIG-REFERENCE.md); Phase 5 (the admin panel) is in
[09-ADMIN-PANEL.md](09-ADMIN-PANEL.md).

## Phase 2 — offline analyzer

Phase 2 adds an **out-of-band Python analyzer** (`analyzer/`) that reads these
same JSONL logs, writes verdicts into Redis, and stops there. It never sees a
live request, never blocks and never challenges — the in-band PHP guard remains
the only component that touches traffic. The guard reads the verdicts as cheap
Redis GETs and folds them into the score it already computes.

Everything Phase 2 adds is **shadow-first**: the verdicts are always logged, but
only change a decision once you switch a `signals` toggle on. See
[`analyzer/README.md`](../analyzer/README.md) for the analyzer's own operator guide.

### Requirements

Python 3.9+ (3.8 is end-of-life) and `python3 -m pip install -r analyzer/requirements.txt` (redis,
scikit-learn, numpy). Redis must be reachable by both the PHP guard and the
analyzer — it is the only channel between them. Without Redis both sides simply
degrade: the guard runs as in Phase 1, the analyzer computes and reports without
storing.

### Verdict contract

All keys are written by Python and read by PHP. All are optional — absence means
no signal — and all carry a TTL, so a stopped analyzer cannot pin a stale
verdict forever.

| key | writer | value | TTL | effect in the guard |
|-----|--------|-------|-----|---------------------|
| `gv:botok:{ip}` | `run_verify` | `"1"` | 86400 | The UA-claimed bot is forward-confirmed. Logged as `botv=ok`; the known-bot pass stands. |
| `gv:botbad:{ip}` | `run_verify` | `"1"` | 3600 (`botbad_ttl`) | The UA claims a known bot but reverse DNS failed. Logged as `botv=bad`; **revokes** the pass and adds `BOT_FAKE` (+35). |
| `gv:rep:{dev}` | `run_nightly` | signed int, clamped [-50, 80] | 1209600 (`rep_ttl`, 14 days) | Behavioural reputation. Logged as `rep`; added to the score when `signals.reputation` is on. |
| `gv:ml:{dev}` | `run_nightly` | int 0..100 | 86400 | Isolation Forest anomaly level. Logged as `ml`; `round(ml * ml_weight)` is added when `signals.ml` is on. |

Positive reputation is suspicious, negative is trustworthy — the same sign
convention the static score uses. `botok`/`botbad` are per IP because bots do
not carry the cookie; `rep`/`ml` are per device because they describe a browsing
identity.

`BOT_FAKE` is deliberately **not** gated by any toggle: it is part of the static
score, because a revoked bot claim is a hard signal. It still does not block on
its own (+35 is below the default `hard_block_score`) — an impersonator is
scored like any other client, not summarily blocked.

### Bot verification is three-state

`run_verify` answers `ok`, `bad` or `unknown`. `bad` is written only on a definitive
refutation (PTR answered and no suffix matches; no PTR record; forward lookup does not
contain the address). Timeouts, SERVFAIL, an unreachable resolver and a known bot with
no `bot_suffixes` entry are `unknown`: nothing is written or deleted and the address is
retried next run. A negative DNS answer only counts while a canary name resolves
(`dns_canary`), because glibc reports a refused resolver as HOST_NOT_FOUND. `ok` keeps
`botv_ttl` (24 h); `bad` uses `botbad_ttl` (1 h) so a wrong verdict heals itself.
`run_verify --recheck` re-resolves addresses that already have a verdict.

### Challenge (what it does and does not do)

The nonce is HMAC-bound to User-Agent (and IP), single use (Redis `SET NX`; with Redis
down the handshake stays open), must be accompanied by a SHA-256 proof of work
(`X-GV-P`), and minting is metered per IP. New log acts: `nonce_replay`, `pow_bad`
(403 with `enforce.challenge`, otherwise logged with `sh=1` and the token is still
issued) and `mint_limited` (429 with `enforce.ratelimit`, else `sh=1`). The funnel counts
a shadowed one as an issued token. A JavaScript challenge cannot stop a real headless
browser and a token can still be shared between machines (bounded by `limits.device`
and, over the long run, by `limits.device_hour` / `device_day`). A headless browser that
throws its token away when a budget runs out pays one proof of work per budget; that
price is `challenge.pow_bits`.

### Cron

```
PATH=/usr/local/bin:/usr/bin:/bin
*/10 * * * * bash /full/path/bot-guard/scripts/analyzer-cron.sh verify  >/dev/null 2>&1
17 4   * * * bash /full/path/bot-guard/scripts/analyzer-cron.sh nightly >/dev/null 2>&1
41 5   * * 0 bash /full/path/bot-guard/scripts/analyzer-cron.sh train   >/dev/null 2>&1
```

Each mode takes a `flock`, so overlapping firings never write partial verdicts: nightly / train / train-clf wait for the shared write lock
(`GV_LOCK_WAIT`, default 900 s), the worker takes it only around a job that writes models or verdicts, the other modes skip when their lock is busy. The weekly `train` run trains a **candidate** model,
never the live one; promote it explicitly (panel "promote" or `ctl.py promote`)
to put it in force.

### New log fields

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

### Keep the two configs in sync

`known_bots` and `bot_suffixes` live in **both** `guard/config.php` and
`analyzer/config.py`. They are one contract seen from two sides: the analyzer
decides which addresses are impersonators, the guard honours the verdict. If
they drift, the guard keeps passing a UA the analyzer never checks.

### Evaluating the signals

To generate labelled bot traffic, point a headless browser or HTTP client you
control at a **staging copy** of the site, let it browse, then run the nightly
job and confirm those device ids come back with a high `ml` and a positive
`rep`. Compare against your own real browsing session on the same staging copy.

### Phase 2 rollout

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

## Phase 3 — measure, tune, then classify

Phase 3 adds no new detection surface. It makes the first two phases
**measurable**: a control group that produces unbiased outcome data, a replay
tool that answers "what would this change have done?" against real history, a
report that turns the KPIs into one command, a fast escape hatch for false
positives — and only then a supervised classifier, trained on labels that do
not come from the guard's own decisions.

### Holdout control group

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

### Operator overrides

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

### Classifier labels: how each source is set up

The supervised classifier trains only when the nightly run has at least `clf_min_positive` (default **50**) bot-labelled *sessions* and at least one human-labelled one. Until then
nightly says `Classifier: skipped: 0 bot-labelled sessions ...`: that is **normal on a new install**, it is shown as an informational note (not "did nothing useful") as long as the
rest of nightly did its work, and the Models page and the dashboard details show the progress: `labels: 0 / 50 positives — sources: honeypot hits, refuted crawler claims, operator ground truth`.
A positive must be independent of the guard's own decisions (see `analyzer/labels.py` for why *challenge unsolved* is never a label). There are three sources:

1. **Honeypot hits.** A link no human can see. Put an invisible link to the guard's honeypot path in your pages, for example
   `<a href="/old-archive" style="display:none" rel="nofollow" tabindex="-1" aria-hidden="true">archive</a>` (the path is `honeypot_path`, default `/old-archive`; it must
   answer 404 today, and `robots.txt` should `Disallow` it so honest crawlers stay away). Every session that requests it is a positive. Nothing else to enable: the guard logs the hit
   (`hp`) whatever `enforce.*` says, and the nightly run reads it.
2. **Refuted crawler claims.** A client that says it is Googlebot (or another entry of `known_bots`) and fails the reverse-DNS check. This needs the `verify` cron job
   (`*/10`, `analyzer-cron.sh verify`) and `known_bots` / `bot_suffixes` in the configuration (shipped for Google, Bing and AdsBot); verdict `bad` is written to the log row (`botv`) and counted.
3. **Operator ground truth.** A text file, `analyzer/ground-truth.txt` (the config key `ground_truth_path`, or `--ground-truth FILE` on `run_nightly.py`), one `identity,label` per line, `1` = bot and `0` = human, `#` comments
   allowed. The identity is a device id or an address. The usual way: run a scraper you control against a staging copy, then list its device ids / addresses as `1`. Ground truth wins over every inferred label.

Humans are labelled only on strong evidence (solved the handshake, browsed at least 20 s, came back more than once, never looked like a script library), so a quiet site may show humans before it shows
positives. The counts are sessions of the labelled identities, the same unit as `clf_min_positive`. Lowering `clf_min_positive` makes the first classifier cheaper and worse; leaving the signal off
(`signals.clf`, the default) means a classifier that is still waiting changes nothing about enforcement.

### New config keys

| key | meaning |
|-----|---------|
| `holdout_pct` | Percent of identities measured but never enforced against. 0 = off, clamped at 5. |
| `holdout_salt` | Stable string that fixes holdout membership. Changing it reshuffles the sample. |
| `signals.clf` | Add the scaled `gv:clf:{dev}` classifier level to the score. Default off (shadow). |
| `clf_weight` | Multiplier turning a classifier level of 0..100 into a score contribution. Default 0.5. |

### New log fields

`clf` (classifier level, `-1` = no verdict), `hold` (1 = in the holdout) and
`ovr` (`allow` / `deny` / empty). A new action, `allow_override`, appears when a
permissive override short-circuits the request.

### Phase 3 rollout

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


---

## Phase 4 — response outcome capture

Everything the guard logged before this phase ended at its own decision. A
device that pulls three hundred product pages and a device that walks a stale
URL list into three hundred 404s looked identical. Phase 4 records **what the
host application actually did** with each allowed request.

This is the first guard code that runs *after* the application, so it is held to
one absolute rule: **the capture may never alter the response.** The shutdown
callback emits no bytes, sends no header, sets no cookie, starts no buffer,
never exits, and swallows every Throwable. It does exactly one thing — append
one short line to a file. The test suite compares response bodies and headers
byte-for-byte with capture on and off, across a normal page, a 404, a 500, a
128 KiB body, custom headers and a fatal error.

### Turning it on

```php
'capture_outcomes' => false,   // Phase 4, off by default
```

Off by default, like every other new behaviour. When off, no closure is
registered and nothing changes anywhere.

### Two kinds of log line

The decision line gains `v` (schema version, `4`) and `rid` (12 hex chars),
placed first. A line without `v` predates this phase and simply has no outcome.

The outcome line is separate and deliberately tiny:

```json
{"o":1,"rid":"a1b2c3d4e5f6","st":404,"by":1183,"dur":38.4,"ts":1786134525.912}
```

| key | value |
|-----|-------|
| `o` | always `1`, so the analyzer can split on one cheap key test |
| `rid` | correlation key, matches a decision line in the same file |
| `st` | `http_response_code()` at shutdown |
| `by` | declared `Content-Length`, or `null` |
| `dur` | total request milliseconds |
| `ts` | shutdown timestamp |

Roughly +40% lines but only a few percent of bytes. The existing rotation
handles it; there is no sampling.

The hook is armed on every path where the guard **returns** and the application
runs — `allow`, `allow_bot`, `exempt`, `allow_override`, and the monitor and
holdout suppressed paths — and on none of the paths where the guard **exits**
having produced the response itself. A `403` or a `challenge` therefore has no
outcome line: `act` already says what happened.

### When there is no outcome line — none of these are bugs

- **The process was killed.** `register_shutdown_function` runs on fatal errors,
  which is exactly why it is the right hook — a request that fataled is itself a
  signal. It does not run on `SIGKILL`, an OOM kill, or a hard server timeout.
  Those requests have no outcome, and the analyzer treats that as unknown.
- **The web server substituted the status.** `http_response_code()` returns what
  PHP knows. A `304` from the server's own cache validation, or an error page it
  generated itself, is invisible here.
- **No `Content-Length` was declared.** `by` is `null`, never guessed. This is
  normal for compressed and streamed responses. Buffering the response to
  measure it would break streaming and downloads, double the memory of large
  pages, and collide with the application's own buffering — so we do not.
  Partial coverage of a safe signal beats full coverage of a dangerous one, and
  the `outcome_cov` feature exists precisely so the model learns how much to
  trust the rest.

If the application calls `fastcgi_finish_request()`, the callback runs after the
client already holds the full response, so the capture costs the visitor nothing.

### Rollout

Outcome capture extends the model feature set, which makes both existing model
bundles stale. **Follow the ordered runbook in [`analyzer/README.md`](../analyzer/README.md)** — getting
it out of order opens a window where the models stop writing verdicts and, if
`signals.ml` or `signals.clf` are on, the effective score silently drops for
everyone.

---
