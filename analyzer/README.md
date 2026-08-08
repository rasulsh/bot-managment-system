# Bot Guard analyzer (Phase 2)

Out-of-band analysis of the Phase 1 JSONL logs. It reads log files, writes
verdicts to Redis, and stops there. It never sees a live request, never blocks,
never challenges, and cannot make the site slower or break it — the worst a
broken analyzer can do is leave stale verdicts, which expire on their own TTL.

## Install

```bash
python3 -m pip install -r analyzer/requirements.txt   # redis, scikit-learn, numpy
python3 analyzer/selftest.py                          # expect exit 0
```

Python 3.8+. Redis must be reachable by both the PHP guard and this analyzer.
Without Redis the jobs still run, report what they computed, and write nothing.
Without scikit-learn everything except the anomaly model works.

## Modules

| file | role |
|------|------|
| `config.py` | defaults; override with `GV_ANALYZER_CONFIG` or `--config` (.json or .py) |
| `logs.py` | JSONL reading (plain + gzip, corrupt lines skipped) and sessionization |
| `features.py` | pure per-session feature math; `FEATURE_ORDER` is the train/score contract |
| `reputation.py` | additive reputation formula; every weight is a named constant |
| `botverify.py` | forward-confirmed reverse DNS, resolver injectable |
| `model.py` | Isolation Forest train/load/score, guarded scikit-learn import |
| `redis_io.py` | verdict writes/reads; never raises on a Redis outage |
| `run_verify.py` | fast entry point: bot claims → `gv:botok` / `gv:botbad` |
| `run_nightly.py` | daily entry point: sessions → features → `gv:rep`, and `gv:ml` |

## Running

```bash
scripts/analyzer-cron.sh verify     # fast reverse-DNS loop
scripts/analyzer-cron.sh nightly    # reputation + anomaly levels
scripts/analyzer-cron.sh train      # nightly run that also retrains the model
```

The wrapper takes a per-mode `flock`, so an overlapping cron firing skips
cleanly instead of writing partial verdicts. Both entry points also accept
`--config`, `--log-dir` and `--dry-run` directly.

Cron:

```
*/10 * * * * /full/path/bot-guard/scripts/analyzer-cron.sh verify  >/dev/null 2>&1
17 4   * * * /full/path/bot-guard/scripts/analyzer-cron.sh nightly >/dev/null 2>&1
41 5   * * 0 /full/path/bot-guard/scripts/analyzer-cron.sh train   >/dev/null 2>&1
```

Exit codes: `0` for a completed run — including one that could not reach Redis
or had no model — and `2` only for the job's own hard failures (bad config,
unreadable log directory).

## Sessionization and features

A session is keyed on the Phase 1 `dev` (the device_id minted by the challenge
handshake) when present, and on `ip|uah` otherwise. An idle gap larger than
`session_gap_s` starts a new session. Features are timing (`gap_mean`,
`gap_std`, `gap_min`, `dur_s`), volume (`n_req`), and behaviour ratios
(`nav_ratio`, `path_uniq_ratio`, `score_mean`, `script_ratio`, `few_hdr_ratio`,
`no_al_ratio`, `detail_no_listing_ratio`) — all derived from fields the guard
already logs.

`path_listing` and `path_detail` are operator-supplied regex lists, empty by
default. Fill them in to enable the "walked straight into detail pages without
browsing a listing" signal; leave them empty and that feature stays a flat 0.0.
Nothing here knows anything about any particular platform.

## Model

Isolation Forest, trained **only on confident-human sessions** (no honeypot hit,
no unsolved challenge, no scripted UA). This is deliberate: the model learns
what normal looks like from whatever it is fed, and in bot-heavy traffic the raw
distribution is partly bot. Training on everything would teach it that scraping
is normal.

Training is refused below `ml_min_train` (default 200) clean sessions — a
manifold fitted on a handful of sessions describes noise. `model.joblib` is
derived from your traffic: it is git-ignored and must never be committed.

Tune `DECISION_SPAN` in `model.py` if the levels in your logs bunch up around 50
(widen it) or saturate at 0 and 100 (narrow it).

## Keeping configs in sync

`known_bots` and `bot_suffixes` exist in **both** `guard/config.php` and
`analyzer/config.py`. They describe one contract seen from two sides: the
analyzer decides which addresses are impersonators, the guard honours the
verdict. If they drift, the guard will keep passing a UA the analyzer never
checks. Change both together.

---

# Phase 3 additions

## The config bridge — thresholds are no longer duplicated

`analyzer/bridge.py` shells out to `php scripts/config-dump.php` and reads the
guard's **effective** configuration: the dump runs through the guard's own
`gv_cfg_load()`, so it reflects the shipped defaults and the forced-monitor
rule. `secret` and `holdout_salt` are stripped unconditionally and there is no
flag to print them.

This is what keeps replay honest — it tunes against the thresholds actually in
force, not a copy that drifted. When PHP is unavailable the bridge warns once
and falls back to the documented defaults; it never raises.

`known_bots` and `bot_suffixes` remain the only intentionally duplicated keys,
because they are the analyzer's own inputs rather than guard thresholds.

## Decision parity

`analyzer/decision.py` mirrors exactly two PHP functions —
`gv_effective_score` and `gv_decide` — and nothing else. Duplicated decision
logic across two languages is a maintenance hazard; the parity test is what
makes it acceptable:

```bash
php scripts/decision-parity.php --emit     # 54 cases of inputs + PHP's answers
python3 analyzer/selftest.py               # recomputes each one and asserts equality
```

The matrix covers every signal-toggle combination, the absent-verdict sentinels
(`rep = 0`, `ml = -1`, `clf = -1`), both sides of `hard_block_score`, every
decision branch, both override values, and the rounding cases — PHP rounds half
away from zero and Python's `round()` does not, which is why
`decision.php_round` exists. If either side changes, the parity test fails
until they match again.

## Replay — never tune a threshold blind

```bash
python3 analyzer/replay.py --set hard_block_score=50
python3 analyzer/replay.py --set signals.clf=true --days 14
python3 analyzer/replay.py --mode full --set ml_weight=0.6
```

`threshold` mode (the default) is cheap and exact: it reuses the `sc`, `rep`,
`ml` and `clf` already in each log row. Use it for `hard_block_score`, the three
weights and the signal toggles. `full` mode re-derives reputation and anomaly
levels from the window, and is only needed when tuning the reputation weights
themselves.

Replay is **read-only by construction** — it imports no Redis client and opens
no file for writing, and the self-test asserts both.

### Reading the movement table

```
Movement table
  allow->403                      240
  challenge->403                   60

Impact by labelled subset
  bot-labelled rows               260
    newly restricted              240   (recall proxy, higher is better)
  human-labelled rows             560
    newly restricted                0   <-- the number that decides this change
  holdout rows                      60
    would newly be restricted      60   (unenforced slice)
```

The movement table says how much changes; the labelled subsets say whether the
change is good. **The human-labelled row is the one that decides it.** A change
that catches 240 more bot requests and restricts zero human ones is free. The
same change restricting even a handful of human-labelled requests is a
different conversation, because each of those is a real customer.

If the human subset is empty, the report says so explicitly — that means the
window has no confidently-human identities, not that there are no false
positives.

## Labels — and what must never become one

`analyzer/labels.py` produces `1` (bot), `0` (human) or `None` (excluded).

**Positives**, all independent of the guard's own gating: a honeypot hit, a
`botv == 'bad'` reverse-DNS refutation, or an identity in the operator ground
truth. **Negatives** require positive evidence of a person: solved the
handshake, real median dwell, more than one session in the window, and no
scripted user agent. **Everything else is excluded from training entirely.**

`challenge_unsolved` is deliberately not a label. It records that the guard
served a gate and got no answer — the guard's own decision handed back as
ground truth. A model trained on it learns to reproduce the rules that produced
it: it scores brilliantly offline and adds nothing in production, because
everything it flags was already flagged. It also inherits those rules' false
positives, so a real customer whose browser could not run the challenge teaches
the model to block people like them. It stays a reputation input, where its
circularity is visible and bounded by a fixed weight.

### Generating real labels

```
# analyzer/ground-truth.txt - one identity,label per line
# comments and blank lines are ignored
a1b2c3d4e5f6a1b2c3d4e5f6,1
203.0.113.44,1
9f8e7d6c5b4a9f8e7d6c5b4a,0
```

Point a headless browser or HTTP client **that you control** at a staging copy
of the site, let it browse, then list those device ids or addresses as
positives. Browse the same staging copy yourself and list your device id as a
negative. That is how genuine labels enter the system; the file is optional and
git-ignored.

## Report

```bash
python3 analyzer/report.py
python3 analyzer/report.py --days 14 --html /tmp/guard-report.html
scripts/analyzer-cron.sh report | mail -s "Bot Guard weekly" you@example.com
```

Eight sections: traffic, decisions split enforced versus shadow, the challenge
funnel judged against the target rate in words, `sc` and `esc` histograms,
verdict coverage, the enforced-versus-holdout comparison, top offenders, and
day-over-day anomalies.

`--html` writes **one self-contained static file**: inline CSS, no JavaScript,
no external assets, no fonts, no charting library. Bars are table rows with
proportional-width divs. It is a report to open or email, not a dashboard, and
it has no live data connection of any kind.

## Supervised classifier

```bash
python3 analyzer/run_nightly.py --train-clf
scripts/analyzer-cron.sh train-clf
```

`HistGradientBoostingClassifier` over **the same `FEATURE_ORDER`** the Isolation
Forest uses. That is deliberate: an unsupervised density and a supervised
boundary are genuinely different signals on identical inputs, and adding new
features at the same time would make it impossible to tell which change helped.

The operating threshold is the **lowest one that reaches
`clf_target_precision`** (default 0.98) on held-out data — not the most
accurate. The classes are heavily imbalanced, so accuracy is meaningless, and
the two errors do not cost the same: a false negative is one scraped page, a
false positive is a paying customer who cannot reach the site. Every training
run prints precision, recall, F1, PR-AUC and the confusion matrix, and says so
in words when no threshold reached the target:

```
  WARNING: no threshold reached the target precision. Do not enable
           signals.clf yet - it would restrict real users.
```

Training returns without writing when positives are below `clf_min_positive`
(default 50) or when either class is missing. Both are ordinary early in a
deployment, not errors — a model fitted on eleven bots is a random number
generator with a confusion matrix.

Holdout identities are excluded from training and from every per-device verdict:
they have no stable device id, so their data is sound in aggregate only.

## New settings

| key | meaning |
|-----|---------|
| `clf_path` | Where the classifier bundle is persisted. Git-ignored. |
| `clf_min_positive` | Refuse to train below this many bot-labelled sessions. |
| `clf_test_size` | Held-out fraction for the metrics. |
| `clf_target_precision` | Precision the operating threshold must reach. |
| `ground_truth_path` | Optional operator label file. |
| `php_bin`, `guard_config_path` | How the bridge reaches the guard's config. |
| `report_days`, `report_top_n` | Report window and table caps. |
| `challenge_success_target` | Below this rate the report warns in words. |

---

# Phase 4 additions

## Outcome join

The guard now writes two line kinds into the same daily file: the wide decision
line, and a tiny outcome line appended at shutdown, correlated by `rid`.
`analyzer/outcomes.py` splits them, indexes by `rid` and attaches the match as
`_out`.

**The join is per file, not per window.** Both lines for a request come from the
same process moments apart, so they land in the same daily file except for
requests straddling midnight. Joining file by file keeps memory flat on a busy
site — a whole week's rid index would be the analyzer's largest allocation — and
loses only those few, which then simply carry no outcome. `logs.py` does this
before yielding, so every consumer above it sees decision rows with `_out`
already populated and never has to know outcome lines exist.

Duplicate rids are counted rather than silently overwritten. A 12-hex id
collides at a negligible rate, so a collision almost always means a file was
concatenated twice or a deployment is broken.

## Five new features

Appended to `FEATURE_ORDER`, never inserted — the order is the contract between
training and scoring:

| feature | meaning |
|---------|---------|
| `notfound_ratio` | share of outcome-known rows with `st == 404` |
| `err_ratio` | share with `st` in 400..499 excluding 404 |
| `srv_err_ratio` | share with `st >= 500` |
| `bytes_mean` | mean of known `by` values, 0.0 when none are known |
| `outcome_cov` | share of the session's rows that have an outcome at all |

The four ratios are computed over **outcome-known rows only**. Computing them
over all rows would make a session with poor coverage look artificially clean,
because the unknown rows would count as "not a 404". `outcome_cov` is what tells
the model how much the other four are worth, which is why it belongs in the
vector rather than being treated as metadata.

Every one is `0.0` for a session recorded before capture was enabled, so old
sessions stay usable and score exactly as they did before.

## Three new reputation rules

| constant | default | fires when |
|----------|---------|-----------|
| `W_NOTFOUND` | +20 | median `notfound_ratio` > `NOTFOUND_RATIO` (0.3), median `n_req` >= `MIN_REQ_OUTCOME` (10) |
| `W_BULK` | +15 | one session moved more than `BULK_BYTES` (50 MB) with a wide path spread |
| `W_SRV_ERR` | +10 | median `srv_err_ratio` > `SRV_ERR_RATIO` (0.1) |

These are the hardest signals in the formula to fake. Timing can be randomised
and every header forged, but a scraper working from a stale URL list cannot
avoid requesting pages that are not there, and nothing lets it extract content
without transferring the bytes.

All three are gated on `outcome_cov >= MIN_COVERAGE` (0.5), so they are inert
until capture has produced data — enabling Phase 4 cannot move a single existing
reputation on its own.

**`NOTFOUND_RATIO` is the first constant to tune.** A site with genuinely broken
internal links produces human 404s and needs a higher threshold; check the
report's status distribution before assuming a 404 rate is adversarial.

## THE MIGRATION RUNBOOK — do these in order

Extending `FEATURE_ORDER` makes both existing bundles stale, and `load()`
correctly refuses one. Out of order, that opens a window where `gv:ml` and
`gv:clf` stop being written, the keys expire within a day, and — if
`signals.ml` or `signals.clf` are on — **the effective score silently drops for
everyone**. A system quietly becoming more permissive is the failure nobody
notices. So:

1. **Deploy Phase 4 with `capture_outcomes` still false.** Confirm nothing
   changed: same responses, same log schema apart from `v` and `rid`.
2. **Turn `capture_outcomes` on.** Confirm outcome lines appear and that the
   site is byte-identical.
3. **Decide about the signals now.** If `signals.ml` or `signals.clf` are on,
   either turn them off for the migration window, or accept that scores lose
   those contributions once the feature set changes. Write down which you chose.
4. **Let outcomes accumulate for at least two weeks.** The new features are
   worthless on a few days of data.
5. `python3 analyzer/run_nightly.py --train --train-clf --candidate`
   — writes to the candidate paths and leaves the live models untouched.
6. **Evaluate before promoting**: `python3 analyzer/report.py --model candidate`
   and `python3 analyzer/replay.py --mode full --model candidate`. For the
   classifier, check held-out precision against `clf_target_precision`.
7. `python3 analyzer/ctl.py promote-model ml`, then `clf`. Promotion refuses a
   missing candidate, a feature-order mismatch, and a classifier below target
   precision.
8. **Re-enable whatever you turned off in step 3, one signal at a time**, as in
   Phase 3.

While a live model is stale, every nightly run prints a loud warning naming the
exact commands to fix it, and the report's verdict-coverage section says a stale
model is the likely cause when reputations are being written but model verdicts
are not.

## New settings

| key | meaning |
|-----|---------|
| `model_candidate_path` | Where `--candidate` writes the anomaly model. Defaults to `model_path` + `.candidate`, so relocating the model takes its candidate with it. Git-ignored. |
| `clf_candidate_path` | Where `--candidate` writes the classifier. Defaults to `clf_path` + `.candidate`. Git-ignored. |
