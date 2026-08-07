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
