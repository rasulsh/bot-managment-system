# Bot Guard — Operational Rollout Checklist

Development is finished. Everything below is operations. Each stage has a pass
criterion; do not start a stage until the previous one has met it. The whole
sequence is roughly 8–10 weeks, and almost all of that is waiting for data.

Rollback at any point: `touch <guard>/guard.off` — instant, no deploy, no restart.

---

## Stage 0 — Install (day 1, ~1 hour)

```bash
openssl rand -hex 32          # -> guard/config.php  'secret'
openssl rand -hex 16          # -> guard/config.php  'holdout_salt'
redis-cli ping                # expect PONG, reachable by BOTH php and python
python3 -m pip install -r analyzer/requirements.txt
```

- Wire the guard: `auto_prepend_file=/full/path/bot-guard/prepend.php` in
  `.user.ini` / `.htaccess` / `php.ini`.
- Set `exempt_paths` / `exempt_params` for every server-to-server endpoint on
  this site: payment gateway callbacks, webhooks, cron URLs, REST/feed clients.
- Add the honeypot: `Disallow: <honeypot_path>` in robots.txt, plus the hidden
  link snippet in the site template.
- Leave everything else at defaults: all `enforce` off, all `signals` off,
  `capture_outcomes` false, `holdout_pct` 0.
- Cron:
  ```
  */10 * * * *  /bin/bash /path/scripts/analyzer-cron.sh verify
  17 3   * * *  /bin/bash /path/scripts/analyzer-cron.sh nightly
  40 3   * * 0  /bin/bash /path/scripts/analyzer-cron.sh train
  10 0   * * *  /bin/bash /path/scripts/guard-logrotate.sh
  0  8   * * 1  /bin/bash /path/scripts/analyzer-cron.sh report
  ```

**Pass:** the site behaves exactly as before, one JSONL line appears per request,
and `guard_ms` (`ms` in the log) stays around 1 ms or below.

---

## Stage 1 — Monitor + holdout (14 days)

- Set `holdout_pct = 2` now. Nothing downstream works without it: the holdout
  needs time to fill, and it is the only unbiased data the system will ever have.
- Change nothing else. Read `python3 analyzer/report.py --days 7` weekly.

**Watch:** real per-IP request distribution (this is where CGNAT shows itself),
share of traffic with no `Accept-Language`, most frequent user agents, honeypot
hits, and the shadow-action distribution — how often the guard *would* have
challenged.

**Pass:** two weeks of logs; `botv` verdicts appearing; no `botv=bad` on
addresses that genuinely belong to Google or Bing (if you see any, fix DNS on the
server before going further).

---

## Stage 2 — Enforce, one step at a time (2–3 weeks)

Enable one, wait several days, read the report, then the next.

1. `enforce.block = true` — only the obvious class (empty or scripted UA).
2. `enforce.challenge = true` — the main event. Watch the challenge funnel.
3. Replace the `limits` defaults with your own p99.9 from the logs, then
   `enforce.ratelimit = true`.

**Before any threshold change:** `python3 analyzer/replay.py --set <key>=<value>`.
The number that decides the change is *human-labelled rows / newly restricted*.
If it moves, do not ship the change.

**Pass:** challenge success rate ≥ ~95%. Below that, real users are burning —
stop and investigate before continuing.

**Stuck customer:** `python3 analyzer/ctl.py show <device|ip>`, then
`python3 analyzer/ctl.py allow <device> --ttl 3600`. Takes effect on the next
request regardless of any toggle.

---

## Stage 3 — Offline signals (2–3 weeks)

- Confirm the report shows `rep` and `ml` coverage above zero. Zero coverage
  means the analyzer is not running or Redis is not shared — fix that first.
- `signals.reputation = true`. Wait several days; read the report.
- `signals.ml = true`. If `ml` levels cluster near 50, tune `DECISION_SPAN` in
  `model.py`; if the signal is too aggressive, lower `ml_weight` from 0.4.
- `signals.clf = true` **only** once the classifier's precision on held-out real
  data is above `clf_target_precision`. It refuses to train below 50 positive
  labels, which on a low-traffic site can take weeks. That is correct, not broken.

**Pass:** `esc` diverges from `sc` in the report, and the false-positive proxy in
replay has not moved.

---

## Stage 4 — Response outcomes (2–3 weeks)

Do these **in order**. Out of order causes a silent permissiveness gap.

1. `capture_outcomes = true`. Confirm outcome lines appear and the site is
   byte-identical.
2. If `signals.ml` or `signals.clf` are on, decide now: turn them off for the
   migration window, or accept that the score loses those contributions once the
   feature set changes. Write down which you chose.
3. Let outcomes accumulate for **at least two weeks**.
4. `python3 analyzer/run_nightly.py --train --train-clf --candidate`
5. `python3 analyzer/report.py --model candidate` and
   `python3 analyzer/replay.py --model candidate`. Check classifier precision.
6. `python3 analyzer/ctl.py promote-model ml`, then `... clf`.
7. Re-enable any signals you turned off, one at a time.

**Pass:** verdict coverage back to normal; the 404-rate gap between the holdout
and enforced populations tells you what enforcement is actually catching.

---

## Steady state

- Weekly: read the report. Three numbers matter — challenge success rate,
  false-positive proxy, and the holdout gap.
- Monthly: `--train` refresh; re-check classifier precision before relying on it.
- After any site change that alters URLs: raise `NOTFOUND_RATIO` temporarily,
  since genuine broken links produce human 404s.
- Never tune a threshold without running replay first.

## Known limitations — none of these are bugs

- Requests killed by OOM or a hard timeout have no outcome line.
- A status the web server substitutes itself (its own error page, a 304) is
  invisible to capture.
- `Content-Length` is absent on compressed or chunked responses, so `by` is null
  for most requests; `outcome_cov` exists so the model knows this.
- Holdout identities have no stable device id, so holdout data is sound in
  aggregate only.
- Verified-bot allowlisting is offline; a forged Googlebot UA gets a pass until
  the next `run_verify` cycle.
