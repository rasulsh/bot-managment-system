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
php panel/setpass.php         # admin panel credentials (optional, recommended)
```

- **Required:** run `bash scripts/exposure-check.sh https://your-site/ /your-panel-path` and
  get `OK` before anything else. It is GET-only and safe on production.
- `redis`: if the server needs a password / db / socket / prefix, set them in the `redis`
  block of `guard/config.php`; the analyzer and panel pick them up from there.

- Wire the guard: `auto_prepend_file=/full/path/bot-guard/prepend.php` in
  `.user.ini` / `.htaccess` / `php.ini`.
- Set `exempt_paths` / `exempt_params` for every server-to-server endpoint on
  this site: payment gateway callbacks, webhooks, cron URLs, REST/feed clients.
- **Add the panel's own URI prefix to `exempt_paths`.** Being challenged out of
  your own admin panel by your own bot guard is a real and stupid failure mode.
  The panel has its own auth, CSRF and login rate limit.
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
  */15 * * * *  /bin/bash /path/scripts/analyzer-cron.sh snapshot   # panel dashboard
  *    * * * *  /bin/bash /path/scripts/analyzer-cron.sh worker     # panel job queue
  ```
  The last two are only needed if you installed the panel. Without `snapshot` the
  dashboard has nothing to read; without `worker` its action buttons queue jobs
  that nobody runs.
- Serve `panel/` over HTTPS and set `ip_allowlist` in `panel/panel.config.php` if
  it is reachable from the internet. If `panel/panel.config.php` does not exist,
  every panel route returns a bare 404 — that is the correct state for an install
  that does not want a panel.

**Pass:** the site behaves exactly as before, one JSONL line appears per request,
and `guard_ms` (`ms` in the log) stays around 1 ms or below. If the panel is
installed, its dashboard opens and shows a fresh snapshot.

> **The panel is optional throughout.** Every stage below gives the panel route
> first and the CLI form in parentheses, for when the panel is not installed or
> not reachable. Config changes made in the panel land in
> `guard/config.local.json`, which overrides `guard/config.php`; the settings
> view's **reset to file** removes a key from the overlay rather than writing the
> old value back. Every change is recorded in `panel/audit.jsonl` with who,
> when, from where, and the old and new value — which is what later connects "the
> false-positive rate jumped on Tuesday" to "hard_block_score was lowered on
> Tuesday".

---

## Stage 1 — Monitor + holdout (14 days)

- Set `holdout_pct = 2` now — **Settings → holdout_pct** (or `holdout_pct` in
  `guard/config.php`). Nothing downstream works without it: the holdout needs
  time to fill, and it is the only unbiased data the system will ever have.
  `holdout_salt` has no panel field on purpose; changing it reshuffles who is in
  the control group and invalidates the comparison. Set it once, in the file.
- Change nothing else. Read the **dashboard** weekly (or
  `python3 analyzer/report.py --days 7`).

**Watch:** real per-IP request distribution (this is where CGNAT shows itself),
share of traffic with no `Accept-Language`, most frequent user agents, honeypot
hits, and the shadow-action distribution — how often the guard *would* have
challenged. The **log explorer** filtered to `sh=1` is the same query as the
shadow-action `jq` line, and its CSV export feeds a spreadsheet if you want one.

**Pass:** two weeks of logs; `botv` verdicts appearing; no `botv=bad` on
addresses that genuinely belong to Google or Bing. A resolver outage can no longer
cause one (it yields `unknown`, which writes nothing); if you still see any, check
`run_verify` output for `flagged` and fix DNS before going further.

---

## Stage 2 — Enforce, one step at a time (2–3 weeks)

Enable one, wait several days, read the report, then the next. Each is a switch
in **Settings** (or a line in `guard/config.php`).

1. `enforce.block = true` — only the obvious class (empty or scripted UA).
2. `enforce.challenge = true` — the main event. Watch the challenge funnel on the
   dashboard; the ≥95% guidance is printed next to the number.
3. Replace the `limits` defaults with your own p99.9 from the logs, then
   `enforce.ratelimit = true`. For `limits.device_hour` / `device_day`, first look at
   who would have been stopped:
   `jq -r 'select(.act=="429" and (.rs|index("DEV_DAY") or index("DEV_HOUR")))|[.dev,.cdh,.cdd,.p]|@tsv' logs/guard-*.jsonl | sort | uniq -c | sort -rn | head -30`.
   Staff in the shop's admin panel belong in `exempt_paths`, not in this list.

**Before any threshold change:** run it through **Replay** with the proposed
value (or `python3 analyzer/replay.py --set <key>=<value>`). The panel's replay
runs the guard's own scoring and decision functions, so the preview and the live
decision cannot drift. The number that decides the change is *human-labelled rows
/ newly restricted*. If it moves, do not ship the change.

**Pass:** challenge success rate ≥ ~95%. Below that, real users are burning —
stop and investigate before continuing.

**Stuck customer:** paste the device id or IP into **Identity** — it shows every
`gv:` verdict on one page — then **Overrides → allow** with a short TTL (or
`python3 analyzer/ctl.py show <device|ip>` and `... allow <device> --ttl 3600`).
Takes effect on the next request regardless of any toggle. The device id is the
leading field of the `_gv` cookie.

---

## Stage 3 — Offline signals (2–3 weeks)

- Confirm `rep` and `ml` coverage is above zero — the dashboard's verdict
  coverage card, or the report. Zero coverage means the analyzer is not running
  or Redis is not shared; the dashboard's status strip says which, since it shows
  Redis reachability and the last successful run of each cron mode.
- `signals.reputation = true`. Wait several days; read the dashboard.
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

1. `capture_outcomes = true` — **Settings** (or `guard/config.php`). Confirm
   outcome lines appear and the site is byte-identical.
2. If `signals.ml` or `signals.clf` are on, decide now: turn them off for the
   migration window, or accept that the score loses those contributions once the
   feature set changes. Write down which you chose — the audit trail records the
   toggle, not the reasoning.
3. Let outcomes accumulate for **at least two weeks**.
4. **Models → train candidate** for each model (or
   `python3 analyzer/run_nightly.py --train --train-clf --candidate`). Panel
   training always writes to the candidate paths and never touches a live model.
5. **Models** shows each bundle's staleness and the classifier's precision on
   held-out data; run **Replay** against the candidate (or
   `python3 analyzer/report.py --model candidate` and
   `python3 analyzer/replay.py --model candidate`).
6. **Models → promote** for ml, then clf (or `python3 analyzer/ctl.py
   promote-model ml`, then `... clf`).
7. Re-enable any signals you turned off, one at a time.

Panel actions in this stage are **queued**, not immediate: they land in the Redis
job queue and run on the next `worker` firing, within a minute. The job's status
and its full output appear in the panel when it finishes.

**Pass:** verdict coverage back to normal; the 404-rate gap between the holdout
and enforced populations tells you what enforcement is actually catching.

---

## Steady state

- Weekly: read the dashboard, or the report. Three numbers matter — challenge
  success rate, false-positive proxy, and the holdout gap.
- Monthly: refresh the model by training a **candidate** (`run_nightly.py
  --train --candidate`, which is also what the weekly `train` cron now does) and
  **promote** it after re-checking classifier precision. Promotion is the
  explicit step that puts a new model in force; the cron never does it for you.
- After any site change that alters URLs: raise `NOTFOUND_RATIO` temporarily,
  since genuine broken links produce human 404s.
- Never tune a threshold without running replay first.
- If the panel is installed: check the dashboard's status strip for a stale
  snapshot or a cron mode that has stopped, and skim `panel/audit.jsonl` — or the
  audit view — after anyone else has been in the panel.

**Emergency:** the kill switch is the dashboard's most prominent control (behind
a confirm step) and `touch <guard>/guard.off` from a shell. Either takes effect
on the very next request. If the panel itself is what is broken, use the shell —
the panel is not in the request path and cannot prevent the file being created.

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
- The dashboard reads a snapshot written every fifteen minutes, so its numbers
  lag by up to that much. Its age is displayed; the log explorer is live.
- Panel actions are queued and run on the next `worker` firing, so they are not
  instant. The two exceptions are deliberate: the kill switch writes `guard.off`
  directly, and overrides are written straight to Redis — both are the emergency
  paths, and neither may wait on cron.
