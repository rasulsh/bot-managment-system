# Bot Guard — Code Review: Bottlenecks & Workflow Issues

Scope: the whole repository, with the request-path guard (`prepend.php`,
`guard/`) weighted most heavily because that is the only code that runs on
every visitor request. The analyzer and panel run out of band, so their cost is
paid by cron and by one operator, not by traffic.

The headline: the architecture is sound. The design keeps DNS, model scoring and
log scanning entirely off the request path, fails open on every error, and never
buffers the response. The issues below are almost all in the request path's
**Redis interaction**, which is where a bot-heavy or high-traffic site will feel
cost — not in the decision logic, which is cheap and correct.

Each item lists the file, why it matters under load, and a concrete fix.

---

## Severity legend

- **P1 — will cause latency or an outage under load.** Fix before a high-traffic
  rollout.
- **P2 — real cost or a correctness edge, but survivable.** Fix soon.
- **P3 — cleanup, hardening, or a papercut.** Fix opportunistically.

---

## P1 — Request-path bottlenecks

### P1-1. A new Redis TCP connection is opened on every request

> **Addressed (differently).** Persistent sockets were rejected (dirty reply stream, stale AUTH/SELECT state). Pipelining leaves two round trips, and a unix socket (`redis.socket`) removes the TCP handshake.


`guard/redis.php` → `gv_redis_connect()` uses `stream_socket_client('tcp://…')`
with no persistence. Every single request that is not exempt pays a full TCP
handshake to Redis, then closes it at the end of `gv_run()`.

Why it matters: on a busy site this is the single largest fixed cost the guard
adds. A TCP connect to loopback is cheap (tens of µs) but not free, and against
a Redis on another host it is a full round trip before any work happens. At a few
hundred requests/second per PHP worker this is thousands of connects/second and a
matching churn of TIME_WAIT sockets.

Fix: use a persistent connection. `pfsockopen()` (or `stream_socket_client` with
`STREAM_CLIENT_PERSISTENT`) reuses one socket per PHP worker process across
requests. The RESP protocol code does not change. The one caveat is that a
persistent socket can be left in a dirty state if a previous request died
mid-reply; guard against it by draining or reconnecting on the first malformed
reply (the client already returns `false` on a bad reply — treat a `false` on the
first command of a request as "reconnect once, then give up").

```php
// gv_redis_connect(), persistent variant
$conn = @pfsockopen('tcp://' . $host . ':' . $port, $errno, $errstr, $to);
// ...and do NOT fclose() a persistent socket at end of request:
// gv_redis_close() should become a no-op (or an explicit drain) for pconns.
```

Expected effect: removes one TCP handshake per request. On loopback Redis this is
a modest but real win; on a networked Redis it is large.

---

### P1-2. 8–14 sequential Redis round trips per navigation, none pipelined

> **Addressed.** Reads and counters are pipelined (two round trips), fail-fast plus a circuit breaker bound a stalled Redis to one timeout. See docs/02-ARCHITECTURE.md, "Redis contract".

This is the big one. Trace a normal logged-in visitor loading an HTML page
(`gv_run()` in `guard/guard.php`, steps 7b–9):

- step 7b: `GET gv:rep:{dev}`, `GET gv:ml:{dev}`, `GET gv:clf:{dev}` — 3 reads
- step 7c: `GET gv:allow:{dev}`, `GET gv:deny:{dev}`, `GET gv:deny:{ip}` — up to 3 reads
- step 8: `GET gv:hp:{ip}` — 1 read
- step 9: `INCR gv:rd:{dev}`, `INCR gv:riu:{…}`, `INCR gv:ri:{ip}` — 3 writes, plus an `EXPIRE` on each key's first hit

Each of these is a separate `fwrite()` + `fgets()` — a **synchronous round trip**.
That is 10–14 sequential round trips to Redis inside the request path. On
loopback each is ~30–50µs, so ~0.5ms of pure Redis latency in the common case;
against a Redis one network hop away (0.2–0.5ms each) it becomes **3–7ms of
serial waiting per request**, all of it blocking the visitor's page.

The reads in 7b, 7c and 8 have no data dependency on each other — they are all
independent key lookups. They are perfect candidates for pipelining or a single
round trip.

Fixes, in order of impact:

1. **Pipeline the independent reads.** Send all of 7b + 7c + 8's `GET`s in one
   `fwrite()`, then read all replies. The RESP client already frames one command
   at a time; add a `gv_redis_pipeline(array $commands)` that writes the
   concatenation of `gv_resp_encode()` for each and reads N replies in order.
   This collapses 7 sequential reads into 1 round trip.

2. **Collapse the three counters into one server-side step.** The `INCR` +
   conditional `EXPIRE` pattern is two round trips per counter on the first hit
   of a window. Replace each with a tiny Lua script (`EVALSHA`) that does
   `INCR` + `EXPIRE NX` atomically, or at minimum pipeline the three `INCR`s
   together and only issue `EXPIRE` for the ones that returned 1. Better still,
   one Lua script handles all three counters and returns all three counts in a
   single round trip.

3. **Fold the whole per-request Redis interaction into one Lua script.** The
   most aggressive option: one `EVALSHA` that takes the dev id, ip, and window,
   and returns rep/ml/clf/overrides/hp plus the three post-increment counter
   values in a single round trip. This turns 10–14 round trips into **one**. It
   is more code, but for a genuinely high-traffic site it is the correct shape.

Expected effect: the dominant per-request latency the guard adds today is this
serial chain. Pipelining alone (option 1+2) removes roughly two-thirds of it;
the Lua approach removes nearly all of it.

---

### P1-3. `LOCK_EX` on every log write serializes all PHP workers

`guard/log.php` → `gv_log()` and `gv_log_outcome()` both do
`file_put_contents($file, $line, FILE_APPEND | LOCK_EX)`, and `gv_emit()` is
called on **every** request (allow, challenge, block, exempt — every path logs
exactly one line). With `capture_outcomes` on, there is a second locked append at
shutdown.

Why it matters: `LOCK_EX` takes an exclusive `flock` on the daily file. Under
concurrency, every worker that wants to log blocks until the current writer
releases the lock. On Linux with a local filesystem, appends under a page size
are effectively atomic without the lock, but `flock` still forces serialization
and a syscall round trip. At high request rates this lock becomes a contention
point that all workers queue on — and it is on the request path for allow
decisions (the common case), because `gv_emit()` runs before `gv_run()` returns.

Fixes:

1. **Cheapest:** drop `LOCK_EX` and rely on `O_APPEND` atomicity for writes
   below `PIPE_BUF` (4096 bytes on Linux). The log lines here are well under that.
   This is how most high-throughput JSONL loggers work. The risk is interleaved
   lines on filesystems that do not honor atomic append (some network
   filesystems); document that the log dir must be local.

2. **More robust:** write logs through a local syslog/journald socket or an async
   sink (e.g. append to a per-worker buffer flushed periodically), so the request
   path never does a blocking filesystem write at all. This is a larger change.

3. **Middle ground:** keep `LOCK_EX` but move the *decision* log write to just
   before `return`/`exit` (it already is) and make sure the outcome write at
   shutdown is the only post-response cost (it already is). Then at least the
   lock is held for the minimum possible time. This does not remove contention,
   only shortens it.

Recommended: option 1 with a documented "log dir must be on a local filesystem"
requirement. It removes a global serialization point for a negligible risk on the
target deployment (cPanel/LiteSpeed local disk).

---

### P1-4. `config.local.json` is read from disk and JSON-decoded on every request

`gv_cfg_load()` calls `gv_overlay_read(gv_overlay_path())`, which does
`file_get_contents()` + `json_decode()` on `guard/config.local.json` every
request. Unlike `guard/config.php` (which is `require`d and therefore cached by
OPcache as compiled bytecode), the JSON overlay is a raw file read + parse on the
hot path, every time, forever.

Why it matters: it is a `stat` + `open` + `read` + `json_decode` per request. On
its own, small. But it is unconditional and it defeats the whole reason
`config.php` is fast (OPcache). On a busy site it is measurable, and it scales
with request volume, not with how often the config actually changes (which is
rarely).

Fixes:

1. **APCu cache with mtime check.** Cache the parsed overlay in APCu keyed by the
   file's mtime; re-read only when mtime changes. One `stat` per request instead
   of a full read+parse. This is the standard pattern and APCu is available on
   the target hosting.

2. **Compile the overlay to a PHP file.** When the panel writes the overlay, also
   write a `config.local.php` that `return`s the same array. The guard `require`s
   it (OPcache-cached) and skips the JSON entirely. The panel already does an
   atomic write; add a second atomic write of the `.php` form. This is the
   fastest option and it makes the overlay exactly as cheap as `config.php`.

3. **If neither is acceptable:** at least skip the read when the file does not
   exist (it already `is_file()`-checks, so a no-overlay install pays only a
   `stat`, which is fine — the cost is real only once the panel has written an
   overlay).

Recommended: option 1 (APCu + mtime) — smallest change, big win, no new files.

---

## P2 — Cost and correctness edges

### P2-1. `gv_match_bot()` and the script-UA scan are linear scans per request

`gv_match_bot()` (`guard/guard.php`) loops over `known_bots` doing
`strtolower()` + `strpos()` for each entry, on every request. `gv_score()` does
the same over a 12-entry `$sig` array of script UA needles. Both re-lowercase and
re-scan on each call.

Why it matters: small today (a handful of needles), but it is O(needles × request)
and the UA string is re-lowercased twice (once in `gv_match_bot`, once in
`gv_score`). If `known_bots` grows to a real crawler allowlist (dozens of
entries) this becomes a per-request cost that scales with the list.

Fix: lowercase the UA once in `gv_facts()` and pass `lua` alongside `ua`. Keep the
needle lists as-is for now — `strpos` in a loop is fine at this size — but if the
lists grow, precompile them into a single alternation regex
(`/googlebot|bingbot|…/`) matched once. Not urgent; note it so it is not
forgotten when the lists grow.

### P2-2. Honeypot write uses a fixed 7-day TTL that ignores config

`gv_run()` step 6 writes `gv:hp:{ip}` with a hard-coded `604800` (7 days), and
step 8 reads it back. The value is not configurable and does not track
`token_ttl` or any limits window. More importantly, the honeypot flag is keyed by
**IP**, and on CGNAT / mobile carriers many real users share one IP — a single
bot tripping the honeypot from a shared egress IP stamps `HP_HIST` (+40) on every
real user behind it for a week.

Why it matters: this is a false-positive vector on exactly the networks the rest
of the system is careful about (the token is deliberately not IP-bound for this
reason; the honeypot undercuts that). +40 is large — combined with any other
signal it can push a real user over `hard_block_score`.

Fix: two options, ideally both. (a) Make the honeypot TTL configurable and
default it shorter (e.g. 24h). (b) Prefer keying the honeypot penalty on the
**device id** when the client has a token, falling back to IP only for
token-less clients — mirroring how rep/ml/clf are already per-device. At minimum,
document that `HP_HIST` is IP-scoped and can catch shared-egress users, and keep
its weight below `hard_block_score` so it can never block on its own.

### P2-3. Panel dashboard freshness depends on a cron the installer can forget

The dashboard (`panel/views/dashboard.php` via `gp_snapshot()`) reads
`analyzer/snapshot.json`, which is only ever written by the `snapshot` cron mode.
If that cron line is missing, the dashboard silently shows stale or empty data
with no loud error — the `generated_at` age is shown, but an operator has to
notice it. The `worker` cron (which drains the panel's job queue) has the same
property: enqueue a job with no worker running and it sits in the queue forever,
the panel showing "queued" indefinitely.

Why it matters: not a performance issue, a workflow trap. The two most
forgettable cron lines (`snapshot`, `worker`) are the two whose absence is
hardest to diagnose from the UI.

Fix: on the dashboard and jobs pages, when the snapshot age exceeds ~2× its
expected interval, or when jobs have been "queued" longer than a threshold with no
worker heartbeat, show a prominent warning naming the exact cron line to add.
`snapshot.json` already carries `last_runs`; use the `worker` marker there to
detect a dead worker and say so.

### P2-4. `worker.py` redirects `sys.stdout`/`sys.stderr` process-wide while a job runs

`analyzer/worker.py` → `run_one()` swaps `sys.stdout`/`sys.stderr` to a capture
buffer around the job call. This is process-global. It works because the worker
runs jobs one at a time, but it means any library that caches a reference to the
real stdout (some logging handlers do, at import time) will either miss the
capture or write to the swapped stream unexpectedly. It also means a job that
spawns a thread doing its own printing will have that output interleaved into the
captured buffer non-deterministically.

Why it matters: low, because the jobs here are single-threaded and the worker is
serial. But it is a fragile pattern that will bite if a future job type uses
threads or a logging framework.

Fix: use `contextlib.redirect_stdout`/`redirect_stderr` as context managers
(cleaner, exception-safe) or, better, have the job handlers return their output as
a string rather than printing it and having the worker capture stdout. Not urgent.

### P2-5. Analyzer sessionization sorts every bucket's rows in Python

`analyzer/logs.py` → `sessionize()` builds `buckets[key]['rows']` as a list of
`(ts, row)` tuples, then for each key does `sorted(bucket['rows'], key=…)`. For a
week of a busy site this is a large in-memory structure and a sort per identity.
`run_nightly.py` also does `list(logs_mod.read_lines(...))` — it materializes the
entire window of decision rows in memory at once.

Why it matters: this is the analyzer, not the request path, so it is paid by cron
on one machine. But on a high-traffic site a 7-day window can be tens of millions
of rows; materializing all of them plus per-key sorted buckets can exhaust memory
on a small VPS. The `outcomes.py` docstring explicitly notes the per-file join
was chosen to keep memory flat — but `run_nightly` then undoes that by
`list()`-ing the whole generator.

Fix: the nightly job does not need every row in memory simultaneously if
sessionization is done streaming per identity. That is a larger refactor. The
cheap mitigation: document a memory budget and let `window_days` be tuned down on
constrained hosts (it already is configurable). For very large sites, process the
window in day-sized chunks and merge per-identity aggregates rather than holding
all rows. Note it as a scaling limit, not a bug — it degrades gracefully (the box
just needs RAM proportional to the window).

---

## P3 — Cleanup and hardening

### P3-1. `prepend.php` fatal-swallowing can hide a broken install indefinitely

> **Addressed.** Swallowed exceptions in `prepend.php` and `guard.php` (and every Redis failure) now write a throttled line to `logs/guard-errors.log`, shown on the panel dashboard.

`prepend.php` and the bottom of `guard.php` both wrap `gv_run()` in
`catch (\Throwable)` and do nothing — fail-open, which is the correct safety
posture. But it means a genuinely broken guard (syntax error in an included
file after an edit, a wrong path, a permissions problem) produces **zero signal**:
the site works, the guard does nothing, and nobody knows it stopped protecting
anything. This is the same "silently more permissive" failure the analyzer's
stale-model warnings were built to catch — but the guard itself has no equivalent.

Fix: keep fail-open, but on the caught `Throwable`, write a single line to a
dedicated `logs/guard-errors.log` (best-effort, in its own try/catch). It costs
nothing on the happy path and turns an invisible outage into a greppable one. The
panel dashboard can then surface "the guard has logged N errors today."

### P3-2. `gv_cidr_match()` is IPv4-only; IPv6 clients silently bypass CDN/allowlist logic

`gv_cidr_match()` returns `false` for any non-IPv4 input, and `gv_client_ip()`
therefore never trusts XFF for an IPv6 `REMOTE_ADDR`, and the panel's
`ip_allowlist` can never match an IPv6 operator. On an IPv6-capable host this
means (a) behind an IPv6 CDN edge, the guard scores the CDN's IP, not the visitor
— collapsing all IPv6 visitors behind one CDN IP into one rate-limit bucket, and
(b) an operator on IPv6 cannot use the panel allowlist.

Why it matters: increasingly common. (a) is a correctness problem for IPv6 CDN
deployments — every IPv6 visitor shares one `gv:ri:` counter and can trip the IP
rate limit collectively. (b) is an operator lockout footgun.

Fix: implement IPv6 CIDR matching (compare `inet_pton()` byte strings under a bit
mask). It is ~15 lines. Until then, document loudly that CDN XFF trust and the
panel allowlist are IPv4-only, and that behind an IPv6-terminating CDN the guard
must be given the real client IP another way (e.g. a trusted header the CDN sets,
added to the fact extraction).

### P3-3. `gv_header_count()` calls `getallheaders()` which is absent on some FastCGI SAPIs

`gv_header_count()` already falls back to scanning `HTTP_*` in `$_SERVER`, so this
is handled — but note that the two paths can disagree (getallheaders includes
some headers the `HTTP_*` scan misses and vice versa), so `hc` and therefore the
`FEW_HDR` signal (+15) can be slightly inconsistent across SAPIs for the same
request. Low impact; just be aware the threshold (`< 5`) is SAPI-sensitive.

Fix: pick one source for consistency, or make the `FEW_HDR` threshold
SAPI-aware. Not urgent — the signal weight is small.

### P3-4. Two config files must be kept in sync by hand (`known_bots`, `bot_suffixes`)

`guard/config.php` and `analyzer/config.py` both declare `known_bots` and
`bot_suffixes`, documented as "must be kept in sync." The bridge
(`analyzer/bridge.py`) already reads the *thresholds* from the guard via
`config-dump.php` — but not these two lists. A drift means the analyzer verifies
bots the guard does not fast-pass, or vice versa.

Fix: extend the bridge to also pull `known_bots` and `bot_suffixes` from
`config-dump.php` (it is already in `GUARD_KEYS` for `known_bots`/`bot_suffixes`
in the dump — verify the analyzer actually consumes them rather than its own
copy). Make the guard the single source of truth for these two lists too, exactly
as it already is for thresholds. Removes the last hand-sync requirement.

### P3-5. `holdout_pct` is clamped to 5 silently in one place, rejected in another

`gv_is_holdout()` clamps `pct > 5` down to 5 silently; the overlay validator
(`gv_overlay_whitelist`) rejects `holdout_pct > 5` outright. So the panel refuses
6, but a hand-edited `config.php` with `holdout_pct: 20` is silently treated as 5.
Two different behaviors for the same out-of-range value.

Fix: pick one. Given the project's stated principle ("out-of-range is rejected,
never clamped, so the mistake is visible"), the clamp in `gv_is_holdout()` is the
inconsistent one — but it is also the last line of defense against a bad config
turning 20% of traffic into an unprotected holdout, so keep it as a safety clamp
and just log/comment that it fired. Low priority; it is a belt-and-suspenders
situation, not a bug.

---

## What is genuinely well done (so it is not "fixed" by mistake later)

These are deliberate and correct; a future refactor should preserve them:

- **Fail-open everywhere in the request path.** Every Redis error, every
  exception, every missing file degrades to "allow" and never breaks the host
  app. This is the right posture for a guard bolted onto a live store.
- **No DNS, no model scoring, no log scanning on the request path.** Reverse DNS
  (`botverify`), Isolation Forest / classifier scoring, and log analysis all run
  in cron and leave a single cheap integer in Redis for the guard to read. This
  is exactly how to keep an ML bot-detector fast.
- **The response is never buffered.** Outcome capture reads the *declared*
  `Content-Length` at shutdown rather than buffering the body — streaming and
  downloads are untouched, memory does not double. The docstring's reasoning is
  correct.
- **Shadow-mode / monitor-first discipline.** Every new signal is off by default
  and visible in logs before it can change an outcome; `secret == CHANGE_ME`
  forces monitor mode. This makes a safe rollout the default and an unsafe one
  require deliberate action.
- **The panel never writes PHP and never builds a shell command.** Config changes
  are validated JSON written atomically; analyzer actions are typed queue
  envelopes run in-process by the worker. For a security tool this closes the two
  classic self-inflicted holes.
- **Single source of validation.** `gv_overlay_validate()` is the one definition
  used both when the panel writes a key and when the guard reads it, so they
  cannot drift.
- **The holdout, and refusing `challenge_unsolved` as a training label.** The
  system measures its own false-negative rate on an unenforced slice, and
  refuses to train the classifier on its own gating decisions (which would make
  the model a mirror of the rules). This is unusually disciplined ML plumbing.

---

## Suggested fix order for a high-traffic rollout

1. **P1-2** (pipeline the Redis reads; Lua for counters) — by far the biggest
   per-request latency win.
2. **P1-1** (persistent Redis connection) — removes a per-request TCP handshake.
3. **P1-4** (APCu-cache the overlay) — removes a per-request disk read+parse.
4. **P1-3** (drop `LOCK_EX`, require local log dir) — removes a global write lock.
5. **P2-2** (honeypot IP-scope false-positive) — correctness on CGNAT.
6. **P3-2** (IPv6 CIDR) — correctness if the site is IPv6/CDN.
7. Everything else opportunistically.

Items 1–4 together should cut the guard's per-request overhead on a busy site
from "10–14 serial Redis round trips + a disk read + a file lock" to
"1–2 round trips on a reused connection, no disk read, no lock" — which is the
difference between the guard being invisible under load and the guard being the
thing that shows up in a slow-request trace.
