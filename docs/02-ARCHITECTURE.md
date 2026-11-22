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

   **3a. IP lists** (`lists/allow.bin`, `lists/block.bin`; see *IP allow / block lists* below). A binary
   search on the client address, only when an enabled list of that type exists. An enforced allow-list
   hit returns here (`allow_override`). The enforced **block** list is decided even earlier, at **1b**,
   right after the facts and *before* the handshake of step 2 (an exempt path still bypasses it). Neither
   touches Redis.

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
   counters (skipped entirely in degraded mode), plus two long fixed windows per
   device: one hour and one day. The short window sees speed; the long ones see the
   client that never hurries and never stops, from whatever address. Any counter
   over its limit sets an "over" flag.

10. **Decision.** Fold the offline verdicts into the static score to get an
    *effective* score (each signal contributes only if its toggle is on — otherwise
    the effective score equals the static score exactly, so signals are visible in
    logs long before they change anything). Then decide, first match wins: deny
    override → block; effective score over the hard block threshold on a GET
    → block; over a rate limit → 429; a GET with no valid token → challenge (the
    gate is the method alone, never `Accept` or `X-Requested-With`, which the
    client chooses);
    otherwise allow.

11. **Act.** Log exactly one line. If the decision is "allow," arm outcome capture
    and return with zero output. Otherwise consult the enforce toggle for that
    action: if enforcement is off (monitor mode) or this request is in the holdout
    slice, log what *would* have happened, allow, and let the app run. If
    enforcement is on, emit the block / 429 / challenge response and exit.

### Access rules

`guard/rules.php`, data in `guard/rules.json` (panel-written, atomic rename). Evaluation is a
pure function of the request facts: **no Redis, no DNS, no file write**. A bad file, a bad rule or
a PCRE error is "no match" plus one rate-limited line in `guard-errors.log`.

Where it sits in `gv_run`, and precedence, highest first:

1. Kill switch (`guard.off`) and `exempt_paths` / `exempt_params`: bypass rules entirely.
2. Operator **allow** override (device or IP): beats any rule (step 7c, before the rule is applied).
3. A **verified** known bot (verdict `ok`) skips a rule with `skip_verified_bots` (default).
   A claimed but unverified, or refuted (`bad`), bot is **not** skipped.
4. Operator **deny**: as before.
5. The first matching enabled, unexpired rule by priority, in `enforce` mode:
   `block` = 403; `challenge` = the existing JS + proof-of-work page for a gated request
   without a valid token (the rule's `pow_bits` if set); with a valid token the request
   continues normally, so a solved challenge cannot loop. A token-less POST with
   `challenge.gate_post` off is logged as a shadow challenge, like the built-in rule.
   `log` only adds the reason.
6. Rule actions are operator actions: the holdout never suppresses them and
   `enforce.block` / `enforce.challenge` do not gate them. Only the rule's `mode` does.
   With the secret unconfigured (`CHANGE_ME`) no rule is loaded.

An enforced `block`/`challenge` rule replaces the free pass of known bots and link-preview
fetchers; a `monitor` or `log` rule does not (the row just carries `SH_RULE:<id>`).
Every request that matched carries `RULE:<id>` (`SH_RULE:<id>` in monitor) in `rs`; still
exactly one log row per request.

**Counters.** The counters (`rd`, `rdh`, `rdd`, `riu`, `ri`) are bumped exactly as for any
request, in the same single pipeline, before the rule's 403/challenge is served. A blocked
client keeps counting up (like under an operator deny) and nothing resets its counters.
No extra Redis round trip is added.

**Score.** Rules and the static score are independent. `UA_SCRIPT` (+30) and `UA_EMPTY` (+40)
still apply and still count toward `hard_block_score`; a rule on the same UA simply acts
sooner and does not depend on the score or `enforce.block`. A matched rule adds nothing to the score.

**Regex safety.** Saved patterns are compiled and stress-tested (catastrophic backtracking is
refused), capped at 300 chars, no back-references. All values of a rule are joined into one
alternation. At request time a PCRE error = no match (also for `exclude`).

**The generated cache.** `guard/rules.json` stays the source of truth. On every save the panel
also writes `guard/rules.cache.php`, generated only with `var_export()` from the validated list:
enabled rules only, sorted by priority, each UA condition carrying its compiled pattern and blank
flag. It is a plain array literal (no code), so OPcache keeps it in shared memory and a request
pays no file read, no JSON decode, no validation and no pattern building. The guard includes the
cache when it is at least as new as `rules.json` (`filemtime`); if the cache is missing or older
(for example `rules.json` was edited by hand) it reads `rules.json` directly and writes one
rate-limited line, `rules cache stale`, to `guard-errors.log`. Saving in the panel rebuilds it. A
missing `rules.json` means no rules whatever the cache says; with no enabled rule the cache is an
empty array and the guard does nothing more. After a save the panel calls `opcache_invalidate()`
on the cache; if the guard runs in another PHP pool, OPcache may serve the previous version for up
to `opcache.revalidate_freq` seconds (default 2).

The JSON is also stamped (`{"v":1,"crc":...}`): a good checksum lets the fallback path skip
per-rule validation; a hand-edited file is validated rule by rule.

**Redis down.** With Redis unreachable no bot verdict can be read. The existing degraded-mode
policy is that a known-bot UA keeps its pass during an outage, so for `skip_verified_bots` the
claim counts as verified: the rule is skipped, the bot keeps its pass, and the row carries the
reason `RULE_SKIP_DEGRADED`. This applies only when Redis is down and a UA matches `known_bots`;
with Redis alive an unverified or refuted claim is never skipped. A rule with
`skip_verified_bots` off still applies, outage or not. The consequence is the same as for the
bot pass itself: during an outage a client that merely claims to be Googlebot is not caught by
rules.

### GeoIP (country / ASN conditions)

`guard/geo.php` answers "which country / AS is this address?" for the rules and, optionally, for the log.

* **Offline compile, online search.** Source databases (`geo/*.mmdb`, `geo/geoip.dat`) are never read by
  PHP. The analyzer (`analyzer/geo.py`, worker job `geo_compile`, or `scripts/analyzer-cron.sh geo`) merges
  them into `geo/country.bin` and `geo/asn.bin`: a 128-byte header (magic `GVRG`, version, kind, build time,
  range counts, sha256 and name of the source) and sorted, non-overlapping ranges (IPv4 `start 4 | end 4 | value`,
  IPv6 `start 16 | end 16 | value`; country value = 2 letters, ASN = uint32). The IP lists (a later release) use the
  same file format and the same lookup. The file is written to a temp name and renamed (atomic); the file it
  replaces stays as `<name>.prev` for rollback. A new table replaces the live one only if it passes the sanity
  checks (minimum range count, a range for IR, the addresses of `geo/known.json` when that file exists).
* **Lookup.** A binary search with `fopen` / `fseek` / `fread` on the compiled file: nothing is loaded into
  memory, the OS page cache does the work, no extension, no DNS, no Redis. The address is the CDN-aware client
  address the guard already resolved (`gv_ip_canon`: an IPv4-mapped IPv6 address is looked up as IPv4). A
  missing, short, wrong-magic, wrong-version or truncated file, or an address in no range, gives "unknown":
  country `''` / ASN `0`, and one rate-limited line in `guard-errors.log` for a broken file.
* **When the file is opened.** Only when an enabled, unexpired rule with a country or ASN condition is
  *reached* in the priority loop (the cheap conditions of a rule - path, then country / ASN, then the UA
  pattern - are tested in that order), or when `geo.log` is on. A site with no geo rule and `geo.log` off never
  opens it. The result is memoised for the request.
* **Unknown never matches.** An unknown country (or ASN) matches neither an `include` nor an `exclude`
  condition. "Block everything except IR" therefore never blocks a visitor that could not be placed.
* **In the generated cache.** `guard/rules.cache.php` carries each country / ASN condition as a lookup set
  (`'set' => array('IR' => true, ...)`), so a rule costs one `isset()` after the request's single search.
* **Log.** `cc` (and `asn` when an ASN database is installed) are added to the row exactly when a lookup ran:
  `cc` is `""` for "looked up, not placed", and a row without the key was not looked up.
* **Precedence is unchanged** (see Access rules): kill switch and exempt paths, operator allow, verified-bot
  skip, operator deny, then the rule. Country and ASN rules are ordinary rules and follow all of it; in
  particular, with Redis down a known-bot UA is treated as verified for `skip_verified_bots` (reason
  `RULE_SKIP_DEGRADED`), so a country rule can never block Googlebot or Bingbot during an outage.

### IP allow / block lists

`guard/iplist.php` (lookup), `panel/iplists.php` (everything else), `analyzer/iplist.py` (compile for big lists). The
operator keeps named lists in the panel (**IP lists**): a type (`allow` or `block`), a mode (`enforce` or `monitor`),
an enabled flag and a text of IPv4 / IPv6 addresses and CIDRs, one per line.

* **Storage.** `lists/lists.json` (metadata, written only by the panel, temp file + rename under a lock),
  `lists/<id>.txt` (the source), and **one compiled file per type**, `lists/allow.bin` / `lists/block.bin`, built from
  *every enabled list of that type*. They use the range format of `geo/*.bin` (kind 3): a 128-byte header and sorted,
  non-overlapping ranges, IPv4 `start 4 | end 4 | value 2`, IPv6 `start 16 | end 16 | value 2`. The value is a
  `uint16`: bit 15 = the list is in monitor mode, bits 0-14 = the list index (never reused). Where lists overlap
  the **smaller value wins**, so an *enforced* list beats a *monitor* list on the same address, then the lower index.
  The file is written to a temp name and renamed (atomic); the file it replaces stays as `<name>.prev`.
* **Safety caps, enforced by the compile itself** (`panel/iplists.php` `gp_ipl_refusal()` and its mirror in `analyzer/iplist.py`; the form
  uses the same function), so a file copied over SFTP or compiled by the worker cannot bypass them: `0.0.0.0/0` and `::/0` are **always**
  dropped (an allow list with it would switch the whole guard off); an allow entry wider than /16 (IPv4) or /32 (IPv6) is dropped; a block entry
  wider than /8 or /32 is dropped; a block entry covering private, loopback, link-local space or the server's own addresses is dropped. The
  list's `force` flag (set only from the panel, audit-logged) keeps everything except `0/0`. Dropped entries and unparseable lines are counted
  per list and reason in `lists/lists-status.json` (with samples), shown on the Compile and Entries tabs, and raised on the dashboard. The
  server's own addresses are recorded by the panel in `lists/lists.json` (`own`) on every metadata write, because the worker has no request.
* **Compile.** In the panel request for small sources (up to 512 KiB in total), through the worker job
  `iplist_compile` for big ones (`analyzer/iplist.py`, the same algorithm: a test compiles the same lists with both
  and compares the files byte for byte). A type with no enabled list that has entries gets its file **deleted**: the
  request path opens a list file only while an enabled list of that type needs it, so "no lists" costs one failed
  `fopen()` per type (about 1 us).
* **Lookup.** `fopen` / `fseek` / `fread` binary search with unbuffered reads, and the last 64 records of the search
  read in one `fread`. Nothing is loaded into memory. The address is the CDN-aware client address (an IPv4-mapped IPv6
  address is looked up as IPv4). A missing, short, wrong-magic, wrong-kind or truncated file is "no match" plus one
  rate-limited line in `guard-errors.log` (the panel raises a dashboard alert while a list is enabled).
* **Precedence**, highest first:
  1. Kill switch and `exempt_paths` / `exempt_params`: unchanged, they bypass lists too.
  2. **Allow list** (enforce) = an operator allow override, decided at step 3a (after the exemptions), before any Redis connection: skips
     rules, scoring, counters, the challenge, the known-bot pass. Row: `act=allow_override`, `ovr=allow`,
     `IPL_ALLOW:<id>`. It also beats an operator *deny* override (an allow override beats a deny too).
  3. **Block list** (enforce) = 403, decided at step **1b**, **before the challenge handshake** (a listed address cannot drive handshake
     `POST`s: no nonce claim, no counters, no Redis round trip), and so before the known-bot pass (a listed address cannot get
     through by claiming to be Googlebot, and a verified crawler address on the list is refused too), before the
     link-preview pass, before the counters. The holdout does not apply and `enforce.block` does not gate it: the list's
     own mode does, like a rule. Row: `act=403`, `IPL_BLOCK:<id>`. No Redis command at all.
  4. Everything else as before (rules, bot pass, overrides, scoring, counters).
  An address in both an allow and a block list is **allowed** (the block check at 1b is skipped while an *enforced* allow list holds the
  address); the panel shows a warning listing the overlapping ranges. An enforced allow list is also checked before any **deny
  override**: a deny for an address inside it has no effect (the panel warns when the deny is created).
* **Monitor lists** never act: the request goes on as usual and the row carries `SH_IPL_ALLOW:<id>` / `SH_IPL_BLOCK:<id>`.
  A monitor allow list does not skip anything. With the secret unconfigured (`CHANGE_ME`) a block list is not applied
  (monitor-first, like every enforcement); an allow list only ever relaxes, so it is.
* **Counters.** A list hit that returns at 3a bumps no counter (an allow-listed or blocked request makes **zero** Redis
  commands). Nothing can be reset by it; the counters of that address simply stop growing while it is listed.
  The allow list stays after the handshake (step 3a): an allow-listed address mints a token like any client.
* **Log and snapshot.** One row per request as always. The analyzer snapshot counts list hits per list (`iplists`,
  24 h / 7 d / last hit, keyed `allow:<id>` / `block:<id>`), shown on the IP lists page.

### Image CAPTCHA and the headless signals

`guard/captcha.php` (image, nonce, scoring, page, the answer handshake), `guard/challenge.php` (token levels, the page script),
`guard/rules.php` (the action). **Self-hosted**: the image is drawn with PHP GD (the only extension this project allows, and optional)
with a shipped open-licensed font (`guard/captcha-font.ttf`, DejaVu Sans Mono Bold, licence next to it) and sent inside the page as a
data URI (no extra public URL to hammer, `Cache-Control: no-store`). No external service: reCAPTCHA, hCaptcha and Turnstile are
unreliable from Iran and leak visitors to third parties. Without GD every `captcha` action falls back to the proof-of-work challenge
with the rule's `pow_bits`.

* **Where it is used.** (1) A rule with the action **Image CAPTCHA**: an HTML request without a CAPTCHA-level token gets the page.
  (2) **Escalation** (`captcha.escalate_score`, off at 0): a proof of work whose headless score reaches it does not get a token but
  a CAPTCHA instead. The client then stays escalated for 10 minutes by two flags, and the next HTML page is the CAPTCHA: a signed cookie (`<cookie>c`, works with Redis down) **and** the Redis key
  `cesc:<md5(ip net|UA hash)>` (works when the client drops cookies). The key is written with `SET .. EX 600` in the handshake's own
  pipeline (or read with `GET` there when this handshake is not itself escalated) and read in the request path's one existing pipeline, so
  escalation adds no round trip: while it exists, a navigation request from that ip + UA without a level-c token gets the CAPTCHA, cookie or no
  cookie, and a proof-of-work handshake from it is answered 202 (reload into the CAPTCHA) instead of a level-p token. A level-c token deletes
  the key (one extra `DEL`, only on that success path; a refused or replayed correct answer does not lift it). It only escalates while
  `enforce.challenge` is on; in monitor mode the row carries `SH_CAPT_ESC` and the token is issued. With escalation on, a token-less navigation
  request carries two more `GET`s (`cesc`, and the CAPTCHA budget) inside the same pipeline; with `escalate_score` 0 nothing is added.
  (3) **`captcha.device_budget`** (off): a device over its
  hourly / daily budget (and over nothing else) gets a CAPTCHA instead of a 429, and a CAPTCHA-level token is waived from those two
  budgets.
* **Redis down: bound proof of work.** The attempt counter lives in Redis, so while it is down a wrong answer cannot be counted. A request that
  SERVES the CAPTCHA while Redis is not alive therefore issues the nonce with `pow_bits = max(configured, 20)` (reason `CAPT_DEGRADED`), and a CAPTCHA
  nonce with 20 or more bits has a proof of work **bound to the typed answer**: the hash covers `nonce:answer-header:counter`, solved by the page
  when the visitor submits (below 20 bits it covers the nonce alone and is solved in the background while the visitor reads the image). Each guess
  needs its own proof, so every guess costs CPU. The remaining window is in [06-KNOWN-LIMITS.md](06-KNOWN-LIMITS.md).
* **Never shown to**: an address in an *enforced* allow list, an operator allow override, a verified crawler (a captcha rule ignores
  `skip_verified_bots`: a verified crawler is skipped regardless; with Redis down a known-bot UA counts as verified), an exempt path,
  a non-HTML request (`gv_is_nav` false: it keeps the normal flow), or a block-listed address (that is a 403 at step 1b, long before).
  A request that is not gated, and a monitor-mode rule, are never asked either.
* **Token level.** A token is `device.issued.signature` (level **p**, proof of work: every token issued before this release, and what
  a proof-of-work handshake still issues) or `device.issued.c.signature` (level **c**, a solved CAPTCHA). The signature covers the
  `c`, so a p token cannot be upgraded. `gv_tok_check()` still returns the device id for both; only a `captcha` rule asks for `c`.
* **The nonce** is `issued.random.bits.time.answer_mac.signature` (six parts; the PoW nonce has four, neither parser accepts the
  other). `answer_mac = HMAC(secret, "cap|" random "|" normalised_answer)`, the signature covers all of it plus the UA / IP binding, and
  `time` is the signed time limit. The answer is never sent to the client. The visitor's text is normalised first: Persian
  (U+06F0-06F9) and Arabic-Indic (U+0660-0669) digits become Latin, spaces and zero-width / direction marks go, letters are
  upper-cased. The answer alphabet has no look-alikes (letters without O I S Z B, digits without 0 1 2 5 8 when mixed with letters).
* **The handshake** (`POST` with `X-GV: <six-part nonce>`, `X-GV-A: <percent-encoded answer>`, `X-GV-P: <PoW counter>`,
  `X-GV-S: <signals>`), always ends in `gv_captcha_handshake()`, cheapest check first: signature / binding / expiry (403 `inv`, 410
  `exp`), proof of work (when `captcha.require_pow`), the answer, then ONE Redis pipeline: the attempt counter `ca:<id>` (every answer
  counts), the single-use claim of a correct answer (`SET NX`, as for the PoW nonce), the usual per-IP counters and the minting limit.
  204 = token level c; 422 = wrong, attempts left; 403 = out of attempts or a replay; 429 = minting limit. Log rows reuse the
  handshake actions (`token_issued`, `nonce_bad`, `pow_bad`, `nonce_replay`, `mint_limited`) and carry `cap` = `ok | wrong | fail |
  exp | inv | esc`, `ct` (seconds to solve) and `tl`.
* **The per-IP CAPTCHA budget** (`captcha.ip_budget` pages per `captcha.ip_window` s, per address / IPv6 /64, key `cpi:<ipn>`) is *read*
  in the single pipeline of GETs (only for a request that may need a CAPTCHA) and *counted* in the single pipeline of counters, in the
  same round trip as the other counters. A client already over its budget gets a **429 with no Redis work for the CAPTCHA at all**: no
  page, no nonce, no key, the counter does not move (`CAPT_BUDGET` on the row). A reload or the "New image" button is just another page
  and counts. The CAPTCHA instead of a device 429 counts its page with one extra command, on that path only.
* **Headless signals.** The challenge script collects a small fixed set of yes / no answers and one number and sends it in `X-GV-S`
  (`w1.h0.m0.l0.c0.p0.g0.s0.n0.t412.i1`): `w` navigator.webdriver, `h` HeadlessChrome in navigator.userAgent, `m` userAgentData
  disagrees with the UA, `l` no languages, `c` no window.chrome on a Chrome UA, `p` no plugins / mimeTypes on a desktop Chrome,
  `g` WebGL renderer SwiftShader / llvmpipe, `s` screen or outer window 0x0, `n` Notification.permission vs the permissions API,
  `t` ms from page load to submit (too fast: under 45 ms on the PoW page, whose own script waits 50 ms first, and under 700 ms on the CAPTCHA page), `i` no trusted pointer /
  keyboard / touch event before submit (CAPTCHA page). Every signal is feature-detected inside try / catch and a missing one is
  neutral. **Nothing else leaves the browser**: no renderer string, plugin list or screen size. The server turns them into a score with
  a pure function (`gv_headless_score`, each signal has a weight in the config, `captcha.w_*`) plus one server-side check (`u`: the
  request UA and the page disagree about HeadlessChrome), and logs `hs` (the score) and `hf` (the letters that fired): short keys, never a raw
  value. A header that is malformed, too long or has unknown letters is ignored.
* **What it is and is not.** The CAPTCHA, the signals and the proof of work raise the cost of automation. They do not make headless
  browsers impossible (stealth plugins, OCR, paid solving services). What limits volume is the per-IP CAPTCHA budget, the device budgets
  and the proof of work.

### Redis contract (request path)

At most two round trips per request: one pipeline of every `GET` the request can need
(token is verified first, it is a pure HMAC), then one pipeline of counters
(`SET k 0 EX w NX` + `INCR` + `TTL`, repaired with `EXPIRE` if the TTL is -1). A
known-bot over its limit makes one extra trip. The first transport or auth failure closes
the connection (no reply desync, one timeout at most) and touches `logs/.redis-down`;
for `redis.breaker_ttl` seconds later requests skip Redis (`rd=1`). Failures go to
`logs/guard-errors.log`, throttled per code. All keys are built by `gv_key()`/`gp_key()`
(prefix-aware). The handshake costs one round trip (nonce claim + counters).

### The challenge

`guard/challenge.php` issues stateless, HMAC-signed tokens and nonces — they carry
their own timestamp and signature, so no server-side storage is needed and the
handshake works identically with or without Redis. The interstitial is a single
inline HTML document with no external assets: it waits a fraction of a second,
`fetch()`es a `POST` back to the same URL carrying the nonce, and reloads when the
guard answers `204`. A real browser sails through transparently. This is **not** a
JavaScript proof-of-work, though: a client that parses the page and issues the one
POST — no JavaScript required — completes the handshake just as well, so the nonce
filters naive fetchers rather than determined ones. The real brake on automated
token minting is the per-IP request rate limit (`gv:ri:{ip}`), not the handshake
itself. The token is deliberately **not** bound to the client IP, so CGNAT and
mobile carrier IP rotation do not re-challenge real users on every network change.

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

A single-operator web console, in English (left-to-right). It reads the logs, the analyzer
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
