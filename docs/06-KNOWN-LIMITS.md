# Known limits and operating requirements

What the guard does not do, what it loses when a dependency is unhealthy, and
what the server around it has to provide. None of this is hidden behaviour; it is
collected here so that nobody has to find it out in production.

## What a challenge can and cannot stop

- A client that runs no JavaScript gets no token and no page. That is the large
  majority of price scrapers.
- A client that solves the challenge pays for it: two requests and a proof of
  work per token (about 60,000 SHA-256 hashes at `pow_bits = 16`; milliseconds in
  compiled code, tens of milliseconds in a script). A token is then bounded by
  `limits.device`, `limits.device_hour` and `limits.device_day`.
- A headless browser that throws its token away when a budget runs out gets a
  fresh one for the same price. The only levers are `challenge.pow_bits` (each
  extra bit doubles the cost, for visitors too) and lower budgets. A patient,
  well-funded scraper with a real browser and many addresses is slowed and made
  visible, not stopped.
- `limits.mint` caps tokens per address (per /64 for IPv6). On a carrier address
  shared by many people it is deliberately generous (300 per window): a low value
  lets one client use the budget up and lock new visitors out for the window.

## Redis

Redis holds every counter, override and verdict. Requirements:

- **Its own instance or database, with `maxmemory-policy noeviction`.** Under an
  evicting policy a flood of new clients pushes out operator deny overrides,
  verdicts and nonce claims. Every key has a TTL, so `volatile-*` policies evict
  them just the same.
- **`redis.host` must be an IP literal, `localhost` or a socket path.** A host
  name is resolved by the system resolver, which the configured timeout does not
  cover: a slow resolver stalls every request.
- Memory: about two short-lived keys per distinct client per window plus three
  per device token (5 minutes, 1 hour, 24 hours). A million distinct clients in
  one window is a few hundred megabytes.

**Degraded mode** (Redis down, the breaker armed, or Redis refusing writes) keeps
the site up and the stateless challenge working. It switches off:

- every rate limit and device budget,
- operator allow and deny overrides,
- bot verdicts: any User-Agent that names a known crawler takes the crawler pass,
  unmetered, for as long as Redis is down (showing a real crawler 503s for the
  length of an outage costs more),
- link-preview passes (no counter, no pass),
- honeypot history,
- nonce single-use and mint metering (one nonce can be replayed, but always
  yields the same device id).

Rows written in degraded mode carry `rd=1`, and `logs/guard-errors.log` names the
reason at most once a minute per reason. Watch that file.

The breaker arms after two timeouts within ten seconds, or one refused
connection, and then skips Redis for `breaker_ttl` (5 s).

## Exemptions

- `exempt_paths` is a prefix match on the raw path: `/admin` also covers
  `/administrator`. End entries with `/` when you mean a directory.
- An exempt request skips everything, including an operator deny.
- Server-to-server GETs (feeds, price APIs, gateway callbacks made by GET, cron
  URLs, uptime monitors, including HEAD checks) have no cookie and must be exempt
  before `enforce.challenge` is switched on.
- Until `challenge.gate_post` is on, a POST is never challenged. If the
  application renders a page for a POST, that is a way round the challenge.

## Access rules

- Rules match the User-Agent, which the client chooses. A UA rule stops lazy tooling, not a
  client that sends a browser UA. Pair it with the challenge and the rate limits.
- During a Redis outage a known-bot UA keeps its pass (as before) and `skip_verified_bots` rules skip it too (row reason `RULE_SKIP_DEGRADED`): a forged Googlebot UA is not caught by rules until Redis is back.
- Exempt paths and the kill switch bypass rules, so a rule never reaches an exempt path.
- Case-insensitivity is ASCII only; a UA is matched as bytes. Regex: no back-references.
- The request path reads the generated `guard/rules.cache.php` (OPcache). Without OPcache, or when the cache is stale and `rules.json` is read instead, 200 rules cost about 1 ms per request; keep the list short and save rules from the panel.
- Hit counts (Rules page) lag by up to one snapshot interval and need the `snapshot` cron job.
- A "Quick block" of a UA longer than 120 chars becomes a prefix rule because the log keeps 120.

## GeoIP

- A country or ASN is a statistical guess from a database: wrong for VPN and proxy users, mobile carriers that
  route through another country, corporate networks and anycast addresses. A country rule that **blocks**
  also blocks every legitimate visitor that appears in that country. Start in `monitor`, then `challenge`.
- "Not IR -> block" blocks Iranian visitors on a VPN or a foreign proxy, and anyone behind a foreign CDN that
  does not pass the real address (set `cdn_ranges` so the real client address is used).
- An address that is not in the database is **unknown** and matches no country or ASN condition, include or
  exclude. This is deliberate (fail-open) and means a gap in the database is a gap in the rule.
- Verified crawlers come from US addresses: a country rule without `skip_verified_bots` blocks them. While
  Redis is down a known-bot UA is treated as verified, so a forged Googlebot UA from any country is not caught by
  a country rule during an outage (same trade-off as the bot pass itself).
- The databases are only as fresh as the last compile. The panel warns at 45 days; the compile is not
  automatic unless the `geo` cron entry is installed (`scripts/analyzer-cron.sh geo`, monthly).
- `geoip.dat` carries no ASN data, and only its 2-letter country tags are used (`private`, `cloudflare`,
  `telegram`, ... are listed on the GeoIP page as ignored). Reading a `.mmdb` needs the optional Python package
  `maxminddb` on the analyzer side; without it the file is reported and skipped.
- Only the newest file that has data of a kind is compiled. An older one is listed as unused.
- With `geo.log` on, every request pays one more small file search (about 0.01 ms warm, 0.05 ms p99); the
  default is off.
- The Rules impact preview reads the country from the log when the row has it; for rows from before
  `geo.log` was on it looks the logged address up in the *current* database, and says so.

## IP lists

- A list is only as good as its source: an address list from a threat feed goes stale, and addresses are reassigned
  (cloud, mobile carriers, home connections). A block list that is not refreshed ends up blocking innocent visitors.
- **Shared addresses.** Everyone behind a carrier-grade NAT or a mobile operator's gateway shares a few addresses. An
  *allow* entry there lets all of them skip the guard; a *block* entry blocks all of them. The panel warns about an allow
  entry in `100.64.0.0/10`, one wider than /16 (IPv4) or /32 (IPv6), and (with the ASN database) one inside a mobile
  operator AS (MCI, Irancell, Rightel: a short fixed list, not complete).
- An allow list is a hole by design: its addresses skip rules, scoring, rate limits and the challenge. Use it for
  monitoring probes and partners, not for "good" countries or big ISPs.
- A block list refuses a verified crawler address too (it is evaluated before the bot pass). The panel warns when a block
  entry covers a verified crawler seen in the recent logs, but only from the logs it can scan.
- The safety caps are enforced by the compile itself, so also for a file copied over SFTP and for the worker: `0.0.0.0/0` and `::/0`
  are always dropped (even for a forced list); allow entries wider than /16 (IPv4) or /32 (IPv6), block entries wider than /8 or /32, and
  block entries covering private, loopback, link-local space or the server's own addresses are dropped unless the list was saved with
  "I know what I'm doing". Dropped entries and unparseable lines are counted and shown (never fatal) and the dashboard warns; it is
  critical when an allow list lost an entry wider than /8. The "server's own addresses" are the ones the panel saw (`SERVER_ADDR`) and
  stored in `lists/lists.json`: on an install where nothing was ever saved from the panel, only the private ranges are protected.
- Changes apply when the compile finishes. Small lists compile in the save request; a big list (over 512 KiB of source)
  needs the `worker` cron, and until the job runs the guard keeps using the previous compiled files (the dashboard
  warns after 10 minutes).
- Compile status and "the file is missing" can only be seen by the panel, not by the guard: with a deleted compiled file
  the guard fails open and treats the list as empty (a critical dashboard alert says so).
- An enforced block list is decided before the challenge handshake, so a listed address cannot drive handshake `POST`s; a block list
  does not stop a request that never reaches PHP (static files served directly by the web server). The allow list is checked after
  the handshake step, so an allow-listed address can still complete one (it is allowed anyway).
- **An enforced allow list beats a deny override.** The allow list is checked before any Redis override, so a deny override for an
  address (or for a device seen on an address) inside an *enforced* allow list has **no effect**. The panel says so when the deny is
  created and keeps showing it on the Overrides and Identity pages, with a link to the list; remove the address from the list or switch the
  list to monitor if the deny is meant to work. A monitor allow list does not shadow a deny.
- IPv6: one list entry is a range, and a /64 or /48 entry blocks every host in it; the per-/64 grouping used by the rate
  counters does not apply here. The number of addresses in the table is shown for IPv4 only (IPv6 counts ranges).
- A block list that covers the **operator's own address** is refused at save time (and so are private, loopback and
  link-local ranges and the server's own address) unless "I know what I'm doing" is ticked. The panel only knows the
  address it sees: an operator behind a proxy the panel does not trust can still lock themselves out. The kill switch
  (`guard.off`) is the way back in.

## Image CAPTCHA and headless signals

- **It raises a cost, it does not stop a determined attacker.** Stealth plugins hide the signals, OCR and paid solving services solve the
  images (a few cents per thousand). The per-IP CAPTCHA budget, the device budgets and the proof of work are what limit volume. Watch the
  dashboard: a solve rate near 100 % with very short median times is a solving service or a bot that reads the image.
- **Accessibility.** An image CAPTCHA excludes people who cannot see it and is hard on small phones at levels 4 and 5. Start at level 2, keep
  the time limit generous, and prefer `challenge` rules where a CAPTCHA is not needed. There is no audio alternative.
- **Redis down.** Binding, expiry and the proof of work still apply, but the attempt counter (`captcha.max_attempts`) and the single-use claim
  need Redis. A CAPTCHA served while Redis is down (`CAPT_DEGRADED`) has a proof of work of at least 20 bits **bound to each typed answer**, so every
  guess costs real CPU instead of being free. **What remains:** (1) a nonce issued while Redis was UP and answered after it went down has the
  normal (unbound, background) proof, so its guesses are unlimited until its time limit ends; the window is at most `captcha time limit` (default
  150 s) after the outage starts. (2) **Enumeration cost.** A CAPTCHA served while Redis is down also has an answer of at least 6 characters (same charset;
  the time limit stays as configured, 60-180 s by level), and each guess needs its own 20-bit proof (about 10^6 hashes: ~1 ms for a native solver at
  ~10^9 hashes/s, ~0.5 s in a browser's JavaScript). Digits: 10^6 answers = ~1000 s of native CPU for the whole space, ~500 s on average, against a
  150 s limit (level 2): about 3-4 native cores finish inside the limit, one core does not. Letters + digits (levels 4-5, 26 symbols, 6-7
  characters): 3.1x10^8 to 8x10^9 answers = 3x10^5 s or more of native CPU, thousands of cores for one image. So this makes an outage guess-farm
  expensive for a single machine, not impossible for a multi-core one; the bits were deliberately kept at 20 (22 would cost real mobile users seconds
  per submit and does not stop a multi-core attacker). Prefer a level with letters if outages are a concern. (3) A
  solved nonce can be replayed until its time limit ends (the single-use claim needs Redis). The per-IP CAPTCHA
  budget is not enforced either (it cannot be read), so pages are served. This is the same fail-open policy as the rest of the guard.
- **GD.** Without it every captcha action is the proof-of-work challenge (the dashboard warns while a CAPTCHA is configured). The panel checks
  GD in the web server's PHP, which is also the guard's; a command-line PHP can differ. A host that serves the shop through a different PHP
  build than the panel (rare) can show a wrong GD status.
- **The page is one self-contained document with a data-URI image.** A site-wide `Content-Security-Policy: img-src 'self'` header added by the
  application (not by this guard) would block the image and the inline script; exempt such pages or allow `data:` images and inline scripts.
- **Shared addresses.** The per-IP budget is per address (an IPv6 /64): a carrier-grade NAT or a school shares it. 10 pages per 15 minutes is
  generous for people and tight for a farm behind one address; raise it before lowering it.
- **The signals are heuristics.** Privacy extensions, unusual browsers, remote desktops, virtual machines with software WebGL and some
  enterprise browsers trip single signals; that is why each has a weight and why escalation needs a *score*, not one signal. Start with
  `captcha.escalate_score` 0 (off), read `hs` / `hf` on the log rows, then try 60 in `monitor` mode (`SH_CAPT_ESC`). A browser with JavaScript
  off cannot be escalated (it cannot get a token either).
- **An escalation needs two page loads** (the handshake answers 202, the next page is the CAPTCHA) and a cookie to keep the token; a browser that
  blocks cookies loops back to the challenge page's own "enable cookies" message.
- **The escalation flag is per ip + UA, for 10 minutes.** Dropping the cookie does not escape it (the Redis key `cesc:` is read on every navigation
  request and in the handshake), but rotating the UA string or the address does (a new key); that is the same ip + UA granularity as the other
  per-client counters. With Redis down the flag cannot be written or read: only the cookie signal works then. The flag is cleared when a level-c
  token is issued; an operator can also `DEL gv:cesc:<md5>`.
- **`captcha.device_budget` is a bypass of the hourly / daily device budgets for anyone who can solve an image** (including a solving
  service). It is off by default; the per-IP budget still caps the number of images.
- A request that is not an HTML page (an XMLHttpRequest, `Accept: application/json`, an image) is never shown a CAPTCHA and keeps the normal flow:
  a scraper that asks for JSON is not stopped by a `captcha` rule (the proof-of-work challenge and the rate limits still apply to it).
- The tokens of this release are not valid for older guard code: rolling back leaves visitors with a CAPTCHA-level cookie that the old code
  treats as invalid (they get the challenge once and a normal token).

## Panel filters, tabs and tooltips

- Filters scan the day's log from the end under the existing scan caps. An *exclude* filter ("is not", "does not
  contain") matches more rows and so fills a page more slowly; when a cap is reached the "scan limit reached" notice
  says the list may be incomplete.
- On fields whose empty value means *unknown* (country, ASN, outcome status, bot verdict) a row without the value matches
  neither "is" nor "is not", as in the rule engine; use `(none)` to list those rows. So "country is not IR" does not
  count rows that were never looked up, and "is IR" + "is not IR" do not add up to all rows. Fields whose empty value is a
  fact (reasons, device id, override) are plain include / exclude.
- Values containing a comma cannot be used in a multi-value choice field (the comma separates values).
- Tabs, tooltips and *Share link* are JavaScript enhancements. Without JavaScript the tabs stack, tooltips open on
  keyboard focus only, and the link is a plain link.
- The layout test needs a Chromium; without it only the markup and CSS checks of the selftest run.

## Background jobs, dashboard alerts and the crontab check

- A job's state comes from the status file the cron wrapper writes. Run a mode by hand with `python3 analyzer/...` (not through
  `scripts/analyzer-cron.sh`) and it leaves only the old `.lastrun-*` heartbeat, no error log.
- **Without the `verify` cron job** real crawlers stay in the shared `limits.bot_unverified` budget for ever (the dashboard calls
  `verify` required and alerts when it is missing or late).
- The panel's crontab check sees the crontab of the user PHP runs as. On a host where PHP runs as another user than the cron
  jobs, or where `proc_open` is disabled, it can only show the copy the cron wrapper leaves (`analyzer/.cron-check.json`, up to 10
  minutes old) or, without that, just the heartbeats; run `scripts/cron-check.sh` over SSH there.
- The schedule check estimates how often an entry runs from its five fields (a list or step counts runs; a day-of-week or
  day-of-month field restricts them). An unusual schedule such as `0 0 1,15 * 1` is judged approximately.
- "Late" is judged against the interval you set in Settings > Analyzer, not against the real crontab. If you change the crontab,
  change the interval too.
- The dashboard alerts read live files and one cheap Redis command each; a slow disk or Redis makes the dashboard slower, never
  wrong. `CONFIG GET` can be forbidden on a hosted Redis: "noeviction not set" is then unknown, and no alert is raised.
- **The free-disk floor only reports by default.** The disk is shared with the whole cPanel server: a full disk caused by backups or
  another site must never make the log rotation delete the training history. Below `log_min_free_mb` the guard stops writing logs
  and `guard-logrotate.sh` records a warning (status, `jobs.log`, dashboard alert) and deletes nothing for that reason. Deleting is
  opt-in: **`log_floor_delete`** (Settings -> Log storage, default off). When on, only archives **older than `log_floor_keep_days`**
  (default 7, minimum 1) are eligible, the oldest first, **at most 10 files per run** (the status records when the limit was hit; the next
  run continues), and never an uncompressed file. The size cap (`log_max_mb`) and the retention keep their own rules.
- **`df` and the quota.** `df` (the rotation script) and PHP's `disk_free_space()` (the guard's logging floor, the dashboard) see the
  *filesystem*, not the cPanel / CloudLinux **user quota**. An account at its quota can still show plenty of free disk, and the guard keeps
  trying to log. When `quota` (or `/usr/bin/quota`) exists, the rotation records the user's usage (`quota -s`) in the logrotate status and the
  dashboard's log-storage card shows it; when it does not exist, nothing is recorded and nothing is reported. Check the quota in cPanel.
- A failure can be marked "seen" on the Jobs page: that silences its alert only until the next failure.
- Job status files and `jobs.log` use ASCII only (non-ASCII bytes in error text are dropped) so they are always valid JSON.

## Crawlers

- Only crawlers in `known_bots` pass. Every other crawler, monitor and SEO tool
  gets the 503 challenge page on every visit.
- A claim is verified out of band by `analyzer-cron.sh verify` (reverse DNS that
  forward-confirms). Until then it draws on `limits.bot_unverified`, one budget
  per crawler name for the whole site. **Without that cron job a real crawler
  never leaves the shared budget**, and anybody sending the same User-Agent can
  use it up.
- Verification handles 200 addresses per run, busiest first.

## Signals from the analyzer: leave them off for now

`signals.reputation`, `signals.ml` and `signals.clf` add the analyzer's verdicts
to a visitor's score. The review found that, as trained today, they are not safe
to enforce:

- The classifier's "bot" examples are all token-less clients and its "human"
  examples all token-bearing ones, so its measured precision says nothing; fast
  but ordinary shoppers (many tabs, a quick purchase) score as bots.
- Reputation and the anomaly score have no minimum amount of evidence: a visitor
  with one or a handful of requests can receive a strong verdict.
- A scraper that solves the challenge and never touches the honeypot is counted
  as a human, in reputation and in the training data.

The verdicts are still computed and logged (`rep`, `ml`, `clf` on every row) when
the cron jobs run, which is how they can be evaluated. Do not switch the three
`signals.*` toggles on until that has been done on real traffic.

Model files are Python pickles. Loading one runs code, so the `analyzer/`
directory must be writable only by the user the cron jobs run as.

## Other

- **Holdout** (`holdout_pct`, default 0): membership is a hash of the device id
  or address. A client can find an identity that lands in the slice by trying a
  few dozen. Keep it at 0 unless you are measuring, and change `holdout_salt`.
- **Honeypot**: a hit marks the address for seven days. On a carrier address
  that is everybody behind it (+40 on the score, which alone does not block).
- **LiteSpeed Cache / CDN**: a page served from a public cache never reaches PHP,
  so the guard neither sees nor limits it. Guard responses carry
  `Cache-Control: no-store` and `X-LiteSpeed-Cache-Control: no-cache`.
- **`.user.ini`** changes take up to five minutes (PHP's `user_ini.cache_ttl`).
  The only instant switch is the kill file: `touch /full/path/bot-guard/guard.off`.
- **File permissions**: `guard/config.php` holds the HMAC secret; `chmod 600` it.
  Logs contain addresses, paths and the first 100 characters of query strings
  (which can include tokens from links in e-mails): keep the project directory
  outside the web root, or verify with `scripts/exposure-check.sh`.
- **Time zones**: log files are named by PHP's date. `guard-logrotate.sh` leaves
  any file written in the last hour alone, so a different system time zone is
  harmless; the analyzer reads the newest files by its own date, so keep PHP and
  the system on the same time zone.
- **PHP 8.0+** is required. Below that `prepend.php` returns at once and the
  guard does nothing; it leaves one line (`php_too_old`) in `logs/guard-errors.log`, at most once an hour.
