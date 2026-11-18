# Phase 5 — admin panel

Setup is also summarised in the [README](../README.md#next-steps).

Everything the first four phases built is operated from a terminal: `jq` over
JSONL, `ctl.py` for overrides, an editor for `guard/config.php`, `replay.py`
before every threshold change. That works, and it is why the panel adds **no new
detection surface and no new decision authority**. It is a window onto data that
already exists and a controlled writer for settings that already exist.

The panel is **optional**. Delete `panel/` and the guard and analyzer behave
exactly as before; the overlay file simply stops being written and the guard
falls back to `guard/config.php`. Pure PHP 8.0+, no Composer, no vendor
directory, no build step, no CDN — it runs on a server with no outbound network
access at all.

## Two rules it is built around

**It never writes PHP and never runs a shell command.** Settings changed in the
panel are written as **JSON** to `guard/config.local.json`, never as PHP source:
a panel that rewrites executable config from form input is a code-injection hole
in a security tool. Analyzer actions are queued in Redis and drained by
`analyzer/worker.py`, which maps a job type to a Python function called
in-process. No `exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`
or backticks appear anywhere in `panel/` — `scripts/panel-selftest.php` fails the
build if one ever does.

**Everything it displays is attacker-controlled.** User agents, paths, referers
and query strings in the logs were written by the bots this system fights. Every
value rendered anywhere goes through `gp_e()`. A stored XSS in the admin panel of
a bot guard would be handing an attacker the console.

## Install the panel

```bash
php panel/setpass.php          # the only terminal command the panel needs
```

It prompts for a username and password, refuses passwords under 12 characters,
generates a session secret distinct from the guard's, and writes
`panel/panel.config.php` at mode 0600. Re-run it to rotate credentials. Then:

> **Installs created before the credential file carried a direct-access guard:**
> the generated file now begins with
> `if (!defined('GP_BOOT')) { http_response_code(404); exit; }`, the same line
> every other file under `panel/` has. An older `panel.config.php` keeps working
> and is unaffected — to pick the guard up, either re-run `setpass.php` or add
> that one line by hand above the `return`.

1. **Add the panel to `exempt_paths` in `guard/config.php`:**

   ```php
   'exempt_paths' => array('/bot-guard/panel/'),   // your panel's URI prefix
   ```

   Being challenged or blocked out of your own admin panel by your own bot guard
   is a real and stupid failure mode. The panel carries its own auth, CSRF and
   login rate limit, so exempting it costs nothing. There is no guard code for
   this on purpose — it is a config line you set.

2. **Add two cron entries** next to the existing analyzer ones:

   ```
   */15 * * * * /full/path/bot-guard/scripts/analyzer-cron.sh snapshot >/dev/null 2>&1
   *    * * * * /full/path/bot-guard/scripts/analyzer-cron.sh worker   >/dev/null 2>&1
   ```

   `snapshot` writes `analyzer/snapshot.json`, which is the only thing the
   dashboard reads — a busy site's dashboard opens as fast as a quiet one's.
   `worker` drains the job queue; without it the panel's action buttons queue
   jobs that nobody runs. Both take the same `flock` as the other modes.

3. Serve `panel/` over HTTPS. The session cookie sets `Secure` on HTTPS,
   `HttpOnly` and `SameSite=Strict` always, with `Path` scoped to the panel
   directory.

How to expose the panel on a URL (symlink, permissions, web server settings,
troubleshooting): [13-PANEL-WEB-ACCESS.md](13-PANEL-WEB-ACCESS.md).

`panel/.htaccess` denies everything except `index.php` and the CSS/font assets,
and denies `panel.config.php` and `audit.jsonl` explicitly. If your server
ignores `.htaccess`, put `panel/` outside the document root and alias only
`index.php` and `assets/`.

## Security model

| control | behaviour |
|---|---|
| **No setup wizard** | If `panel/panel.config.php` is absent or malformed, **every panel route returns a bare 404** — no hint that a panel exists. A first-run setup screen reachable by whoever finds the URL first is how admin panels get taken over; one install-time command is the correct trade. |
| **Session** | Signed cookie `gp_sess` = `user.issued_at.hmac`, verified with `hash_equals`, sliding renewal at half of `session_ttl` (default 12 h). Tampering with any part invalidates it. |
| **CSRF** | Per-session token in a hidden field on every state-changing POST, verified with `hash_equals`. GET routes never change state. |
| **Login rate limit** | 5 attempts per 15 minutes per IP (`gp:login:{ip}`), plus a second global counter across all addresses (`gp:login:user`) at four times that, so an attempt spread over many IPs is caught too. Wrong user and wrong password give an identical message and an identical response time. |
| **Redis down** | The limiter falls back to a **file counter**, not to no limit. This is the one place in the whole system that deliberately does **not** fail open. |
| **IP allowlist** | Optional `ip_allowlist` in `panel/panel.config.php`: IPv4 and IPv6 addresses or CIDR ranges. Empty means no restriction (default, so upgrades lock nobody out); a non-empty list with no valid entry refuses everyone (fail closed). It is checked before any route, login included. `X-Forwarded-For` is read only when the connection comes from an address in `trusted_proxies`, walking from the right past trusted hops. The same address feeds the login rate limit and the audit trail. |
| **Search engines** | `X-Robots-Tag: noindex, nofollow, noarchive, nosnippet` on every response (PHP, and `.htaccess` for assets and server errors) plus a robots meta tag. No `robots.txt`, on purpose. |
| **Audit trail** | Every accepted config change, override, job and login — success *and* failure — appends one JSONL line to `panel/audit.jsonl` with timestamp, actor, key, old value, new value and client IP. Append-only; the panel offers no delete. An untraceable config change in a security tool is unacceptable. |

Nothing sensitive is committed: `panel/panel.config.php`, `panel/audit.jsonl`,
`guard/config.local.json` and `analyzer/snapshot.json` are all git-ignored, and
`scripts/config-dump.php` strips the panel credentials from its output.

## The config overlay and its precedence

```
shipped defaults  →  guard/config.php  →  guard/config.local.json
```

The overlay is a flat JSON object written only by the panel, atomically (temp
file in the same directory, `chmod 0640`, then `rename()`), so a half-written
overlay is never observable by the guard.

- Missing file: ignored silently.
- Unreadable, malformed, or non-object JSON: ignored silently. The guard
  continues on `guard/config.php`. **Never fatal, never a warning that could
  reach output.**
- Only whitelisted keys are read; anything else in the file is discarded. A key
  with the wrong type or an out-of-range value is discarded **individually**, not
  the whole file.

Validation lives in `gv_overlay_validate()` in `guard/guard.php`, not in
`panel/`, and both sides call it. The panel is optional and deleting it must
change nothing — so what the panel accepts on write has to be the same code the
guard runs on read, permanently.

**Whitelist:** `gv_overlay_whitelist()` in `guard/guard.php` is the complete list, with
the type and range of every key (the **Config file** page prints it too). It covers
enforcement, signals and weights, every rate limit, the challenge (`pow_bits`, `gate_post`,
`bind_ip`, `token_ttl`, `nonce_ttl`), the challenge page text
(`strings.*`), holdout and outcome capture, exemptions and the honeypot,
`exempt_params_paths`, `cdn_ranges`, `known_bots`, `preview_bots`, `bot_suffixes`, and the
analyzer's operational settings (`analyzer.*`).

Editing `guard/config.php` by hand still works and is still authoritative for
anything not in the overlay. To go back to the file, use **reset to file** in the
settings view — it removes the key from the overlay rather than writing the old
value back.

## Where each setting lives

| Category | Where | Keys |
|---|---|---|
| **A. Install and secrets** | `guard/config.php`, over SSH | `secret`, `holdout_salt`, `redis.*` (host, port, socket, username, password, db, prefix, timeout, breaker_ttl), `log_dir`, `cookie_name`, `challenge.test_key`, `challenge.trust_headers` (rollback switch that weakens the challenge); the panel login (`setpass.php`); analyzer paths and `php_bin` (`GV_ANALYZER_CONFIG`) |
| **B. Operation** | Panel: **Settings** or **Config file** | everything on the whitelist above |

Category A is what the guard needs before it can read anything else (Redis, the log
directory), or a secret whose change breaks every token or reshuffles the holdout. The
**Settings** page shows their state at the bottom (set / not set, endpoint), never a
secret value.

Precedence, guard: shipped defaults → `guard/config.php` → `guard/config.local.json`.
Precedence, analyzer: `analyzer/config.py` defaults → `GV_ANALYZER_CONFIG` file → panel
(`analyzer.*` keys, read through `scripts/config-dump.php`).

When a change takes effect: the guard reads the overlay on every request (no cache; the
file is JSON, so OPcache does not hold an old copy). The analyzer reads it at the start of
every run. The settings form writes only the keys you changed; a value that comes from
`guard/config.php` stays there.

## The config file editor

**Config file** in the menu edits `guard/config.local.json` as text, with JSON syntax
highlighting and a live syntax check in the browser. The browser check is a convenience;
the server decides. Nothing is written unless the whole file passes:

- strict JSON, one object, no duplicate keys (a parser that reports line and column,
  because `json_decode()` only says "Syntax error");
- every key on the whitelist and every value accepted by `gv_overlay_validate()`;
- the file has not changed since the editor opened it (another tab, the settings form).

Every error is listed with its line and a sentence that says what is wrong; clicking it
selects the line. On success the previous version is copied to `guard/config-backups/`
(newest 20 kept; also on every settings save and reset), the new text is written to a
temp file and renamed into place, and each changed key goes to the audit trail as
`config_file`. A backup can be opened in the editor and saved like any other edit.

The editor is a textarea over a highlighted `<pre>` (about 80 lines of inline JS, no
library). CodeMirror or Monaco would add 150 KB+ of vendored code to a panel that has no
build step and no CDN, for one small JSON file. Without JavaScript the page is a plain
textarea and the server check still applies. It edits JSON only: `guard/config.php` stays
read-only for the panel, because a web form that writes PHP is code execution for anyone
who steals the session.

## What deliberately has no UI

| setting | why |
|---|---|
| `secret`, `holdout_salt`, `redis`, `log_dir`, `cookie_name`, `challenge.test_key`, `challenge.trust_headers` | Not on the whitelist and there is no form for them (category A above). Rotating `secret` invalidates every issued token at once; changing `holdout_salt` silently reshuffles the control group and invalidates the comparison the holdout exists to provide. Both are `openssl rand` + an editor, once. |
| Panel username, password, session secret | `setpass.php` only. A panel that can rewrite its own credentials from a session is one XSS away from a permanent backdoor. |
| Reputation weights (`analyzer/reputation.py`), `DECISION_SPAN`, model internals | Code, not configuration. Changing them changes what every historical score meant, and the honest way to do that is a diff, a replay and a deploy. |
| Log deletion, audit deletion | Append-only by design. Rotation is `scripts/guard-logrotate.sh`. |
| Arbitrary jobs | The queue accepts exactly eight named types — `verify`, `nightly`, `train`, `train_clf`, `replay_full`, `promote_ml`, `promote_clf`, `snapshot`. Queued training always writes to `--candidate`, so a job fired from a browser can never make the guard more permissive while nobody is watching. |

## What the panel does

- **Dashboard** — kill-switch state, every toggle, Redis reachability, and the
  last successful `run_verify` / `run_nightly` / `snapshot` / `worker` times with
  a stale warning. KPI cards, inline-SVG charts generated in PHP, and the
  kill-switch control itself behind a confirm step.
- **Log explorer** — the replacement for `grep` and `jq`. Filters on date, `act`,
  `sh`, `hold`, `ovr`, `tok`, device, IP, path substring, reason, response status
  and score ranges; reverse-streamed with a hard cap of 200 rows per page. It
  never loads a whole log file into memory, and CSV export of the current filter.
- **Identity drill-down** — every `gv:` verdict for one device or IP on one page:
  the `ctl.py show` output that answers "why was this customer blocked?".
- **Overrides** — the `ctl.py allow` / `deny` five-second fix, with the same TTL
  ceiling of 30 days and the same rule that allow is ungated and deny respects
  `enforce.block`.
- **Replay** — `replay.py` against real history before a threshold change, run
  natively in PHP through the guard's own `gv_effective_score()` and
  `gv_decide()`, so the preview and the live decision cannot drift.
- **Models** — bundle status, staleness, classifier precision, and the buttons
  that queue training and promotion.
- **Audit** — the append-only trail, searchable.

## Testing

```bash
php scripts/panel-selftest.php     # exit 0 on success
```

It covers overlay precedence and the never-fatal rules, that `secret` and
`holdout_salt` are unreachable through the overlay, every whitelist bound, the
atomic write and audit append, the bounded tail reader, session signing and
expiry and tampering, CSRF, the login rate limit with Redis up *and* down, stored
XSS (asserted by parsing the rendered HTML with `DOMDocument` and counting what a
browser would actually execute, not by matching a regex), and a token-level scan
proving no shell function, backtick or `eval` exists under `panel/`.

## Themes

The sidebar and login page have a Light / Dark / Automatic switcher. The choice is kept in the browser (`localStorage`, key `gp_theme`) and applied before first paint, so there is no flash. Automatic follows the system setting. All colours are CSS variables defined once in `panel/assets/app.src.css`; the self-test checks the contrast of every text/background pair in both themes (4.5:1 for text, 3:1 for control borders). The switcher needs JavaScript; without it the panel follows the system setting.

## Why the panel is still exposed by symlink

Replacing the symlink with an `.htaccess` rewrite was tested on Apache 2.4 with mod_php. A per-directory `RewriteRule` cannot target a path outside the document root: Apache prepends the docroot, so the panel answers 404. `Alias` would work but needs the server or vhost config, which shared hosting does not give you. A small PHP stub in the docroot that `require`s the real panel would work, but it adds a second entry point that must repeat every guard (allowlist, headers, direct-access rules). Not worth the extra attack surface, so the symlink stays. OpenLiteSpeed was not tested.
