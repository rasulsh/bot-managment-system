# Bot Guard

Bot Guard sits in front of your PHP site and keeps scrapers and bots away from it.
It works with WordPress, OpenCart, Laravel or plain PHP. You add one line of PHP
configuration, and your application code stays untouched.

Out of the box it only **watches and logs**. It does not block anyone until you
turn that on, step by step.

## Quick Start

This gets the guard running in **monitor mode**: it logs every request and changes
nothing for your visitors.

**You need**

- PHP 8.0 or newer. No Composer, no extensions. (On older PHP the guard does
  nothing, your site runs as before, and one line goes to `logs/guard-errors.log`.)
- Shell access to the server.
- Redis and Python 3.9+ are **optional**. You do not need them for this Quick Start
  (see [Next steps](#next-steps)).

**1. Put the files in place**

Keep this directory **outside** your web root, for example `/home/youruser/bot-guard`
(your site stays in `public_html`). Make the log folder writable by PHP:

```bash
cd /home/youruser/bot-guard
mkdir -p logs && chmod 0775 logs
```

**2. Set a secret**

```bash
openssl rand -hex 32     # copy the output
openssl rand -hex 16     # copy this one too
```

Open `guard/config.php`. Paste the first value as `'secret'` and the second as
`'holdout_salt'`. Never commit them. Leave everything else as it is.

> While `'secret'` is still `CHANGE_ME`, all blocking is forced off. This is a
> safety net: an unconfigured install cannot affect your site.

**3. Connect the guard to PHP**

Use **one** of these. Use your own absolute path.

| Where you can edit | Line to add |
|---|---|
| `.user.ini` in your web root (PHP-FPM, LiteSpeed, CGI) | `auto_prepend_file=/home/youruser/bot-guard/prepend.php` |
| `.htaccess` (mod_php, lsapi) | `php_value auto_prepend_file /home/youruser/bot-guard/prepend.php` |
| `php.ini` or cPanel MultiPHP INI Editor | `auto_prepend_file = "/home/youruser/bot-guard/prepend.php"` |
| Last resort: first line of your site's `index.php` | `require '/home/youruser/bot-guard/prepend.php';` |

`auto_prepend_file` is the best choice: it runs before any application code and
needs no change to your site. `.user.ini` changes can take a few minutes to apply.

**4. Check that it works**

Open your site in a browser, then:

```bash
tail -1 logs/guard-*.jsonl
```

You should see one JSON line per request, and your site should answer as usual.
A line with `"sh":1` ("shadow") shows what the guard *would* do once you turn
enforcement on, for example `"act":"challenge"`. In monitor mode nothing is
actually done. If no line appears, the `auto_prepend_file` path is wrong, PHP
has not reloaded yet (a `.user.ini` change takes up to 5 minutes), or the page
came from a cache without running PHP. Look at `logs/guard-errors.log` for hints
and at [docs/11-TESTING-PIPELINE.md](docs/11-TESTING-PIPELINE.md), which lists
every cause in order and has an exact test.

Also check that the guard files cannot be opened from the internet:

```bash
bash scripts/exposure-check.sh https://your-site.example none
```

(Use `none` when you have not installed the admin panel. Otherwise give the panel
path, for example `/gv-admin`.)

**5. Know the emergency switch**

```bash
touch /home/youruser/bot-guard/guard.off     # guard off, from the very next request
rm    /home/youruser/bot-guard/guard.off     # guard on again
```

The file must be in the top directory (next to `prepend.php`), not inside `guard/`.

That is all. Leave it in monitor mode and read the logs for about two weeks
before you turn anything on. See [Turning enforcement on](#turning-enforcement-on).

### Try it locally

You can test the guard on your own computer without a real site:

```bash
php scripts/guard-selftest.php                     # unit tests, exit code 0 = success
php -S 127.0.0.1:8080 scripts/dev-router.php &     # the guard in front of a test page
bash scripts/guard-test.sh http://127.0.0.1:8080   # sends test requests, prints a table
```

The test server uses `scripts/config.dev.php` (a public secret, every blocking
option on, very small limits). **Use it for testing only. Never deploy it.** It
writes its log to your system temp folder (`/tmp/gv-logs/`). Without Redis, some
rows of the table show `SKIP` or degraded results. That is expected.

## Next steps

Do these after the guard has run in monitor mode.

**Add the analyzer (recommended).** A Python program that reads the logs, checks
whether "Googlebot" is really Google, and scores visitors. To pass its verdicts
to the guard it needs Redis, reachable from both PHP and Python.

```bash
python3 -m pip install -r analyzer/requirements.txt
chmod +x scripts/*.sh        # cron runs these files directly; without this they fail silently
```

If `python3 --version` shows less than 3.9 (common on older CloudLinux), install a
newer Python, create a virtual environment with it
(`/path/to/python3.11 -m venv .venv`, then `.venv/bin/pip install -r analyzer/requirements.txt`)
and put `GV_PYTHON=/home/youruser/bot-guard/.venv/bin/python` at the top of the
crontab. The cron wrapper uses that interpreter.

Add two cron jobs (use your own path):

```
*/10 * * * * /home/youruser/bot-guard/scripts/analyzer-cron.sh verify  >/dev/null 2>&1
17 4   * * * /home/youruser/bot-guard/scripts/analyzer-cron.sh nightly >/dev/null 2>&1
```

Without these, a real search-engine crawler can never be confirmed, so it will
share one small request budget with anyone who copies its name.

**Add the admin panel (optional).**

```bash
php panel/setpass.php        # asks for a username and a password (12+ characters)
```

Then add the panel's URL path to `exempt_paths` in `guard/config.php`
(for example `array('/gv-admin/')`), so the guard does not block your own panel.
Add two more cron jobs: `analyzer-cron.sh snapshot` every 15 minutes and
`analyzer-cron.sh worker` every minute. Details: [docs/09-ADMIN-PANEL.md](docs/09-ADMIN-PANEL.md).

The panel has light, dark and automatic themes (switcher in the header, remembered
per browser) and sends `noindex` headers on every response.
**Restrict it by IP:** set `ip_allowlist` in `panel/panel.config.php` to IPv4/IPv6
addresses or CIDR ranges, for example `array('203.0.113.7', '2001:db8::/32')`.
Empty means open to everyone (the dashboard warns); a non-empty list with no valid
entry locks everyone out. Behind your own proxy or CDN, also set `trusted_proxies`.
The dashboard card **Data pipeline** shows whether requests are being logged.

**Add the honeypot.** A hidden link that only bots follow. See
[docs/07-CONFIG-REFERENCE.md](docs/07-CONFIG-REFERENCE.md#honeypot).

**Rotate the logs.** Add one cron job for `scripts/guard-logrotate.sh`
(example in [docs/07-CONFIG-REFERENCE.md](docs/07-CONFIG-REFERENCE.md#log-rotation)).

## Turning enforcement on

Go slowly. Each step should be quiet in the logs before you take the next one.

1. Set a real `secret` (done in the Quick Start).
2. Run about 14 days in monitor mode and read the logs.
3. Turn on `enforce.block`.
4. After a few quiet days, turn on `enforce.challenge`.
5. Tune the `limits` from what the logs show.
6. Turn on `enforce.ratelimit` last.

**Before step 4**, list every address that is called by a program and not by a
browser. These have no cookie and would be challenged: payment gateway callbacks,
webhooks, cron URLs, feeds, uptime monitors (they use HEAD or GET) and REST
endpoints. Add them to `exempt_paths` or `exempt_params` in `guard/config.php`.
Ready-made lists for WordPress, OpenCart and others are in
[docs/04-CMS-INTEGRATION.md](docs/04-CMS-INTEGRATION.md). The full day-by-day
checklist with a pass criterion for every stage is [ROLLOUT.md](ROLLOUT.md).

## How it works

Three parts that talk to each other only through Redis and the daily log files:

- **The guard** (`guard/`, `prepend.php`): PHP that runs on every request. It
  gives the request a score and decides: allow, challenge, rate limit (429) or
  block (403). A *challenge* is a short page that a real browser passes
  automatically with a cookie, and a simple script cannot.
- **The analyzer** (`analyzer/`): Python on cron. It reads the logs, checks bots
  with reverse DNS, scores visitors, and leaves small verdicts in Redis for the
  guard to read. It never touches live requests.
- **The panel** (`panel/`): an optional web console for one operator, in
  English, with Latin digits everywhere. It has dashboards, a log search, per-visitor overrides and
  settings. It writes settings as validated JSON and never runs shell commands.

Four rules shape the whole design:

- **Fail open.** If anything goes wrong (an error, no Redis, an unwritable log
  folder), the request is allowed. The guard may fail; the site may not.
- **Monitor first.** Every blocking action is off by default and logged as
  "would have happened" (`sh=1`) until you switch it on.
- **IP is a weak signal.** Mobile carriers and shared VPNs put many people behind
  one address, so the guard never blocks on IP alone and prefers a challenge to
  a block.
- **Redis is optional.** Without it the guard still logs, scores and runs the
  challenge. It loses rate limits, device budgets, operator overrides, bot
  verdicts, honeypot memory and one-time nonces. The full list is in
  [docs/06-KNOWN-LIMITS.md](docs/06-KNOWN-LIMITS.md).

## Documentation

| Read this | When |
|---|---|
| [docs/03-SETUP.md](docs/03-SETUP.md) | The full, exact install guide (analyzer, cron, panel, honeypot, enforcement) |
| [ROLLOUT.md](ROLLOUT.md) | The day-by-day rollout checklist |
| [docs/07-CONFIG-REFERENCE.md](docs/07-CONFIG-REFERENCE.md) | Every `guard/config.php` setting, platform notes, honeypot, KPI commands |
| [docs/04-CMS-INTEGRATION.md](docs/04-CMS-INTEGRATION.md) | WordPress, OpenCart, Magento, Drupal, Joomla, caching and CDN |
| [docs/06-KNOWN-LIMITS.md](docs/06-KNOWN-LIMITS.md) | What the guard cannot do, and what Redis and the server must provide |
| [docs/01-OVERVIEW.md](docs/01-OVERVIEW.md) | What the tool is and why it exists |
| [docs/02-ARCHITECTURE.md](docs/02-ARCHITECTURE.md) | How the parts fit together; what happens on one request |
| [docs/08-ANALYZER-PHASES.md](docs/08-ANALYZER-PHASES.md) | Phases 2 to 4: analyzer, verdicts, holdout group, overrides, outcome capture |
| [analyzer/README.md](analyzer/README.md) | Analyzer internals and the model migration runbook |
| [docs/09-ADMIN-PANEL.md](docs/09-ADMIN-PANEL.md) | Panel install, security model, settings overlay |
| [docs/05-ACCESS-LOG-REPORT.md](docs/05-ACCESS-LOG-REPORT.md) | Finding slow scrapers in your web server's access log |
| [docs/10-UPGRADE-NOTES.md](docs/10-UPGRADE-NOTES.md) | What changed in each release and what to do about it |
| [docs/11-TESTING-PIPELINE.md](docs/11-TESTING-PIPELINE.md) | "Nothing shows in the panel": how the data flows, why it may not arrive, how to test it end to end |
| [docs/CODE-REVIEW.md](docs/CODE-REVIEW.md) | Performance and workflow review notes |
| [docs/README.md](docs/README.md) | The documentation index |

## Testing

```bash
php scripts/guard-selftest.php           # guard
php scripts/redis-selftest.php           # Redis layer
php scripts/panel-selftest.php           # admin panel
python3 -m analyzer.selftest             # analyzer
python3 scripts/accesslog_selftest.py    # access-log report
bash scripts/e2e-pipeline.sh             # end to end: real HTTP traffic -> log -> snapshot -> panel
```

Each one exits with code 0 when everything passes. The last one needs `php`, `curl`,
`python3` and `redis-server`; it starts its own temporary server and Redis and
checks several client addresses, parallel tabs and concurrent requests
([docs/11-TESTING-PIPELINE.md](docs/11-TESTING-PIPELINE.md)).
