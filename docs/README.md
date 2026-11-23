# Bot Guard documentation index

The [root README](../README.md) is the entry point. It has two parts: **Part 1** for site
owners and operators (no programming needed) and **Part 2** for developers and power users.
This folder holds the depth behind it. Nothing here is a second copy of the README: the README
summarises and links to these files.

## Where to start

| You are | Read first | Then |
|---|---|---|
| A site owner or operator | [README Part 1](../README.md#part-1--for-site-owners-and-operators) | [03-SETUP.md](03-SETUP.md) for the exact install; [ROLLOUT.md](../ROLLOUT.md) for the day-by-day plan |
| Installing it | [README §2.6](../README.md#26-installation-by-environment) | [03-SETUP.md](03-SETUP.md), [13-PANEL-WEB-ACCESS.md](13-PANEL-WEB-ACCESS.md), [04-CMS-INTEGRATION.md](04-CMS-INTEGRATION.md) |
| Operating it day to day | [README §1.7 recipes](../README.md#17-everyday-tasks-recipes) | [09-ADMIN-PANEL.md](09-ADMIN-PANEL.md), [11-TESTING-PIPELINE.md](11-TESTING-PIPELINE.md) |
| A developer | [README Part 2](../README.md#part-2--for-developers-and-power-users) | [02-ARCHITECTURE.md](02-ARCHITECTURE.md), [07-CONFIG-REFERENCE.md](07-CONFIG-REFERENCE.md) |
| Upgrading | [README §2.15](../README.md#215-upgrade-and-rollback) | [10-UPGRADE-NOTES.md](10-UPGRADE-NOTES.md) |

## The documents

| File | What it covers | README section |
|---|---|---|
| [01-OVERVIEW.md](01-OVERVIEW.md) | What the tool is, the problem it solves, monitor first, what a visitor experiences, what it is not | [1.1](../README.md#11-what-bot-guard-does-in-plain-words) |
| [02-ARCHITECTURE.md](02-ARCHITECTURE.md) | The three parts, the request flow of `gv_run()`, access rules, GeoIP, IP lists, image CAPTCHA, the Redis contract, the challenge, the analyzer pipeline, the panel | [2.1](../README.md#21-architecture-overview), [2.2](../README.md#22-request-lifecycle-and-precedence) |
| [03-SETUP.md](03-SETUP.md) | The exact install: prerequisites, config, wiring, analyzer, cron, panel, honeypot, monitor period, enforcement | [1.2](../README.md#12-what-you-need-before-you-start), [1.3](../README.md#13-installation-paths), [2.6](../README.md#26-installation-by-environment), [2.8](../README.md#28-scheduled-jobs) |
| [04-CMS-INTEGRATION.md](04-CMS-INTEGRATION.md) | Integration methods and the exemption list for WordPress, OpenCart, Magento, Drupal, Joomla, Laravel and plain PHP; caching and CDN | [2.7](../README.md#27-application-and-cms-integration) |
| [05-ACCESS-LOG-REPORT.md](05-ACCESS-LOG-REPORT.md) | Finding slow scrapers in a web server's access log (`scripts/accesslog_report.py`) | |
| [06-KNOWN-LIMITS.md](06-KNOWN-LIMITS.md) | What the guard cannot do, what degraded mode switches off, what Redis and the server must provide | [2.3](../README.md#23-fail-open-model-and-degraded-mode), [2.16](../README.md#216-known-limits) |
| [07-CONFIG-REFERENCE.md](07-CONFIG-REFERENCE.md) | Every configuration key, the rules file, job status files, GeoIP, CAPTCHA, IP list files, platform notes, honeypot, log rotation, KPIs | [2.9](../README.md#29-configuration-model), [2.10](../README.md#210-data-formats) |
| [08-ANALYZER-PHASES.md](08-ANALYZER-PHASES.md) | Analyzer phases 2 to 4: verdict contract, bot verification, holdout, overrides, outcome capture | [2.11](../README.md#211-analyzer) |
| [../analyzer/README.md](../analyzer/README.md) | Analyzer internals and the model migration runbook | [2.11](../README.md#211-analyzer) |
| [09-ADMIN-PANEL.md](09-ADMIN-PANEL.md) | Panel install, security model, settings overlay, every page, dashboard alerts, tabs and filters | [1.4](../README.md#14-first-login-and-a-tour-of-the-panel), [1.5](../README.md#15-reading-the-dashboard), [2.12](../README.md#212-security-model) |
| [10-UPGRADE-NOTES.md](10-UPGRADE-NOTES.md) | What changed in each release, upgrade steps, rollback, measured cost | [2.4](../README.md#24-performance-budgets), [2.15](../README.md#215-upgrade-and-rollback) |
| [11-TESTING-PIPELINE.md](11-TESTING-PIPELINE.md) | "Nothing shows in the panel": how data flows, why it may not arrive, how to test it end to end | [1.9](../README.md#19-troubleshooting-by-symptom), [2.14](../README.md#214-testing-and-ci) |
| [12-CHALLENGE-TEST.md](12-CHALLENGE-TEST.md) | Show the real check page to yourself (`challenge.test_key`) | |
| [13-PANEL-WEB-ACCESS.md](13-PANEL-WEB-ACCESS.md) | Making the panel reachable: symlink, permissions, Apache, LiteSpeed, troubleshooting, what was verified | [1.4](../README.md#14-first-login-and-a-tour-of-the-panel), [2.6](../README.md#26-installation-by-environment) |
| [14-REASON-CODES.md](14-REASON-CODES.md) | Every log reason code and short field (`act`, `tok`, `ovr`, `botv`, `sh`, ...) with its full name and meaning; generated from the panel's registry | [1.5](../README.md#reading-the-logs) |
| [CODE-REVIEW.md](CODE-REVIEW.md) | Performance and workflow review notes | |
| [../ROLLOUT.md](../ROLLOUT.md) | The operational, day-by-day rollout checklist | [1.6](../README.md#16-safe-rollout-plan) |

`img/` holds the three sample CAPTCHA images used by the README and by 09-ADMIN-PANEL.md.

## Conventions used in these documents

- **Placeholders**: `<install-dir>`, `<site-root>`, `<web-user>`, `<php-binary>`, `<python-binary>`, `example.com`, and the documentation address ranges `192.0.2.0/24` and `2001:db8::/32`. Some older examples still use `/home/youruser/bot-guard`; read it the same way.
- **Where code and a document disagree, the code wins**; please fix the document.
- **Tested or not**: the README's [support matrix](../README.md#25-requirements-and-support-matrix) says what CI covers. A statement in these documents that something "works" on a platform the matrix lists as untested is an expectation, not a test result.
