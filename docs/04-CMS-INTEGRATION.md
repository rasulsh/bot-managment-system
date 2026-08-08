# Bot Guard — CMS Integration

Bot Guard attaches to a PHP application from the outside. It does not need to know
anything about the CMS, and the CMS does not need to know anything about it. This
doc covers how to integrate it cleanly with any PHP CMS, and the specific paths
you must exempt for common platforms.

## The integration model

The guard runs via **`auto_prepend_file`** — PHP loads `prepend.php` before your
application's front controller on every request. This is the whole integration:
one `php.ini` / `.user.ini` line. The guard makes its decision and either gets out
of the way (letting your CMS run normally) or produces its own response (challenge
/ block / 429) before your CMS ever executes.

Because it hooks at the PHP layer, not inside the CMS, it works with any PHP CMS
without a plugin, module, or code change to the CMS. It also means it protects the
CMS *and* everything else served by the same PHP pool.

```
Request ─▶ PHP ─▶ prepend.php (the guard) ─┬─ allow  ─▶ your CMS runs normally
                                            ├─ exempt ─▶ your CMS runs normally
                                            ├─ challenge/403/429 ─▶ guard responds, CMS never runs
                                            └─ any error ─▶ fail-open, your CMS runs normally
```

## Three integration methods, in order of preference

### Method 1 — `auto_prepend_file` (recommended, zero CMS changes)

Set it globally for the PHP pool that serves your CMS:

```ini
; php.ini, .user.ini in the web root, or cPanel MultiPHP INI Editor
auto_prepend_file = "/home/youruser/bot-guard/prepend.php"
```

Pros: no CMS code touched; survives CMS updates; protects the whole pool. This is
the intended method and what the rest of the docs assume.

### Method 2 — include from the CMS entry point

If you cannot set `auto_prepend_file` (some managed hosts restrict it), add one
line at the very top of the CMS's front controller — before it bootstraps:

```php
<?php
require '/home/youruser/bot-guard/prepend.php';
// ... the CMS's own index.php continues below ...
```

Put it as early as possible, before the CMS loads its own framework, so the guard
decides before the CMS spends any work. The guard's fail-open `try/catch` means a
guard error still lets the CMS run.

Caveat: this only protects requests that actually go through that entry point. If
the CMS has multiple entry points (a separate admin `index.php`, an API endpoint),
add the line to each, or prefer Method 1.

### Method 3 — a CMS-native hook (last resort)

Most CMSes have an earliest-possible hook (an mu-plugin in WordPress, a
pre-dispatch event, a bootstrap file). You can `require prepend.php` from there.
This runs later than Methods 1–2 (the CMS framework has already partly loaded), so
you lose some of the "decide before doing any work" benefit, but it still enforces.
Use only when you control neither `php.ini` nor the front controller.

## The exemption list is the important part

Whatever method you use, the one thing you must get right for a CMS is
**`exempt_paths`** (and sometimes `exempt_params`) in `guard/config.php`. Exempt
anything that:

- must never be challenged or blocked (payment callbacks, webhooks, cron, health
  checks), or
- is a machine-to-machine endpoint that legitimately has no browser, no
  Accept-Language, and no cookie (REST/GraphQL APIs, XML-RPC, feeds).

Remember the decision logic already protects you here: **the challenge only fires
on navigations** — a GET that asks for HTML and is not an AJAX request. So your
CSS/JS/image sub-resources and your XHR/fetch API calls are never challenged just
by being sub-resources. And a POST is never a navigation, so form submits and
payment callbacks are never challenged. Exemptions are for the cases where even the
*scoring* or *rate limiting* would be wrong — endpoints that must be completely
untouched.

### WordPress

```php
'exempt_paths' => array(
    '/wp-admin/',        // the dashboard
    '/wp-login.php',     // login (has its own protections; don't double up)
    '/wp-cron.php',      // pseudo-cron pings
    '/wp-json/',         // the REST API
    '/xmlrpc.php',       // XML-RPC (or block it entirely at the server if unused)
),
```

If you run WooCommerce, also exempt the payment gateway callback/IPN paths — they
vary by gateway, but they live under `/wc-api/` or `/?wc-api=...` (use
`exempt_params` for the query-string form: `'wc-api' => array('')` exempts any
value, or list the specific gateway prefixes).

### OpenCart

OpenCart routes through `index.php?route=...`, so exemptions are usually by
**parameter**, not path:

```php
'exempt_params' => array(
    'route' => array(
        'payment/',      // all payment extension callbacks
        'api/',          // the OpenCart API
        'checkout/',     // optionally, to never risk the checkout flow
    ),
),
'exempt_paths' => array(
    '/admin/',           // the admin panel (adjust if you renamed it)
),
```

This is the platform the system was originally built alongside, so the
`exempt_params` mechanism exists specifically for this `route=` shape. Add the
admin directory (renamed admin folders are common — use your actual one).

### Magento

```php
'exempt_paths' => array(
    '/admin/',           // or your custom admin frontname
    '/rest/',            // the REST API
    '/graphql',          // the GraphQL endpoint
    '/soap/',            // SOAP API if used
    '/pub/health_check.php',
    // payment callbacks vary by method — exempt each gateway's return/IPN path
),
```

### Drupal

```php
'exempt_paths' => array(
    '/admin/',
    '/jsonapi/',
    '/user/login',
    '/cron/',            // if you expose cron over HTTP with a key
),
```

### Joomla

```php
'exempt_paths' => array(
    '/administrator/',
    '/api/',
),
```

### A generic checklist for any CMS

Exempt, at minimum:

1. The admin/back-office path.
2. The login endpoint (it usually has its own brute-force protection; layering the
   challenge on top can lock admins out).
3. Any cron-over-HTTP endpoint.
4. Every REST/GraphQL/SOAP/XML-RPC API base path.
5. Every payment gateway callback / IPN / webhook path (these are server-to-server;
   a challenge would break payments silently).
6. Health checks and uptime-monitor endpoints.

Then run the **monitor period** and read the logs: any legitimate machine client
that shows up with a high shadow-action rate is a missing exemption. Add it before
you enforce.

## Making the honeypot fit the CMS

Set `honeypot_path` to something that 404s on your CMS and that you can link to
invisibly. On most CMSes any unused path works (`/old-archive`, `/legacy`, etc.) —
confirm it genuinely returns 404 and does not collide with a CMS route or a
catch-all. Add the invisible link in a template the CMS renders on every page
(the footer template), and disallow the path in `robots.txt`. See the Setup guide
for the exact link markup.

## The challenge and CMS caching / CDN

Two interactions to know about:

- **Full-page caching (Varnish, CMS page cache, CDN).** The challenge interstitial
  is served with `Cache-Control: no-store`, so it must not be cached. If your cache
  ignores `no-store`, exclude the guard's behaviour from caching — but in practice
  the challenge only fires for token-less navigations, which a good page cache
  should be serving from cache anyway (a cache hit never reaches PHP, so the guard
  never runs on it). Bot Guard is most useful for the *uncached* traffic (logged-in
  users, dynamic pages, and the bots hammering endpoints that bust the cache).
- **The guard cookie and cache keys.** The guard sets a `_gv` cookie. If your cache
  varies on cookies, make sure the `_gv` cookie does not fragment your cache
  needlessly — typically you already strip unknown cookies from the cache key;
  `_gv` can be treated like any other non-cache-affecting cookie.

## CDN in front of the CMS

If a CDN terminates connections in front of your origin, the guard sees the CDN's
IP as `REMOTE_ADDR` unless you tell it otherwise. Set `cdn_ranges` to the CDN's
IPv4 ranges so the guard trusts the last hop of `X-Forwarded-For` to recover the
real client IP. Without this, every visitor behind the CDN shares one IP for
rate-limiting purposes. (CIDR matching is IPv4 only — if your CDN edge is IPv6, see
the code review; you will need to feed the real client IP another way.)

## Updating the CMS

Because the integration is a single `php.ini` / `.user.ini` line (Method 1) or one
`require` (Method 2), a CMS update does not touch Bot Guard and Bot Guard does not
touch the CMS. After a major CMS update, just re-check that no new admin/API path
needs exempting — run a short monitor window and read the logs.

## Multiple sites / multi-tenant

One Bot Guard install can front several sites on the same PHP pool: they share the
guard, the analyzer, and the panel, and their traffic is distinguished in the logs
by host. If sites need different thresholds, run separate installs with separate
`GV_CONFIG` files (point each vhost's `auto_prepend_file` at a different
`prepend.php`, or set the `GV_CONFIG` environment variable per vhost to a different
`config.php`). The config loader honors `GV_CONFIG` before falling back to the
shipped `guard/config.php`.
