# Bot Guard — Overview

## What it is

Bot Guard is a self-hosted bot and scraper defense system for PHP websites. It
sits in front of a host application (an e-commerce store, a CMS, any PHP site),
scores every incoming request, and decides whether to allow it, challenge it
with a lightweight JavaScript/cookie check, rate-limit it, or block it.

It is built in three cooperating parts:

- **The guard** (PHP) — runs in the request path, on every request, and makes the
  in-band decision. It is designed to be fast and to fail open: any error at all
  results in the request being allowed, so the guard can never take the host site
  down.
- **The analyzer** (Python) — runs out of band, on a schedule (cron). It reads the
  guard's logs, verifies bot claims via reverse DNS, computes a behavioural
  reputation per visitor, trains and runs machine-learning models, and writes its
  verdicts back to Redis for the guard to read cheaply.
- **The admin panel** (PHP) — an English web console for one operator. It shows
  traffic, lets the operator tune thresholds, override decisions for a specific
  visitor, replay "what would this config change have done," and trigger analyzer
  jobs. It writes configuration as validated JSON; it never rewrites executable
  code.

The two sides communicate through **Redis** (small verdict keys) and **daily
JSONL log files** (one line per request).

## What problem it solves

Automated traffic — content scrapers, price scrapers, credential-stuffing
scripts, aggressive crawlers — costs a site money and bandwidth and degrades the
experience for real users. Off-the-shelf answers are either a third-party service
you route all traffic through (a dependency and a privacy cost) or a heavyweight
WAF. Bot Guard is the middle path: a system you host yourself, that starts by
only *watching*, and that you turn up gradually as you gain confidence it is not
blocking real customers.

The whole design is organized around one fear: **blocking a paying customer is
far more expensive than missing a scraped page.** Every default, every threshold,
every rollout step is biased toward not producing false positives.

## The core idea: monitor first, enforce later

Bot Guard ships in **monitor mode**. Out of the box it scores every request and
writes a log line saying what it *would* have done — but it enforces nothing. The
site behaves exactly as if the guard were not there. This is not a demo mode; it
is the intended first phase of every deployment, and it is enforced by a safety
rule: while the configured `secret` is still the placeholder `CHANGE_ME`, every
enforcement toggle is forced off regardless of what the config says.

An operator runs in monitor mode for around two weeks, watches the logs and the
dashboard, confirms that the requests the guard would have challenged really are
bots and the requests it would have allowed really are customers, and only then
turns on enforcement — one mechanism at a time (block, then challenge, then rate
limit), each with a small unenforced "holdout" slice kept as a control group to
measure what is being missed.

## What a visitor experiences

- **A normal visitor** loading a page: nothing. The guard reads a few Redis keys,
  decides "allow," writes a log line, and gets out of the way with zero bytes of
  its own output. If they have never been seen before, their first HTML page load
  briefly shows a "please wait a moment" interstitial that completes on its own in
  a fraction of a second and sets a cookie; every subsequent page is invisible to
  them for a week.
- **A scraper** hitting many pages fast, or from a self-identifying HTTP client,
  or walking a list of URLs into pages that do not exist: accumulates a score and
  a bad reputation, and — once enforcement is on — starts getting challenged (which
  a script cannot solve), rate-limited, or blocked.
- **A verified good crawler** (a real Googlebot, confirmed by reverse DNS out of
  band): gets a fast pass and is never challenged, as long as it stays under a
  generous rate ceiling.

## The five phases

The system was built in five layers, each of which is useful on its own and each
of which is turned on deliberately after the previous one is trusted:

1. **The request guard** — static per-request scoring (empty/script user agents,
   missing headers, rate counters) and the JavaScript/cookie challenge. This alone
   is a working bot defense.
2. **The offline analyzer** — reverse-DNS bot verification and a transparent
   behavioural reputation score per visitor, computed nightly from the logs and
   read cheaply in-band.
3. **Measurement and learning** — a holdout control group to estimate false
   negatives, counterfactual replay to test config changes against real history,
   and a supervised classifier trained only on labels the guard did not itself
   produce.
4. **Response-outcome capture** — recording what the host application did with each
   allowed request (its status code and size), which reveals scrapers whose timing
   looks human but who walk into 404s or pull whole catalogues.
5. **The admin panel** — the web console that ties all of it together for an
   operator who does not want to read logs or run Python.

## What it is not

- It is not a reverse proxy or a CDN. It runs inside your PHP application, not in
  front of your web server.
- It is not a general-purpose WAF. It does not inspect request bodies for SQL
  injection or XSS payloads; it detects *automation*, not *exploitation*.
- It is not a turnkey "block everything suspicious" appliance. It is deliberately
  slow to enforce and biased against false positives, and it expects an operator
  to make the enforcement decisions.
- It does no fingerprinting beyond what the guard already logs. Every ML feature
  is computed from ordinary request fields the guard records anyway — there is no
  hidden tracking layer.

## Where to go next

- **Architecture & Workflow** (`02-ARCHITECTURE.md`) — how the three parts fit
  together and what happens on a single request.
- **Setup Guide** (`03-SETUP.md`) — exact installation and configuration steps.
- **CMS Integration** (`04-CMS-INTEGRATION.md`) — how to bolt the guard onto any
  PHP application.
