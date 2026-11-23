# 15. The dashboard

The dashboard (`?r=dashboard`) is one 12-column grid. Every card has a fixed span at each of three breakpoints, cards in a row have equal height,
the gap is one value (`1rem`) everywhere. All charts are server-rendered inline SVG (no library, no JavaScript needed to read them).
Every number names its period and its comparison; every tile and top-list row links to **Logs** (or **Live**) with the matching filter.

The page reads **only** `analyzer/snapshot.json` plus the cheap live checks that already decide alerts (kill switch, Redis, permissions,
storage, job status files). Every new report (hourly buckets, sparklines, rollout readiness, funnel, top lists with outcome mix) is computed
by the analyzer snapshot (`analyzer/snapshot.py`, key `dash`), never in the page request.

## 15.1 Grid and breakpoints

| Breakpoint | Width | Columns used |
|---|---|---|
| Desktop | 1280 px and wider (designed at 1440 to 1680) | 12 |
| Tablet | 768 to 1279 px | 12 (spans below), most cards full width |
| Mobile | under 768 px (designed at 390) | 12, every card spans all 12 or a half |

## 15.2 Layout spec: grid span per card

| # | Card | Desktop | Tablet | Mobile (390) |
|---|---|---|---|---|
| 1 | **Status strip**: protection mode, guard / kill switch, open alerts (critical / warning), job health, last snapshot age, version | 12 (one row of 6 chips) | 12 (chips wrap, 3 per row) | 12 (2 per row) |
| 1b | **Alerts** (collapsible, only when there are alerts) | 12 | 12 | 12 |
| 2 | **KPI tiles** (6): requests, allowed, challenged (+ solve rate), blocked, rate limited, would act if enforced; each with value, delta and a 24 h sparkline | 2 each (6 x 2) | 4 each (3 x 2) | 6 each (2 x 3) |
| 3 | **Requests per hour** (24 h, toggle 7 d), stacked by outcome, distinct-IP line | 12 | 12 | 12 |
| 4a | **Rollout readiness** (rules and IP lists in monitor mode) | 7 | 12 | 12 |
| 4b | **Challenge and CAPTCHA funnel** | 5 | 12 | 12 |
| 5 | **Top lists** in tabs: IPs, devices, User-Agents, paths, countries, ASNs | 12 | 12 | 12 |
| 6 | **System** (compact): Jobs, Redis and guard, Storage, Models (with classifier label progress), GeoIP and feeds, Permissions | 4 each (3 per row) | 6 each | 12 each |
| 7 | **More** (collapsed): score histograms, status codes, reasons, coverage, holdout | 6 each | 12 | 12 |

Rules that apply to every card: a card is a `gp-dcard` (same padding, border, radius and title row); the title row says the period
("Last 24 hours") and the comparison where there is one ("vs previous 24 hours"); a card in a row has the height of the tallest card in
that row (grid `align-items: stretch`, card body is a flex column); no card sets its own width.

## 15.3 Charts

- Inline SVG, `viewBox` scaled to the card, text in the page font via CSS classes (`gp-chart-label`, `gp-chart-axis`).
- **Main chart:** requests per hour, stacked columns (outcome), plus a line for distinct IPs on the same axis; the Y axis has 3 tick labels and
  the unit ("requests / hour"), the X axis has the hour (24 h) or the day (7 d); a legend only because there is more than one series.
- **Sparklines:** one polyline, no axes, in the tile's outcome colour, `aria-label` with the first and last value.
- **Colours** (the outcome colours Live and Logs use, colour-blind-safe pairing, always with a text label, never colour alone):
  allowed = `--gp-chart-ok` (teal green), challenged = `--gp-chart-warn` (amber), CAPTCHA = `--gp-chart-info` (blue), blocked = `--gp-chart-bad`
  (red-rose), rate limited = `--gp-chart-accent` (violet), monitor-only (would act) = `--gp-chart-neutral` (slate, hatched in the stacked chart).
  All six tokens have a light and a dark value in `app.src.css`.

## 15.4 New snapshot data (`dash`, written by `analyzer/snapshot.py`)

| Key | Content |
|---|---|
| `dash.hours` | 24 hourly buckets (UTC hour start), oldest first: `t`, `n` requests, `a` allowed, `c` challenged, `p` CAPTCHA, `b` blocked, `r` rate limited, `m` monitor-only, `ips` distinct addresses |
| `dash.days7` | 168 hourly buckets in the same shape for the 7 d view |
| `dash.readiness` | per rule id and per IP list id that is enabled in monitor mode: `h24`, `d7`, `ips`, `devs` (7 d), `tok` (share of hits that carried a valid token, 7 d) |
| `dash.funnel` | per level (`js`, `captcha`): `served`, `solved`, `passed`, `failed`, `median_s` |
| `dash.top` | per kind (`ips`, `devices`, `uas`, `paths`, `countries`, `asns`): rows `[key, n, allowed, challenged, blocked, limited, monitor]` |
| `kpi.cur.would_act` / `kpi.prev.would_act` | monitor-only hits: rows that would have been blocked, limited or challenged |

Older snapshots (no `dash`) still render: the cards show an empty state that says the snapshot job has not produced the new data yet.

## 15.4b Funnel stages

Each stage counts distinct visitors (the device id, else the address, because a visitor with no token has no device yet) and is a subset of the stage before, so a number can only go down from left to right:

| Stage | Definition from the log fields |
|---|---|
| Served | `act = challenge` and not monitor-only (check page), or `cap = show` (image CAPTCHA) |
| Solved | a served visitor with a later (or same-time) accepted answer: `act = token_issued` (or a monitor-only issue), or `cap = ok` |
| Passed | a solved visitor with a later allowed request carrying a valid token (`tok = v`) |
| Failed | a served visitor with a refused attempt (`nonce_bad` and the other rejections; `cap` = wrong, fail, inv, exp); not a stage of the chain, always at most Served |

Percentages are of Served. `analyzer/selftest.py` checks `passed <= solved <= served` and `failed <= served` on 300 random logs.

## 15.4c Kill switch and alerts

Stopping the guard needs a confirmation step on the page itself (no browser dialog): *Stop the guard? This switches off all protection.* [Stop] [Cancel]; the server refuses a stop POST that lacks `confirm=1` by redirecting to the confirmation. Starting needs no confirmation. The alert card always shows the first critical alert; the rest is a list that opens by itself from 768 px upward and stays collapsed on a phone behind *5 critical · 5 warning - show all (N more)*.

## 15.5 Empty and stale states

| Situation | What the page says |
|---|---|
| No snapshot file | "No snapshot yet" with the cron line / **Jobs** link to run the snapshot job |
| Snapshot older than 1 hour | a **Stale** badge in the status strip and in every card title |
| No monitor-mode rule or list | Rollout card: "Nothing is in monitor mode" with links to **Rules** and **IP lists** |
| No countries / ASNs in the logs | "No geo data yet: compile the GeoIP database" with a link to **GeoIP** |
| No CAPTCHA served | Funnel shows the JS level only, with "no CAPTCHA was served in this period" |
| Demo role | aggregate tiles and the main chart only: no identities, no top lists, no readiness rows, no System card |
