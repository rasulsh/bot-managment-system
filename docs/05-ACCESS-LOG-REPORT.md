# Access-log report

`scripts/accesslog_report.py` reads the web server's own access log (combined
format, as cPanel / LiteSpeed / Apache write it) and lists the clients that read
the catalogue like a program. It is independent of the guard: it needs no Redis,
no PHP and nothing but the Python standard library (3.6+), it only reads, and it
blocks nothing.

It replaces the "requests per IP, sorted" script. That view finds a loud scraper
and misses the one on a mobile carrier that changes address every few requests
and fetches a page every few seconds: no single address ever looks busy.

## Run it

```bash
python3 scripts/accesslog_report.py /path/to/access.log
python3 scripts/accesslog_report.py --rdns --json /tmp/report.json yesterday.log.gz today.log
```

| option | meaning |
|--------|---------|
| `--min-pages N` | page requests an actor needs before it is scored (default 30) |
| `--top N` | rows per section (default 20) |
| `--catalog-regex RE` | which URLs are catalogue pages (default fits OpenCart, with and without SEO URLs) |
| `--rdns` | verify search-engine claims by forward-confirmed reverse DNS |
| `--ignore CIDR[,CIDR]` | leave these addresses out entirely: your own servers and tools, monitors, the office (repeatable) |
| `--all` | also list actors below the review score |
| `--json FILE` | also write every actor, with its numbers, as JSON |

Give it the **whole** log, static files included. A log already filtered down to
page requests still works, but the strongest signal (pages without assets) turns
itself off and the report says so.

## How it decides

1. **Client** = one (address, User-Agent) pair. The User-Agent is used only to
   tell apart people who share a carrier address; nothing is concluded from what
   it claims.
2. **Candidate** = a client that requested pages and not one stylesheet, script
   or image (or that read 150+ pages).
3. **Actor** = the candidates of one `/24` (IPv6 `/48`) together. Actors whose
   page lists overlap by half or more are merged: one crawl list fetched from two
   networks is one crawler. Candidates left in groups too small to score are
   regrouped per `/16` (`/32`), which is where a carrier's address pool shows up.
4. **Score** on behaviour:

| signal | points | kind |
|--------|-------:|------|
| `no_assets` pages but never an asset | 10 | shape |
| `no_referer` 90%+ of page requests without a Referer | 10 | shape |
| `breadth` 30+ different catalogue pages | 10 | shape |
| `breadth_wide` 100+ | 5 | shape |
| `deep` 100+ different catalogue pages per address it used | 25 | machine |
| `repoll` 30%+ of its pages fetched 3+ times | 20 | machine |
| `cadence` steady interval, or 60+ pages in a minute | 20 | machine |
| `hours` active in 18+ hours of the day | 10 | machine |
| `hours_all` 22+ | 5 | machine |
| `http1` 90%+ HTTP/1.x while the browsers in the log use HTTP/2 or 3 | 10 | machine |
| `declared` the User-Agent names a program | 5 | low weight |

60+ is listed as a likely scraper, 40-59 as worth a look.

The *shape* signals add up to 35 at most, on purpose. A crowd of real customers
on one carrier network can show all of them at once (cached site, arriving from
an app that sends no Referer, many different products between them), and that
must never be enough. An actor is only listed when it also does something only a
program does.

## Reading the result

- Your own tools look exactly like scrapers (pages only, round the clock). Run the
  report once, find them in the list, and pass their addresses to `--ignore` from
  then on.
- In the address table, `cat%` is the share of an address's pages that are
  catalogue pages. Thousands of pages with assets and a low `cat%` are usually
  staff working in the admin panel.

- Addresses are printed as evidence of where an actor was seen. **They are not a
  block list**: a carrier address is shared with customers and belongs to someone
  else within hours.
- A scraper that runs a real browser, loads every asset, and reads fewer than 150
  pages per address-and-browser pair is not a candidate here. That client is the
  guard's job: it needs a token, and the token has an hourly and a daily budget.
- An actor that claims to be a search engine is listed separately as unverified.
  With `--rdns` a confirmed claim moves to "verified crawlers" and a failed one
  stays where its behaviour put it.

## Test

```bash
python3 scripts/accesslog_selftest.py
```

It builds a synthetic day (ordinary customers, returning customers with a full
cache, a campaign crowd, customers behind the same carrier addresses as a
scraper, and three kinds of scraper on changing addresses with browser
User-Agents) and checks both directions.
