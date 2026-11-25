#!/usr/bin/env python3
"""Daily web-server access-log report: who is reading the catalogue like a machine.

    python3 scripts/accesslog_report.py /path/to/access.log [more.log.gz ...]
    python3 scripts/accesslog_report.py --date 2026-11-15 --rdns archive.gz live.log
    python3 scripts/accesslog_report.py --json report.json --ignore 192.0.2.10 access.log

Standard library only (Python 3.6+), read-only, and it never blocks anything:
it prints evidence for an operator to read. Feed it ONE DAY at a time (--date
picks a day out of a longer file).

Why not "requests per IP"
-------------------------
Counting requests per address finds the loud scraper and misses the one that
matters: a client on a mobile carrier that changes address every few requests
and fetches one page every few seconds. No single address ever looks busy. So
an address is not treated as an identity here, and neither is a User-Agent
(any client can send a browser's). The report is built on what a scraper
cannot easily change - what it reads and when:

  client    one (address, User-Agent) pair. The User-Agent is only a way to
            tell apart the people sharing a carrier address (CGNAT); nothing
            is concluded from what it says.
  candidate a client that was served pages but (almost) no stylesheet, script
            or image, or a heavy reader with far fewer assets than a browser.
  actor     the candidates of one network (/24, or /48 for IPv6) taken
            together. Actors that already look like a machine and whose page
            lists largely coincide are merged, because one crawl list fetched
            from two networks is one crawler. Candidates left in small groups
            are looked at again per /16, which is where a carrier's address
            pool shows up.

An actor is scored on behaviour only (see SIGNALS). It is listed when the score
reaches REVIEW_SCORE and it read at least --min-pages pages, so a handful of
odd requests can never produce a finding.

Only what was actually served counts (pages answered 2xx/304, assets answered
200/206/304), and a page is identified by its path plus the parameters that
select content, so tracking tags and cache-busting values do not make new pages.

The old top-addresses-by-requests table is still printed, for continuity.
"""

from __future__ import print_function

import argparse
import collections
import datetime
import gzip
import io
import ipaddress
import json
import re
import socket
import sys
import threading
import zlib

LINE_RE = re.compile(
    r'^(?:[A-Za-z0-9_.-]+(?::\d+)? )?'                       # optional vhost[:port] prefix
    r'(?P<ip>[0-9A-Fa-f:.]+) \S+ .*? \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Za-z-]+) (?P<url>\S+)(?: (?P<proto>[^"]*))?" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?')

ASSET_RE = re.compile(
    r'\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3)$',
    re.I)

# Pages that make up the catalogue. The default fits OpenCart with and without
# SEO URLs; override with --catalog-regex for anything else. Only the page
# routes themselves: route=product/search (live search fires once per keystroke)
# and route=product/product/review (loaded by every product page) are XHR calls
# of a real browser, and counting them made customers look like a steady loop.
DEFAULT_CATALOG = r'^/(?:product|category)/|[?&]route=product/(?:product|category)(?:&|$)'

# Query parameters that say WHICH page is meant. Everything else in a query
# string is dropped before a URL is remembered: tracking tags and cache-busting
# values would otherwise make every request a "different page" (and let a client
# inflate this script's memory at will).
KEEP_PARAMS = ('route', 'product_id', 'path', 'category_id', 'manufacturer_id', 'information_id', 'page')

# User-Agents that say outright that they are a program. LOW weight on purpose:
# it adds a little to an actor that already behaves like a crawler and can
# never list one by itself.
DECLARED_RE = re.compile(
    r'bot\b|bot/|crawl|spider|scrap|checker|updater|monitor|python|curl/|wget/|'
    r'go-http|okhttp|java/|libwww|httpclient|node-fetch|axios|headless', re.I)

# Search engines publish how to verify their crawlers (reverse DNS that
# forward-confirms). Only used with --rdns; without it a claim stays a claim.
CRAWLER_SUFFIXES = (
    ('google', ('.googlebot.com', '.google.com')),
    ('bingbot', ('.search.msn.com',)),
    ('yandex', ('.yandex.ru', '.yandex.net', '.yandex.com')),
    ('applebot', ('.applebot.apple.com',)),
)

MONTHS = dict((m, i + 1) for i, m in enumerate(
    'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()))

# Scoring. Two kinds of signal, weighted so that the first kind alone can never
# list an actor:
#   shape    what a crowd of real customers on one carrier network can also show
#            when their browsers have the site cached and they arrive from an app
#            (no assets, no Referer, many different pages between them). 35 at most.
#   machine  what only a program does. Each of these is measured so that many
#            independent people cannot produce it together:
#              repoll   the pages are fetched again and again ON A SCHEDULE (a
#                       crowd returns to popular products too, at random times);
#              cadence  ONE client keeps a steady interval, or the actor as a
#                       whole does at 3 s or slower (random arrivals of a busy
#                       crowd look "steady" below that, so they do not count);
#              deep     ONE client reads 100+ different catalogue pages;
#              hours    ONE client with no nights off (single-day logs only).
# Breadth, re-polling, cadence and hours are measured on catalogue pages only, so
# the XHR calls a real page fires a second after loading are not mistaken for a
# steady interval.
SIGNALS = (
    # key, points, what it says
    ('no_assets', 10, 'shape: requested pages but (almost) never a stylesheet, script or image'),
    ('no_referer', 10, 'shape: at least 90% of its page requests carry no Referer'),
    ('breadth', 10, 'shape: read 30 or more different catalogue pages'),
    ('breadth_wide', 5, 'shape: ...and 100 or more'),
    ('deep', 25, 'machine: one client (address + User-Agent) read 100+ different catalogue pages'),
    ('repoll', 20, 'machine: comes back to its pages on a schedule (half of them 3+ times, at regular gaps)'),
    ('cadence', 20, 'machine: a steady interval between requests, or one client bursting 60+/minute'),
    ('hours', 10, 'machine: one client active in 18 or more hours of the day'),
    ('hours_all', 5, 'machine: ...and in 22 or more'),
    ('http1', 10, 'machine: 90%+ over HTTP/1.x while the browsers in this log use HTTP/2 or 3'),
    ('declared', 5, 'the User-Agent names a program (low weight)'),
)
POINTS = dict((key, pts) for key, pts, _ in SIGNALS)
SHAPE_SIGNALS = ('no_assets', 'no_referer', 'breadth', 'breadth_wide')
HIGH_SCORE = 60
REVIEW_SCORE = 40
HEAVY_PAGES = 150          # a client reading this many pages is a candidate even with a few assets
HEAVY_ASSET_RATIO = 0.2    # ...as long as it fetched far fewer assets than a browser would
BARE_ASSET_RATIO = 0.02    # "no assets": at most this share (one stray .css does not hide a crawler)
MERGE_JACCARD = 0.5        # page-list overlap that makes two actors one crawler
MERGE_MIN_URLS = 20
MERGE_MAX_GROUPS = 400
MAX_SPAN_HOURS = 36        # a longer log makes the hour-of-day signals meaningless
RDNS_TIMEOUT_S = 4.0
RDNS_MAX_ACTORS = 15
CONTROL_RE = re.compile(u'[\\x00-\\x1f\\x7f-\\x9f\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]')


def parse_time(text):
    """'15/Nov/2026:15:57:05 +0330' -> (epoch, local hour, UTC offset in seconds), or None."""
    try:
        stamp, _, zone = text.partition(' ')
        day, mon, rest = stamp.split('/', 2)
        year, hh, mm, ss = rest.split(':')
        local = datetime.datetime(int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss))
        offset = 0
        if len(zone) == 5 and zone[0] in '+-':
            offset = (int(zone[1:3]) * 3600 + int(zone[3:5]) * 60) * (1 if zone[0] == '+' else -1)
        epoch = int((local - datetime.datetime(1970, 1, 1)).total_seconds()) - offset
        return epoch, int(hh), offset
    except (ValueError, KeyError):
        return None


def canon_ip(ip):
    """::ffff:1.2.3.4 is the IPv4 address 1.2.3.4; everything else is returned as it is."""
    if ':' not in ip:
        return ip
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    mapped = getattr(addr, 'ipv4_mapped', None)
    return str(mapped) if mapped is not None else str(addr)


def network_of(ip, wide=False):
    """The network an address is grouped by: /24 (wide: /16), or /48 (/32) for IPv6."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 4:
        bits = 16 if wide else 24
    else:
        bits = 32 if wide else 48
    return str(ipaddress.ip_network('%s/%d' % (ip, bits), strict=False))


def page_key(url):
    """The identity of a page: its path plus only the parameters that select content."""
    path, sep, query = url.partition('?')
    if not sep or not query:
        return path
    kept = []
    for pair in query.split('&'):
        name = pair.partition('=')[0]
        if name in KEEP_PARAMS:
            kept.append(pair[:120])
    return path + ('?' + '&'.join(kept) if kept else '')


def clean(text):
    """Text safe to print on a terminal: no control or direction-override characters."""
    return CONTROL_RE.sub('?', text)


class Client(object):
    """Everything kept about one (address, User-Agent) pair."""
    __slots__ = ('ip', 'ua', 'pages', 'assets', 'no_ref', 'http1', 'hits')

    def __init__(self, ip, ua):
        self.ip = ip
        self.ua = ua
        self.pages = 0
        self.assets = 0
        self.no_ref = 0
        self.http1 = 0
        self.hits = []          # (epoch, hour, url id) per page request


def open_log(path):
    if path == '-':
        return io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8', errors='replace')
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', encoding='utf-8', errors='replace')
    return io.open(path, 'r', encoding='utf-8', errors='replace')


def parse_networks(values):
    """['10.0.0.0/8,192.0.2.7', ...] -> list of ip_network. Raises ValueError on a bad one."""
    nets = []
    for value in values or []:
        for item in str(value).split(','):
            item = item.strip()
            if item:
                nets.append(ipaddress.ip_network(item, strict=False))
    return nets


def is_ignored(ip, nets, cache):
    """True when the address is inside an --ignore network. Cached per address."""
    hit = cache.get(ip)
    if hit is None:
        try:
            addr = ipaddress.ip_address(ip)
            hit = any(addr.version == net.version and addr in net for net in nets)
        except ValueError:
            hit = False
        cache[ip] = hit
    return hit


def read_logs(paths, ignore=None, catalog_re=None, day=None):
    """Parse the logs into per-client and per-address tallies.

    Returns a dict: clients, by_ip, urls (id -> page key), catalog (set of url
    ids, or None when the pattern matched nothing), lines, bad, ignored,
    other_days, truncated, pages, assets, first, last.

    Only what was actually SERVED counts: a page is a GET answered 2xx or 304,
    an asset one answered 200, 206 or 304. A scanner collecting 404s is not
    reading the catalogue, a client following a redirect did not read two pages,
    and a request for a stylesheet that does not exist is not a browser.
    `day` ('YYYY-MM-DD', in the log's own time zone) keeps that day only.
    """
    ignore = ignore or []
    ignore_cache = {}
    clients = {}
    by_ip = {}
    url_ids = {}
    is_cat = []                         # url id -> is a catalogue page
    out = {'lines': 0, 'bad': 0, 'ignored': 0, 'other_days': 0, 'truncated': [],
           'pages': 0, 'assets': 0, 'assets_http1': 0, 'first': None, 'last': None, 'tz': 0}
    day_tag = None
    if day:
        when = datetime.datetime.strptime(day, '%Y-%m-%d')
        day_tag = '%02d/%s/%04d:' % (when.day, 'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()[when.month - 1],
                                     when.year)
    for path in paths:
        handle = open_log(path)
        try:
            for line in handle:
                out['lines'] += 1
                if day_tag is not None and ('[' + day_tag) not in line:
                    out['other_days'] += 1
                    continue
                match = LINE_RE.match(line)
                when = parse_time(match.group('ts')) if match else None
                if when is None:
                    out['bad'] += 1
                    continue
                epoch, hour, out['tz'] = when
                ip = canon_ip(match.group('ip'))
                if ignore and is_ignored(ip, ignore, ignore_cache):
                    out['ignored'] += 1
                    continue
                ua = match.group('ua') or ''
                url = match.group('url')
                ref = match.group('ref') or ''
                status = match.group('status')
                http1 = (match.group('proto') or '').startswith('HTTP/1')
                is_asset = bool(ASSET_RE.search(url.split('?', 1)[0]))
                if out['first'] is None or epoch < out['first']:
                    out['first'] = epoch
                if out['last'] is None or epoch > out['last']:
                    out['last'] = epoch

                tally = by_ip.get(ip)
                if tally is None:
                    tally = by_ip[ip] = {'req': 0, 'pages': 0, 'assets': 0, 'no_ref': 0,
                                         'http1': 0, 'bytes': 0, 'uas': set(), 'cat': 0}
                tally['req'] += 1
                tally['http1'] += 1 if http1 else 0
                size = match.group('size')
                tally['bytes'] += int(size) if size.isdigit() else 0
                if len(tally['uas']) < 50:
                    tally['uas'].add(ua)

                key = (ip, ua)
                client = clients.get(key)
                if client is None:
                    client = clients[key] = Client(ip, ua)
                if is_asset:
                    if status in ('200', '206', '304'):
                        out['assets'] += 1
                        out['assets_http1'] += 1 if http1 else 0
                        tally['assets'] += 1
                        client.assets += 1
                    continue
                if match.group('method').upper() != 'GET' or not (status[0] == '2' or status == '304'):
                    continue
                out['pages'] += 1
                tally['pages'] += 1
                client.pages += 1
                if ref in ('', '-'):
                    client.no_ref += 1
                    tally['no_ref'] += 1
                if http1:
                    client.http1 += 1
                pkey = page_key(url)
                uid = url_ids.get(pkey)
                if uid is None:
                    uid = url_ids[pkey] = len(url_ids)
                    is_cat.append(bool(catalog_re.search(pkey)) if catalog_re is not None else False)
                if is_cat[uid]:
                    tally['cat'] += 1
                client.hits.append((epoch, hour, uid))
        except (EOFError, OSError, zlib.error) as exc:
            # A .gz cut short (still being written, a broken download): keep what
            # was read and say so, instead of a traceback after minutes of work.
            out['truncated'].append('%s (%s)' % (path, exc.__class__.__name__))
        finally:
            try:
                handle.close()
            except Exception:
                pass
    out['clients'] = clients
    out['by_ip'] = by_ip
    out['urls'] = dict((uid, url) for url, uid in url_ids.items())
    catalog = set(uid for uid, flag in enumerate(is_cat) if flag)
    out['catalog'] = catalog or None
    return out


def cadence(times):
    """(steady share, median gap, peak requests per minute) of a request timeline.

    steady share is the part of the gaps that sit within 25% (at least one
    second) of the median gap: a person's page views are spread all over, a
    loop with a sleep in it is not. Gaps longer than ten minutes are pauses
    between runs and are left out.
    """
    times = sorted(times)
    gaps = [b - a for a, b in zip(times, times[1:]) if (b - a) <= 600]
    per_minute = collections.Counter(t // 60 for t in times)
    peak = max(per_minute.values()) if per_minute else 0
    if len(gaps) < 20:
        return 0.0, 0, peak
    ordered = sorted(gaps)
    median = ordered[len(ordered) // 2]
    if median < 1:
        return 0.0, median, peak
    tolerance = max(1.0, 0.25 * median)
    steady = sum(1 for g in gaps if abs(g - median) <= tolerance)
    return float(steady) / len(gaps), median, peak


def regular_repoll(times_by_url):
    """True when pages are re-fetched the way a poller does it: on a schedule.

    A crowd "re-fetches" too - many people open the same popular products - so
    counting repeats is not enough, however evenly they fall. What a crowd
    cannot do is come back to each page at a regular interval. For every page
    fetched 3+ times the gaps between its fetches are compared with their own
    median; the page is "regular" when 60% of them are within 30% of it (one
    long pause, a night off, does not spoil it). A poller is an actor where at
    least half of its pages were fetched 3+ times (10 at the very least) and at
    least half of those are regular. For independent visitors the chance that a
    page looks regular is well under one in three.
    """
    total = len(times_by_url)
    judged = regular = 0
    for times in times_by_url.values():
        if len(times) < 3:
            continue
        times = sorted(times)
        gaps = sorted(b - a for a, b in zip(times, times[1:]))
        median = gaps[len(gaps) // 2]
        judged += 1
        if median >= 10 and sum(1 for g in gaps if abs(g - median) <= 0.3 * median) >= 0.6 * len(gaps):
            regular += 1
    return total >= 20 and judged >= max(10, 0.5 * total) and regular >= 0.5 * judged


def build_actor(name, members, env, urls):
    """Fold candidate clients into one actor and score its behaviour.

    env carries what was learned from the whole log: assets_logged, http1_tells,
    single_day and catalog (the set of url ids that are catalogue pages, or None
    when the catalogue pattern matched nothing and every page has to count).
    """
    catalog = env['catalog']
    hits = []
    pages = no_ref = http1 = assets = 0
    ips = collections.Counter()
    uas = collections.Counter()
    busiest_hours = 0           # most different hours of the day ONE client was active in
    deepest = 0                 # most different catalogue pages read by ONE client
    steady_pages = 0            # catalogue pages belonging to individually steady clients
    burst = 0                   # highest per-minute rate of ONE client
    for client in members:
        mine = client.hits if catalog is None else [h for h in client.hits if h[2] in catalog]
        hits.extend(mine)
        pages += client.pages
        no_ref += client.no_ref
        http1 += client.http1
        assets += client.assets
        ips[client.ip] += client.pages
        uas[client.ua] += client.pages
        if mine:
            deepest = max(deepest, len(set(h[2] for h in mine)))
            busiest_hours = max(busiest_hours, len(set(h[1] for h in mine)))
            c_steady, _, c_peak = cadence([h[0] for h in mine])
            burst = max(burst, c_peak)
            if c_steady >= 0.5:
                steady_pages += len(mine)
    per_url = collections.Counter(uid for _, _, uid in hits)
    unique = len(per_url)
    repolled = sum(1 for count in per_url.values() if count >= 3)
    hours = len(set(hour for _, hour, _ in hits))
    steady, median_gap, peak = cadence([epoch for epoch, _, _ in hits])
    top_ua = uas.most_common(1)[0][0] if uas else ''

    signals = []
    if env['assets_logged'] and assets <= BARE_ASSET_RATIO * max(1, pages):
        signals.append('no_assets')
    if pages and float(no_ref) / pages >= 0.9:
        signals.append('no_referer')
    if unique >= 30:
        signals.append('breadth')
    if unique >= 100:
        signals.append('breadth_wide')
    if deepest >= 100:
        signals.append('deep')
    times_by_url = collections.defaultdict(list)
    for epoch, _, uid in hits:
        times_by_url[uid].append(epoch)
    if regular_repoll(times_by_url):
        signals.append('repoll')
    # Steady per client, or steady as a whole at 3 s or slower (see SIGNALS).
    if ((hits and float(steady_pages) / len(hits) >= 0.5)
            or (steady >= 0.5 and median_gap >= 3) or burst >= 60):
        signals.append('cadence')
    # Hours are counted per client: a network of customers covers most of the
    # clock between them, one person does not.
    if env['single_day'] and busiest_hours >= 18:
        signals.append('hours')
    if env['single_day'] and busiest_hours >= 22:
        signals.append('hours_all')
    if env['http1_tells'] and pages and float(http1) / pages >= 0.9:
        signals.append('http1')
    if top_ua and DECLARED_RE.search(top_ua):
        signals.append('declared')

    times = [epoch for epoch, _, _ in hits]
    all_urls = set(uid for c in members for _, _, uid in c.hits)
    return {
        'name': name,
        'score': min(100, sum(POINTS[s] for s in signals)),
        'signals': signals,
        'pages': pages,
        'unique_pages': unique,
        'repolled_pages': repolled,
        'deepest_client': deepest,
        'catalog_share': round(float(len(hits)) / pages, 3) if pages else 0.0,
        'no_referer_share': round(float(no_ref) / pages, 3) if pages else 0.0,
        'http1_share': round(float(http1) / pages, 3) if pages else 0.0,
        'assets': assets,
        'active_hours': hours,
        'client_hours': busiest_hours,
        'steady_share': round(steady, 3),
        'median_gap_s': median_gap,
        'peak_per_minute': max(peak, burst),
        'first': min(times) if times else None,
        'last': max(times) if times else None,
        'addresses': len(ips),
        'top_addresses': ips.most_common(10),
        'user_agents': len(uas),
        'top_user_agents': uas.most_common(3),
        'url_ids': all_urls,
        'members': members,
    }


def merge_by_crawl_list(groups, urls_of):
    """Union groups whose page lists overlap by MERGE_JACCARD or more."""
    names = sorted(groups, key=lambda n: -len(urls_of[n]))[:MERGE_MAX_GROUPS]
    names = [n for n in names if len(urls_of[n]) >= MERGE_MIN_URLS]
    parent = dict((n, n) for n in groups)

    def find(n):
        while parent[n] != n:
            parent[n] = parent[parent[n]]
            n = parent[n]
        return n

    for i, a in enumerate(names):
        for b in names[i + 1:]:
            small, large = sorted((urls_of[a], urls_of[b]), key=len)
            if len(small) < len(large) * MERGE_JACCARD:
                continue                       # sizes alone rule the overlap out
            common = len(small & large)
            if float(common) / (len(small) + len(large) - common) >= MERGE_JACCARD:
                parent[find(a)] = find(b)
    merged = collections.defaultdict(list)
    for name in groups:
        merged[find(name)].append(name)
    return merged


def is_candidate(client, assets_logged):
    """A client worth looking at: pages with (almost) no assets, or a heavy reader."""
    if not client.pages:
        return False
    if not assets_logged:
        # No asset requests in this log at all (a pre-filtered log, or assets on
        # another host), so "no assets" cannot single anybody out. The next best
        # thing a browser leaves behind is the Referer of its own clicks.
        return client.no_ref >= 0.9 * client.pages
    if client.assets <= BARE_ASSET_RATIO * client.pages:
        return True
    return client.pages >= HEAVY_PAGES and client.assets < HEAVY_ASSET_RATIO * client.pages


def find_actors(data, min_pages):
    """Candidates -> actors per network -> merge the machine-like ones -> residue per /16."""
    served = data['pages'] + data['assets']
    assets_logged = data['assets'] > 0 and data['assets'] >= 0.02 * max(1, served)
    span = (data['last'] - data['first']) if data['first'] is not None else 0
    env = {
        'assets_logged': assets_logged,
        # HTTP/1.x only says something when the real browsers here do not use it.
        # Their asset requests show what they use; behind a proxy that speaks
        # HTTP/1.1 to this server everyone looks the same and the signal is off.
        'http1_tells': not assets_logged or data['assets_http1'] < 0.9 * data['assets'],
        'catalog': data['catalog'],
        # "Active in 18 hours of the day" means nothing over a week of log: any
        # busy network covers the clock eventually. The hour signals are only
        # used when the log is about one day long.
        'single_day': span <= MAX_SPAN_HOURS * 3600,
        'span_hours': round(span / 3600.0, 1),
    }
    candidates = [c for c in data['clients'].values() if is_candidate(c, assets_logged)]
    groups = collections.defaultdict(list)
    for client in candidates:
        groups[network_of(client.ip)].append(client)

    # Score every network by itself first. Only networks that already behave
    # like a machine are merged by crawl list: when the same popular products
    # are read from many ordinary networks their page lists overlap too, and
    # merging those chained unrelated customers into one giant "actor".
    solo = {}
    residue = []
    for name, members in groups.items():
        if sum(c.pages for c in members) < min_pages:
            residue.extend(members)
            continue
        solo[name] = build_actor(name, members, env, data['urls'])
    machine = dict((n, groups[n]) for n, a in solo.items() if a['score'] >= REVIEW_SCORE)
    urls_of = dict((n, solo[n]['url_ids']) for n in machine)

    actors = [a for n, a in solo.items() if n not in machine]
    for root, names in merge_by_crawl_list(machine, urls_of).items():
        if len(names) == 1:
            actors.append(solo[names[0]])
            continue
        members = [c for name in names for c in groups[name]]
        label = ' + '.join(sorted(names)[:4]) + (' + %d more' % (len(names) - 4) if len(names) > 4 else '')
        actors.append(build_actor(label, members, env, data['urls']))

    wide = collections.defaultdict(list)
    for client in residue:
        wide[network_of(client.ip, wide=True)].append(client)
    for name, members in wide.items():
        if sum(c.pages for c in members) >= min_pages:
            actors.append(build_actor(name + ' (wide)', members, env, data['urls']))
    actors.sort(key=lambda a: (-a['score'], -a['pages']))
    return actors, env


def claimed_crawler(user_agent):
    lowered = (user_agent or '').lower()
    for name, suffixes in CRAWLER_SUFFIXES:
        if name in lowered:
            return name, suffixes
    return None, ()


def rdns_verified(ip, suffixes, resolver=socket):
    """Forward-confirmed reverse DNS. True only on a positive, confirmed answer."""
    try:
        answer = resolver.gethostbyaddr(ip)
        names = [answer[0]] + list(answer[1] or [])             # the PTR name and its aliases
    except Exception:
        return False
    hosts = [h.lower().rstrip('.') for h in names]
    for host in hosts:
        # A whole-label match: "notgooglebot.com" is not under ".googlebot.com".
        if not any(host == s.lstrip('.') or host.endswith('.' + s.lstrip('.')) for s in suffixes):
            continue
        try:
            addresses = [info[4][0] for info in resolver.getaddrinfo(host, None)]
        except Exception:
            continue
        if any(_same_ip(ip, a) for a in addresses):
            return True
    return False


def _same_ip(a, b):
    """Two textual addresses are the same address (2001:db8::1 equals 2001:0db8:0:0:0:0:0:1; ::ffff:1.2.3.4 equals 1.2.3.4)."""
    try:
        x, y = ipaddress.ip_address(str(a).split('%')[0]), ipaddress.ip_address(str(b).split('%')[0])
    except ValueError:
        return str(a) == str(b)
    x = x.ipv4_mapped if getattr(x, 'ipv4_mapped', None) else x
    y = y.ipv4_mapped if getattr(y, 'ipv4_mapped', None) else y
    return x == y


def rdns_verified_within(ip, suffixes, resolver, timeout):
    """rdns_verified with a deadline: a resolver that never answers verifies nothing."""
    box = []
    worker = threading.Thread(target=lambda: box.append(rdns_verified(ip, suffixes, resolver)))
    worker.daemon = True
    worker.start()
    worker.join(timeout)
    return bool(box and box[0])


def classify(actors, use_rdns, resolver=socket, timeout=RDNS_TIMEOUT_S):
    """Give every actor a verdict: scraper / review / verified-crawler / ''.

    A User-Agent that claims to be a search engine changes nothing by itself:
    the actor keeps the verdict its behaviour earned, with the claim noted. Only
    a claim confirmed by reverse DNS (--rdns) moves it to the verified list.
    """
    checked = 0
    for actor in actors:
        top_ua = actor['top_user_agents'][0][0] if actor['top_user_agents'] else ''
        name, suffixes = claimed_crawler(top_ua)
        actor['claims'] = name or ''
        verdict = ''
        if actor['score'] >= HIGH_SCORE:
            verdict = 'scraper'
        elif actor['score'] >= REVIEW_SCORE:
            verdict = 'review'
        if name and verdict and use_rdns and checked < RDNS_MAX_ACTORS:
            checked += 1
            sample = [ip for ip, _ in actor['top_addresses'][:3]]
            if sample and all(rdns_verified_within(ip, suffixes, resolver, timeout) for ip in sample):
                verdict = 'verified-crawler'
        actor['verdict'] = verdict
    return actors


def fmt_time(epoch, tz=0):
    """Render an epoch in the log's own time zone, which is what the operator reads."""
    if epoch is None:
        return '-'
    local = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=epoch + tz)
    return local.strftime('%Y-%m-%d %H:%M')


def render(data, actors, env, top, show_all):
    out = []
    add = out.append
    tz = data.get('tz', 0)
    add('Access-log report (times in the log\'s own time zone, UTC%+03d:%02d)'
        % (int(tz / 3600), abs(tz) % 3600 // 60))
    add('  lines %d (unparsed %d, ignored %d, other days %d)   pages served %d   assets served %d'
        % (data['lines'], data['bad'], data['ignored'], data['other_days'], data['pages'], data['assets']))
    add('  from %s to %s   addresses %d   clients (address + User-Agent) %d'
        % (fmt_time(data['first'], tz), fmt_time(data['last'], tz), len(data['by_ip']), len(data['clients'])))
    if not env['assets_logged']:
        add('  NOTE: this log holds (almost) no asset requests, so the "no assets" signal is off')
        add('        and a candidate is a client whose page requests carry no Referer. A crawler')
        add('        that fakes a Referer is not seen in this mode: feed the full log.')
    if not env['http1_tells']:
        add('  NOTE: the browsers in this log use HTTP/1.x themselves (a proxy in front?), so the')
        add('        "http1" signal is off.')
    if env['catalog'] is None:
        add('  NOTE: --catalog-regex matched no URL in this log; every page counts as catalogue.')
    elif data['pages'] and sum(t['cat'] for t in data['by_ip'].values()) < 0.05 * data['pages']:
        add('  NOTE: --catalog-regex matches under 5% of the pages served. If product pages have')
        add('        another URL shape here, pass a pattern that fits; breadth, re-polling and')
        add('        cadence are measured on catalogue pages only.')
    if not env['single_day']:
        add('  NOTE: this log spans %.0f hours. The hour-of-day signals are OFF, and breadth and'
            % env['span_hours'])
        add('        re-polling add up over days, so ordinary networks score higher than they')
        add('        would on one day. Analyse one day at a time with --date YYYY-MM-DD.')
    for item in data['truncated']:
        add('  WARNING: stopped reading early, the file is cut short: %s' % clean(item))
    seen = data['lines'] - data['other_days']
    if seen >= 100 and data['bad'] > 0.2 * seen:
        add('  WARNING: %d of %d lines could not be parsed. This does not look like the combined'
            % (data['bad'], seen))
        add('           log format; the result below covers only what was understood.')
    add('')

    sections = (
        ('scraper', 'LIKELY SCRAPERS (score %d+)' % HIGH_SCORE),
        ('review', 'WORTH A LOOK (score %d-%d)' % (REVIEW_SCORE, HIGH_SCORE - 1)),
        ('verified-crawler', 'VERIFIED SEARCH-ENGINE CRAWLERS (reverse DNS confirmed)'),
    )
    if show_all:
        sections += (('', 'BELOW THE REVIEW SCORE (shown because of --all)'),)
    for verdict, title in sections:
        chosen = [a for a in actors if a['verdict'] == verdict][:top]
        add('== %s: %d' % (title, len([a for a in actors if a['verdict'] == verdict])))
        for actor in chosen:
            add('')
            claim = ''
            if actor.get('claims') and verdict != 'verified-crawler':
                claim = '   [claims to be %s: NOT verified%s]' % (
                    actor['claims'], '' if verdict == '' else ', judged on behaviour')
            add('  %s   score %d%s' % (clean(actor['name']), actor['score'], claim))
            add('    pages %d, different catalogue pages %d (%d fetched 3+ times, most by one client %d), '
                'catalogue share %d%%'
                % (actor['pages'], actor['unique_pages'], actor['repolled_pages'], actor['deepest_client'],
                   round(actor['catalog_share'] * 100)))
            add('    addresses %d, User-Agents %d, active hours %d/24 (busiest client %d), %s -> %s'
                % (actor['addresses'], actor['user_agents'], actor['active_hours'], actor['client_hours'],
                   fmt_time(actor['first'], tz), fmt_time(actor['last'], tz)))
            add('    median gap %ss, steady %d%%, peak %d/min, no Referer %d%%, HTTP/1.x %d%%, assets %d'
                % (actor['median_gap_s'], round(actor['steady_share'] * 100), actor['peak_per_minute'],
                   round(actor['no_referer_share'] * 100), round(actor['http1_share'] * 100),
                   actor['assets']))
            add('    why: ' + ', '.join(actor['signals']))
            add('    addresses seen (pages): '
                + ', '.join('%s (%d)' % pair for pair in actor['top_addresses'][:6])
                + (' ...' if actor['addresses'] > 6 else ''))
            for ua, count in actor['top_user_agents']:
                add('    UA (%d): %s' % (count, clean(ua[:110]) or '(empty)'))
        add('')

    add('== SIGNALS')
    for key, pts, text in SIGNALS:
        add('  %-13s +%-2d %s' % (key, pts, text))
    add('')
    add('== TOP ADDRESSES BY REQUESTS (the old view; an address is not an identity)')
    add('  cat% = share of its pages that are catalogue pages. Thousands of pages with a low cat%')
    add('  are usually staff in the admin panel or one of your own tools: pass those to --ignore.')
    add('  %-39s %8s %7s %7s %5s %6s %6s %4s %9s'
        % ('address', 'requests', 'pages', 'assets', 'cat%', 'noRef%', 'http1%', 'UAs', 'MB'))
    ranked = sorted(data['by_ip'].items(), key=lambda kv: -kv[1]['req'])[:top]
    for ip, t in ranked:
        in_cat = t['pages'] if env['catalog'] is None else t['cat']
        add('  %-39s %8d %7d %7d %5d %6d %6d %4d %9.1f'
            % (clean(ip), t['req'], t['pages'], t['assets'],
               round(100.0 * in_cat / t['pages']) if t['pages'] else 0,
               round(100.0 * t['no_ref'] / t['pages']) if t['pages'] else 0,
               round(100.0 * t['http1'] / t['req']) if t['req'] else 0,
               len(t['uas']), t['bytes'] / 1e6))
    add('')
    add('Addresses above are evidence of where an actor was seen, not a block list:')
    add('carrier addresses are shared with customers and handed to someone else within hours.')
    return '\n'.join(out)


def to_json(data, actors, env):
    listed = []
    for actor in actors:
        row = dict((k, v) for k, v in actor.items() if k not in ('url_ids', 'members'))
        listed.append(row)
    return {
        'lines': data['lines'], 'unparsed': data['bad'], 'ignored': data['ignored'],
        'other_days': data['other_days'], 'truncated': data['truncated'],
        'single_day': env['single_day'], 'span_hours': env['span_hours'],
        'pages': data['pages'],
        'assets': data['assets'], 'assets_logged': env['assets_logged'],
        'http1_tells': env['http1_tells'], 'catalog_matched': env['catalog'] is not None,
        'first': data['first'], 'last': data['last'], 'utc_offset_s': data.get('tz', 0),
        'addresses': len(data['by_ip']), 'clients': len(data['clients']),
        'actors': listed,
    }


def analyse(paths, min_pages=30, catalog=DEFAULT_CATALOG, use_rdns=False, resolver=socket,
            ignore=None, day=None):
    data = read_logs(paths, ignore, re.compile(catalog), day)
    actors, env = find_actors(data, min_pages)
    classify(actors, use_rdns, resolver)
    return data, actors, env


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Find machine-like readers in a web-server access log (combined format).')
    parser.add_argument('logs', nargs='+', help='access log files (.gz accepted, - for stdin)')
    parser.add_argument('--min-pages', type=int, default=30,
                        help='page requests an actor needs before it is scored (default 30)')
    parser.add_argument('--top', type=int, default=20, help='rows per section (default 20)')
    parser.add_argument('--catalog-regex', default=DEFAULT_CATALOG,
                        help='regex matching catalogue pages (default fits OpenCart)')
    parser.add_argument('--rdns', action='store_true',
                        help='verify search-engine claims by reverse DNS (needs working DNS)')
    parser.add_argument('--ignore', action='append', default=[], metavar='CIDR[,CIDR...]',
                        help='addresses or networks to leave out entirely: your own servers, '
                             'tools, monitors, office (repeatable)')
    parser.add_argument('--date', default=None, metavar='YYYY-MM-DD',
                        help='analyse only this day (in the log\'s own time zone); use it with '
                             'archives that hold many days')
    parser.add_argument('--all', action='store_true', help='also list actors below the review score')
    parser.add_argument('--json', default=None, help='also write the findings to this JSON file')
    args = parser.parse_args(argv)
    try:
        re.compile(args.catalog_regex)
    except re.error as exc:
        print('ERROR: bad --catalog-regex: %s' % exc, file=sys.stderr)
        return 2
    try:
        ignore = parse_networks(args.ignore)
    except ValueError as exc:
        print('ERROR: bad --ignore value: %s' % exc, file=sys.stderr)
        return 2
    if args.date:
        try:
            datetime.datetime.strptime(args.date, '%Y-%m-%d')
        except ValueError:
            print('ERROR: --date must look like 2026-11-15', file=sys.stderr)
            return 2
    try:
        data, actors, env = analyse(args.logs, args.min_pages, args.catalog_regex, args.rdns,
                                    ignore=ignore, day=args.date)
    except (IOError, OSError) as exc:
        print('ERROR: cannot read a log: %s' % exc, file=sys.stderr)
        return 2
    print(render(data, actors, env, args.top, args.all))
    status = 0
    if args.json:
        try:
            with io.open(args.json, 'w', encoding='utf-8') as handle:
                handle.write(json.dumps(to_json(data, actors, env), indent=1, sort_keys=True))
                handle.write(u'\n')
        except (IOError, OSError) as exc:
            print('ERROR: cannot write %s: %s' % (args.json, exc), file=sys.stderr)
            status = 2
    seen = data['lines'] - data['other_days']
    if data['truncated'] or (seen >= 100 and data['bad'] > 0.2 * seen):
        status = status or 1          # the report is partial: let a cron job notice
    return status


if __name__ == '__main__':
    sys.exit(main())
