#!/usr/bin/env python3
"""Daily web-server access-log report: who is reading the catalogue like a machine.

    python3 scripts/accesslog_report.py /path/to/access.log [more.log.gz ...]
    python3 scripts/accesslog_report.py --json report.json --top 30 access.log

Standard library only (Python 3.6+), read-only, and it never blocks anything:
it prints evidence for an operator to read.

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
  candidate a client that requested pages but not one stylesheet, script or
            image, or that read an unusually large number of pages.
  actor     the candidates of one network (/24, or /48 for IPv6) taken
            together. Actors whose page lists largely coincide are merged,
            because one crawl list fetched from two networks is one crawler.
            Candidates left in small groups are looked at again per /16, which
            is where a carrier's address pool shows up.

An actor is scored on behaviour only (see SIGNALS). It is listed when the score
reaches REVIEW_SCORE and it read at least --min-pages pages, so a handful of
odd requests can never produce a finding.

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

LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+)(?: (?P<proto>[^"]*))?" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')

ASSET_RE = re.compile(
    r'\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3)$',
    re.I)

# Pages that make up the catalogue. The default fits OpenCart with and without
# SEO URLs; override with --catalog-regex for anything else.
DEFAULT_CATALOG = r'^/(?:product|category)/|[?&]route=product/(?:product|category|search)'

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
#   machine  what only a program does: polling the same pages again and again, a
#            steady interval, no nights off, plain HTTP/1.x.
# Breadth, re-polling, cadence and hours are measured on catalogue pages only, so
# the XHR calls a real page fires a second after loading are not mistaken for a
# steady interval.
SIGNALS = (
    # key, points, what it says
    ('no_assets', 10, 'shape: requested pages but never a stylesheet, script or image'),
    ('no_referer', 10, 'shape: at least 90% of its page requests carry no Referer'),
    ('breadth', 10, 'shape: read 30 or more different catalogue pages'),
    ('breadth_wide', 5, 'shape: ...and 100 or more'),
    ('repoll', 20, 'machine: polls the same pages again and again (30%+ fetched 3+ times)'),
    ('cadence', 20, 'machine: a steady interval between requests, or a burst of 60+/minute'),
    ('hours', 10, 'machine: active in 18 or more hours of the day'),
    ('hours_all', 5, 'machine: ...and in 22 or more'),
    ('http1', 10, 'machine: 90%+ over HTTP/1.x while the browsers in this log use HTTP/2 or 3'),
    ('declared', 5, 'the User-Agent names a program (low weight)'),
)
POINTS = dict((key, pts) for key, pts, _ in SIGNALS)
SHAPE_SIGNALS = ('no_assets', 'no_referer', 'breadth', 'breadth_wide')
HIGH_SCORE = 60
REVIEW_SCORE = 40
HEAVY_PAGES = 150          # a client reading this many pages is a candidate even with assets
MERGE_JACCARD = 0.5        # page-list overlap that makes two actors one crawler
MERGE_MIN_URLS = 20
MERGE_MAX_GROUPS = 400


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


def read_logs(paths):
    """Parse the logs into per-client and per-address tallies.

    Returns a dict: clients, by_ip, urls (id -> url), lines, bad, pages, assets,
    first, last.
    """
    clients = {}
    by_ip = {}
    url_ids = {}
    out = {'lines': 0, 'bad': 0, 'pages': 0, 'assets': 0, 'assets_http1': 0,
           'first': None, 'last': None, 'tz': 0}
    for path in paths:
        with open_log(path) as handle:
            for line in handle:
                out['lines'] += 1
                match = LINE_RE.match(line)
                when = parse_time(match.group('ts')) if match else None
                if when is None:
                    out['bad'] += 1
                    continue
                epoch, hour, out['tz'] = when
                ip = match.group('ip')
                ua = match.group('ua') or ''
                url = match.group('url')
                ref = match.group('ref') or ''
                http1 = (match.group('proto') or '').startswith('HTTP/1')
                is_asset = bool(ASSET_RE.search(url.split('?', 1)[0]))
                if out['first'] is None or epoch < out['first']:
                    out['first'] = epoch
                if out['last'] is None or epoch > out['last']:
                    out['last'] = epoch

                tally = by_ip.get(ip)
                if tally is None:
                    tally = by_ip[ip] = {'req': 0, 'pages': 0, 'assets': 0, 'no_ref': 0,
                                         'http1': 0, 'bytes': 0, 'uas': set()}
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
                    out['assets'] += 1
                    out['assets_http1'] += 1 if http1 else 0
                    tally['assets'] += 1
                    client.assets += 1
                    continue
                if match.group('method') != 'GET':
                    continue
                out['pages'] += 1
                tally['pages'] += 1
                client.pages += 1
                if ref in ('', '-'):
                    client.no_ref += 1
                    tally['no_ref'] += 1
                if http1:
                    client.http1 += 1
                uid = url_ids.get(url)
                if uid is None:
                    uid = url_ids[url] = len(url_ids)
                client.hits.append((epoch, hour, uid))
    out['clients'] = clients
    out['by_ip'] = by_ip
    out['urls'] = dict((uid, url) for url, uid in url_ids.items())
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


def build_actor(name, members, env, urls):
    """Fold candidate clients into one actor and score its behaviour.

    env carries what was learned from the whole log: assets_logged, http1_tells
    and catalog (the set of url ids that are catalogue pages, or None when the
    catalogue pattern matched nothing and every page has to count).
    """
    hits = []
    pages = no_ref = http1 = assets = 0
    ips = collections.Counter()
    uas = collections.Counter()
    for client in members:
        hits.extend(client.hits)
        pages += client.pages
        no_ref += client.no_ref
        http1 += client.http1
        assets += client.assets
        ips[client.ip] += client.pages
        uas[client.ua] += client.pages
    all_urls = set(uid for _, _, uid in hits)
    reads = hits if env['catalog'] is None else [h for h in hits if h[2] in env['catalog']]
    per_url = collections.Counter(uid for _, _, uid in reads)
    unique = len(per_url)
    repolled = sum(1 for count in per_url.values() if count >= 3)
    hours = len(set(hour for _, hour, _ in reads))
    steady, median_gap, peak = cadence([epoch for epoch, _, _ in reads])
    catalog = len(reads)
    top_ua = uas.most_common(1)[0][0] if uas else ''

    signals = []
    if env['assets_logged'] and assets == 0:
        signals.append('no_assets')
    if pages and float(no_ref) / pages >= 0.9:
        signals.append('no_referer')
    if unique >= 30:
        signals.append('breadth')
    if unique >= 100:
        signals.append('breadth_wide')
    if unique >= 20 and float(repolled) / unique >= 0.3:
        signals.append('repoll')
    if steady >= 0.5 or peak >= 60:
        signals.append('cadence')
    if hours >= 18:
        signals.append('hours')
    if hours >= 22:
        signals.append('hours_all')
    if env['http1_tells'] and pages and float(http1) / pages >= 0.9:
        signals.append('http1')
    if top_ua and DECLARED_RE.search(top_ua):
        signals.append('declared')

    times = [epoch for epoch, _, _ in hits]
    return {
        'name': name,
        'score': min(100, sum(POINTS[s] for s in signals)),
        'signals': signals,
        'pages': pages,
        'unique_pages': unique,
        'repolled_pages': repolled,
        'catalog_share': round(float(catalog) / pages, 3) if pages else 0.0,
        'no_referer_share': round(float(no_ref) / pages, 3) if pages else 0.0,
        'http1_share': round(float(http1) / pages, 3) if pages else 0.0,
        'assets': assets,
        'active_hours': hours,
        'steady_share': round(steady, 3),
        'median_gap_s': median_gap,
        'peak_per_minute': peak,
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
            if len(small) * 2 < len(large) * MERGE_JACCARD:
                continue                       # sizes alone rule the overlap out
            common = len(small & large)
            if float(common) / (len(small) + len(large) - common) >= MERGE_JACCARD:
                parent[find(a)] = find(b)
    merged = collections.defaultdict(list)
    for name in groups:
        merged[find(name)].append(name)
    return merged


def find_actors(data, min_pages, catalog_re):
    """Candidates -> actors per network (merged by crawl list) -> residue per /16."""
    assets_logged = data['assets'] > 0 and data['assets'] >= 0.02 * max(1, data['lines'])
    catalog = set(uid for uid, url in data['urls'].items() if catalog_re.search(url))
    env = {
        'assets_logged': assets_logged,
        # HTTP/1.x only says something when the real browsers here do not use it.
        # Their asset requests show what they use; behind a proxy that speaks
        # HTTP/1.1 to this server everyone looks the same and the signal is off.
        'http1_tells': not assets_logged or data['assets_http1'] < 0.9 * data['assets'],
        'catalog': catalog or None,
    }
    candidates = [c for c in data['clients'].values()
                  if c.pages and ((assets_logged and c.assets == 0) or not assets_logged
                                  or c.pages >= HEAVY_PAGES)]
    groups = collections.defaultdict(list)
    for client in candidates:
        groups[network_of(client.ip)].append(client)
    urls_of = dict((name, set(uid for c in members for _, _, uid in c.hits))
                   for name, members in groups.items())

    actors = []
    residue = []
    for root, names in merge_by_crawl_list(groups, urls_of).items():
        members = [c for name in names for c in groups[name]]
        if sum(c.pages for c in members) < min_pages:
            residue.extend(members)
            continue
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
        host = resolver.gethostbyaddr(ip)[0].lower().rstrip('.')
    except Exception:
        return False
    if not any(host.endswith(s) for s in suffixes):
        return False
    try:
        return ip in set(info[4][0] for info in resolver.getaddrinfo(host, None))
    except Exception:
        return False


def classify(actors, use_rdns, resolver=socket):
    """Give every actor a verdict: scraper / review / crawler-claimed / verified-crawler / ''."""
    for actor in actors:
        top_ua = actor['top_user_agents'][0][0] if actor['top_user_agents'] else ''
        name, suffixes = claimed_crawler(top_ua)
        actor['claims'] = name or ''
        verdict = ''
        if actor['score'] >= HIGH_SCORE:
            verdict = 'scraper'
        elif actor['score'] >= REVIEW_SCORE:
            verdict = 'review'
        if name and verdict:
            if use_rdns:
                sample = [ip for ip, _ in actor['top_addresses'][:3]]
                if sample and all(rdns_verified(ip, suffixes, resolver) for ip in sample):
                    verdict = 'verified-crawler'
                # a claim that fails verification keeps the behavioural verdict
            else:
                verdict = 'crawler-claimed'
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
    add('  lines %d (unparsed %d)   page requests %d   asset requests %d'
        % (data['lines'], data['bad'], data['pages'], data['assets']))
    add('  from %s to %s   addresses %d   clients (address + User-Agent) %d'
        % (fmt_time(data['first'], tz), fmt_time(data['last'], tz), len(data['by_ip']), len(data['clients'])))
    if not env['assets_logged']:
        add('  NOTE: this log holds (almost) no asset requests, so the "no assets" signal is off')
        add('        and every client with a page request is a candidate. Feed the full log for')
        add('        the sharpest result.')
    if not env['http1_tells']:
        add('  NOTE: the browsers in this log use HTTP/1.x themselves (a proxy in front?), so the')
        add('        "http1" signal is off.')
    if env['catalog'] is None:
        add('  NOTE: --catalog-regex matched no URL in this log; every page counts as catalogue.')
    add('')

    sections = (
        ('scraper', 'LIKELY SCRAPERS (score %d+)' % HIGH_SCORE),
        ('review', 'WORTH A LOOK (score %d-%d)' % (REVIEW_SCORE, HIGH_SCORE - 1)),
        ('crawler-claimed', 'CLAIM TO BE A SEARCH ENGINE - not verified (run with --rdns)'),
        ('verified-crawler', 'VERIFIED SEARCH-ENGINE CRAWLERS (reverse DNS confirmed)'),
    )
    if show_all:
        sections += (('', 'BELOW THE REVIEW SCORE (shown because of --all)'),)
    for verdict, title in sections:
        chosen = [a for a in actors if a['verdict'] == verdict][:top]
        add('== %s: %d' % (title, len([a for a in actors if a['verdict'] == verdict])))
        for actor in chosen:
            add('')
            add('  %s   score %d' % (actor['name'], actor['score']))
            add('    pages %d, different catalogue pages %d (%d fetched 3+ times), catalogue share %d%%'
                % (actor['pages'], actor['unique_pages'], actor['repolled_pages'],
                   round(actor['catalog_share'] * 100)))
            add('    addresses %d, User-Agents %d, active hours %d/24, %s -> %s'
                % (actor['addresses'], actor['user_agents'], actor['active_hours'],
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
                add('    UA (%d): %s' % (count, ua[:110] or '(empty)'))
        add('')

    add('== SIGNALS')
    for key, pts, text in SIGNALS:
        add('  %-13s +%-2d %s' % (key, pts, text))
    add('')
    add('== TOP ADDRESSES BY REQUESTS (the old view; an address is not an identity)')
    add('  %-39s %8s %7s %7s %6s %6s %4s %9s'
        % ('address', 'requests', 'pages', 'assets', 'noRef%', 'http1%', 'UAs', 'MB'))
    ranked = sorted(data['by_ip'].items(), key=lambda kv: -kv[1]['req'])[:top]
    for ip, t in ranked:
        add('  %-39s %8d %7d %7d %6d %6d %4d %9.1f'
            % (ip, t['req'], t['pages'], t['assets'],
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
        'lines': data['lines'], 'unparsed': data['bad'], 'pages': data['pages'],
        'assets': data['assets'], 'assets_logged': env['assets_logged'],
        'http1_tells': env['http1_tells'], 'catalog_matched': env['catalog'] is not None,
        'first': data['first'], 'last': data['last'], 'utc_offset_s': data.get('tz', 0),
        'addresses': len(data['by_ip']), 'clients': len(data['clients']),
        'actors': listed,
    }


def analyse(paths, min_pages=30, catalog=DEFAULT_CATALOG, use_rdns=False, resolver=socket):
    data = read_logs(paths)
    actors, env = find_actors(data, min_pages, re.compile(catalog))
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
    parser.add_argument('--all', action='store_true', help='also list actors below the review score')
    parser.add_argument('--json', default=None, help='also write the findings to this JSON file')
    args = parser.parse_args(argv)
    try:
        re.compile(args.catalog_regex)
    except re.error as exc:
        print('ERROR: bad --catalog-regex: %s' % exc, file=sys.stderr)
        return 2
    try:
        data, actors, env = analyse(args.logs, args.min_pages, args.catalog_regex, args.rdns)
    except (IOError, OSError) as exc:
        print('ERROR: cannot read a log: %s' % exc, file=sys.stderr)
        return 2
    print(render(data, actors, env, args.top, args.all))
    if args.json:
        with io.open(args.json, 'w', encoding='utf-8') as handle:
            handle.write(json.dumps(to_json(data, actors, env), indent=1, sort_keys=True))
            handle.write(u'\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
