#!/usr/bin/env python3
"""Self-test for scripts/accesslog_report.py. Standard library only.

    python3 scripts/accesslog_selftest.py

Builds a synthetic day of traffic in a temp directory - real-looking customers
next to the scrapers the report exists to find - and checks both directions:
the scrapers are found, and the customers are not.
"""

from __future__ import print_function

import gzip
import io
import json
import os
import random
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import accesslog_report as rep                                    # noqa: E402

PASS = FAIL = 0


def ok(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print('PASS  ' + name)
    else:
        FAIL += 1
        print('FAIL  ' + name)


def section(name):
    print('\n-- ' + name)


CHROME = ('Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) '
          'Chrome/126.0.0.0 Mobile Safari/537.36')
SAFARI = ('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 '
          '(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1')
FIREFOX = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0'
GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
DAY0 = 1794700800 - 12600           # 00:00 local (+0330) on the synthetic day, as an epoch
MON = 'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()


def stamp(epoch):
    import datetime
    local = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=epoch + 12600)
    return '%02d/%s/%d:%02d:%02d:%02d +0330' % (local.day, MON[local.month - 1], local.year,
                                                 local.hour, local.minute, local.second)


def line(epoch, ip, url, ua, ref='-', proto='HTTP/2', status=200, size=20000, method='GET'):
    return (epoch, '%s - - [%s] "%s %s %s" %d %d "%s" "%s"'
            % (ip, stamp(epoch), method, url, proto, status, size, ref, ua))


def human_visit(rng, out, ip, ua, start, pages, cached=False, landing_ref='https://www.google.com/'):
    """A person: pages a few irregular seconds-to-minutes apart, each with its assets."""
    t = start
    prev = landing_ref
    for _ in range(pages):
        url = '/product/item-%d' % rng.randint(1, 400)
        out.append(line(t, ip, url, ua, ref=prev))
        if not cached:
            for asset in ('/catalog/view/theme/x/stylesheet.css', '/catalog/view/javascript/app.js',
                          '/image/cache/p-%d.jpg' % rng.randint(1, 900)):
                out.append(line(t + 1, ip, asset, ua, ref='https://shop.example' + url, size=9000))
        out.append(line(t + 2, ip, '/index.php?route=common/cart/info', ua,
                        ref='https://shop.example' + url, size=600))
        out.append(line(t + 3, ip, '/index.php?route=product/product/review&product_id=%d'
                        % rng.randint(1, 400), ua, ref='https://shop.example' + url, size=900))
        prev = 'https://shop.example' + url
        t += rng.randint(8, 240)


def build_day(rng):
    out = []
    # 1. Ordinary customers, spread over many networks, daytime, with assets and referers.
    for i in range(260):
        ip = '31.%d.%d.%d' % (rng.randint(2, 60), rng.randint(0, 255), rng.randint(2, 250))
        human_visit(rng, out, ip, rng.choice((CHROME, SAFARI, FIREFOX)),
                    DAY0 + rng.randint(8 * 3600, 23 * 3600), rng.randint(1, 9))
    # 2. Returning customers on ONE carrier /24 with everything cached: pages only, but
    #    they click through (referers), a few pages each, daytime.
    for i in range(45):
        human_visit(rng, out, '37.129.10.%d' % rng.randint(2, 250), rng.choice((CHROME, SAFARI)),
                    DAY0 + rng.randint(9 * 3600, 22 * 3600), rng.randint(1, 5), cached=True)
    # 3. A campaign: many people on one carrier /24 open the same two links from a
    #    messenger, no referer, assets cached. 120 bare page views, two URLs.
    for i in range(120):
        out.append(line(DAY0 + rng.randint(18 * 3600, 21 * 3600), '37.130.44.%d' % rng.randint(2, 250),
                        rng.choice(('/product/campaign-a', '/product/campaign-b')),
                        rng.choice((CHROME, SAFARI))))
    # 4. SLOW scraper on a rotating carrier /24, browser User-Agent, one page every ~40s
    #    around the clock, 300 products re-polled. No address sends more than a few.
    t = DAY0 + 60
    n = 0
    while t < DAY0 + 86000:
        ip = '5.200.7.%d' % (2 + (n // 4) % 240)             # a new address every 4 requests
        out.append(line(t, ip, '/product/sku-%d' % (n % 300), CHROME, proto='HTTP/1.1'))
        t += 40 + rng.randint(-3, 3)
        n += 1
    # 4b. ...and customers behind the very same carrier addresses (CGNAT).
    for i in range(30):
        human_visit(rng, out, '5.200.7.%d' % rng.randint(2, 241), SAFARI,
                    DAY0 + rng.randint(9 * 3600, 22 * 3600), rng.randint(2, 6))
    # 5. THIN scraper spread over a carrier /16: 60 different /24s, a handful of pages
    #    from each, irregular timing, 110 products fetched three times.
    t = DAY0 + 300
    for n in range(330):
        ip = '89.40.%d.%d' % (rng.randint(0, 59), rng.randint(2, 250))
        out.append(line(t, ip, '/product/thin-%d' % (n % 110), FIREFOX, proto='HTTP/1.1'))
        t += rng.randint(20, 480)
    # 6. One crawl list fetched from two unrelated networks (a scraper with two exits).
    for net, off in (('102.33.1.9', 0), ('185.90.2.77', 20)):
        t = DAY0 + 3600 + off
        for n in range(160):
            out.append(line(t, net, '/product/shared-%d' % (n % 80), CHROME, proto='HTTP/1.1'))
            t += 30
    # 7. Googlebot: real crawl behaviour, claims a search engine.
    t = DAY0 + 100
    for n in range(200):
        out.append(line(t, '66.249.66.%d' % (1 + n % 3), '/product/item-%d' % (n % 180), GOOGLEBOT,
                        proto='HTTP/1.1'))
        t += 400
    # 9. One address with a browser User-Agent and faked Referers walks 400 products once,
    #    irregularly, inside three hours: no re-polling, no steady pace, no long hours.
    t = DAY0 + 50000
    for n in range(400):
        out.append(line(t, '46.245.89.90', '/product/walk-%d' % n, CHROME,
                        ref='https://shop.example/category/x', proto='HTTP/1.1'))
        t += rng.randint(3, 50)
    # 10. Our own tool on our own server: pages only, round the clock, and customers who
    #     type in the live search (one XHR per keystroke, a second apart).
    for n in range(600):
        out.append(line(DAY0 + 30 + n * 140, '198.51.100.7', '/product/own-%d' % (n % 40),
                        'OwnTool/1.0', proto='HTTP/1.1'))
    for i in range(12):
        t = DAY0 + rng.randint(10 * 3600, 22 * 3600)
        for k in range(25):
            out.append(line(t + k, '37.129.10.%d' % (10 + i),
                            '/index.php?route=product/search&search=ps%d' % k, SAFARI,
                            ref='https://shop.example/'))
    # 8. A tiny bare client: 5 pages. Below any threshold.
    for n in range(5):
        out.append(line(DAY0 + 40000 + n * 7, '203.0.113.50', '/product/x-%d' % n, 'curl/8.5',
                        proto='HTTP/1.1'))
    out.sort(key=lambda pair: pair[0])
    return [text for _, text in out]


def actor_of(actors, ip):
    """The actor holding an address as a candidate, or None."""
    for actor in actors:
        if any(c.ip == ip for c in actor['members']):
            return actor
    return None


tmp = tempfile.mkdtemp(prefix='gv-accesslog-selftest-')
try:
    rng = random.Random(20261116)
    lines = build_day(rng)
    log = os.path.join(tmp, 'access.log')
    with io.open(log, 'w', encoding='utf-8') as fh:
        fh.write(u'\n'.join(lines) + u'\n')
        fh.write(u'this line is not a log line\n')
        fh.write(u'1.2.3.4 - - [99/Foo/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"\n')

    # -----------------------------------------------------------------------
    section('Parsing')
    ok('a combined-format time parses with its zone',
       rep.parse_time('15/Nov/2026:15:57:05 +0330') == (1794745625, 15, 12600))
    ok('a malformed time is refused, not guessed', rep.parse_time('99/Foo/2026:00:00:00 +0000') is None
       and rep.parse_time('garbage') is None)
    ok('IPv4 groups by /24 and by /16', rep.network_of('5.134.175.101') == '5.134.175.0/24'
       and rep.network_of('5.134.175.101', wide=True) == '5.134.0.0/16')
    ok('IPv6 groups by /48 and by /32', rep.network_of('2a01:5ec0:1:2::9') == '2a01:5ec0:1::/48'
       and rep.network_of('2a01:5ec0:1:2::9', wide=True) == '2a01:5ec0::/32')
    ok('an unparsable address is its own group', rep.network_of('not-an-ip') == 'not-an-ip')

    data, actors, env = rep.analyse([log])
    assets_logged = env['assets_logged']
    ok('every good line is read and the two bad ones are counted',
       data['lines'] == len(lines) + 2 and data['bad'] == 2)
    ok('assets are present, so the no-assets signal is on', assets_logged is True)
    ok('a request with a query string is still classified by its path',
       rep.ASSET_RE.search('/a/b.css') and not rep.ASSET_RE.search('/index.php'))

    # -----------------------------------------------------------------------
    section('Cadence')
    ok('a fixed sleep is steady', rep.cadence([i * 3 for i in range(60)])[0] > 0.9)
    ok('human spacing is not', rep.cadence(sorted(rng.randint(0, 40000) for _ in range(60)))[0] < 0.5)
    ok('too few requests give no cadence verdict', rep.cadence([0, 3, 6, 9])[0] == 0.0)
    ok('a burst is reported as a per-minute peak', rep.cadence([1000 + i // 5 for i in range(400)])[2] >= 60)

    # -----------------------------------------------------------------------
    section('Scrapers on changing addresses, with a browser User-Agent')
    slow = actor_of(actors, '5.200.7.10')
    ok('the slow rotating scraper is one actor, found as a scraper (score %s)'
       % (slow and slow['score']), slow is not None and slow['verdict'] == 'scraper')
    ok('...although no address of it sent more than a handful of pages',
       slow is not None and slow['addresses'] >= 200 and max(n for _, n in slow['top_addresses']) <= 12)
    ok('...and its User-Agent is a plain browser: the finding does not rest on it',
       slow is not None and 'declared' not in slow['signals'])
    ok('...on behaviour: no assets, breadth, scheduled re-polling, steady pace, HTTP/1.x',
       slow is not None and set(['no_assets', 'breadth_wide', 'repoll', 'cadence', 'http1'])
       <= set(slow['signals']))
    ok('...and not on hours: no single address of it is active for long', 'hours' not in slow['signals'])
    ok('customers sharing those carrier addresses are not part of the actor',
       slow is not None and all(c.ua == CHROME for c in slow['members'])
       and slow['pages'] == sum(1 for l in lines if '/product/sku-' in l))

    thin = [a for a in actors if a['name'].startswith('89.40.0.0/16')]
    ok('the thin scraper spread over 60 networks surfaces per /16 (score %s)'
       % (thin and thin[0]['score']), len(thin) == 1 and thin[0]['verdict'] == 'scraper'
       and '(wide)' in thin[0]['name'])
    ok('...without any steady pace to lean on', len(thin) == 1 and 'cadence' not in thin[0]['signals'])

    shared = actor_of(actors, '102.33.1.9')
    ok('one crawl list from two unrelated networks is merged into one actor',
       shared is not None and shared is actor_of(actors, '185.90.2.77')
       and shared['verdict'] == 'scraper' and shared['addresses'] == 2)

    # -----------------------------------------------------------------------
    section('Customers are left alone')
    flagged = [a for a in actors if a['verdict'] in ('scraper', 'review')]
    flagged_ips = set(c.ip for a in flagged for c in a['members'])
    ok('the three scrapers, the walker, the unlisted own tool and the unverified "Googlebot" are flagged (%d)'
       % len(flagged), len(flagged) == 6)
    walker = actor_of(actors, '46.245.89.90')
    ok('one address walking 400 products once is a scraper on depth alone (score %s)'
       % (walker and walker['score']),
       walker is not None and walker['verdict'] == 'scraper' and 'deep' in walker['signals']
       and 'repoll' not in walker['signals'] and 'no_referer' not in walker['signals'])
    ok('a crowd reading many pages between them is not deep',
       slow is not None and 'deep' not in thin[0]['signals'])
    ok('live-search and review XHR are not catalogue pages',
       not __import__('re').search(rep.DEFAULT_CATALOG, '/index.php?route=product/search&search=ps')
       and not __import__('re').search(rep.DEFAULT_CATALOG, '/index.php?route=product/product/review&product_id=3')
       and __import__('re').search(rep.DEFAULT_CATALOG, '/index.php?route=product/product&product_id=3')
       and __import__('re').search(rep.DEFAULT_CATALOG, '/index.php?path=1&route=product/category'))

    section('--ignore: your own servers and tools')
    own = actor_of(actors, '198.51.100.7')
    ok('an own tool that is not listed looks like a scraper (that is why --ignore exists)',
       own is not None and own['verdict'] == 'scraper')
    d_ign, a_ign, _ = rep.analyse([log], ignore=rep.parse_networks(['198.51.100.0/24, 203.0.113.50']))
    ok('--ignore drops it from actors and from the address table',
       actor_of(a_ign, '198.51.100.7') is None and '198.51.100.7' not in d_ign['by_ip']
       and d_ign['ignored'] == 605)
    ok('...and nothing else changes', len([a for a in a_ign if a['verdict'] in ('scraper', 'review')]) == 5)
    ok('a bad --ignore value is refused', rep.main([log, '--ignore', 'not-a-network']) == 2)
    ok('no ordinary customer network is flagged', not any(ip.startswith('31.') for ip in flagged_ips))
    ok('returning customers with a full cache (pages only) are not flagged',
       not any(ip.startswith('37.129.10.') for ip in flagged_ips))
    campaign = actor_of(actors, [l for l in lines if 'campaign-a' in l][0].split(' ')[0])
    ok('a campaign crowd (120 bare views of two links) is seen but scores low (%s)'
       % (campaign and campaign['score']),
       campaign is not None and campaign['score'] < rep.REVIEW_SCORE and campaign['verdict'] == '')
    ok('a client below --min-pages is never scored', actor_of(actors, '203.0.113.50') is None)
    ok('the User-Agent signal alone can never list an actor',
       rep.POINTS['declared'] < rep.REVIEW_SCORE and rep.POINTS['declared'] <= 5)
    ok('the shape signals a crowd of customers can show never reach the review score together',
       sum(rep.POINTS[s] for s in rep.SHAPE_SIGNALS) < rep.REVIEW_SCORE)
    cached = actor_of(actors, [l for l in lines if l.startswith('37.129.10.')][0].split(' ')[0])
    ok('the XHR a real page fires a second later is not read as a machine interval',
       cached is not None and 'cadence' not in cached['signals'] and 'repoll' not in cached['signals'])

    # -----------------------------------------------------------------------
    section('Search-engine claims')
    google = actor_of(actors, '66.249.66.1')
    ok('a Googlebot User-Agent buys nothing: unverified, the actor is judged on its behaviour',
       google is not None and google['verdict'] in ('scraper', 'review') and google['claims'] == 'google')
    ok('...and the report says the claim is not verified',
       'claims to be google: NOT verified' in rep.render(data, actors, env, 50, False))

    class Dns(object):
        def __init__(self, good):
            self.good = good

        def gethostbyaddr(self, ip):
            if not self.good:
                return ('host-%s.example.net' % ip.replace('.', '-'), [], [ip])
            return ('crawl-%s.googlebot.com' % ip.replace('.', '-'), [], [ip])

        def getaddrinfo(self, host, port):
            ip = host.split('.')[0].split('-', 1)[1].replace('-', '.')
            return [(2, 1, 6, '', (ip, 0))]

    _, verified, _ = rep.analyse([log], use_rdns=True, resolver=Dns(True))
    ok('with --rdns a confirmed claim becomes a verified crawler',
       actor_of(verified, '66.249.66.1')['verdict'] == 'verified-crawler')
    _, forged, _ = rep.analyse([log], use_rdns=True, resolver=Dns(False))
    ok('...and a claim that fails reverse DNS is judged on its behaviour like anyone else',
       actor_of(forged, '66.249.66.1')['verdict'] in ('scraper', 'review'))

    class DeadDns(object):
        def gethostbyaddr(self, ip):
            raise OSError('resolver down')

        def getaddrinfo(self, host, port):
            raise OSError('resolver down')

    ok('a dead resolver verifies nothing and does not crash',
       rep.rdns_verified('66.249.66.1', ('.googlebot.com',), DeadDns()) is False)

    # -----------------------------------------------------------------------
    section('A log without asset requests (pre-filtered)')
    pages_only = os.path.join(tmp, 'pages.log.gz')
    with gzip.open(pages_only, 'wt', encoding='utf-8') as fh:
        for text in lines:
            if not rep.ASSET_RE.search(text.split('"')[1].split(' ')[1]):
                fh.write(text + '\n')
    data2, actors2, env2 = rep.analyse([pages_only])
    assets_logged2 = env2['assets_logged']
    ok('a .gz log is read', data2['lines'] > 1000)
    ok('the no-assets signal switches itself off', assets_logged2 is False
       and not any('no_assets' in a['signals'] for a in actors2))
    slow2 = actor_of(actors2, '5.200.7.10')
    ok('the rotating scraper is still found without it', slow2 is not None and slow2['verdict'] == 'scraper')
    ok('...and ordinary customer networks still are not',
       not any(c.ip.startswith('31.') for a in actors2 if a['verdict'] in ('scraper', 'review')
               for c in a['members']))

    # -----------------------------------------------------------------------
    section('Only what was served counts')

    def run(lines_, **kw):
        path = os.path.join(tmp, 'case-%d.log' % len(os.listdir(tmp)))
        with io.open(path, 'w', encoding='utf-8') as fh2:
            fh2.write(u'\n'.join(text for _, text in sorted(lines_)) + u'\n')
        return rep.analyse([path], **kw)

    def flagged_of(actors_):
        return [a for a in actors_ if a['verdict'] in ('scraper', 'review')]

    base_humans = []
    for i in range(120):                                  # so the log has assets and HTTP/2 browsers
        human_visit(rng, base_humans, '31.9.%d.%d' % (i % 200, 2 + i % 250), CHROME, DAY0 + 30000 + i * 97, 3)

    scan = list(base_humans)
    for n in range(300):
        scan.append(line(DAY0 + 1000 + n * 6, '203.0.113.9', '/product/guess-%d' % n, CHROME, proto='HTTP/1.1', status=404))
    _, a_scan, _ = run(scan)
    ok('a scanner collecting 300 x 404 is not a catalogue reader', actor_of(a_scan, '203.0.113.9') is None)

    redir = list(base_humans)
    for n in range(60):
        redir.append(line(DAY0 + 1000 + n * 20, '203.0.113.10', '/product/old-%d' % n, CHROME, proto='HTTP/1.1', status=301))
        redir.append(line(DAY0 + 1001 + n * 20, '203.0.113.10', '/product/new-%d' % n, CHROME, proto='HTTP/1.1'))
    d_r, a_r, _ = run(redir)
    ok('a redirect is not a second page', actor_of(a_r, '203.0.113.10')['pages'] == 60)

    css = list(base_humans)
    for n in range(300):
        css.append(line(DAY0 + 1000 + n * 6, '203.0.113.11', '/product/c-%d' % n, CHROME, proto='HTTP/1.1'))
    css.append(line(DAY0 + 999, '203.0.113.11', '/favicon.ico', CHROME, proto='HTTP/1.1', size=300))
    css.append(line(DAY0 + 998, '203.0.113.11', '/does-not-exist.css', CHROME, proto='HTTP/1.1', status=404))
    _, a_css, _ = run(css)
    one = actor_of(a_css, '203.0.113.11')
    ok('one stray asset request no longer hides a crawler', one is not None and one['verdict'] == 'scraper'
       and 'no_assets' in one['signals'])

    bust = list(base_humans)
    for n in range(400):
        bust.append(line(DAY0 + 1000 + n * 5, '203.0.113.12', '/product/b-%d?utm=%d&x=%d' % (n % 10, n, n * 7), CHROME,
                         proto='HTTP/1.1'))
    d_b, a_b, _ = run(bust)
    ok('cache-busting query strings do not make new pages (10, not 400)',
       actor_of(a_b, '203.0.113.12')['unique_pages'] == 10)
    ok('content-selecting parameters are kept, the rest dropped',
       rep.page_key('/index.php?route=product/product&product_id=7&utm=1&x=2') == '/index.php?route=product/product&product_id=7'
       and rep.page_key('/product/a?fbclid=zzz') == '/product/a' and rep.page_key('/product/a') == '/product/a')

    # -----------------------------------------------------------------------
    section('Crowds of real customers')

    def crowd(net, users, per_user, products, start, span, ua_pool, days=1):
        out_ = []
        for d in range(days):
            for u in range(users):
                ip = '%s.%d' % (net, 2 + u % 250)
                t = DAY0 + d * 86400 + start + rng.randint(0, span)
                for _ in range(per_user):
                    # popularity is skewed: a few hot products, a long tail
                    prod = int(products * (rng.random() ** 3))
                    out_.append(line(t, ip, '/product/hot-%d' % prod, rng.choice(ua_pool)))
                    t += rng.randint(5, 180)
        return out_

    busy = base_humans + crowd('100.64.7', 250, 6, 60, 6 * 3600, 17 * 3600, (CHROME, SAFARI))
    _, a_busy, _ = run(busy)
    hit = actor_of(a_busy, '100.64.7.10')
    ok('a busy carrier /24 (250 cached customers, hot products, all day) is not flagged (score %s)'
       % (hit and hit['score']), hit is not None and hit['verdict'] == '')
    ok('...many people arriving close together are not a "steady interval"', 'cadence' not in hit['signals'])
    ok('...and returning to a few hot products is not polling', 'repoll' not in hit['signals'])

    week = base_humans + crowd('100.64.8', 60, 5, 80, 6 * 3600, 17 * 3600, (CHROME, SAFARI), days=7)
    d_w, a_w, env_w = run(week)
    hit = actor_of(a_w, '100.64.8.10')
    ok('the same crowd over a 7-day log is still not flagged (score %s)' % (hit and hit['score']),
       hit is not None and hit['verdict'] == '')
    ok('a multi-day log switches the hour signals off and says so',
       env_w['single_day'] is False and 'hours' not in hit['signals']
       and 'one day at a time with --date' in rep.render(d_w, a_w, env_w, 5, False))
    d_1, a_1, env_1 = run(week, day='2026-11-15')
    ok('--date keeps one day of it', env_1['single_day'] is True and d_1['other_days'] > 0 and d_1['pages'] < d_w['pages'])

    campus = list(base_humans)
    for u in range(600):                                  # one address, one User-Agent, real browsing
        human_visit(rng, campus, '198.18.0.1', CHROME, DAY0 + rng.randint(7 * 3600, 23 * 3600), 6)
    _, a_c, _ = run(campus)
    ok('600 people behind one address with one User-Agent, loading assets, are not a candidate',
       actor_of(a_c, '198.18.0.1') is None)

    spread = []
    for net in range(6):                                  # no assets logged; six unrelated networks, same hot products
        for u in range(120):
            ip = '172.16.%d.%d' % (20 + net, 2 + u)
            t = DAY0 + rng.randint(6 * 3600, 23 * 3600)
            prev = 'https://www.google.com/'
            for _ in range(8):
                url = '/product/hot-%d' % int(40 * (rng.random() ** 2))
                spread.append(line(t, ip, url, rng.choice((CHROME, SAFARI)), ref=prev))
                prev = 'https://shop.example' + url
                t += rng.randint(5, 200)
    _, a_s, env_s = run(spread)
    ok('with no assets in the log, customers who click through (Referer) are not candidates',
       env_s['assets_logged'] is False and flagged_of(a_s) == [])

    # -----------------------------------------------------------------------
    section('Parsing')
    ok('a vhost:port prefix is accepted',
       rep.LINE_RE.match('shop.example:443 1.2.3.4 - - [15/Nov/2026:10:00:00 +0330] "GET /product/a HTTP/2" 200 5 "-" "x"')
       .group('ip') == '1.2.3.4')
    ok('a basic-auth user with a space, a lower-case method and an escaped quote in the User-Agent parse',
       rep.LINE_RE.match('1.2.3.4 - john doe [15/Nov/2026:10:00:00 +0330] "get /a HTTP/1.1" 200 5 "-" "a \\"b\\" c"')
       .group('ua') == 'a \\"b\\" c')
    ok('an IPv4-mapped IPv6 client is the IPv4 address', rep.canon_ip('::ffff:198.51.100.7') == '198.51.100.7'
       and rep.canon_ip('2001:DB8::1') == '2001:db8::1' and rep.canon_ip('1.2.3.4') == '1.2.3.4')
    mapped = list(base_humans)
    for n in range(200):
        mapped.append(line(DAY0 + 500 + n * 30, '::ffff:198.51.100.7', '/product/m-%d' % (n % 50), 'Monitor/1', proto='HTTP/1.1'))
    d_m, a_m, _ = run(mapped, ignore=rep.parse_networks(['198.51.100.0/24']))
    ok('--ignore with an IPv4 network also covers its IPv4-mapped spelling', d_m['ignored'] == 200)

    junk = os.path.join(tmp, 'junk.log')
    with io.open(junk, 'w', encoding='utf-8') as fh2:
        fh2.write(u''.join(u'2026-11-15T10:00:00Z 1.2.3.4 GET /product/%d 200\n' % i for i in range(500)))
    real_stdout, sys.stdout = sys.stdout, io.StringIO()
    try:
        junk_code = rep.main([junk])
        junk_out = sys.stdout.getvalue()
    finally:
        sys.stdout = real_stdout
    ok('a log in another format is reported as such and exits non-zero, not "0 findings, all fine"',
       junk_code == 1 and 'could not be parsed' in junk_out)

    cut = os.path.join(tmp, 'cut.log.gz')
    with gzip.open(cut, 'wt', encoding='utf-8') as fh2:
        fh2.write(u'\n'.join(lines) + u'\n')
    with open(cut, 'rb') as fh2:
        blob = fh2.read()
    with open(cut, 'wb') as fh2:
        fh2.write(blob[:len(blob) // 2])
    d_cut, a_cut, env_cut = rep.analyse([cut])
    ok('a .gz cut short yields what could be read, a warning and no traceback',
       d_cut['lines'] > 100 and len(d_cut['truncated']) == 1
       and 'cut short' in rep.render(d_cut, a_cut, env_cut, 5, False))

    esc = list(base_humans)
    for n in range(120):
        esc.append(line(DAY0 + 1000 + n * 6, '203.0.113.13', '/product/e-%d' % n, u'Evil\x1b]0;owned\x07\u202eBot', proto='HTTP/1.1'))
    d_e, a_e, env_e = run(esc)
    text_e = rep.render(d_e, a_e, env_e, 20, False)
    ok('control and direction-override characters from a User-Agent never reach the terminal',
       u'\x1b' not in text_e and u'\x07' not in text_e and u'\u202e' not in text_e and 'Evil?' in text_e)

    class SlowDns(object):
        def gethostbyaddr(self, ip):
            time.sleep(30)

        def getaddrinfo(self, host, port):
            time.sleep(30)

    import time
    t_start = time.time()
    rep.classify(list(actors), True, SlowDns(), timeout=0.2)
    ok('--rdns against a resolver that never answers gives up (%.1f s), verifying nothing'
       % (time.time() - t_start), time.time() - t_start < 5
       and not any(a['verdict'] == 'verified-crawler' for a in actors))
    rep.classify(actors, False)

    section('Output')
    text = rep.render(data, actors, env, 20, False)
    ok('the report names the sections and the old top-address table',
       'LIKELY SCRAPERS' in text and 'TOP ADDRESSES BY REQUESTS' in text and 'not a block list' in text
       and 'CLAIM TO BE' not in text)
    ok('the address table shows the catalogue share', ' cat% ' in text)
    ok('times are printed in the log zone', "UTC+03:30" in text)
    ok('--all adds the low scorers', 'BELOW THE REVIEW SCORE' in rep.render(data, actors, env, 20, True))
    out_json = os.path.join(tmp, 'r.json')
    real_stdout, sys.stdout = sys.stdout, io.StringIO()         # main() prints the report
    try:
        code = rep.main([log, '--json', out_json, '--top', '3'])
        printed = sys.stdout.getvalue()
    finally:
        sys.stdout = real_stdout
    with io.open(out_json, encoding='utf-8') as fh:
        doc = json.load(fh)
    ok('the CLI exits 0 and writes valid JSON with every actor',
       code == 0 and len(doc['actors']) == len(actors) and 'members' not in doc['actors'][0]
       and 'LIKELY SCRAPERS' in printed)
    ok('a missing file is an error, not a traceback', rep.main([os.path.join(tmp, 'nope.log')]) == 2)
    ok('a bad --catalog-regex is refused', rep.main([log, '--catalog-regex', '(']) == 2)
    ok('a higher --min-pages hides the smaller actors',
       len(rep.analyse([log], min_pages=5000)[1]) < len(actors))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print('\nPASS %d  FAIL %d' % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
