#!/usr/bin/env python3
"""Generate a synthetic multi-day guard log for benchmarks and parity tests.

    python3 scripts/gen-log-fixture.py --out /tmp/logs --days 9 --rows-per-day 335000 [--seed 1]

Rows follow guard/guard.php gv_log_row() (the same keys and types) plus the outcome lines of capture_outcomes. The
mix (about 92 % allowed, a few percent challenged / blocked / limited, some crawler claims, some rule and list hits) is
only a plausible shape, not a model of any real site. Day files are named after the host's local date, like the guard
does when PHP and the host share a time zone. Standard library only.
"""
import argparse
import datetime
import json
import os
import random
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--days', type=int, default=9)
    ap.add_argument('--rows-per-day', type=int, default=335000)
    ap.add_argument('--seed', type=int, default=1)
    ap.add_argument('--today-fraction', type=float, default=0.6, help='share of today already written')
    ap.add_argument('--gzip-old', action='store_true', help='compress every day except today')
    args = ap.parse_args()
    rnd = random.Random(args.seed)
    os.makedirs(args.out, exist_ok=True)
    now = time.time()
    today = datetime.date.fromtimestamp(now)
    ips = ['%d.%d.%d.%d' % (rnd.randint(1, 223), rnd.randint(0, 255), rnd.randint(0, 255), rnd.randint(1, 254)) for _ in range(40000)]
    devs = ['%012x' % rnd.getrandbits(48) for _ in range(20000)]
    uas = ['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/%d.0 Safari/537.36' % (90 + i % 40) for i in range(300)]
    paths = ['/index.php', '/'] + ['/product/%d' % i for i in range(3000)] + ['/category/%d' % i for i in range(200)]
    ccs = ['IR', 'DE', 'US', 'NL', 'TR', 'AE', 'GB', 'FR']
    bots = ['googlebot', 'bingbot', 'adsbot-google']
    rules = ['R%d' % i for i in range(1, 12)]
    for off in range(args.days - 1, -1, -1):
        day = today - datetime.timedelta(days=off)
        start = datetime.datetime.combine(day, datetime.time()).timestamp()
        end = start + 86400
        if off == 0:
            end = start + (now - start) * 1.0
        n = args.rows_per_day if off else int(args.rows_per_day * args.today_fraction)
        if off == 0:
            end = min(now, start + 86400)
        stamps = sorted(rnd.uniform(start, end) for _ in range(n))
        path = os.path.join(args.out, 'guard-%s.jsonl' % day.strftime('%Y%m%d'))
        with open(path, 'w') as fh:
            for i, ts in enumerate(stamps):
                x = rnd.random()
                ip = rnd.choice(ips)
                dev = rnd.choice(devs) if rnd.random() < 0.7 else ''
                rid = '%012x' % rnd.getrandbits(48)
                act, sh, cap, rs, tok, bot, botv = 'allow', 0, '', [], 'v' if dev else '', '', ''
                if x < 0.03:
                    act, tok = 'challenge', ''
                elif x < 0.05:
                    act, rs = '403', ['RULE:' + rnd.choice(rules)]
                elif x < 0.06:
                    act = '429'
                elif x < 0.065:
                    act, tok = 'token_issued', ''
                elif x < 0.07:
                    bot, botv = rnd.choice(bots), rnd.choice(['', 'ok', 'bad'])
                if rnd.random() < 0.02:
                    rs = rs + ['IPL_BLOCK:L%d' % rnd.randint(1, 3)]
                if act == 'challenge' and rnd.random() < 0.1:
                    cap = 'show'
                row = {'v': 5, 'rid': rid, 'ts': round(ts, 3), 'ip': ip, 'ua': rnd.choice(uas), 'uah': '%012x' % rnd.getrandbits(48),
                       'm': 'GET', 'p': rnd.choice(paths), 'q': '', 'aj': 0, 'nav': 1, 'gate': 0, 'tok': tok, 'dev': dev, 'sf': '',
                       'al': 1, 'hc': 4, 'sc': rnd.randint(0, 30), 'esc': rnd.randint(0, 30), 'rs': rs, 'cd': 0, 'cdh': 0, 'cdd': 0,
                       'ciu': 0, 'ci': 0, 'rd': 0, 'hp': 0, 'bot': bot, 'ref': '', 'botv': botv, 'rep': 0, 'ml': -1, 'clf': -1,
                       'hold': 0, 'ovr': '', 'act': act, 'sh': sh, 'ms': round(rnd.random() * 3, 2),
                       'cc': rnd.choice(ccs), 'asn': rnd.randint(1000, 9000)}
                if cap:
                    row['cap'] = cap
                fh.write(json.dumps(row, separators=(',', ':')) + '\n')
                if act == 'allow' and rnd.random() < 0.9:
                    fh.write(json.dumps({'o': 1, 'rid': rid, 'ts': round(ts + 0.2, 3), 'st': rnd.choice([200, 200, 200, 301, 404, 500]), 'by': 5000}, separators=(',', ':')) + '\n')
        if args.gzip_old and off:
            os.system('gzip -6 -f "%s"' % path)
    print('wrote %s' % args.out)


if __name__ == '__main__':
    main()
