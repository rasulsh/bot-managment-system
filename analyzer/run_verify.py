#!/usr/bin/env python3
"""Fast loop: forward-confirm reverse DNS for IPs that claimed to be a bot.

Cron cadence around every 10 minutes. Reads the Phase 1 logs, finds addresses
whose User-Agent claimed a known bot, and writes gv:botok / gv:botbad. Exits
non-zero only on its own hard failure (bad config, unreadable log dir) - never
because Redis was down.
"""

from __future__ import print_function

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import config as config_mod
from analyzer import botverify
from analyzer import logs as logs_mod
from analyzer import redis_io

# DNS is a shared resource and these lookups are not urgent.
DNS_SLEEP_S = 0.05
MAX_LOOKUPS_PER_RUN = 200


def collect_bot_ips(rows, known_bots):
    """Map ip -> claimed bot name for every row whose bot field is set."""
    claims = {}
    known = set(str(b).lower() for b in known_bots or [])
    for row in rows:
        bot = str(row.get('bot') or '').lower()
        ip = str(row.get('ip') or '')
        if not bot or not ip:
            continue
        if known and bot not in known:
            continue
        claims.setdefault(ip, bot)
    return claims


def parse_args(argv):
    parser = argparse.ArgumentParser(description='Forward-confirm known-bot claims.')
    parser.add_argument('--config', default=None, help='path to a .json or .py config override')
    parser.add_argument('--log-dir', default=None, help='override the log directory')
    parser.add_argument('--max-lookups', type=int, default=MAX_LOOKUPS_PER_RUN,
                        help='cap DNS lookups for this run')
    parser.add_argument('--dry-run', action='store_true',
                        help='resolve and report without writing verdicts')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        cfg = config_mod.load(args.config)
    except Exception as exc:
        print('ERROR: bad configuration: %s' % exc, file=sys.stderr)
        return 2
    if args.log_dir:
        cfg['log_dir'] = args.log_dir
    if not os.path.isdir(cfg['log_dir']):
        print('ERROR: log directory not readable: %s' % cfg['log_dir'], file=sys.stderr)
        return 2

    rows = logs_mod.read_lines(cfg['log_dir'], cfg['window_days'])
    claims = collect_bot_ips(rows, cfg['known_bots'])

    client = redis_io.connect(cfg)
    verified = 0
    flagged = 0
    skipped = 0

    for ip in sorted(claims):
        if (verified + flagged) >= int(args.max_lookups):
            skipped += 1
            continue
        # A fresh verdict is still valid; do not re-resolve it.
        if client is not None and redis_io.get_botv(client, ip) is not None:
            skipped += 1
            continue
        verdict = botverify.verify_ip(ip, claims[ip], cfg['bot_suffixes'])
        if verdict == 'ok':
            verified += 1
        else:
            flagged += 1
        if not args.dry_run:
            redis_io.set_botv(client, ip, verdict, cfg['botv_ttl'])
        time.sleep(DNS_SLEEP_S)

    if client is None:
        print('Redis unavailable: verdicts were computed but not stored.')
    print('Bot verification: verified %d, flagged %d, skipped %d, candidates %d.'
          % (verified, flagged, skipped, len(claims)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
