#!/usr/bin/env python3
"""Fast loop: forward-confirm reverse DNS for IPs that claimed to be a bot.

Cron cadence around every 10 minutes. Reads the crawler claims of the Phase 1 logs
(only the bytes appended since the last run, from the store of analyzer/ingest.py;
--full-read parses the logs), finds addresses whose User-Agent claimed a known bot,
and writes gv:botok / gv:botbad. Exits
non-zero only on its own hard failure (bad config, unreadable log dir) - never
because Redis was down.
"""

from __future__ import print_function

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if __name__ == '__main__':
    # No bytecode, and files a manual run creates are not group-writable: a __pycache__ made under cron's umask 002 was 0775.
    sys.dont_write_bytecode = True
    os.umask(0o022)

from analyzer import config as config_mod
from analyzer import jobreport
from analyzer import lowprio as lowprio_mod
from analyzer import fsmode
from analyzer import botverify
from analyzer import ingest as ingest_mod
from analyzer import logs as logs_mod
from analyzer import redis_io
from analyzer import snapshot as snapshot_mod

# DNS is a shared resource and these lookups are not urgent.
DNS_SLEEP_S = 0.05
MAX_LOOKUPS_PER_RUN = 200
MAX_SECONDS_PER_RUN = 240          # the job runs every ten minutes; never overlap the next one


def claim_counts(rows, known_bots):
    """Map ip -> number of requests that claimed a known bot from it."""
    counts = {}
    known = set(str(b).lower() for b in known_bots or [])
    for row in rows:
        bot = str(row.get('bot') or '').lower()
        ip = str(row.get('ip') or '')
        if not bot or not ip or (known and bot not in known):
            continue
        counts[ip] = counts.get(ip, 0) + 1
    return counts


def collect_claims(rows, known_bots):
    """(ip -> claimed bot name, ip -> claim count) in ONE pass over `rows`.

    `rows` is a generator when it comes from logs.read_lines; calling collect_bot_ips() and claim_counts() on it one after the
    other left the second with nothing to read (counts always {}), and the volume ordering of lookup_order() was dead.
    """
    claims, counts = {}, {}
    known = set(str(b).lower() for b in known_bots or [])
    for row in rows:
        bot = str(row.get('bot') or '').lower()
        ip = str(row.get('ip') or '')
        if not bot or not ip or (known and bot not in known):
            continue
        claims.setdefault(ip, bot)
        counts[ip] = counts.get(ip, 0) + 1
    return claims, counts


def read_claims(cfg, now=None, full_read=False):
    """(claims, counts) over the last window_days of logs: from the ingest store (only new bytes are parsed), or by reading the
    log files when the store is unavailable."""
    if not full_read:
        try:
            ingest_mod.update(cfg, now)
            import datetime
            with ingest_mod.reader(cfg) as store:
                return store.claims(cfg['window_days'], logs_mod.day_of(now), cfg['known_bots'])
        except Exception as exc:                 # fail open: the logs themselves are always readable
            print('WARNING: the incremental store is unavailable (%s); reading the logs directly.' % exc, file=sys.stderr)
            jobreport.warn('incremental log store unavailable (%s): bot verification read the log files directly' % exc)
    return collect_claims(logs_mod.read_lines(cfg['log_dir'], cfg['window_days'], fields=('bot', 'ip')), cfg['known_bots'])


def lookup_order(claims, counts):
    """Busiest addresses first.

    The run is capped, so the order decides who gets a verdict. In address order
    a flood of fake claims from thousands of addresses filled every run with the
    same first few hundred, and a real crawler that sorted after them was never
    reached. A real crawler makes many requests from few addresses; a rotating
    impersonator makes few from each. Sorting by volume reaches the crawler
    first whatever the impersonators do.
    """
    return sorted(claims, key=lambda ip: (-int(counts.get(ip, 0)), ip))


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
    parser.add_argument('--full-read', action='store_true', help='read the log files directly (no incremental store)')
    parser.add_argument('--recheck', action='store_true',
                        help='re-resolve addresses that already carry a fresh verdict')
    return parser.parse_args(argv)


def main(argv=None, resolver=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if __name__ == '__main__':
        lowprio_mod.apply()               # idle CPU priority for a run started by hand (the cron wrapper also sets I/O)
    try:
        cfg = config_mod.load(args.config)
    except Exception as exc:
        print('ERROR: bad configuration: %s' % exc, file=sys.stderr)
        return 2
    # Files an earlier run (cron umask 002) left group- or world-writable in the analyzer directory (the model, the markers, the status
    # files) are corrected now; new files are created 0644 by analyzer/fsmode.py.
    fsmode.tidy_for(cfg)
    if args.log_dir:
        cfg['log_dir'] = args.log_dir
    if not os.path.isdir(cfg['log_dir']):
        print('ERROR: log directory not readable: %s' % cfg['log_dir'], file=sys.stderr)
        return 2
    if resolver is None:
        resolver = botverify.DefaultResolver(canary=cfg.get('dns_canary') or botverify.DEFAULT_CANARY)

    # A bot with no suffix list can never be verified. That is a configuration
    # gap, not an impersonator: say so once and never produce 'bad' for it.
    for name in cfg['known_bots']:
        if not (cfg['bot_suffixes'] or {}).get(str(name).lower()):
            print('WARN: known bot %r has no entry in bot_suffixes; it cannot be verified '
                  'and will be left unjudged.' % (name,), file=sys.stderr)

    claims, counts = read_claims(cfg, full_read=args.full_read)
    started = time.time()

    client = redis_io.connect(cfg, write=not args.dry_run)
    verified = 0
    flagged = 0
    unknown = 0
    skipped = 0

    for ip in lookup_order(claims, counts):
        if ((verified + flagged + unknown) >= int(args.max_lookups)
                or (time.time() - started) > MAX_SECONDS_PER_RUN):
            skipped += 1
            continue
        # A fresh verdict is still valid; do not re-resolve it.
        if (not args.recheck and client is not None
                and redis_io.get_botv(client, ip) is not None):
            skipped += 1
            continue
        verdict = botverify.verify_ip(ip, claims[ip], cfg['bot_suffixes'], resolver)
        if verdict == 'ok':
            verified += 1
            if not args.dry_run:
                redis_io.set_botv(client, ip, 'ok', cfg['botv_ttl'])
        elif verdict == 'bad':
            flagged += 1
            if not args.dry_run:
                redis_io.set_botv(client, ip, 'bad', cfg['botbad_ttl'])
        else:
            # Could not verify: write NOTHING and delete NOTHING. An existing
            # verdict stays until its TTL and the address is retried next run.
            unknown += 1
        time.sleep(DNS_SLEEP_S)

    if client is None:
        reason = redis_io.unavailable_reason(cfg)
        print(reason + '.')
        jobreport.warn(reason)
    if not claims:
        jobreport.warn('no known-bot claims in the last %s day(s) of logs: nothing to verify' % cfg['window_days'])
    print('Bot verification: verified %d, flagged %d, unknown %d, skipped %d, candidates %d.'
          % (verified, flagged, unknown, skipped, len(claims)))
    if unknown:
        print('%d address(es) could not be verified (resolver trouble or no suffix list); '
              'no verdict was written for them and they will be retried.' % unknown)
    if not args.dry_run:
        snapshot_mod.record_stats(cfg, 'run_verify', {
            'verified': verified, 'flagged': flagged, 'unknown': unknown,
            'skipped': skipped, 'candidates': len(claims)})
    jobreport.result({'verified': verified, 'flagged': flagged, 'unknown': unknown, 'skipped': skipped, 'candidates': len(claims)})
    snapshot_mod.touch_run(cfg, 'run_verify')
    return 0


if __name__ == '__main__':
    sys.exit(main())
