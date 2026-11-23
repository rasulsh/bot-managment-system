#!/usr/bin/env python3
"""Operator control: the five-second fix when someone reports being blocked.

  python3 analyzer/ctl.py show  <device_id|ip>
  python3 analyzer/ctl.py allow <device_id> [--ttl 3600]
  python3 analyzer/ctl.py deny  <device_id|ip> [--ttl 86400]
  python3 analyzer/ctl.py challenge <device_id|ip> [--ttl 86400]    the check page until the client holds a token
  python3 analyzer/ctl.py captcha   <device_id|ip> [--ttl 86400]    the image CAPTCHA until the client solved one
  python3 analyzer/ctl.py list  [--kind allow|deny|challenge|captcha]
  python3 analyzer/ctl.py clear <device_id|ip>

`show` first. It prints every gv: verdict touching an identity - reputation,
anomaly level, classifier level, bot verification, honeypot history and any
override - which is usually enough to explain what happened without reading a
single log line.

An allow override is not gated by any enforce toggle: it can only ever make the
guard less strict, so it takes effect on the customer's next request. A deny
override is an enforcement action and respects enforce.block like everything
else, so setting one in monitor mode records the intent without blocking.

A challenge / captcha override challenges that ONE client until it holds a token (a CAPTCHA-level one for captcha) and, unlike a
deny, does not wait for any enforce switch: it works while everything else is in monitor mode. Precedence: allow > deny >
captcha > challenge; a verified crawler keeps its pass; an enforced IP allow list is checked first.

Every override carries a TTL. An override without an expiry is a config change
in disguise, and it will be forgotten - so TTLs above 30 days are refused.
"""

from __future__ import print_function

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import config as config_mod
from analyzer import promote as promote_mod
from analyzer import redis_io

MAX_TTL = 30 * 86400
DEFAULT_TTL = 86400


def _fmt_ttl(seconds):
    if seconds is None:
        return 'no expiry'
    if seconds >= 86400:
        return '%.1f days' % (seconds / 86400.0)
    if seconds >= 3600:
        return '%.1f hours' % (seconds / 3600.0)
    return '%d seconds' % seconds


def cmd_show(client, args):
    verdicts = redis_io.identity_verdicts(client, args.identity)
    print('Identity: %s' % args.identity)
    print('  reputation       %s' % _or_none(verdicts['reputation']))
    print('  anomaly level    %s' % _or_none(verdicts['ml']))
    print('  classifier level %s' % _or_none(verdicts['clf']))
    print('  bot verified ok  %s' % ('yes' if verdicts['botok'] else 'no'))
    print('  bot refuted      %s' % ('yes' if verdicts['botbad'] else 'no'))
    print('  honeypot history %s' % ('yes' if verdicts['honeypot'] else 'no'))
    allow_ttl = verdicts['overrides'].get('allow')
    deny_ttl = verdicts['overrides'].get('deny')
    print('  allow override   %s' % ('set, expires in ' + _fmt_ttl(allow_ttl)
                                     if allow_ttl is not None else 'none'))
    print('  deny override    %s' % ('set, expires in ' + _fmt_ttl(deny_ttl)
                                     if deny_ttl is not None else 'none'))
    for kind in ('challenge', 'captcha'):
        ttl = verdicts['overrides'].get(kind)
        print('  %-16s %s' % (kind + ' override', 'set, expires in ' + _fmt_ttl(ttl) if ttl is not None else 'none'))
    if verdicts['overrides'].get('allow') is None and (
            verdicts['botbad'] or verdicts['honeypot']
            or (verdicts['reputation'] or 0) > 0):
        print('')
        print('  This identity carries restrictive signals. If it is a real customer,')
        print('  `ctl.py allow %s --ttl 3600` unblocks them immediately.' % args.identity)
    return 0


def _or_none(value):
    return 'none' if value is None else str(value)


def cmd_allow(client, args):
    if not redis_io.set_override(client, 'allow', args.identity, args.ttl):
        print('ERROR: could not write the allow override', file=sys.stderr)
        return 1
    print('Allow override set for %s, expires in %s.' % (args.identity, _fmt_ttl(args.ttl)))
    print('It takes effect on the next request: a permissive override is not gated')
    print('by any enforce toggle.')
    return 0


def cmd_deny(client, args):
    if not redis_io.set_override(client, 'deny', args.identity, args.ttl):
        print('ERROR: could not write the deny override', file=sys.stderr)
        return 1
    print('Deny override set for %s, expires in %s.' % (args.identity, _fmt_ttl(args.ttl)))
    print('It is an enforcement action, so it only blocks when enforce.block is on.')
    return 0


def _cmd_chal(kind, what):
    def run(client, args):
        if not redis_io.set_override(client, kind, args.identity, args.ttl):
            print('ERROR: could not write the %s override' % kind, file=sys.stderr)
            return 1
        print('%s override set for %s, expires in %s.' % (kind.capitalize(), args.identity, _fmt_ttl(args.ttl)))
        print('The client is shown %s until it holds a valid token' % what
              + (' (a CAPTCHA-level one)' if kind == 'captcha' else '') + '; it needs no enforce switch.')
        return 0
    return run


cmd_challenge = _cmd_chal('challenge', 'the check page')
cmd_captcha = _cmd_chal('captcha', 'the image CAPTCHA')


def cmd_list(client, args):
    rows = redis_io.list_overrides(client, args.kind)
    if not rows:
        print('No override is currently set.')
        return 0
    print('%-9s %-40s %s' % ('kind', 'identity', 'expires in'))
    for kind, identity, ttl in sorted(rows):
        print('%-9s %-40s %s' % (kind, identity[:40], _fmt_ttl(ttl)))
    print('')
    print('%d override(s) set.' % len(rows))
    return 0


def cmd_promote_model(client, args):
    """Move a trained candidate over the live model. Needs no Redis."""
    cfg = args.cfg
    live, candidate = promote_mod.paths_for(args.kind, cfg)
    verdict = promote_mod.check(args.kind, cfg)
    if not verdict['ok']:
        print('Refusing to promote the %s model: %s' % (args.kind, verdict['reason']),
              file=sys.stderr)
        return 1

    info = verdict['inspection']
    if args.kind == 'clf' and info.get('metrics'):
        from analyzer import classifier as clf_mod
        print('Candidate metrics on held-out data:')
        print(clf_mod.format_metrics(info['metrics']))

    result = promote_mod.promote(args.kind, cfg)
    if not result['ok']:
        print('ERROR: %s' % result['reason'], file=sys.stderr)
        return 1
    print('Promoted the %s candidate to %s.' % (args.kind, live))
    print('The next nightly run will write verdicts from it.')
    return 0


def cmd_clear(client, args):
    removed = redis_io.clear_override(client, args.identity)
    if removed:
        print('Cleared %d override(s) for %s.' % (removed, args.identity))
    else:
        print('No override was set for %s.' % args.identity)
    return 0


def parse_args(argv):
    parser = argparse.ArgumentParser(description='Operator control for the guard verdicts.')
    parser.add_argument('--config', default=None, help='analyzer config override')
    sub = parser.add_subparsers(dest='command')

    for name, help_text in (('show', 'print every verdict for an identity'),
                            ('allow', 'set a permissive override'),
                            ('deny', 'set a restrictive override'),
                            ('challenge', 'show the check page until the client holds a token'),
                            ('captcha', 'show the image CAPTCHA until the client solved one'),
                            ('clear', 'remove every override for an identity')):
        node = sub.add_parser(name, help=help_text)
        node.add_argument('identity')
        if name in ('allow', 'deny', 'challenge', 'captcha'):
            node.add_argument('--ttl', type=int, default=DEFAULT_TTL,
                              help='seconds until the override expires (default %d)'
                                   % DEFAULT_TTL)

    node = sub.add_parser('list', help='list the overrides currently set')
    node.add_argument('--kind', choices=('allow', 'deny', 'challenge', 'captcha'), default=None)

    node = sub.add_parser('promote-model',
                          help='move a trained candidate model over the live one')
    node.add_argument('kind', choices=promote_mod.KINDS)

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return None
    return args


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args is None:
        return 2

    ttl = getattr(args, 'ttl', None)
    if ttl is not None:
        if ttl < 1:
            print('ERROR: --ttl must be at least 1 second', file=sys.stderr)
            return 2
        if ttl > MAX_TTL:
            print('ERROR: --ttl above %d seconds (30 days) is refused. An override that'
                  % MAX_TTL, file=sys.stderr)
            print('       never expires is a config change in disguise, and it will be',
                  file=sys.stderr)
            print('       forgotten. Change guard/config.php instead.', file=sys.stderr)
            return 2

    try:
        cfg = config_mod.load(args.config)
    except Exception as exc:
        print('ERROR: bad configuration: %s' % exc, file=sys.stderr)
        return 2
    args.cfg = cfg

    handlers = {'show': cmd_show, 'allow': cmd_allow, 'deny': cmd_deny, 'challenge': cmd_challenge, 'captcha': cmd_captcha,
                'list': cmd_list, 'clear': cmd_clear,
                'promote-model': cmd_promote_model}

    # Promotion moves a file on disk; it has nothing to do with Redis and must
    # work during an outage, which is exactly when someone is retraining.
    if args.command == 'promote-model':
        return handlers[args.command](None, args)

    client = redis_io.connect(cfg, write=args.command in ('allow', 'deny', 'challenge', 'captcha', 'clear'))
    if client is None:
        print('ERROR: Redis is unreachable, so no verdict can be read or written.',
              file=sys.stderr)
        return 1

    return handlers[args.command](client, args)


if __name__ == '__main__':
    sys.exit(main())
