#!/usr/bin/env python3
"""Write the dashboard snapshot.

The panel's dashboard reads only analyzer/snapshot.json, so its cost is one
small JSON read rather than a log scan - a busy site's dashboard opens as fast
as a quiet one's. This runs from cron after the nightly job and every fifteen
minutes.

generated_at is included on purpose: the panel shows the snapshot's age, and a
stale snapshot is itself a useful alert that the analyzer has stopped.

READ-ONLY with respect to the guard: this reads logs and Redis and writes one
file of its own. It never touches a verdict.
"""

from __future__ import print_function

import argparse
import datetime
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import classifier as clf_mod
from analyzer import config as config_mod
from analyzer import logs as logs_mod
from analyzer import model as model_mod
from analyzer import outcomes as outcomes_mod
from analyzer import redis_io

DECISION_ACTS = ('allow', 'challenge', '403', '429')
SCORE_BUCKETS = ((0, 0), (1, 14), (15, 29), (30, 44), (45, 59), (60, 79), (80, 10 ** 9))


def bucket_label(low, high):
    if low == high:
        return str(low)
    if high >= 10 ** 9:
        return '%d+' % low
    return '%d-%d' % (low, high)


def bucketize(values):
    out = {}
    for low, high in SCORE_BUCKETS:
        out[bucket_label(low, high)] = sum(1 for v in values if low <= v <= high)
    return out


def build(rows, cfg, guard_cfg=None):
    """Fold decision rows into the snapshot payload. Pure."""
    rows = list(rows)
    traffic = {'requests': len(rows), 'devices': 0, 'addresses': 0, 'degraded': 0}
    devices = set()
    addresses = set()
    decisions = {}
    reasons = {}
    status = {}
    sc_values = []
    esc_values = []
    timeline = {}
    challenge_served = 0
    token_issued = 0
    has = {'rep': 0, 'ml': 0, 'clf': 0}
    holdout = {'requests': 0, 'challenge': 0, 'honeypot': 0}
    enforced = {'requests': 0, 'challenge': 0, 'honeypot': 0}
    outcome_known = 0

    for row in rows:
        act = str(row.get('act') or '')
        shadow = int(row.get('sh') or 0) == 1
        held = int(row.get('hold') or 0) == 1

        dev = str(row.get('dev') or '')
        if dev:
            devices.add(dev)
        ip = str(row.get('ip') or '')
        if ip:
            addresses.add(ip)
        if int(row.get('rd') or 0) == 1:
            traffic['degraded'] += 1

        decisions[act] = decisions.get(act, 0) + 1
        if act == 'challenge' and not shadow:
            challenge_served += 1
        if act == 'token_issued':
            token_issued += 1

        for reason in (row.get('rs') or []):
            if isinstance(reason, str):
                reasons[reason] = reasons.get(reason, 0) + 1

        try:
            sc = int(row.get('sc') or 0)
            esc = int(row.get('esc', sc) if row.get('esc') is not None else sc)
        except (TypeError, ValueError):
            sc, esc = 0, 0
        sc_values.append(sc)
        esc_values.append(esc)

        if row.get('rep') is not None and int(row.get('rep') or 0) != 0:
            has['rep'] += 1
        if row.get('ml') is not None and int(row.get('ml', -1)) >= 0:
            has['ml'] += 1
        if row.get('clf') is not None and int(row.get('clf', -1)) >= 0:
            has['clf'] += 1

        side = holdout if held else enforced
        side['requests'] += 1
        if act == 'challenge':
            side['challenge'] += 1
        if int(row.get('hp') or 0) == 1:
            side['honeypot'] += 1

        bucket_name = outcomes_mod.status_class(row.get('_out'))
        if bucket_name is not None:
            outcome_known += 1
            status[bucket_name] = status.get(bucket_name, 0) + 1

        # Hourly buckets for the decisions-over-time chart.
        try:
            hour = datetime.datetime.utcfromtimestamp(
                float(row.get('ts') or 0)).strftime('%H:00')
        except Exception:
            hour = '??'
        slot = timeline.setdefault(hour, {})
        if act in DECISION_ACTS:
            slot[act] = slot.get(act, 0) + 1

    traffic['devices'] = len(devices)
    traffic['addresses'] = len(addresses)
    total = max(1, len(rows))

    ordered_hours = sorted(timeline)
    timeline_list = [{'label': hour, 'values': timeline[hour]} for hour in ordered_hours]

    payload = {
        'generated_at': round(time.time(), 3),
        'window_days': int(cfg.get('window_days', 7)),
        'traffic': traffic,
        'decisions': dict(sorted(decisions.items(), key=lambda kv: -kv[1])),
        'reasons': dict(sorted(reasons.items(), key=lambda kv: -kv[1])[:8]),
        'status': status,
        'sc_hist': bucketize(sc_values),
        'esc_hist': bucketize(esc_values),
        'timeline': timeline_list,
        'funnel': {
            'challenge_served': challenge_served,
            'token_issued': token_issued,
            'success_rate': (100.0 * token_issued / challenge_served)
                            if challenge_served else None,
            'target': float(cfg.get('challenge_success_target', 0.95)) * 100.0,
        },
        'coverage': {
            'rep': 100.0 * has['rep'] / total,
            'ml': 100.0 * has['ml'] / total,
            'clf': 100.0 * has['clf'] / total,
            'outcome': 100.0 * outcome_known / total,
        },
        'holdout': {
            'enabled': holdout['requests'] > 0,
            'holdout_requests': holdout['requests'],
            'enforced_requests': enforced['requests'],
            'holdout_challenge_rate': (100.0 * holdout['challenge'] / holdout['requests'])
                                      if holdout['requests'] else 0.0,
            'enforced_challenge_rate': (100.0 * enforced['challenge'] / enforced['requests'])
                                       if enforced['requests'] else 0.0,
            'holdout_honeypot_rate': (100.0 * holdout['honeypot'] / holdout['requests'])
                                     if holdout['requests'] else 0.0,
            'enforced_honeypot_rate': (100.0 * enforced['honeypot'] / enforced['requests'])
                                      if enforced['requests'] else 0.0,
        },
        'models': model_metadata(cfg),
        'last_runs': read_last_runs(cfg),
    }
    if guard_cfg:
        payload['guard'] = guard_cfg
    return payload


def describe_model(module, path):
    """Metadata for one bundle, shaped for the panel's models page."""
    info = module.inspect(path)
    out = {
        'exists': bool(info.get('exists')),
        'loadable': bool(info.get('loadable')),
        'stale': bool(info.get('stale')),
        'error': info.get('error') or '',
        'feature_count': len(info.get('feature_order') or []),
        'metrics': info.get('metrics') if isinstance(info.get('metrics'), dict) else None,
        'mtime': None,
    }
    try:
        if os.path.isfile(path):
            out['mtime'] = round(os.path.getmtime(path), 3)
    except Exception:
        pass
    return out


def model_metadata(cfg):
    return {
        'ml': {
            'live': describe_model(model_mod, cfg['model_path']),
            'candidate': describe_model(model_mod, cfg['model_candidate_path']),
        },
        'clf': {
            'live': describe_model(clf_mod, cfg['clf_path']),
            'candidate': describe_model(clf_mod, cfg['clf_candidate_path']),
        },
    }


def marker_path(cfg, name):
    return os.path.join(os.path.dirname(os.path.abspath(cfg['model_path'])),
                        '.lastrun-' + name)


def touch_run(cfg, name):
    """Record that a cron mode completed, so the panel can show freshness."""
    try:
        with open(marker_path(cfg, name), 'w') as handle:
            handle.write(str(round(time.time(), 3)))
    except Exception:
        pass


def read_last_runs(cfg):
    out = {}
    for name in ('run_verify', 'run_nightly', 'snapshot', 'worker'):
        value = 0.0
        try:
            path = marker_path(cfg, name)
            if os.path.isfile(path):
                with open(path, 'r') as handle:
                    value = float((handle.read() or '0').strip() or 0)
        except Exception:
            value = 0.0
        out[name] = value
    return out


def write(payload, path):
    """Atomic write, so the panel never reads a half-written snapshot."""
    tmp = path + '.tmp'
    try:
        with open(tmp, 'w') as handle:
            json.dump(payload, handle, ensure_ascii=False)
        os.replace(tmp, path)
        return True
    except Exception as exc:
        print('ERROR: could not write the snapshot: %s' % exc, file=sys.stderr)
        try:
            if os.path.isfile(tmp):
                os.unlink(tmp)
        except Exception:
            pass
        return False


def parse_args(argv):
    parser = argparse.ArgumentParser(description='Write the dashboard snapshot.')
    parser.add_argument('--config', default=None)
    parser.add_argument('--log-dir', default=None)
    parser.add_argument('--days', type=int, default=None)
    parser.add_argument('--out', default=None)
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
    days = args.days or 1
    if not os.path.isdir(cfg['log_dir']):
        print('ERROR: log directory not readable: %s' % cfg['log_dir'], file=sys.stderr)
        return 2

    rows = list(logs_mod.read_lines(cfg['log_dir'], days))
    payload = build(rows, cfg)
    payload['redis'] = redis_io.connect(cfg) is not None

    out_path = args.out or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'snapshot.json')
    if not write(payload, out_path):
        return 2
    touch_run(cfg, 'snapshot')
    print('Snapshot written to %s (%d rows, %d decisions).'
          % (out_path, len(rows), sum(payload['decisions'].values())))
    return 0


if __name__ == '__main__':
    sys.exit(main())
