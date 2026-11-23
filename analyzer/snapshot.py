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
from analyzer import fsmode
from analyzer import jobreport
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


RULE_PREFIXES = ('RULE:', 'SH_RULE:')


def rule_ids(row):
    """Access-rule ids a decision row carries (RULE:<id> or SH_RULE:<id>). Pure."""
    out = []
    for reason in (row.get('rs') or []):
        if not isinstance(reason, str):
            continue
        for prefix in RULE_PREFIXES:
            if reason.startswith(prefix) and 0 < len(reason) - len(prefix) <= 16:
                out.append(reason[len(prefix):])
    return out


LIST_PREFIXES = (('IPL_ALLOW:', 'allow'), ('SH_IPL_ALLOW:', 'allow'), ('IPL_BLOCK:', 'block'), ('SH_IPL_BLOCK:', 'block'))


def list_ids(row):
    """IP-list hits a decision row carries: 'allow:<id>' / 'block:<id>' (IPL_* and SH_IPL_* reasons). Pure."""
    out = []
    for reason in (row.get('rs') or []):
        if not isinstance(reason, str):
            continue
        for prefix, kind in LIST_PREFIXES:
            if reason.startswith(prefix) and 0 < len(reason) - len(prefix) <= 24:
                out.append('%s:%s' % (kind, reason[len(prefix):]))
    return out


def count_rule_hits(rows, since=0.0):
    """{id: [hits with ts >= since, last ts]} over decision rows. Pure.

    Access-rule ids are keyed as they are; IP-list hits are keyed 'ipl:<allow|block>:<id>'
    (collect_rule_hits splits them out into the snapshot's 'iplists').
    """
    out = {}
    for row in rows:
        ids = rule_ids(row) + ['ipl:' + x for x in list_ids(row)]
        if not ids:
            continue
        try:
            ts = float(row.get('ts') or 0)
        except (TypeError, ValueError):
            continue
        for rid in ids:
            slot = out.setdefault(rid, [0, 0.0])
            if ts >= since:
                slot[0] += 1
            slot[1] = max(slot[1], ts)
    return out


def collect_rule_hits(log_dir, now, cache_path=None, days=7):
    """Per-rule hit counts for the panel's Rules page: {id: {h24, d7, last}}.

    Hits come from the logs, never from Redis counters in the request path. The
    last two days are always re-read (the 24 h window reaches back into
    yesterday); older finished days are counted once and kept in a small cache
    file, so the 15-minute snapshot does not re-read a week of logs every time.
    """
    today = datetime.date.fromtimestamp(now)
    cache = {}
    if cache_path:
        try:
            with open(cache_path, 'r') as handle:
                loaded = json.load(handle)
            if isinstance(loaded, dict) and isinstance(loaded.get('days'), dict):
                cache = loaded['days']
        except Exception:
            cache = {}
    totals = {}
    fresh = {}
    for offset in range(int(days)):
        day = today - datetime.timedelta(days=offset)
        key = day.strftime('%Y%m%d')
        recent = {}
        if offset >= 2 and isinstance(cache.get(key), dict):
            counts = cache[key]
        else:
            rows = list(logs_mod.read_lines(log_dir, 1, today=day, join_outcomes=False))
            counts = count_rule_hits(rows)
            if offset < 2:
                recent = count_rule_hits(rows, since=now - 86400)
        if offset >= 2:
            fresh[key] = counts
        for rid, pair in counts.items():
            slot = totals.setdefault(rid, {'h24': 0, 'd7': 0, 'last': 0.0})
            slot['d7'] += int(pair[0])
            slot['last'] = max(slot['last'], float(pair[1]))
        for rid, pair in recent.items():
            totals.setdefault(rid, {'h24': 0, 'd7': 0, 'last': 0.0})['h24'] += int(pair[0])
    if cache_path:
        try:
            tmp = cache_path + '.tmp'
            with fsmode.open_text(tmp) as handle:
                json.dump({'days': fresh}, handle)
            os.replace(tmp, cache_path)
        except Exception:
            pass
    for slot in totals.values():
        slot['last'] = round(slot['last'], 3)
    return totals


def split_list_hits(totals):
    """(rule hits, list hits) out of collect_rule_hits' one table. List keys: 'allow:<id>' / 'block:<id>'. Pure."""
    rules, lists = {}, {}
    for key, slot in totals.items():
        if key.startswith('ipl:'):
            lists[key[4:]] = slot
        else:
            rules[key] = slot
    return rules, lists


ALLOW_ACTS = ('allow', 'allow_bot', 'allow_preview', 'allow_override', 'exempt')
SERVED_ACTS = ('403', '429', 'challenge')


def kpi_counts(rows):
    """The dashboard's headline numbers over one window of decision rows. Pure."""
    out = {'requests': 0, 'allowed': 0, 'blocked': 0, 'limited': 0, 'challenged': 0, 'token_issued': 0,
           'rule_hits': 0, 'honeypot': 0, 'degraded': 0,
           'captcha_shown': 0, 'captcha_solved': 0, 'captcha_failed': 0, 'captcha_expired': 0}
    solve_times = []
    for row in rows:
        act = str(row.get('act') or '')
        shadow = int(row.get('sh') or 0) == 1
        out['requests'] += 1
        if act in SERVED_ACTS and not shadow:
            out[{'403': 'blocked', '429': 'limited', 'challenge': 'challenged'}[act]] += 1
        elif act in ALLOW_ACTS or (act in SERVED_ACTS and shadow):
            out['allowed'] += 1
        if logs_mod.token_was_issued(row):
            out['token_issued'] += 1
        if rule_ids(row):
            out['rule_hits'] += 1
        if int(row.get('hp') or 0) == 1:
            out['honeypot'] += 1
        if int(row.get('rd') or 0) == 1:
            out['degraded'] += 1
        # The image CAPTCHA (log key cap): show = a page served, ok = solved (ct = seconds it took), wrong / fail / inv =
        # a failed attempt, exp = answered after the time limit.
        cap = str(row.get('cap') or '')
        if cap == 'show':
            out['captcha_shown'] += 1
        elif cap == 'ok':
            out['captcha_solved'] += 1
            try:
                solve_times.append(float(row.get('ct')))
            except (TypeError, ValueError):
                pass
        elif cap in ('wrong', 'fail', 'inv'):
            out['captcha_failed'] += 1
        elif cap == 'exp':
            out['captcha_expired'] += 1
    solve_times.sort()
    if solve_times:
        mid = len(solve_times) // 2
        out['captcha_median_s'] = solve_times[mid] if len(solve_times) % 2 else (solve_times[mid - 1] + solve_times[mid]) / 2.0
    else:
        out['captcha_median_s'] = None
    # Solve rate: solved / shown. A rate of 100 % with very short times looks like a solving service.
    out['captcha_solve_rate'] = (100.0 * out['captcha_solved'] / out['captcha_shown']) if out['captcha_shown'] else None
    out['challenge_success'] = (100.0 * out['token_issued'] / out['challenged']) if out['challenged'] else None
    return out


def _top(counter, n=8):
    return [[key, count] for key, count in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]]


def top_lists(rows):
    """Top lists over one window: rules, reasons, and who/what is being acted on. Pure."""
    rules, reasons, ips, devs, uas, paths, countries = {}, {}, {}, {}, {}, {}, {}

    def bump(table, key):
        if key and (key in table or len(table) < 5000):
            table[key] = table.get(key, 0) + 1
    for row in rows:
        for rid in rule_ids(row):
            bump(rules, rid)
        for reason in (row.get('rs') or []):
            if isinstance(reason, str) and not reason.startswith(RULE_PREFIXES):
                bump(reasons, reason)
        if str(row.get('cc') or ''):
            bump(countries, str(row['cc']))
        if str(row.get('act') or '') in SERVED_ACTS and int(row.get('sh') or 0) != 1:
            bump(ips, str(row.get('ip') or ''))
            bump(devs, str(row.get('dev') or ''))
            bump(uas, str(row.get('ua') or ''))
            bump(paths, str(row.get('p') or ''))
    return {'rules': _top(rules), 'reasons': _top(reasons), 'ips': _top(ips), 'devices': _top(devs),
            'uas': _top(uas), 'paths': _top(paths), 'countries': _top(countries)}


def local_tz():
    """The analyzer host's time zone: daily log names, logrotate and 'today' follow it."""
    try:
        offset = datetime.datetime.now().astimezone().utcoffset()
        return {'name': time.tzname[0], 'offset': int(offset.total_seconds()) if offset is not None else 0}
    except Exception:
        return {'name': '', 'offset': 0}


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
    handshake_rejected = 0
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
        if logs_mod.token_was_issued(row):
            token_issued += 1
        if logs_mod.handshake_rejected(row):
            handshake_rejected += 1

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
            # See report.py: the utc* constructor is deprecated as of 3.12, and
            # the module-level UTC alias is 3.11+ while our floor is 3.8.
            hour = datetime.datetime.fromtimestamp(
                float(row.get('ts') or 0), datetime.timezone.utc).strftime('%H:00')
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
            'handshake_rejected': handshake_rejected,
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
        'bot_verify': read_stats(cfg, 'run_verify'),
        # How far the supervised classifier is from enough labels (written by every nightly run): positives of clf_min_positive, by source.
        'clf_labels': read_stats(cfg, 'run_nightly').get('clf_labels'),
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
        with fsmode.open_text(marker_path(cfg, name)) as handle:
            handle.write(str(round(time.time(), 3)))
    except Exception:
        pass


def stats_path(cfg, name):
    return os.path.join(os.path.dirname(os.path.abspath(cfg['model_path'])),
                        '.laststats-' + name)


def record_stats(cfg, name, stats):
    """Persist a small JSON summary of the last run, for the panel and report."""
    try:
        payload = dict(stats)
        payload['at'] = round(time.time(), 3)
        tmp = stats_path(cfg, name) + '.tmp'
        with fsmode.open_text(tmp) as handle:
            json.dump(payload, handle)
        os.replace(tmp, stats_path(cfg, name))
    except Exception:
        pass


def read_stats(cfg, name):
    try:
        with open(stats_path(cfg, name), 'r') as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


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
        with fsmode.open_text(tmp) as handle:
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
    # Files an earlier run (cron umask 002) left group- or world-writable in the analyzer directory (the model, the markers, the status
    # files) are corrected now; new files are created 0644 by analyzer/fsmode.py.
    fsmode.tidy_for(cfg)
    if args.log_dir:
        cfg['log_dir'] = args.log_dir
    days = args.days or 1
    if not os.path.isdir(cfg['log_dir']):
        print('ERROR: log directory not readable: %s' % cfg['log_dir'], file=sys.stderr)
        return 2

    # "Last 24 h" is a rolling window of timestamps (not "today's file", which would
    # change meaning at local midnight and differ from the panel's time zone): read
    # enough daily files for the window and the one before it, then cut by ts.
    now = time.time()
    window = days * 86400
    all_rows = list(logs_mod.read_lines(cfg['log_dir'], days * 2 + 1))

    def ts_of(row):
        try:
            return float(row.get('ts') or 0)
        except (TypeError, ValueError):
            return 0.0
    rows = [r for r in all_rows if ts_of(r) >= now - window]
    prev_rows = [r for r in all_rows if now - 2 * window <= ts_of(r) < now - window]
    payload = build(rows, cfg)
    payload['kpi'] = {'cur': kpi_counts(rows), 'prev': kpi_counts(prev_rows), 'window_h': days * 24}
    payload['top'] = top_lists(rows)
    payload['tz'] = local_tz()
    payload['redis'] = redis_io.connect(cfg) is not None
    if not payload['redis']:
        jobreport.warn('Redis unreachable: the snapshot has no live Redis status')
    if not all_rows:
        jobreport.warn('no log rows in the last %d day(s): the dashboard shows nothing (is the guard logging?)' % (days * 2 + 1))
    try:
        hit_totals = collect_rule_hits(
            cfg['log_dir'], time.time(),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '.rule-hits.json'))
        payload['rules'], payload['iplists'] = split_list_hits(hit_totals)
    except Exception as exc:                  # hit counts are a convenience, never fatal
        print('WARNING: rule hit counts skipped: %s' % exc, file=sys.stderr)

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
