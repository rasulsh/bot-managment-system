#!/usr/bin/env python3
"""Period report: the KPIs from all three phases in one command.

READ-ONLY. Reads JSONL, prints text, and optionally writes one self-contained
HTML file to a path the operator names. It never touches Redis and never writes
to the log directory.

The HTML is a report, not a dashboard: inline CSS, no JavaScript, no external
assets, no fonts, no charting library, no live data connection of any kind. Bar
charts are table rows with proportional-width divs. Open it in a browser or
mail it to yourself.

Usage:
  python3 analyzer/report.py
  python3 analyzer/report.py --days 14 --html /tmp/guard-report.html
"""

from __future__ import print_function

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import bridge
from analyzer import config as config_mod
from analyzer import logs as logs_mod
from analyzer import outcomes as outcomes_mod
from analyzer import snapshot as snapshot_mod

STATUS_ORDER = ('2xx', '3xx', '404', '4xx', '5xx', 'other')

SCORE_BUCKETS = ((0, 0), (1, 14), (15, 29), (30, 44), (45, 59), (60, 79), (80, 10 ** 9))


def _pct(part, whole):
    return (100.0 * part / whole) if whole else 0.0


def _percentile(values, fraction):
    if not values:
        return 0.0
    ordered = sorted(values)
    index = int(round(fraction * (len(ordered) - 1)))
    return float(ordered[max(0, min(len(ordered) - 1, index))])


def _bucket_label(low, high):
    if low == high:
        return str(low)
    if high >= 10 ** 9:
        return '%d+' % low
    return '%d-%d' % (low, high)


def _bucketize(values):
    counts = []
    for low, high in SCORE_BUCKETS:
        counts.append((_bucket_label(low, high),
                       sum(1 for v in values if low <= v <= high)))
    return counts


def collect(rows, cfg, guard_cfg):
    """Fold a row iterable into every statistic the report prints. Pure."""
    rows = list(rows)
    stats = {
        'requests': len(rows),
        'devices': set(),
        'addresses': set(),
        'degraded': 0,
        'ms': [],
        'acts': {},
        'acts_shadow': {},
        'nav': 0,
        'nav_challenged': 0,
        'challenge_served': 0,
        'token_issued': 0,
        'sc': [],
        'esc': [],
        'diverged': 0,
        'has_rep': 0,
        'has_ml': 0,
        'has_clf': 0,
        'botv': {},
        'verify_unknown': 0,
        'holdout_requests': 0,
        'holdout_identities': set(),
        'holdout_challenge': 0,
        'holdout_hp': 0,
        'enforced_requests': 0,
        'enforced_identities': set(),
        'enforced_challenge': 0,
        'enforced_hp': 0,
        'by_day': {},
        'top_rep': {},
        'top_clf': {},
        'top_hp': {},
        'overrides': {},
        # Phase 4 response outcomes.
        'outcome_known': 0,
        'status': {},
        'status_holdout': {},
        'status_enforced': {},
        'dur': [],
        'top_404': {},
        'top_bytes': {},
        'bytes_total': 0.0,
    }

    for r in rows:
        dev = str(r.get('dev') or '')
        ip = str(r.get('ip') or '')
        act = str(r.get('act') or '')
        shadow = int(r.get('sh') or 0) == 1
        held = int(r.get('hold') or 0) == 1
        key, _ = logs_mod.session_key(r)

        if dev:
            stats['devices'].add(dev)
        if ip:
            stats['addresses'].add(ip)
        if int(r.get('rd') or 0) == 1:
            stats['degraded'] += 1
        try:
            stats['ms'].append(float(r.get('ms') or 0))
        except (TypeError, ValueError):
            pass

        stats['acts'][act] = stats['acts'].get(act, 0) + 1
        if shadow:
            stats['acts_shadow'][act] = stats['acts_shadow'].get(act, 0) + 1

        if int(r.get('nav') or 0) == 1:
            stats['nav'] += 1
            if act == 'challenge':
                stats['nav_challenged'] += 1
        if act == 'challenge' and not shadow:
            stats['challenge_served'] += 1
        if logs_mod.token_was_issued(r):
            stats['token_issued'] += 1

        try:
            sc = int(r.get('sc') or 0)
            esc = int(r.get('esc', sc) if r.get('esc') is not None else sc)
        except (TypeError, ValueError):
            sc, esc = 0, 0
        stats['sc'].append(sc)
        stats['esc'].append(esc)
        if sc != esc:
            stats['diverged'] += 1

        rep = r.get('rep')
        if rep is not None and int(rep or 0) != 0:
            stats['has_rep'] += 1
            if key:
                stats['top_rep'][key] = max(stats['top_rep'].get(key, -10 ** 9), int(rep))
        if r.get('ml') is not None and int(r.get('ml', -1)) >= 0:
            stats['has_ml'] += 1
        if r.get('clf') is not None and int(r.get('clf', -1)) >= 0:
            stats['has_clf'] += 1
            if key:
                stats['top_clf'][key] = max(stats['top_clf'].get(key, -1), int(r['clf']))

        botv = str(r.get('botv') or '')
        if str(r.get('bot') or ''):
            stats['botv'][botv or '(none)'] = stats['botv'].get(botv or '(none)', 0) + 1

        ovr = str(r.get('ovr') or '')
        if ovr:
            stats['overrides'][ovr] = stats['overrides'].get(ovr, 0) + 1

        if int(r.get('hp') or 0) == 1 and key:
            stats['top_hp'][key] = stats['top_hp'].get(key, 0) + 1

        # --- Phase 4: what the application actually did ------------------
        out = r.get('_out')
        bucket_name = outcomes_mod.status_class(out)
        if bucket_name is not None:
            stats['outcome_known'] += 1
            stats['status'][bucket_name] = stats['status'].get(bucket_name, 0) + 1
            side = 'status_holdout' if held else 'status_enforced'
            stats[side][bucket_name] = stats[side].get(bucket_name, 0) + 1
            if bucket_name == '404' and key:
                stats['top_404'][key] = stats['top_404'].get(key, 0) + 1
            size = out.get('by')
            if isinstance(size, (int, float)) and not isinstance(size, bool) and size >= 0:
                stats['bytes_total'] += float(size)
                if key:
                    stats['top_bytes'][key] = stats['top_bytes'].get(key, 0.0) + float(size)
            duration = out.get('dur')
            if isinstance(duration, (int, float)) and not isinstance(duration, bool):
                stats['dur'].append(float(duration))

        if held:
            stats['holdout_requests'] += 1
            if key:
                stats['holdout_identities'].add(key)
            if act == 'challenge':
                stats['holdout_challenge'] += 1
            if int(r.get('hp') or 0) == 1:
                stats['holdout_hp'] += 1
        else:
            stats['enforced_requests'] += 1
            if key:
                stats['enforced_identities'].add(key)
            if act == 'challenge':
                stats['enforced_challenge'] += 1
            if int(r.get('hp') or 0) == 1:
                stats['enforced_hp'] += 1

        # Day-over-day series for the anomaly section.
        try:
            import datetime
            # fromtimestamp(..., timezone.utc) rather than the deprecated
            # utcfromtimestamp(), which prints a warning into the middle of the
            # report an operator is reading and is scheduled for removal.
            # timezone.utc, not the module-level UTC alias: that alias is 3.11+
            # and this project's floor is 3.8.
            day = datetime.datetime.fromtimestamp(
                float(r.get('ts') or 0), datetime.timezone.utc).strftime('%Y-%m-%d')
        except Exception:
            day = 'unknown'
        bucket = stats['by_day'].setdefault(day, {'requests': 0, 'nonce_bad': 0,
                                                  'botv_bad': 0, 'block': 0, 'degraded': 0})
        bucket['requests'] += 1
        if logs_mod.handshake_rejected(r):
            bucket['nonce_bad'] += 1             # every refused handshake (key kept for the anomaly table)
        if botv == 'bad':
            bucket['botv_bad'] += 1
        if act == '403':
            bucket['block'] += 1
        if int(r.get('rd') or 0) == 1:
            bucket['degraded'] += 1

    stats['guard'] = guard_cfg
    stats['models'] = cfg.get('_models') or {}
    stats['challenge_target'] = float(cfg.get('challenge_success_target', 0.95))
    stats['top_n'] = int(cfg.get('report_top_n', 20))
    try:
        stats['verify_unknown'] = int(snapshot_mod.read_stats(cfg, 'run_verify').get('unknown') or 0)
    except Exception:
        stats['verify_unknown'] = 0
    return stats


def anomalies(by_day):
    """Day-over-day jumps worth a look. Returns a list of English sentences."""
    out = []
    days = sorted(d for d in by_day if d != 'unknown')
    if len(days) < 2:
        return out
    metrics = (('nonce_bad', 'failed handshakes'),
               ('botv_bad', 'refuted bot claims'),
               ('block', '403 responses'),
               ('degraded', 'degraded-mode requests'))
    previous, current = by_day[days[-2]], by_day[days[-1]]
    for key, name in metrics:
        before, after = previous.get(key, 0), current.get(key, 0)
        if after >= 10 and after >= before * 3 and before >= 0:
            out.append('%s rose from %d to %d between %s and %s'
                       % (name, before, after, days[-2], days[-1]))
        elif before >= 10 and after * 3 <= before:
            out.append('%s fell from %d to %d between %s and %s'
                       % (name, before, after, days[-2], days[-1]))
    return out


def render_text(stats, days):
    L = []
    A = L.append
    total = stats['requests']

    A('Bot Guard report - last %d day(s)' % days)
    A('=' * 62)
    A('')

    A('1. Traffic')
    A('   requests              %d' % total)
    A('   unique devices        %d' % len(stats['devices']))
    A('   unique addresses      %d' % len(stats['addresses']))
    A('   degraded (rd=1)       %d (%.1f%%)' % (stats['degraded'], _pct(stats['degraded'], total)))
    A('   guard time median     %.2f ms' % _percentile(stats['ms'], 0.5))
    A('   guard time p99        %.2f ms' % _percentile(stats['ms'], 0.99))
    A('')

    A('2. Decisions')
    A('   %-16s %8s %8s %8s' % ('action', 'total', 'enforced', 'shadow'))
    for act in sorted(stats['acts'], key=lambda a: -stats['acts'][a]):
        shadow = stats['acts_shadow'].get(act, 0)
        A('   %-16s %8d %8d %8d' % (act, stats['acts'][act],
                                    stats['acts'][act] - shadow, shadow))
    A('   navigations challenged %.1f%% (%d of %d)'
      % (_pct(stats['nav_challenged'], stats['nav']), stats['nav_challenged'], stats['nav']))
    if stats['overrides']:
        A('   operator overrides seen: %s'
          % ', '.join('%s=%d' % (k, v) for k, v in sorted(stats['overrides'].items())))
    A('')

    A('3. Challenge funnel')
    served = stats['challenge_served']
    issued = stats['token_issued']
    rate = _pct(issued, served)
    A('   challenges served     %d' % served)
    A('   tokens issued         %d' % issued)
    A('   success rate          %.1f%%' % rate)
    if served == 0:
        A('   No challenge was served in this window, so there is nothing to judge yet.')
    elif rate < stats['challenge_target'] * 100:
        A('   BELOW TARGET (%.0f%%). Real users are burning on the challenge: check that'
          % (stats['challenge_target'] * 100))
        A('   the JS runs and the cookie sticks before enabling anything stricter.')
    else:
        A('   At or above the %.0f%% target.' % (stats['challenge_target'] * 100))
    A('')

    A('4. Score distribution')
    A('   %-10s %10s %10s' % ('bucket', 'sc', 'esc'))
    sc_b = dict(_bucketize(stats['sc']))
    esc_b = dict(_bucketize(stats['esc']))
    for label, _ in _bucketize([]):
        A('   %-10s %10d %10d' % (label, sc_b.get(label, 0), esc_b.get(label, 0)))
    A('   rows where esc differs from sc: %d (%.1f%%)'
      % (stats['diverged'], _pct(stats['diverged'], total)))
    if stats['diverged'] == 0:
        A('   The offline signals are not moving the score at all. That is expected')
        A('   while every signals toggle is off.')
    A('')

    A('5. Verdict coverage')
    A('   requests carrying rep %d (%.1f%%)' % (stats['has_rep'], _pct(stats['has_rep'], total)))
    A('   requests carrying ml  %d (%.1f%%)' % (stats['has_ml'], _pct(stats['has_ml'], total)))
    A('   requests carrying clf %d (%.1f%%)' % (stats['has_clf'], _pct(stats['has_clf'], total)))
    if stats['botv']:
        A('   bot verification: %s'
          % ', '.join('%s=%d' % (k, v) for k, v in sorted(stats['botv'].items())))
    else:
        A('   bot verification: no known-bot traffic in this window')
    if stats.get('verify_unknown'):
        A('   %d address(es) could not be verified on the last run_verify (resolver'
          % stats['verify_unknown'])
        A('   trouble or no suffix list); they carry no verdict and are retried.')
    if total and stats['has_rep'] == 0 and stats['has_ml'] == 0 and stats['has_clf'] == 0:
        A('   NO VERDICTS AT ALL. The analyzer is probably not running, or Redis is not')
        A('   shared between the guard and the analyzer. Check the cron jobs first.')
    elif total and stats['has_rep'] and not (stats['has_ml'] or stats['has_clf']):
        A('   Reputations are being written but no model verdicts are. That usually')
        A('   means a stale model after a feature-set change: run_nightly.py --train')
        A('   --train-clf --candidate, then ctl.py promote-model ml and clf.')
    for kind, info in sorted((stats.get('models') or {}).items()):
        if info.get('stale'):
            A('   STALE %s MODEL: %s' % (kind.upper(), info.get('error', '')))
        elif not info.get('exists'):
            A('   no %s model on disk yet' % kind)
    A('')

    A('6. Response outcomes')
    known = stats['outcome_known']
    coverage = _pct(known, total)
    A('   requests with an outcome  %d (%.1f%%)' % (known, coverage))
    if known == 0:
        A('   No outcome lines in this window. Either capture_outcomes is off, or')
        A('   Phase 4 has only just been deployed. Nothing below applies yet.')
    else:
        if coverage < 80.0:
            A('   Coverage under ~80%% is normal when the application does not declare')
            A('   a Content-Length (compressed or streamed responses), or when capture')
            A('   was enabled part way through this window. It is not an error - the')
            A('   outcome_cov feature exists so the model knows how much to trust the')
            A('   rest.')
        A('')
        A('   %-8s %10s %8s' % ('status', 'count', 'share'))
        for name in STATUS_ORDER:
            count = stats['status'].get(name, 0)
            if count:
                A('   %-8s %10d %7.1f%%' % (name, count, _pct(count, known)))
        A('')
        A('   Non-holdout population vs holdout')
        enf = stats['status_enforced']
        held = stats['status_holdout']
        enf_n = sum(enf.values())
        held_n = sum(held.values())
        if held_n == 0:
            A('   No holdout outcomes yet, so there is nothing to compare against.')
        else:
            A('   %-8s %12s %12s' % ('status', 'non-holdout', 'holdout'))
            for name in STATUS_ORDER:
                if enf.get(name, 0) or held.get(name, 0):
                    A('   %-8s %11.1f%% %11.1f%%'
                      % (name, _pct(enf.get(name, 0), enf_n), _pct(held.get(name, 0), held_n)))
            A('   A 404 rate higher in the holdout slice than in the rest estimates')
            A('   what the guard\'s decisions catch, or would catch in monitor mode.')
        A('')
        A('   total bytes served      %.1f MB' % (stats['bytes_total'] / (1024.0 * 1024.0)))
        A('   request time median     %.1f ms' % _percentile(stats['dur'], 0.5))
        A('   request time p99        %.1f ms' % _percentile(stats['dur'], 0.99))
        A('')
        _top_block(A, 'top identities by 404 count', stats['top_404'], stats['top_n'])
        _top_block(A, 'top identities by bytes served',
                   dict((k, int(v)) for k, v in stats['top_bytes'].items()), stats['top_n'])
    A('')

    A('7. Holdout comparison')
    if int(stats['guard'].get('holdout_pct', 0) or 0) == 0 and stats['holdout_requests'] == 0:
        A('   holdout disabled (holdout_pct = 0), so there is no unbiased slice to')
        A('   compare against and no false-negative estimate is possible.')
    else:
        held_n = stats['holdout_requests']
        enf_n = stats['enforced_requests']
        A('   %-22s %12s %12s' % ('', 'non-holdout', 'holdout'))
        A('   %-22s %12d %12d' % ('requests', enf_n, held_n))
        A('   %-22s %12d %12d' % ('identities', len(stats['enforced_identities']),
                                  len(stats['holdout_identities'])))
        A('   %-22s %11.1f%% %11.1f%%' % ('challenge rate',
                                          _pct(stats['enforced_challenge'], enf_n),
                                          _pct(stats['holdout_challenge'], held_n)))
        A('   %-22s %11.1f%% %11.1f%%' % ('honeypot rate',
                                          _pct(stats['enforced_hp'], enf_n),
                                          _pct(stats['holdout_hp'], held_n)))
        A('   %-22s %12.1f %12.1f' % ('requests per identity',
                                      (float(enf_n) / len(stats['enforced_identities']))
                                      if stats['enforced_identities'] else 0.0,
                                      (float(held_n) / len(stats['holdout_identities']))
                                      if stats['holdout_identities'] else 0.0))
        A('   The gap between these columns is the false-negative estimate: what the holdout')
        A('   shows and the non-holdout population does not is the guard\'s effect.')
    A('')

    A('8. Top offenders')
    top_n = stats['top_n']
    _top_block(A, 'by reputation', stats['top_rep'], top_n)
    _top_block(A, 'by classifier level', stats['top_clf'], top_n)
    _top_block(A, 'by honeypot hits', stats['top_hp'], top_n)
    A('')

    A('9. Anomalies worth a look')
    found = anomalies(stats['by_day'])
    if not found:
        A('   nothing stood out day over day')
    for line in found:
        A('   - ' + line)
    return '\n'.join(L)


def _top_block(A, title, mapping, top_n):
    A('   %s:' % title)
    if not mapping:
        A('     (none)')
        return
    ordered = sorted(mapping.items(), key=lambda kv: -kv[1])[:top_n]
    for key, value in ordered:
        A('     %-44s %8d' % (key[:44], value))


def _esc_html(text):
    return (str(text).replace('&', '&amp;').replace('<', '&lt;')
            .replace('>', '&gt;').replace('"', '&quot;'))


def _bar_rows(pairs, total):
    out = []
    for label, value in pairs:
        width = _pct(value, total)
        out.append('<tr><th>%s</th><td class="n">%d</td>'
                   '<td class="b"><div style="width:%.1f%%"></div></td></tr>'
                   % (_esc_html(label), value, width))
    return '\n'.join(out)


def render_html(stats, days):
    """One self-contained file: inline CSS, no scripts, no external assets."""
    total = stats['requests']
    served = stats['challenge_served']
    rate = _pct(stats['token_issued'], served)
    parts = []
    A = parts.append

    A('<!doctype html>')
    A('<html lang="en"><head><meta charset="utf-8">')
    A('<meta name="viewport" content="width=device-width,initial-scale=1">')
    A('<title>Bot Guard report</title>')
    A('<style>')
    A('body{margin:0;padding:2rem;background:#f6f7f9;color:#1c1e21;'
      'font:15px/1.6 system-ui,-apple-system,Segoe UI,Arial,sans-serif}')
    A('main{max-width:60rem;margin:0 auto}')
    A('h1{font-size:1.4rem;margin:0 0 .3rem}')
    A('h2{font-size:1.05rem;margin:2rem 0 .6rem;padding-bottom:.3rem;'
      'border-bottom:1px solid #d8dbe0}')
    A('p.sub{margin:0 0 1rem;color:#5a5f66}')
    A('table{border-collapse:collapse;width:100%;margin:.4rem 0}')
    A('th,td{text-align:left;padding:.3rem .5rem;border-bottom:1px solid #e6e8eb;'
      'font-weight:400;vertical-align:middle}')
    A('th{color:#41454b;width:14rem}')
    A('td.n{width:6rem;text-align:right;font-variant-numeric:tabular-nums}')
    A('td.b div{height:.7rem;background:#5b7cfa;border-radius:2px;min-width:1px}')
    A('.note{background:#fff6e5;border-left:3px solid #e0a53d;padding:.6rem .8rem;'
      'margin:.6rem 0;color:#6b5220}')
    A('.good{background:#eaf7ee;border-left:3px solid #3f9e5a;padding:.6rem .8rem;'
      'margin:.6rem 0;color:#25542f}')
    A('code{background:#eceef1;padding:.1rem .3rem;border-radius:3px}')
    A('</style></head><body><main>')

    A('<h1>Bot Guard report</h1>')
    A('<p class="sub">Last %d day(s) &#183; %d requests &#183; thresholds from %s</p>'
      % (days, total, _esc_html(stats['guard'].get('source', 'defaults'))))

    A('<h2>1. Traffic</h2><table>')
    for label, value in (('requests', total),
                         ('unique devices', len(stats['devices'])),
                         ('unique addresses', len(stats['addresses'])),
                         ('degraded (rd=1)', stats['degraded'])):
        A('<tr><th>%s</th><td class="n">%d</td><td></td></tr>' % (_esc_html(label), value))
    A('<tr><th>guard time median</th><td class="n">%.2f ms</td><td></td></tr>'
      % _percentile(stats['ms'], 0.5))
    A('<tr><th>guard time p99</th><td class="n">%.2f ms</td><td></td></tr>'
      % _percentile(stats['ms'], 0.99))
    A('</table>')

    A('<h2>2. Decisions</h2><table>')
    A(_bar_rows(sorted(stats['acts'].items(), key=lambda kv: -kv[1]), total))
    A('</table>')
    A('<p class="sub">%.1f%% of navigations were challenged (%d of %d).</p>'
      % (_pct(stats['nav_challenged'], stats['nav']), stats['nav_challenged'], stats['nav']))

    A('<h2>3. Challenge funnel</h2><table>')
    A('<tr><th>challenges served</th><td class="n">%d</td><td></td></tr>' % served)
    A('<tr><th>tokens issued</th><td class="n">%d</td><td></td></tr>' % stats['token_issued'])
    A('<tr><th>success rate</th><td class="n">%.1f%%</td><td></td></tr>' % rate)
    A('</table>')
    if served == 0:
        A('<p class="sub">No challenge was served in this window.</p>')
    elif rate < stats['challenge_target'] * 100:
        A('<div class="note">Below the %.0f%% target. Real users are burning on the '
          'challenge &#8212; check that the script runs and the cookie sticks before '
          'enabling anything stricter.</div>' % (stats['challenge_target'] * 100))
    else:
        A('<div class="good">At or above the %.0f%% target.</div>'
          % (stats['challenge_target'] * 100))

    A('<h2>4. Score distribution</h2><table>')
    A('<tr><th>bucket</th><td class="n">sc</td><td class="n">esc</td></tr>')
    sc_b = dict(_bucketize(stats['sc']))
    esc_b = dict(_bucketize(stats['esc']))
    for label, _ in _bucketize([]):
        A('<tr><th>%s</th><td class="n">%d</td><td class="n">%d</td></tr>'
          % (_esc_html(label), sc_b.get(label, 0), esc_b.get(label, 0)))
    A('</table>')
    A('<p class="sub">%d rows (%.1f%%) have an effective score different from the static '
      'score.</p>' % (stats['diverged'], _pct(stats['diverged'], total)))

    A('<h2>5. Verdict coverage</h2><table>')
    A(_bar_rows((('rep', stats['has_rep']), ('ml', stats['has_ml']),
                 ('clf', stats['has_clf'])), total))
    A('</table>')
    if stats['botv']:
        A('<p class="sub">Bot verification: %s</p>'
          % _esc_html(', '.join('%s=%d' % kv for kv in sorted(stats['botv'].items()))))
    if stats.get('verify_unknown'):
        A('<p class="sub">%d address(es) could not be verified on the last run_verify; '
          'they carry no verdict and are retried.</p>' % stats['verify_unknown'])
    if total and not (stats['has_rep'] or stats['has_ml'] or stats['has_clf']):
        A('<div class="note">No verdicts at all. The analyzer is probably not running, '
          'or Redis is not shared between the guard and the analyzer.</div>')

    A('<h2>6. Response outcomes</h2>')
    known = stats['outcome_known']
    if known == 0:
        A('<p class="sub">No outcome lines in this window &#8212; either '
          '<code>capture_outcomes</code> is off, or Phase 4 has only just been '
          'deployed.</p>')
    else:
        A('<p class="sub">%d of %d requests (%.1f%%) matched an outcome line.</p>'
          % (known, total, _pct(known, total)))
        if _pct(known, total) < 80.0:
            A('<div class="note">Coverage under ~80% is normal when the application '
              'does not declare a Content-Length (compressed or streamed responses), '
              'or when capture was enabled part way through this window.</div>')
        A('<table>')
        A(_bar_rows([(n, stats['status'].get(n, 0)) for n in STATUS_ORDER
                     if stats['status'].get(n, 0)], known))
        A('</table>')
        enf = stats['status_enforced']
        held_st = stats['status_holdout']
        enf_n = sum(enf.values())
        held_n = sum(held_st.values())
        if held_n:
            A('<p class="sub">Non-holdout population vs holdout</p><table>')
            A('<tr><th>status</th><td class="n">non-holdout</td><td class="n">holdout</td></tr>')
            for name in STATUS_ORDER:
                if enf.get(name, 0) or held_st.get(name, 0):
                    A('<tr><th>%s</th><td class="n">%.1f%%</td><td class="n">%.1f%%</td></tr>'
                      % (_esc_html(name), _pct(enf.get(name, 0), enf_n),
                         _pct(held_st.get(name, 0), held_n)))
            A('</table>')
            A('<p class="sub">A 404 rate higher in the holdout slice than in the rest '
              'estimates what the guard\'s decisions catch, or would catch in monitor '
              'mode.</p>')
        A('<table>')
        A('<tr><th>total bytes served</th><td class="n">%.1f MB</td><td></td></tr>'
          % (stats['bytes_total'] / (1024.0 * 1024.0)))
        A('<tr><th>request time median</th><td class="n">%.1f ms</td><td></td></tr>'
          % _percentile(stats['dur'], 0.5))
        A('<tr><th>request time p99</th><td class="n">%.1f ms</td><td></td></tr>'
          % _percentile(stats['dur'], 0.99))
        A('</table>')
        for title, mapping in (('Top identities by 404 count', stats['top_404']),
                               ('Top identities by bytes served',
                                dict((k, int(v)) for k, v in stats['top_bytes'].items()))):
            A('<p class="sub">%s</p><table>' % _esc_html(title))
            ordered = sorted(mapping.items(), key=lambda kv: -kv[1])[:stats['top_n']]
            if not ordered:
                A('<tr><th>(none)</th><td class="n"></td><td></td></tr>')
            else:
                A(_bar_rows(ordered, ordered[0][1] or 1))
            A('</table>')

    A('<h2>7. Holdout comparison</h2>')
    if int(stats['guard'].get('holdout_pct', 0) or 0) == 0 and stats['holdout_requests'] == 0:
        A('<p class="sub">Holdout disabled (<code>holdout_pct = 0</code>). No unbiased '
          'slice, so no false-negative estimate is possible.</p>')
    else:
        enf_n = stats['enforced_requests']
        held_n = stats['holdout_requests']
        A('<table><tr><th></th><td class="n">non-holdout</td><td class="n">holdout</td></tr>')
        A('<tr><th>requests</th><td class="n">%d</td><td class="n">%d</td></tr>'
          % (enf_n, held_n))
        A('<tr><th>identities</th><td class="n">%d</td><td class="n">%d</td></tr>'
          % (len(stats['enforced_identities']), len(stats['holdout_identities'])))
        A('<tr><th>challenge rate</th><td class="n">%.1f%%</td><td class="n">%.1f%%</td></tr>'
          % (_pct(stats['enforced_challenge'], enf_n), _pct(stats['holdout_challenge'], held_n)))
        A('<tr><th>honeypot rate</th><td class="n">%.1f%%</td><td class="n">%.1f%%</td></tr>'
          % (_pct(stats['enforced_hp'], enf_n), _pct(stats['holdout_hp'], held_n)))
        A('</table>')
        A('<p class="sub">The gap between these columns is the false-negative estimate.</p>')

    A('<h2>8. Top offenders</h2>')
    for title, mapping in (('By reputation', stats['top_rep']),
                           ('By classifier level', stats['top_clf']),
                           ('By honeypot hits', stats['top_hp'])):
        A('<p class="sub">%s</p><table>' % _esc_html(title))
        ordered = sorted(mapping.items(), key=lambda kv: -kv[1])[:stats['top_n']]
        if not ordered:
            A('<tr><th>(none)</th><td class="n"></td><td></td></tr>')
        else:
            top = ordered[0][1] or 1
            A(_bar_rows(ordered, top))
        A('</table>')

    A('<h2>9. Anomalies worth a look</h2>')
    found = anomalies(stats['by_day'])
    if not found:
        A('<p class="sub">Nothing stood out day over day.</p>')
    else:
        A('<ul>')
        for line in found:
            A('<li>%s</li>' % _esc_html(line))
        A('</ul>')

    A('</main></body></html>')
    return '\n'.join(parts)


def parse_args(argv):
    parser = argparse.ArgumentParser(description='Period report over the guard logs.')
    parser.add_argument('--config', default=None, help='analyzer config override')
    parser.add_argument('--log-dir', default=None, help='override the log directory')
    parser.add_argument('--days', type=int, default=None, help='window in days')
    parser.add_argument('--html', default=None, help='also write a standalone HTML file here')
    parser.add_argument('--model', choices=('live', 'candidate'), default='live',
                        help='which model bundle to describe (candidate lets a '
                             'migration be evaluated before promotion)')
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
    days = args.days or int(cfg.get('report_days', 7))
    if not os.path.isdir(cfg['log_dir']):
        print('ERROR: log directory not readable: %s' % cfg['log_dir'], file=sys.stderr)
        return 2

    guard_cfg = bridge.guard_config(cfg)

    # Describe whichever bundle the operator asked about, so a candidate can be
    # evaluated before it goes anywhere near production.
    from analyzer import promote as promote_mod
    described = dict(cfg)
    if args.model == 'candidate':
        described['model_path'] = cfg['model_candidate_path']
        described['clf_path'] = cfg['clf_candidate_path']
    cfg['_models'] = promote_mod.live_status(described)

    rows = list(logs_mod.read_lines(cfg['log_dir'], days))
    stats = collect(rows, cfg, guard_cfg)

    print(render_text(stats, days))

    if args.html:
        try:
            with open(args.html, 'w') as handle:
                handle.write(render_html(stats, days))
            print('')
            print('HTML report written to %s' % args.html)
        except Exception as exc:
            print('ERROR: could not write the HTML report: %s' % exc, file=sys.stderr)
            return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
