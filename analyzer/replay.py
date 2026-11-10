#!/usr/bin/env python3
"""Counterfactual replay: what a config change would have done to real traffic.

READ-ONLY BY CONSTRUCTION. This module never connects to Redis, never writes a
verdict, and never touches the log files it reads. It opens historical JSONL,
recomputes decisions under a candidate config, and prints. That is all it can
do, and the self-test asserts it.

Two modes:

  threshold (default)  Cheap and exact. Uses the sc, rep, ml and clf already in
                       each log row and re-applies the decision mirror under the
                       candidate config. Correct for tuning hard_block_score,
                       the three weights and the signal toggles.
  full                 Re-derives reputation and anomaly levels from the window
                       with candidate analyzer settings, then applies
                       thresholds. Needed only when tuning reputation weights.

Usage:
  python3 analyzer/replay.py --set hard_block_score=50 --set signals.clf=true
  python3 analyzer/replay.py --mode full --set ml_weight=0.6 --days 14
"""

from __future__ import print_function

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import bridge
from analyzer import config as config_mod
from analyzer import decision
from analyzer import features as features_mod
from analyzer import labels as labels_mod
from analyzer import logs as logs_mod

ACTIONS = ('allow', 'challenge', '403', '429')

# Rows whose outcome the decision engine never produced: they short-circuit
# before the decision step, so replaying them would be meaningless.
NON_DECISION_ACTS = ('exempt', 'allow_bot', '404_hp', 'token_issued',
                     'nonce_bad', 'nonce_replay', 'pow_bad', 'mint_limited',
                     'allow_override')


def parse_set(pairs):
    """Turn --set key=value strings into a typed override mapping."""
    out = {}
    for pair in pairs or []:
        if '=' not in pair:
            raise ValueError('--set expects key=value, got %r' % pair)
        key, _, raw = pair.partition('=')
        key = key.strip()
        raw = raw.strip()
        low = raw.lower()
        if low in ('true', 'yes', 'on', '1') and key.startswith('signals.'):
            value = True
        elif low in ('false', 'no', 'off', '0') and key.startswith('signals.'):
            value = False
        else:
            try:
                value = int(raw)
            except ValueError:
                try:
                    value = float(raw)
                except ValueError:
                    value = raw
        out[key] = value
    return out


def row_decision(row, cfg):
    """Recompute (esc, action) for one log row under a candidate config."""
    esc = decision.effective_score(
        int(row.get('sc') or 0),
        int(row.get('rep') or 0),
        int(row.get('ml', -1) if row.get('ml') is not None else -1),
        int(row.get('clf', -1) if row.get('clf') is not None else -1),
        cfg)
    over = str(row.get('act') or '') == '429'
    nav = int(row.get('nav') or 0) == 1
    tok = str(row.get('tok') or 'm')
    ovr = str(row.get('ovr') or '')
    return esc, decision.decide(esc, over, nav, tok, cfg['hard_block_score'], ovr)


def baseline_action(row):
    """The decision the guard actually reached for this row.

    A shadow row (sh == 1) still records the intended action in act, which is
    exactly what we want to compare against - replay compares decisions, not
    what enforcement happened to be switched on at the time.
    """
    return str(row.get('act') or '')


def replay_rows(rows, base_cfg, cand_cfg, identity_labels=None):
    """Compare baseline and candidate decisions row by row.

    Returns a result dict with counts, a movement table and the label split.
    Pure: it takes rows and configs and returns numbers.
    """
    identity_labels = identity_labels or {}
    result = {
        'considered': 0,
        'skipped_non_decision': 0,
        'baseline': dict((a, 0) for a in ACTIONS),
        'candidate': dict((a, 0) for a in ACTIONS),
        'movement': {},
        'bot_newly_caught': 0,
        'bot_rows': 0,
        'human_newly_restricted': 0,
        'human_rows': 0,
        'holdout_rows': 0,
        'holdout_newly_restricted': 0,
        'esc_changed': 0,
    }

    for row in rows:
        act = baseline_action(row)
        if act in NON_DECISION_ACTS:
            result['skipped_non_decision'] += 1
            continue
        if act not in ACTIONS:
            result['skipped_non_decision'] += 1
            continue

        base_esc, base_act = row_decision(row, base_cfg)
        cand_esc, cand_act = row_decision(row, cand_cfg)
        result['considered'] += 1
        result['baseline'][base_act] = result['baseline'].get(base_act, 0) + 1
        result['candidate'][cand_act] = result['candidate'].get(cand_act, 0) + 1
        if base_esc != cand_esc:
            result['esc_changed'] += 1
        if base_act != cand_act:
            key = base_act + '->' + cand_act
            result['movement'][key] = result['movement'].get(key, 0) + 1

        restricted = _is_more_restrictive(base_act, cand_act)
        key, _ = logs_mod.session_key(row)
        label = identity_labels.get(key)
        if label == 1:
            result['bot_rows'] += 1
            if restricted:
                result['bot_newly_caught'] += 1
        elif label == 0:
            result['human_rows'] += 1
            if restricted:
                result['human_newly_restricted'] += 1
        if int(row.get('hold') or 0) == 1:
            result['holdout_rows'] += 1
            if restricted:
                result['holdout_newly_restricted'] += 1

    return result


# Ordered from most permissive to most restrictive, so "did this get stricter?"
# is a single comparison.
_SEVERITY = {'allow': 0, 'challenge': 1, '429': 2, '403': 3}


def _is_more_restrictive(before, after):
    return _SEVERITY.get(after, 0) > _SEVERITY.get(before, 0)


def identity_label_map(sessions, ground_truth=None):
    """Label every session key as bot (1), human (0) or unknown (absent)."""
    ground_truth = ground_truth or {}
    per_key = {}
    for session in sessions:
        key = session['key']
        per_key.setdefault(key, []).append(session)

    out = {}
    for key, group in per_key.items():
        history = []
        for session in group:
            history.extend(session.get('rows') or [])
        feats = [features_mod.session_features(s) for s in group]
        dwells = sorted(f['dur_s'] for f in feats)
        median_dwell = dwells[len(dwells) // 2] if dwells else 0.0
        merged = dict(group[0])
        merged['features'] = feats[0] if feats else {}
        label_set = features_mod.session_labels(group[0], history)
        for session in group[1:]:
            more = features_mod.session_labels(session, history)
            for name in label_set:
                if int(more.get(name) or 0) == 1:
                    label_set[name] = 1
        verdict = labels_mod.bot_labels(merged, label_set, history, ground_truth,
                                        session_count=len(group),
                                        median_dwell=median_dwell)
        if verdict is not None:
            out[key] = verdict
    return out


def recompute_rows_full(rows, sessions, cfg, guard_cfg):
    """Re-derive rep and ml per identity with candidate analyzer settings.

    Returns a new row list with rep/ml replaced. Used by --mode full when the
    reputation weights themselves are being tuned. Holdout rows are left alone:
    their identities never carry a stable device id.
    """
    from analyzer import model as model_mod
    from analyzer import reputation as reputation_mod

    per_key = {}
    for session in sessions:
        per_key.setdefault(session['key'], []).append(session)

    bundle = None
    if model_mod.SKLEARN_AVAILABLE:
        bundle = model_mod.load(cfg['model_path'])

    derived = {}
    for key, group in per_key.items():
        history = []
        for session in group:
            history.extend(session.get('rows') or [])
        feats = [features_mod.session_features(
            s, cfg.get('path_listing'), cfg.get('path_detail')) for s in group]
        per_labels = [features_mod.session_labels(s, history) for s in group]
        agg = reputation_mod.aggregate_labels(per_labels)
        rep = reputation_mod.device_reputation(feats, agg, cfg['rep_clamp'])
        ml = -1
        if bundle is not None:
            levels = []
            for f in feats:
                try:
                    levels.append(model_mod.score(bundle, features_mod.feature_vector(f)))
                except Exception:
                    continue
            if levels:
                ml = max(levels)
        derived[key] = (rep, ml)

    out = []
    for row in rows:
        key, _ = logs_mod.session_key(row)
        if key in derived:
            new_row = dict(row)
            new_row['rep'], new_row['ml'] = derived[key]
            out.append(new_row)
        else:
            out.append(row)
    return out


def format_report(result, base_cfg, cand_cfg, overrides, mode, source):
    """Render the replay result as plain text."""
    lines = []
    lines.append('Counterfactual replay (%s mode, thresholds from %s)' % (mode, source))
    lines.append('')
    lines.append('Candidate changes:')
    if not overrides:
        lines.append('  (none - baseline replayed against itself)')
    for key in sorted(overrides):
        before = _lookup(base_cfg, key)
        lines.append('  %-22s %s -> %s' % (key, before, overrides[key]))
    lines.append('')
    lines.append('Rows considered: %d (skipped %d that never reached the decision step)'
                 % (result['considered'], result['skipped_non_decision']))
    lines.append('Rows whose effective score moved: %d' % result['esc_changed'])
    lines.append('')

    lines.append('%-12s %10s %10s %10s' % ('decision', 'baseline', 'candidate', 'delta'))
    lines.append('-' * 46)
    for act in ACTIONS:
        base = result['baseline'].get(act, 0)
        cand = result['candidate'].get(act, 0)
        lines.append('%-12s %10d %10d %+10d' % (act, base, cand, cand - base))
    lines.append('')

    lines.append('Movement table')
    lines.append('-' * 46)
    if not result['movement']:
        lines.append('  no request changed decision')
    for key in sorted(result['movement'], key=lambda k: -result['movement'][k]):
        lines.append('  %-26s %8d' % (key, result['movement'][key]))
    lines.append('')

    lines.append('Impact by labelled subset')
    lines.append('-' * 46)
    lines.append('  bot-labelled rows          %8d' % result['bot_rows'])
    lines.append('    newly restricted         %8d   (recall proxy, higher is better)'
                 % result['bot_newly_caught'])
    lines.append('  human-labelled rows        %8d' % result['human_rows'])
    lines.append('    newly restricted         %8d   <-- the number that decides this change'
                 % result['human_newly_restricted'])
    lines.append('  holdout rows               %8d' % result['holdout_rows'])
    lines.append('    would newly be restricted%8d   (unenforced slice)'
                 % result['holdout_newly_restricted'])
    lines.append('')
    if result['human_rows'] == 0:
        lines.append('NOTE: no rows carry a human label, so the false-positive column is')
        lines.append('      empty. Do not read that as "no false positives" - it means the')
        lines.append('      window has no confidently-human identities to measure against.')
    lines.append('Nothing was written: replay reads logs and prints, and cannot do anything else.')
    return '\n'.join(lines)


def _lookup(cfg, dotted):
    node = cfg
    for part in dotted.split('.'):
        if not isinstance(node, dict) or part not in node:
            return '?'
        node = node[part]
    return node


def parse_args(argv):
    parser = argparse.ArgumentParser(description='Replay historical logs under a candidate config.')
    parser.add_argument('--config', default=None, help='analyzer config override')
    parser.add_argument('--log-dir', default=None, help='override the log directory')
    parser.add_argument('--days', type=int, default=None, help='window in days')
    parser.add_argument('--mode', choices=('threshold', 'full'), default='threshold')
    parser.add_argument('--set', action='append', dest='sets', default=[],
                        metavar='KEY=VALUE',
                        help='candidate override, e.g. hard_block_score=50 or signals.clf=true')
    parser.add_argument('--ground-truth', default=None, help='operator label file')
    parser.add_argument('--model', choices=('live', 'candidate'), default='live',
                        help='which model bundle full mode should score with')
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
    if args.days:
        cfg['window_days'] = args.days
    if not os.path.isdir(cfg['log_dir']):
        print('ERROR: log directory not readable: %s' % cfg['log_dir'], file=sys.stderr)
        return 2

    try:
        overrides = parse_set(args.sets)
    except ValueError as exc:
        print('ERROR: %s' % exc, file=sys.stderr)
        return 2

    guard_cfg = bridge.guard_config(cfg)
    base_cfg = bridge.decision_config(guard_cfg)
    cand_cfg = bridge.decision_config(guard_cfg, overrides)

    rows = list(logs_mod.read_lines(cfg['log_dir'], cfg['window_days']))
    sessions = logs_mod.sessionize(rows, cfg['session_gap_s'])

    ground_truth = labels_mod.load_ground_truth(
        args.ground_truth or cfg.get('ground_truth_path'))
    identity_labels = identity_label_map(sessions, ground_truth)

    if args.mode == 'full':
        if args.model == 'candidate':
            cfg = dict(cfg, model_path=cfg['model_candidate_path'])
        rows = recompute_rows_full(rows, sessions, cfg, guard_cfg)

    result = replay_rows(rows, base_cfg, cand_cfg, identity_labels)
    print(format_report(result, base_cfg, cand_cfg, overrides, args.mode,
                        guard_cfg.get('source', 'defaults')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
