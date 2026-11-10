#!/usr/bin/env python3
"""Nightly job: sessions -> features -> reputation -> anomaly level.

Run daily. Pass --train weekly, or whenever there is no model file yet. Exits
non-zero only on its own hard failure (bad config, unreadable log dir) - a
missing Redis or a missing scikit-learn degrades and is reported.
"""

from __future__ import print_function

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import classifier as clf_mod
from analyzer import config as config_mod
from analyzer import features as features_mod
from analyzer import labels as labels_mod
from analyzer import logs as logs_mod
from analyzer import model as model_mod
from analyzer import promote as promote_mod
from analyzer import redis_io
from analyzer import snapshot as snapshot_mod
from analyzer import reputation as reputation_mod


def build_device_view(sessions, cfg):
    """Group sessions by key and attach features and labels to each device."""
    history = logs_mod.device_history(sessions)
    devices = {}
    for session in sessions:
        feats = features_mod.session_features(
            session, cfg.get('path_listing'), cfg.get('path_detail'))
        labels = features_mod.session_labels(session, history.get(session['key']))
        entry = devices.setdefault(session['key'], {
            'is_device': session['is_device'],
            'dev': session['dev'],
            'features': [],
            'labels': [],
            'sessions': [],
            'holdout': False,
        })
        entry['features'].append(feats)
        entry['labels'].append(labels)
        entry['sessions'].append(session)
        # A row only counts as holdout when it was actually suppressed (sh == 1):
        # hold marks holdout membership for every request, but an enforced 429
        # carries hold=1 with sh=0, and rate limiting is never held out. Keying
        # off hold alone excluded devices whose traffic was in fact fully
        # enforced from their own per-device reputation.
        if any(int(r.get('hold') or 0) == 1 and int(r.get('sh') or 0) == 1
               for r in (session.get('rows') or [])):
            entry['holdout'] = True
    return devices


def _median(values):
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return float(ordered[middle])
    return (float(ordered[middle - 1]) + float(ordered[middle])) / 2.0


def collect_training_set(devices, ground_truth):
    """Build (X, y) from identities that carry a label independent of the guard.

    Sessions of unlabelled identities are dropped entirely rather than assumed
    human - see analyzer/labels.py for why challenge_unsolved in particular
    never becomes a label.
    """
    X = []
    y = []
    for entry in devices.values():
        if entry.get('holdout'):
            continue
        rows = []
        for session in entry['sessions']:
            rows.extend(session.get('rows') or [])
        agg = reputation_mod.aggregate_labels(entry['labels'])
        median_dwell = _median([f.get('dur_s', 0.0) for f in entry['features']])
        merged = dict(entry['sessions'][0])
        merged['features'] = entry['features'][0] if entry['features'] else {}
        label = labels_mod.bot_labels(merged, agg, rows, ground_truth,
                                      session_count=len(entry['sessions']),
                                      median_dwell=median_dwell)
        if label is None:
            continue
        for feats in entry['features']:
            X.append(features_mod.feature_vector(feats))
            y.append(int(label))
    return X, y


def collect_clean_vectors(devices):
    """Feature vectors of confident-human sessions only, for training."""
    vectors = []
    for entry in devices.values():
        for feats, labels in zip(entry['features'], entry['labels']):
            if model_mod.is_clean_session(labels, feats):
                vectors.append(features_mod.feature_vector(feats))
    return vectors


def parse_args(argv):
    parser = argparse.ArgumentParser(description='Nightly behavioural analysis.')
    parser.add_argument('--config', default=None, help='path to a .json or .py config override')
    parser.add_argument('--log-dir', default=None, help='override the log directory')
    parser.add_argument('--train', action='store_true', help='retrain the anomaly model')
    parser.add_argument('--train-clf', action='store_true',
                        help='retrain the supervised classifier')
    parser.add_argument('--candidate', action='store_true',
                        help='train to the candidate paths and leave the live '
                             'models untouched (the documented default for a '
                             'feature-set migration)')
    parser.add_argument('--ground-truth', default=None, help='operator label file')
    parser.add_argument('--dry-run', action='store_true',
                        help='compute and report without writing verdicts')
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

    rows = list(logs_mod.read_lines(cfg['log_dir'], cfg['window_days']))
    sessions = logs_mod.sessionize(rows, cfg['session_gap_s'])
    devices = build_device_view(sessions, cfg)

    client = redis_io.connect(cfg, write=not args.dry_run)

    # --- reputation -------------------------------------------------------
    rep_written = 0
    holdout_skipped = 0
    for key, entry in devices.items():
        if not entry['is_device']:
            continue          # rep/ml are per browsing identity, not per IP
        if entry.get('holdout'):
            holdout_skipped += 1
            continue          # holdout data is aggregate-only, never per device
        labels = reputation_mod.aggregate_labels(entry['labels'])
        value = reputation_mod.device_reputation(entry['features'], labels, cfg['rep_clamp'])
        entry['reputation'] = value
        if not args.dry_run and redis_io.set_rep(client, entry['dev'], value, cfg['rep_ttl']):
            rep_written += 1

    # --- model ------------------------------------------------------------
    trained = False
    train_n = 0
    train_note = 'not requested'
    bundle = None

    ml_train_path = cfg['model_candidate_path'] if args.candidate else cfg['model_path']
    clf_train_path = cfg['clf_candidate_path'] if args.candidate else cfg['clf_path']

    # --candidate never implies training: it only redirects where training
    # writes. Without --train it would otherwise silently start writing a
    # candidate on every nightly run. The second clause is the ONLY path that
    # writes a LIVE model without an explicit --candidate: a genuinely fresh
    # install with no model file yet, where training a first live model is
    # acceptable. Every other training route (panel jobs, the weekly cron) passes
    # --candidate and must be promoted explicitly.
    want_train = args.train or (not args.candidate
                                and not os.path.isfile(cfg['model_path']))
    if not model_mod.SKLEARN_AVAILABLE:
        train_note = 'scikit-learn unavailable, no ML this run'
    elif want_train:
        vectors = collect_clean_vectors(devices)
        train_n = len(vectors)
        try:
            trained = model_mod.train(vectors, cfg['contamination'],
                                      ml_train_path, cfg['ml_min_train'])
            train_note = ('trained on %d clean sessions -> %s'
                          % (train_n, os.path.basename(ml_train_path)) if trained
                          else 'skipped: %d clean sessions is below ml_min_train=%d'
                               % (train_n, cfg['ml_min_train']))
        except Exception as exc:
            train_note = 'failed: %s' % exc

    ml_written = 0
    if model_mod.SKLEARN_AVAILABLE:
        bundle = model_mod.load(cfg['model_path'])
    if bundle is not None:
        for key, entry in devices.items():
            if not entry['is_device'] or entry.get('holdout'):
                continue
            levels = []
            for feats in entry['features']:
                try:
                    levels.append(model_mod.score(bundle, features_mod.feature_vector(feats)))
                except Exception:
                    continue
            if not levels:
                continue
            # The device's most anomalous recent session represents it.
            entry['ml'] = max(levels)
            if not args.dry_run and redis_io.set_ml(client, entry['dev'], entry['ml'], cfg['ml_ttl']):
                ml_written += 1

    # --- supervised classifier --------------------------------------------
    ground_truth = labels_mod.load_ground_truth(
        args.ground_truth or cfg.get('ground_truth_path'))
    clf_note = 'not requested'
    clf_bundle = None
    clf_written = 0

    want_clf_train = args.train_clf or (not args.candidate
                                        and not os.path.isfile(cfg['clf_path']))
    if not clf_mod.SKLEARN_AVAILABLE:
        clf_note = 'scikit-learn unavailable, no classifier this run'
    elif want_clf_train:
        X, y = collect_training_set(devices, ground_truth)
        positives = sum(1 for v in y if v == 1)
        try:
            written = clf_mod.train(X, y, clf_train_path,
                                    min_positive=cfg['clf_min_positive'],
                                    test_size=cfg['clf_test_size'],
                                    target_precision=cfg['clf_target_precision'])
            if written:
                clf_note = 'trained on %d labelled sessions (%d bot, %d human) -> %s' % (
                    len(y), positives, len(y) - positives,
                    os.path.basename(clf_train_path))
            else:
                clf_note = ('skipped: %d bot-labelled sessions is below '
                            'clf_min_positive=%d, or one class was missing'
                            % (positives, cfg['clf_min_positive']))
        except Exception as exc:
            clf_note = 'failed: %s' % exc

    if clf_mod.SKLEARN_AVAILABLE:
        clf_bundle = clf_mod.load(cfg['clf_path'])
    if clf_bundle is not None:
        for key, entry in devices.items():
            if not entry['is_device'] or entry.get('holdout'):
                continue
            levels = []
            for feats in entry['features']:
                try:
                    levels.append(clf_mod.score(clf_bundle, features_mod.feature_vector(feats)))
                except Exception:
                    continue
            if not levels:
                continue
            entry['clf'] = max(levels)
            if not args.dry_run and redis_io.set_clf(client, entry['dev'], entry['clf'],
                                                     cfg['ml_ttl']):
                clf_written += 1

    # --- summary ----------------------------------------------------------
    device_keys = sum(1 for e in devices.values()
                      if e['is_device'] and not e.get('holdout'))

    # A stale live model is the one failure mode that makes the system quietly
    # more permissive, so it is said out loud with the fix attached.
    for kind, info in sorted(promote_mod.live_status(cfg).items()):
        warning = promote_mod.stale_warning(kind, info)
        if warning:
            print(warning, file=sys.stderr)
            print(warning)

    if client is None:
        print('Redis unavailable: verdicts were computed but not stored.')
    if bundle is None and model_mod.SKLEARN_AVAILABLE:
        print('No usable model on disk: skipping ML verdicts. Run with --train.')
    if clf_bundle is None and clf_mod.SKLEARN_AVAILABLE:
        print('No usable classifier on disk: skipping clf verdicts. Run with --train-clf.')
    print('Nightly analysis: %d rows, %d sessions, %d devices scored.'
          % (len(rows), len(sessions), device_keys))
    if holdout_skipped:
        print('Holdout identities skipped for per-device verdicts: %d '
              '(their data is sound in aggregate only).' % holdout_skipped)
    print('Reputations written: %d. Model: %s. ML verdicts written: %d.'
          % (rep_written, train_note, ml_written))
    print('Classifier: %s. clf verdicts written: %d.' % (clf_note, clf_written))
    if clf_bundle is not None and clf_bundle.get('metrics'):
        print('Classifier metrics on held-out data:')
        print(clf_mod.format_metrics(clf_bundle['metrics']))
    snapshot_mod.touch_run(cfg, 'run_nightly')
    return 0


if __name__ == '__main__':
    sys.exit(main())
