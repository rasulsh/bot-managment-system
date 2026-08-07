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

from analyzer import config as config_mod
from analyzer import features as features_mod
from analyzer import logs as logs_mod
from analyzer import model as model_mod
from analyzer import redis_io
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
        })
        entry['features'].append(feats)
        entry['labels'].append(labels)
    return devices


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

    client = redis_io.connect(cfg)

    # --- reputation -------------------------------------------------------
    rep_written = 0
    for key, entry in devices.items():
        if not entry['is_device']:
            continue          # rep/ml are per browsing identity, not per IP
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

    want_train = args.train or not os.path.isfile(cfg['model_path'])
    if not model_mod.SKLEARN_AVAILABLE:
        train_note = 'scikit-learn unavailable, no ML this run'
    elif want_train:
        vectors = collect_clean_vectors(devices)
        train_n = len(vectors)
        try:
            trained = model_mod.train(vectors, cfg['contamination'],
                                      cfg['model_path'], cfg['ml_min_train'])
            train_note = ('trained on %d clean sessions' % train_n if trained
                          else 'skipped: %d clean sessions is below ml_min_train=%d'
                               % (train_n, cfg['ml_min_train']))
        except Exception as exc:
            train_note = 'failed: %s' % exc

    ml_written = 0
    if model_mod.SKLEARN_AVAILABLE:
        bundle = model_mod.load(cfg['model_path'])
    if bundle is not None:
        for key, entry in devices.items():
            if not entry['is_device']:
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

    # --- summary ----------------------------------------------------------
    device_keys = sum(1 for e in devices.values() if e['is_device'])
    if client is None:
        print('Redis unavailable: verdicts were computed but not stored.')
    if bundle is None and model_mod.SKLEARN_AVAILABLE:
        print('No usable model on disk: skipping ML verdicts. Run with --train.')
    print('Nightly analysis: %d rows, %d sessions, %d devices scored.'
          % (len(rows), len(sessions), device_keys))
    print('Reputations written: %d. Model: %s. ML verdicts written: %d.'
          % (rep_written, train_note, ml_written))
    return 0


if __name__ == '__main__':
    sys.exit(main())
