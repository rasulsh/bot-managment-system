#!/usr/bin/env python3
"""Nightly job: sessions -> features -> reputation -> anomaly level.

Run daily. Pass --train weekly, or whenever there is no model file yet. Exits
non-zero only on its own hard failure (bad config, unreadable log dir) - a
missing Redis or a missing scikit-learn degrades and is reported.
"""

from __future__ import print_function

import argparse
import os
import random
import resource
import shutil
import sys
import time
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if __name__ == '__main__':
    # No bytecode, and files a manual run creates are not group-writable: a __pycache__ made under cron's umask 002 was 0775.
    sys.dont_write_bytecode = True
    os.umask(0o022)

from analyzer import classifier as clf_mod
from analyzer import config as config_mod
from analyzer import fsmode
from analyzer import ingest as ingest_mod
from analyzer import features as features_mod
from analyzer import iplist as iplist_mod
from analyzer import jobreport
from analyzer import lowprio as lowprio_mod
from analyzer import labels as labels_mod
from analyzer import logs as logs_mod
from analyzer import model as model_mod
from analyzer import promote as promote_mod
from analyzer import redis_io
from analyzer import snapshot as snapshot_mod
from analyzer import reputation as reputation_mod


# ---------------------------------------------------------------------------------------------------- bounded memory
# The window's rows are spooled into SPOOL_BUCKETS files by a hash of the identity (a device id, else address|UA hash), then each
# bucket is sessionized, featurised and reduced on its own: the identities of one bucket never appear in another, so every
# per-identity result is the one a single pass over all rows would give, while memory is one bucket (a hundredth of the window)
# plus what the training needs. Training reads a random but reproducible sample of at most TRAIN_CAP sessions (the same sample for the
# same logs); under the cap it is every session, in the original order.
SPOOL_BUCKETS = 128
SPOOL_FLUSH_ROWS = 1000
TRAIN_CAP = 200000


class Reservoir(object):
    """A uniform random sample of at most `cap` items from a stream (Algorithm R, seeded: same stream, same sample)."""

    def __init__(self, cap, seed=0):
        self.cap, self.rng, self.n, self.items = int(cap), random.Random(seed), 0, []

    def add(self, tag, payload):
        self.n += 1
        if len(self.items) < self.cap:
            self.items.append((tag, payload))
            return
        j = self.rng.randrange(self.n)
        if j < self.cap:
            self.items[j] = (tag, payload)

    def result(self):
        """The sampled payloads in tag order: the order a full pass visits them in (identity key, then session)."""
        self.items.sort(key=lambda pair: pair[0])
        return [payload for _, payload in self.items]


class Spool(object):
    """Rows partitioned by identity into compressed bucket files in a private directory (removed by close())."""

    def __init__(self, base_dir, buckets=SPOOL_BUCKETS):
        self.nb = int(buckets)
        self.dir = os.path.join(base_dir, '.nightly-spool-%d' % os.getpid())
        os.makedirs(self.dir, 0o755)
        self.buffers = [[] for _ in range(self.nb)]

    def _path(self, b):
        return os.path.join(self.dir, '%03d.dat' % b)

    def add(self, row):
        key, _is_device = logs_mod.session_key(row)
        if key in ('', '|'):
            return                                  # sessionize drops these rows too
        b = zlib.crc32(key.encode('utf-8', 'replace')) % self.nb
        self.buffers[b].append(row)
        if len(self.buffers[b]) >= SPOOL_FLUSH_ROWS:
            self._flush(b)

    def _flush(self, b):
        if self.buffers[b]:
            ingest_mod.append_frames(self._path(b), [ingest_mod.frame(self.buffers[b])])
            self.buffers[b] = []

    def seal(self):
        for b in range(self.nb):
            self._flush(b)

    def buckets(self):
        """The rows of each non-empty bucket, one bucket in memory at a time."""
        for b in range(self.nb):
            rows = []
            for frame in ingest_mod.iter_frames(self._path(b)):
                rows.extend(frame)
            if rows:
                yield rows

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def remove_stale_spools(base_dir, max_age_s=86400):
    """A spool left by a run that was killed: removed once it is a day old."""
    try:
        for name in os.listdir(base_dir):
            path = os.path.join(base_dir, name)
            if name.startswith('.nightly-spool-') and os.path.isdir(path) and time.time() - os.path.getmtime(path) > max_age_s:
                shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass


def peak_rss_mb():
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024)


def build_spool(cfg, count):
    """Read the window once, in a stream, into a Spool. `count` is a one-element list that receives the number of rows."""
    spool = Spool(ingest_mod.base_dir(cfg))
    try:
        for row in logs_mod.read_lines(cfg['log_dir'], cfg['window_days'], fields=logs_mod.SESSION_FIELDS):
            count[0] += 1
            spool.add(row)
        spool.seal()
    except BaseException:
        spool.close()
        raise
    return spool


def score_devices(devices, bundle, scorer, field, write, ttl, dry_run, client, clf=False):
    """Set entry[field] (the highest level over the identity's sessions) with one batched scorer call; returns verdicts written."""
    entries, vectors = [], []
    for entry in devices.values():
        if not entry['is_device'] or entry.get('holdout'):
            continue
        start = len(vectors)
        if clf:      # the classifier's own inputs (features.clf_features), the anomaly model's are the plain ones
            vectors.extend(features_mod.clf_vector(f, sess) for f, sess in zip(entry['features'], entry['sessions']))
        else:
            vectors.extend(features_mod.feature_vector(f) for f in entry['features'])
        entries.append((entry, start, len(vectors)))
    levels = scorer(bundle, vectors) if vectors else []
    written = 0
    for entry, a, b in entries:
        got = [v for v in levels[a:b] if v is not None]
        if not got:
            continue
        entry[field] = max(got)
        if not dry_run and write(client, entry['dev'], entry[field], ttl):
            written += 1
    return written


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


_median = labels_mod.median


def _labelled(devices, ground_truth):
    """Yield (entry, label, source) for every identity that carries a label independent of the guard."""
    for entry in devices.values():
        if entry.get('holdout'):
            continue
        rows = []
        for session in entry['sessions']:
            rows.extend(session.get('rows') or [])
        agg = reputation_mod.aggregate_labels(entry['labels'])
        median_dwell = _median([f.get('dur_s', 0.0) for f in entry['features']])
        merged = dict(entry['sessions'][0])
        merged['features'] = labels_mod.identity_features(entry['features'])
        label, source = labels_mod.bot_label_source(merged, agg, rows, ground_truth,
                                                    session_count=len(entry['sessions']),
                                                    median_dwell=median_dwell)
        if label is None:
            continue
        yield entry, int(label), source


def label_note(progress):
    """One line for the job status and the Models page: where the classifier's labels stand."""
    src = progress['sources']
    return ('classifier waiting for labels: %d / %d positives (honeypot hits %d, refuted crawler claims %d, operator ground truth %d), %d human-labelled sessions'
            % (progress['positives'], progress['needed'], src.get('honeypot', 0), src.get('refuted_claim', 0), src.get('ground_truth', 0), progress['humans']))


def collect_training_set(devices, ground_truth):
    """Build (X, y) from identities that carry a label independent of the guard.

    Sessions of unlabelled identities are dropped entirely rather than assumed
    human - see analyzer/labels.py for why challenge_unsolved in particular
    never becomes a label.
    """
    X = []
    y = []
    for entry, label, _source in _labelled(devices, ground_truth):
        for feats, sess in zip(entry['features'], entry['sessions']):
            X.append(features_mod.clf_vector(feats, sess))
            y.append(label)
    return X, y


def label_progress(devices, ground_truth, needed):
    """How far the supervised classifier is from having enough labels, counted the way training counts them (sessions of labelled
    identities): positives and humans, and where the positives came from. The panel shows it on the Models page and the dashboard."""
    sources = {labels_mod.SOURCE_HONEYPOT: 0, labels_mod.SOURCE_REFUTED: 0, labels_mod.SOURCE_GROUND_TRUTH: 0}
    positives = humans = 0
    identities = 0
    for entry, label, source in _labelled(devices, ground_truth):
        n = len(entry['features'])
        if label == 1:
            positives += n
            identities += 1
            if source in sources:
                sources[source] += n
        else:
            humans += n
    return {'positives': positives, 'humans': humans, 'needed': int(needed), 'positive_identities': identities, 'sources': sources}


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


def recompile_expired_lists(dry_run=False):
    """Recompile the IP lists when an enabled source still holds an entry past its `# expires=` time. Returns the number of expired
    entries that the compile ignored and removed (0 when nothing was due). Never fatal: lists are not what nightly is for."""
    if dry_run:
        return 0
    try:
        lists_dir = iplist_mod.default_dir()
        if not iplist_mod.has_expired(lists_dir):
            return 0
        status = iplist_mod.compile_lists(lists_dir)
        n = sum(int(v.get('expired', 0)) for v in (status.get('lists') or {}).values())
        print('IP lists: %d expired entr%s removed, lists recompiled.' % (n, 'y' if n == 1 else 'ies'))
        if not status.get('ok'):
            jobreport.warn('IP list recompile after an expiry reported errors: %s' % '; '.join(status.get('errors') or [])[:200])
        return n
    except Exception as exc:
        jobreport.warn('IP list expiry check failed: %s' % exc)
        return 0


def main(argv=None):
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

    phases = {}
    t_phase = time.time()
    remove_stale_spools(ingest_mod.base_dir(cfg))
    row_count = [0]
    try:
        spool = build_spool(cfg, row_count)
    except OSError as exc:
        print('ERROR: cannot spool the window under %s: %s' % (ingest_mod.base_dir(cfg), exc), file=sys.stderr)
        return 2
    phases['read'] = round(time.time() - t_phase, 1)
    try:
        return run_window(args, cfg, spool, row_count, phases)
    finally:
        spool.close()


def first_pass(spool, cfg, ground_truth, ml_sample, clf_sample, on_rep):
    """Pass 1 over the spooled buckets. For every identity with a browsing device and no holdout, on_rep(entry, reputation) is called;
    the clean sessions go to ml_sample and the labelled ones to clf_sample (each a Reservoir, or None when that model is not trained
    this run). Returns the label progress (additive over buckets), the counts and the number of sessions."""
    progress = {'positives': 0, 'humans': 0, 'needed': int(cfg['clf_min_positive']), 'positive_identities': 0,
                'sources': {labels_mod.SOURCE_HONEYPOT: 0, labels_mod.SOURCE_REFUTED: 0, labels_mod.SOURCE_GROUND_TRUTH: 0}}
    holdout_skipped = device_keys = session_count = 0
    for rows in spool.buckets():
        sessions = logs_mod.sessionize(rows, cfg['session_gap_s'])
        session_count += len(sessions)
        devices = build_device_view(sessions, cfg)
        del rows, sessions
        for entry in devices.values():
            if not entry['is_device']:
                continue          # rep/ml are per browsing identity, not per IP
            if entry.get('holdout'):
                holdout_skipped += 1
                continue          # holdout data is aggregate-only, never per device
            device_keys += 1
            labels = reputation_mod.aggregate_labels(entry['labels'])
            on_rep(entry, reputation_mod.device_reputation(entry['features'], labels, cfg['rep_clamp']))
        if ml_sample is not None:
            for key, entry in devices.items():
                for i, (feats, labels) in enumerate(zip(entry['features'], entry['labels'])):
                    if model_mod.is_clean_session(labels, feats):
                        ml_sample.add((key, i), features_mod.feature_vector(feats))
        for entry, label, source in _labelled(devices, ground_truth):
            n = len(entry['features'])
            if label == 1:
                progress['positives'] += n
                progress['positive_identities'] += 1
                if source in progress['sources']:
                    progress['sources'][source] += n
            else:
                progress['humans'] += n
            if clf_sample is not None:
                for i, feats in enumerate(entry['features']):
                    clf_sample.add((entry['sessions'][0]['key'], i), (features_mod.clf_vector(feats, entry['sessions'][i]), label))
        del devices
    return {'progress': progress, 'holdout_skipped': holdout_skipped, 'device_keys': device_keys, 'sessions': session_count}


def run_window(args, cfg, spool, row_count, phases):
    client = redis_io.connect(cfg, write=not args.dry_run)

    # --- IP list entries past their `# expires=` time: recompile, so the compiled files stop matching them and the lines go.
    lists_expired = recompile_expired_lists(args.dry_run)

    # --- what this run trains (decided before the pass: the pass collects the samples) ------------------------------
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
    want_clf_train = args.train_clf or (not args.candidate
                                        and not os.path.isfile(cfg['clf_path']))
    ground_truth = labels_mod.load_ground_truth(
        args.ground_truth or cfg.get('ground_truth_path'))

    # --- pass 1: per bucket: sessions, features, labels -> reputation, label progress, training samples ------------
    t_phase = time.time()
    ml_sample = Reservoir(TRAIN_CAP)
    clf_sample = Reservoir(TRAIN_CAP)
    rep_written = [0]

    def on_rep(entry, value):
        if not args.dry_run and redis_io.set_rep(client, entry['dev'], value, cfg['rep_ttl']):
            rep_written[0] += 1
    first = first_pass(spool, cfg, ground_truth, ml_sample if (want_train and model_mod.SKLEARN_AVAILABLE) else None,
                       clf_sample if (want_clf_train and clf_mod.SKLEARN_AVAILABLE) else None, on_rep)
    progress, holdout_skipped, device_keys, session_count = first['progress'], first['holdout_skipped'], first['device_keys'], first['sessions']
    rep_written = rep_written[0]
    phases['sessions+features'] = round(time.time() - t_phase, 1)

    # --- model ------------------------------------------------------------
    t_phase = time.time()
    trained = False
    train_n = 0
    train_note = 'not requested'
    bundle = None
    if not model_mod.SKLEARN_AVAILABLE:
        train_note = 'scikit-learn unavailable, no ML this run'
    elif want_train:
        vectors = ml_sample.result()
        train_n = ml_sample.n
        try:
            trained = model_mod.train(vectors, cfg['contamination'],
                                      ml_train_path, cfg['ml_min_train'])
            sampled = '' if ml_sample.n == len(vectors) else ' (a random sample of %d of them)' % len(vectors)
            train_note = ('trained on %d clean sessions%s -> %s'
                          % (train_n, sampled, os.path.basename(ml_train_path)) if trained
                          else 'skipped: %d clean sessions is below ml_min_train=%d'
                               % (train_n, cfg['ml_min_train']))
        except Exception as exc:
            train_note = 'failed: %s' % exc
        del vectors
    if model_mod.SKLEARN_AVAILABLE:
        bundle = model_mod.load(cfg['model_path'])

    # --- supervised classifier --------------------------------------------
    clf_note = 'not requested'
    clf_bundle = None
    if not clf_mod.SKLEARN_AVAILABLE:
        clf_note = 'scikit-learn unavailable, no classifier this run'
    elif want_clf_train:
        pairs = clf_sample.result()
        X = [v for v, _ in pairs]
        y = [lab for _, lab in pairs]
        del pairs
        positives = sum(1 for v in y if v == 1)
        try:
            written = clf_mod.train(X, y, clf_train_path,
                                    min_positive=cfg['clf_min_positive'],
                                    test_size=cfg['clf_test_size'],
                                    target_precision=cfg['clf_target_precision'])
            sampled = '' if clf_sample.n == len(y) else ' (a random sample of %d of %d)' % (len(y), clf_sample.n)
            if written:
                clf_note = 'trained on %d labelled sessions%s (%d bot, %d human) -> %s' % (
                    len(y), sampled, positives, len(y) - positives,
                    os.path.basename(clf_train_path))
            else:
                clf_note = ('skipped: %d bot-labelled sessions is below '
                            'clf_min_positive=%d, or one class was missing'
                            % (positives, cfg['clf_min_positive']))
        except Exception as exc:
            clf_note = 'failed: %s' % exc
        del X, y
    if clf_mod.SKLEARN_AVAILABLE:
        clf_bundle = clf_mod.load(cfg['clf_path'])
    phases['training'] = round(time.time() - t_phase, 1)

    # --- pass 2: score every identity with the models as they are now -----------------------------------------------
    t_phase = time.time()
    ml_written = clf_written = 0
    if bundle is not None or clf_bundle is not None:
        for rows in spool.buckets():
            devices = build_device_view(logs_mod.sessionize(rows, cfg['session_gap_s']), cfg)
            del rows
            if bundle is not None:
                # The device's most anomalous recent session represents it.
                ml_written += score_devices(devices, bundle, model_mod.score_many, 'ml', redis_io.set_ml, cfg['ml_ttl'], args.dry_run, client)
            if clf_bundle is not None:
                clf_written += score_devices(devices, clf_bundle, clf_mod.score_many, 'clf', redis_io.set_clf, cfg['ml_ttl'], args.dry_run, client, clf=True)
            del devices
    phases['scoring'] = round(time.time() - t_phase, 1)
    phases['peak_rss_mb'] = peak_rss_mb()
    sessions = range(session_count)

    # --- summary ----------------------------------------------------------
    # A stale live model is the one failure mode that makes the system quietly
    # more permissive, so it is said out loud with the fix attached.
    for kind, info in sorted(promote_mod.live_status(cfg).items()):
        warning = promote_mod.stale_warning(kind, info)
        if warning:
            print(warning, file=sys.stderr)
            print(warning)

    # What a "successful" run that did nothing useful must say out loud (status: warning).
    if client is None:
        reason = redis_io.unavailable_reason(cfg)
        print(reason + '.')
        jobreport.warn(reason)
    if not row_count[0]:
        jobreport.warn('no input rows: the log directory has no decision rows in the last %s day(s)' % cfg['window_days'])
    if not model_mod.SKLEARN_AVAILABLE:
        jobreport.warn('scikit-learn is not installed for this Python: no model or classifier (check GV_PYTHON)')
    elif bundle is None:
        jobreport.warn('model missing: no usable anomaly model at %s (run train, then promote)' % os.path.basename(cfg['model_path']))
    if want_train and model_mod.SKLEARN_AVAILABLE and not trained:
        jobreport.warn('model training produced no candidate: %s' % train_note)
    if want_clf_train and clf_mod.SKLEARN_AVAILABLE and clf_note.startswith('failed'):
        jobreport.warn('classifier training produced no candidate: %s' % clf_note)
    elif want_clf_train and clf_mod.SKLEARN_AVAILABLE and clf_note.startswith('skipped'):
        # Waiting for labels is never a warning by itself: an install with no positive labels yet (no honeypot hit, no refuted crawler,
        # no operator ground truth) has nothing to train on, whatever else the run did. It is the informational note with the progress.
        # (It used to warn whenever no identity carried a device id, i.e. on every install that has not enforced the challenge yet.)
        # Real problems keep their own warnings above: no rows, Redis unreachable, scikit-learn missing, a model that failed to train.
        jobreport.info(label_note(progress))
    if args.train or args.train_clf or want_train or want_clf_train:
        metrics = clf_bundle.get('metrics') if clf_bundle is not None and isinstance(clf_bundle.get('metrics'), dict) else None
        jobreport.result({
            'candidate_mode': bool(args.candidate),
            'ml_trained': bool(trained), 'ml_samples': train_n, 'ml_note': train_note,
            'clf_note': clf_note,
            'clf_metrics': {k: v for k, v in (metrics or {}).items() if isinstance(v, (int, float, str))},
            'rows': row_count[0], 'devices_scored': device_keys,
            'clf_labels': progress,
            'iplists_expired': lists_expired,
        })
    if not args.dry_run:
        # The label progress for the Models page and the dashboard (snapshot.py copies it); every nightly run, trained or not.
        snapshot_mod.record_stats(cfg, 'run_nightly', {'clf_labels': progress, 'devices_scored': device_keys, 'rows': row_count[0], 'phases': phases})
    if bundle is None and model_mod.SKLEARN_AVAILABLE:
        print('No usable model on disk: skipping ML verdicts. Run with --train.')
    if clf_bundle is None and clf_mod.SKLEARN_AVAILABLE:
        print('No usable classifier on disk: skipping clf verdicts. Run with --train-clf.')
    print('Nightly phases (s): %s' % ', '.join('%s %s' % kv for kv in sorted(phases.items())))
    print('Nightly analysis: %d rows, %d sessions, %d devices scored.'
          % (row_count[0], len(sessions), device_keys))
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
