"""Candidate model promotion.

Extending FEATURE_ORDER makes every existing bundle stale, and both load()
functions correctly refuse one. Left alone that means gv:ml and gv:clf stop
being written, the keys expire within a day, and - if signals.ml or signals.clf
are enabled - the effective score quietly drops for everyone until retraining
lands. A system silently becoming more permissive is exactly the kind of
failure nobody notices.

So training during a migration writes to a candidate path, the live model keeps
working, and promotion is an explicit act that checks the candidate first.
"""

from __future__ import print_function

import os
import shutil

from analyzer import classifier as clf_mod
from analyzer import features as features_mod
from analyzer import model as model_mod

KINDS = ('ml', 'clf')


def paths_for(kind, cfg):
    """Return (live_path, candidate_path) for a model kind."""
    if kind == 'ml':
        return cfg['model_path'], cfg['model_candidate_path']
    if kind == 'clf':
        return cfg['clf_path'], cfg['clf_candidate_path']
    raise ValueError('unknown model kind: %r' % (kind,))


def check(kind, cfg):
    """Inspect a candidate and decide whether it may be promoted.

    Returns {ok, reason, inspection}. Refuses a missing candidate, a
    feature-order mismatch, and - for the classifier - stored metrics below
    clf_target_precision, because promoting a model that never reached its
    precision bar is how a false-positive problem gets shipped.
    """
    if kind not in KINDS:
        return {'ok': False, 'reason': 'unknown model kind: %s' % kind, 'inspection': None}
    _live, candidate = paths_for(kind, cfg)

    module = model_mod if kind == 'ml' else clf_mod
    info = module.inspect(candidate)

    if not info['exists']:
        return {'ok': False,
                'reason': 'no candidate at %s. Train one first with '
                          'run_nightly.py --%s --candidate'
                          % (candidate, 'train' if kind == 'ml' else 'train-clf'),
                'inspection': info}
    if info['stale']:
        return {'ok': False,
                'reason': 'the candidate does not match the current feature set (%s). '
                          'Retrain it: the analyzer now has %d features.'
                          % (info['error'], len(features_mod.FEATURE_ORDER)),
                'inspection': info}
    if not info['loadable']:
        return {'ok': False, 'reason': info['error'] or 'candidate is not usable',
                'inspection': info}

    if kind == 'clf':
        metrics = info.get('metrics') or {}
        target = float(cfg.get('clf_target_precision', 0.98))
        precision = float(metrics.get('precision', 0.0))
        if not metrics:
            return {'ok': False, 'reason': 'the candidate carries no stored metrics',
                    'inspection': info}
        if precision < target:
            return {'ok': False,
                    'reason': 'held-out precision %.3f is below the target %.2f. '
                              'Promoting this would restrict real users.'
                              % (precision, target),
                    'inspection': info}

    return {'ok': True, 'reason': 'candidate passes every check', 'inspection': info}


def promote(kind, cfg):
    """Move a checked candidate over the live path.

    The move is os.replace when candidate and live are on one filesystem (the default paths are siblings in analyzer/): one atomic
    rename. When they are not, shutil.move would copy straight over the live path (not atomic, and a half-written live model is worse
    than a stale one), so the candidate is copied beside the live file first and renamed into place. Callers take the write lock
    (analyzer/worker.py WriteLock) so a training run cannot swap the candidate between check() and the move.
    """
    verdict = check(kind, cfg)
    if not verdict['ok']:
        return verdict
    live, candidate = paths_for(kind, cfg)
    try:
        try:
            os.replace(candidate, live)
        except OSError:
            tmp = '%s.tmp.%d' % (live, os.getpid())
            try:
                shutil.copy2(candidate, tmp)
                os.replace(tmp, live)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            os.unlink(candidate)
    except Exception as exc:
        return {'ok': False, 'reason': 'could not move the candidate into place: %s' % exc,
                'inspection': verdict['inspection']}
    verdict['promoted_to'] = live
    verdict['reason'] = 'promoted %s to %s' % (os.path.basename(candidate), live)
    return verdict


def live_status(cfg):
    """Inspect both live models, for the stale-model warning."""
    return {'ml': model_mod.inspect(cfg['model_path']),
            'clf': clf_mod.inspect(cfg['clf_path'])}


def stale_warning(kind, info):
    """The loud one-line warning naming the fix, or '' when nothing is wrong."""
    if info and info.get('unusable'):
        return ('WARNING: the live %s model cannot be used (%s). No gv:%s verdicts are written until it is replaced; the guard keeps working '
                'without that signal (nothing is blocked more because of it). The next nightly run trains a new one by itself%s.'
                % (kind, info.get('error', 'unreadable'), kind,
                   '' if kind == 'ml' else ' once there are enough labelled sessions'))
    if not info or not info.get('stale'):
        return ''
    return ('WARNING: the live %s model is stale (%s). No gv:%s verdicts will be '
            'written until it is replaced, and if signals.%s is on the effective '
            'score has silently dropped. Fix: run_nightly.py --%s --candidate, '
            'then ctl.py promote-model %s.'
            % (kind, info.get('error', 'feature order mismatch'), kind, kind,
               'train' if kind == 'ml' else 'train-clf', kind))
