"""Supervised bot classifier - offline only, like every other model here.

Same discipline as model.py: guarded import, persisted bundle, deterministic
scoring, never invoked in the request path. The guard reads one integer from
Redis and knows nothing about any of this.

WHY A SECOND MODEL ON THE SAME FEATURES
---------------------------------------
Feature vectors come from features.FEATURE_ORDER, unchanged. That is
deliberate. An Isolation Forest learns a density - "how unusual is this?" - and
a gradient-boosted classifier learns a boundary - "which side of the labelled
examples does this fall on?". On identical inputs those are genuinely different
signals, and either can be right when the other is wrong. Adding new features
at the same time would make it impossible to tell whether an improvement came
from the new model or the new inputs.

WHY PRECISION, NOT ACCURACY
---------------------------
The classes are heavily imbalanced, so accuracy is meaningless: a model that
calls everything human scores 97% and is worthless. Worse, the two errors do
not cost the same. A false negative is one scraped page. A false positive is a
paying customer who cannot reach the site and does not come back. So the
operating threshold is chosen as the lowest one that still reaches a target
precision on held-out data, and precision, recall, F1 and PR-AUC are printed on
every training run.
"""

from __future__ import print_function

import os

from analyzer import fsmode
from analyzer.features import FEATURE_ORDER

try:
    import numpy
    import joblib
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import (average_precision_score, confusion_matrix,
                                 precision_recall_curve)
    from sklearn.model_selection import train_test_split
    SKLEARN_AVAILABLE = True
    SKLEARN_ERROR = ''
except Exception as exc:                      # pragma: no cover - env dependent
    SKLEARN_AVAILABLE = False
    SKLEARN_ERROR = str(exc)


class ClassifierUnavailable(RuntimeError):
    """Raised when an operation needs scikit-learn and it is not installed."""


def _require_sklearn():
    if not SKLEARN_AVAILABLE:
        raise ClassifierUnavailable('scikit-learn/numpy not available: ' + SKLEARN_ERROR)


def choose_threshold(y_true, scores, target_precision):
    """Lowest probability threshold whose precision reaches the target.

    Lowest, not best: among the thresholds that are precise enough we want the
    one that catches the most bots. Falls back to the most precise threshold
    available when nothing reaches the target, and reports the precision it
    actually achieved so the operator is never misled into enabling a signal
    that did not meet its bar.
    """
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    best = None
    # precision_recall_curve returns len(thresholds) + 1 precision entries.
    for index, cut in enumerate(thresholds):
        if precision[index] >= target_precision:
            if best is None or cut < best[0]:
                best = (float(cut), float(precision[index]), float(recall[index]))
    if best is not None:
        return {'threshold': best[0], 'precision': best[1], 'recall': best[2],
                'reached_target': True}
    # Nothing was precise enough: take the most precise operating point there is.
    index = int(numpy.argmax(precision[:-1])) if len(precision) > 1 else 0
    cut = float(thresholds[index]) if len(thresholds) else 1.0
    return {'threshold': cut, 'precision': float(precision[index]),
            'recall': float(recall[index]), 'reached_target': False}


def train(X, y, model_path, min_positive=50, test_size=0.25,
          target_precision=0.98, random_state=0):
    """Fit, evaluate on a held-out split, and persist. Return True when written.

    Returns False - without raising - when there are too few positives or when
    either class is missing entirely. Both are ordinary situations early in a
    deployment, not errors: a model fitted on eleven bots is a random number
    generator with a confusion matrix.
    """
    _require_sklearn()
    X = list(X or [])
    y = [int(v) for v in (y or [])]
    if len(X) != len(y):
        raise ValueError('X and y must have the same length')

    positives = sum(1 for v in y if v == 1)
    negatives = len(y) - positives
    if positives < int(min_positive):
        return False
    if negatives == 0 or positives == 0:
        return False

    matrix = numpy.asarray(X, dtype=float)
    if matrix.ndim != 2 or matrix.shape[1] != len(FEATURE_ORDER):
        raise ValueError('training vectors must have %d columns' % len(FEATURE_ORDER))
    target = numpy.asarray(y, dtype=int)

    X_train, X_test, y_train, y_test = train_test_split(
        matrix, target, test_size=float(test_size), random_state=random_state,
        stratify=target)

    model = HistGradientBoostingClassifier(random_state=random_state)
    model.fit(X_train, y_train)

    scores = model.predict_proba(X_test)[:, 1]
    chosen = choose_threshold(y_test, scores, float(target_precision))
    predicted = (scores >= chosen['threshold']).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test, predicted, labels=[0, 1]).ravel()
    precision = float(tp) / (tp + fp) if (tp + fp) else 0.0
    recall = float(tp) / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    metrics = {
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'pr_auc': float(average_precision_score(y_test, scores)),
        'confusion': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)},
        'threshold': chosen['threshold'],
        'reached_target': bool(chosen['reached_target']),
        'target_precision': float(target_precision),
        'n_train': int(len(y_train)),
        'n_test': int(len(y_test)),
        'n_positive': int(positives),
        'n_negative': int(negatives),
    }

    from analyzer.model import _dump_atomic
    _dump_atomic({'model': model, 'feature_order': list(FEATURE_ORDER),
                            'threshold': chosen['threshold'], 'metrics': metrics,
                            'trained_at': None}, model_path)
    return True


def load(model_path):
    """Return the persisted bundle, or None when there is nothing usable."""
    if not SKLEARN_AVAILABLE:
        return None
    from analyzer.model import load_bundle
    bundle, problem = load_bundle(model_path)      # never unpickles a file somebody else could have written; a version mismatch is "unusable"
    if problem:
        return None
    if not isinstance(bundle, dict):
        return None
    if bundle.get('feature_order') != list(FEATURE_ORDER):
        return None                # feature set changed: the model is stale
    if 'model' not in bundle:
        return None
    return bundle


def inspect(model_path):
    """Why a classifier bundle did or did not load. Returns a dict, never raises.

    Same reasoning as model.inspect: a stale classifier stops gv:clf being
    written, and with signals.clf on the effective score silently drops.
    """
    out = {'exists': False, 'loadable': False, 'stale': False, 'unusable': False,
           'feature_order': None, 'metrics': None, 'error': ''}
    if not os.path.isfile(model_path):
        out['error'] = 'no file at %s' % model_path
        return out
    out['exists'] = True
    if not SKLEARN_AVAILABLE:
        out['error'] = 'scikit-learn unavailable'
        return out
    from analyzer.model import load_bundle
    bundle, problem = load_bundle(model_path)
    if problem:
        out['error'] = problem
        out['unusable'] = True
        return out
    if not isinstance(bundle, dict) or 'model' not in bundle:
        out['error'] = 'not a classifier bundle'
        return out
    out['feature_order'] = bundle.get('feature_order')
    out['metrics'] = bundle.get('metrics')
    if out['feature_order'] != list(FEATURE_ORDER):
        out['stale'] = True
        out['error'] = ('feature order mismatch: bundle has %d features, the '
                        'analyzer now has %d'
                        % (len(out['feature_order'] or []), len(FEATURE_ORDER)))
        return out
    out['loadable'] = True
    return out


SCORE_BATCH = 20000


def score_many(bundle, vectors):
    """score() for many vectors at once (see model.score_many): the same levels, a vector that cannot be scored is None."""
    _require_sklearn()
    if bundle is None:
        raise ClassifierUnavailable('no classifier bundle loaded')
    out = []
    for i in range(0, len(vectors), SCORE_BATCH):
        chunk = vectors[i:i + SCORE_BATCH]
        try:
            matrix = numpy.asarray([list(v) for v in chunk], dtype=float)
            for p in bundle['model'].predict_proba(matrix)[:, 1]:
                out.append(int(max(0, min(100, round(float(p) * 100)))))
        except Exception:
            for v in chunk:
                try:
                    out.append(score(bundle, v))
                except Exception:
                    out.append(None)
    return out


def score(bundle, vector):
    """Map one feature vector to a bot-likelihood level in 0..100.

    Straight from predict_proba, so the level is a calibrated-ish probability
    rather than an arbitrary scale, and the same vector always yields the same
    number. The operating threshold lives in the bundle for reporting; the
    guard applies its own weight to the level and does not see the threshold.
    """
    _require_sklearn()
    if bundle is None:
        raise ClassifierUnavailable('no classifier bundle loaded')
    matrix = numpy.asarray([list(vector)], dtype=float)
    probability = float(bundle['model'].predict_proba(matrix)[0][1])
    return int(max(0, min(100, round(probability * 100))))


def format_metrics(metrics):
    """One English block an operator can read without opening anything."""
    if not metrics:
        return 'No stored metrics.'
    lines = []
    lines.append('  trained on %d sessions (%d bot, %d human), tested on %d'
                 % (metrics.get('n_train', 0) + metrics.get('n_test', 0),
                    metrics.get('n_positive', 0), metrics.get('n_negative', 0),
                    metrics.get('n_test', 0)))
    lines.append('  precision %.3f   recall %.3f   F1 %.3f   PR-AUC %.3f'
                 % (metrics.get('precision', 0.0), metrics.get('recall', 0.0),
                    metrics.get('f1', 0.0), metrics.get('pr_auc', 0.0)))
    matrix = metrics.get('confusion') or {}
    lines.append('  confusion: tn=%d fp=%d fn=%d tp=%d'
                 % (matrix.get('tn', 0), matrix.get('fp', 0),
                    matrix.get('fn', 0), matrix.get('tp', 0)))
    lines.append('  operating threshold %.3f (target precision %.2f)'
                 % (metrics.get('threshold', 0.0), metrics.get('target_precision', 0.0)))
    if not metrics.get('reached_target', False):
        lines.append('  WARNING: no threshold reached the target precision. Do not enable')
        lines.append('           signals.clf yet - it would restrict real users.')
    return '\n'.join(lines)
