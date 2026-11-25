"""Isolation Forest anomaly detection - offline only.

The model NEVER runs in the request path. It is trained here, its verdict is
written to Redis as a plain integer, and the in-band guard reads that integer.

The import of scikit-learn is guarded: the rest of the analyzer must keep
working on a host where the package is missing, so the entry points degrade to
"no ML this run" instead of crashing.

Training set: confident-human sessions only (no honeypot hit, no unsolved
challenge, no scripted UA). This matters. Isolation Forest learns what "normal"
looks like from whatever it is fed, and in bot-heavy traffic the raw
distribution IS partly bot - training on everything would teach the model that
scraping is normal and quietly neutralise the signal.
"""

import os

from analyzer import fsmode
from analyzer.features import FEATURE_ORDER

try:
    import numpy
    import joblib
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
    SKLEARN_ERROR = ''
except Exception as exc:                      # pragma: no cover - env dependent
    SKLEARN_AVAILABLE = False
    SKLEARN_ERROR = str(exc)


# decision_function magnitude that maps to the end of the 0..100 range. Widen
# it if the levels in your logs bunch up around 50, narrow it if they saturate.
DECISION_SPAN = 0.2


class ModelUnavailable(RuntimeError):
    """Raised when a model operation needs scikit-learn and it is not installed."""


def _require_sklearn():
    if not SKLEARN_AVAILABLE:
        raise ModelUnavailable('scikit-learn/numpy not available: ' + SKLEARN_ERROR)


def is_clean_session(labels, features):
    """Training-set filter: only sessions we are confident came from a person."""
    return (int(labels.get('hp_any') or 0) == 0
            and int(labels.get('challenge_unsolved') or 0) == 0
            and float(features.get('script_ratio') or 0.0) == 0.0)


def train(vectors, contamination, model_path, min_train=200):
    """Fit and persist {scaler, model, feature_order}. Return True when written.

    Returns False - without raising - when there is too little clean data: a
    manifold fitted on a handful of sessions describes noise, not normality.
    """
    _require_sklearn()
    if vectors is None or len(vectors) < int(min_train):
        return False

    matrix = numpy.asarray(vectors, dtype=float)
    if matrix.ndim != 2 or matrix.shape[1] != len(FEATURE_ORDER):
        raise ValueError('training vectors must have %d columns' % len(FEATURE_ORDER))

    scaler = StandardScaler()
    scaled = scaler.fit_transform(matrix)
    model = IsolationForest(contamination=float(contamination), random_state=0)
    model.fit(scaled)

    _dump_atomic({'scaler': scaler, 'model': model, 'feature_order': list(FEATURE_ORDER)},
                 model_path)
    return True


def _dump_atomic(bundle, path):
    """Write a model next to its destination, then rename it into place.

    A dump straight to the live path that is cut short (disk full, a kill)
    leaves a truncated file that is neither missing nor loadable: nothing
    retrains it and verdicts quietly stop. A rename is all-or-nothing.
    """
    tmp = '%s.tmp.%d' % (path, os.getpid())
    try:
        joblib.dump(bundle, tmp)
        fsmode.set_mode(tmp, fsmode.FILE_MODE)       # a model is a pickle: never group-writable, whatever the umask
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def load(model_path):
    """Return the persisted bundle, or None when there is nothing usable."""
    if not SKLEARN_AVAILABLE:
        return None
    try:
        bundle = joblib.load(model_path)
    except Exception:
        return None
    if not isinstance(bundle, dict):
        return None
    if bundle.get('feature_order') != list(FEATURE_ORDER):
        return None                # feature set changed: the model is stale
    if 'scaler' not in bundle or 'model' not in bundle:
        return None
    return bundle


def inspect(model_path):
    """Why a bundle did or did not load. Returns a dict, never raises.

    Distinguishing "no model yet" from "stale model" matters: the second case
    means gv:ml stops being written and, if signals.ml is on, the effective
    score quietly drops for everyone. A system silently becoming more
    permissive is exactly the failure nobody notices, so the caller needs to be
    able to say so out loud.
    """
    out = {'exists': False, 'loadable': False, 'stale': False,
           'feature_order': None, 'error': ''}
    if not os.path.isfile(model_path):
        out['error'] = 'no file at %s' % model_path
        return out
    out['exists'] = True
    if not SKLEARN_AVAILABLE:
        out['error'] = 'scikit-learn unavailable'
        return out
    try:
        bundle = joblib.load(model_path)
    except Exception as exc:
        out['error'] = 'unreadable: %s' % exc
        return out
    if not isinstance(bundle, dict) or 'model' not in bundle or 'scaler' not in bundle:
        # Require exactly what load() requires: a bundle missing its scaler
        # loads as None, so inspect() must not report it loadable - otherwise
        # promote.check() passes a candidate that then yields no ML verdicts,
        # silently making the guard more permissive.
        out['error'] = 'not a model bundle'
        return out
    out['feature_order'] = bundle.get('feature_order')
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
    """score() for many vectors at once: the same levels, one scikit-learn call per SCORE_BATCH instead of one per vector.

    A single decision_function call costs milliseconds whatever its size, so scoring a night's sessions one by one dominated the
    nightly job. A batch that raises is scored vector by vector; a vector that cannot be scored is None.
    """
    _require_sklearn()
    if bundle is None:
        raise ModelUnavailable('no model bundle loaded')
    out = []
    for i in range(0, len(vectors), SCORE_BATCH):
        chunk = vectors[i:i + SCORE_BATCH]
        try:
            matrix = numpy.asarray([list(v) for v in chunk], dtype=float)
            decisions = bundle['model'].decision_function(bundle['scaler'].transform(matrix))
            for d in decisions:
                level = 50.0 - (float(d) / DECISION_SPAN) * 50.0
                out.append(int(max(0, min(100, round(level)))))
        except Exception:
            for v in chunk:
                try:
                    out.append(score(bundle, v))
                except Exception:
                    out.append(None)
    return out


def score(bundle, vector):
    """Map one feature vector to an anomaly level in 0..100 (higher = stranger).

    decision_function is positive for inliers and negative for outliers, and is
    already centred on the contamination boundary chosen at fit time, so 0 is
    the natural midpoint. Isolation Forest keeps that value in a narrow band
    rather than growing without bound, so the mapping spreads DECISION_SPAN of
    magnitude across each half of the range and clamps the tails:

        level = clamp(50 - (decision / DECISION_SPAN) * 50, 0, 100)

    A decision of +DECISION_SPAN (deep inside the normal manifold) gives 0, a
    decision of 0.0 (right on the boundary) gives 50, and -DECISION_SPAN or
    below gives 100. The transform is fixed, so the same vector against the
    same bundle always produces the same level.
    """
    _require_sklearn()
    if bundle is None:
        raise ModelUnavailable('no model bundle loaded')
    matrix = numpy.asarray([list(vector)], dtype=float)
    scaled = bundle['scaler'].transform(matrix)
    decision = float(bundle['model'].decision_function(scaled)[0])
    level = 50.0 - (decision / DECISION_SPAN) * 50.0
    return int(max(0, min(100, round(level))))
