"""Per-session feature extraction.

Every feature is computed only from fields the Phase 1 guard already logs - no
new capture, no fingerprinting. All functions are pure: they take a session
dict from logs.sessionize and return numbers.

FEATURE_ORDER is the contract between training and scoring. The model only ever
sees the numeric block below; the labels further down are used to filter the
training set and to feed the reputation formula, and are deliberately NOT
features (they encode outcomes the guard produced, not client behaviour).
"""

import re

FEATURE_ORDER = [
    'n_req',
    'dur_s',
    'gap_mean',
    'gap_std',
    'gap_min',
    'nav_ratio',
    'path_uniq_ratio',
    'score_mean',
    'script_ratio',
    'few_hdr_ratio',
    'no_al_ratio',
    'detail_no_listing_ratio',
    # --- Phase 4 response outcomes. APPENDED, never inserted: the order is the
    # contract between training and scoring, and reordering it silently
    # mislabels every column of an existing model.
    'notfound_ratio',
    'err_ratio',
    'srv_err_ratio',
    'bytes_mean',
    'outcome_cov',
]


def _mean(values):
    return float(sum(values)) / len(values) if values else 0.0


def _std(values):
    if len(values) < 2:
        return 0.0
    mean = _mean(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return variance ** 0.5


def _compile(patterns):
    compiled = []
    for pattern in patterns or []:
        try:
            compiled.append(re.compile(pattern))
        except re.error:
            continue          # an operator typo must not break the nightly run
    return compiled


def _matches(compiled, path):
    for rx in compiled:
        if rx.search(path):
            return True
    return False


def _has_reason(row, code):
    reasons = row.get('rs')
    return isinstance(reasons, list) and code in reasons


def detail_no_listing_ratio(rows, path_listing=None, path_detail=None):
    """Share of detail-page hits reached without any listing page earlier.

    A human browses a category and then opens products; a scraper walks a URL
    list straight into detail pages. Returns 0.0 when the operator has not
    configured any path patterns.
    """
    listing = _compile(path_listing)
    detail = _compile(path_detail)
    if not listing or not detail:
        return 0.0
    seen_listing = False
    total = 0
    cold = 0
    for row in rows:
        path = str(row.get('p') or '')
        if _matches(detail, path):
            total += 1
            if not seen_listing:
                cold += 1
        if _matches(listing, path):
            seen_listing = True
    return float(cold) / total if total else 0.0


def outcome_features(rows):
    """Response-outcome features for one session's rows.

    Ratios are computed over OUTCOME-KNOWN rows only, never over all rows. A
    session where only a third of requests produced an outcome line would
    otherwise look artificially clean, because the unknown two thirds would
    count as "not a 404". outcome_cov is what tells the model how much weight
    the other four deserve, which is why it belongs in the vector rather than
    being treated as metadata.

    Every value is 0.0 for a session recorded before capture was enabled, so old
    sessions stay usable - they simply carry no outcome signal.
    """
    rows = rows or []
    total = len(rows)
    if total == 0:
        return {'notfound_ratio': 0.0, 'err_ratio': 0.0, 'srv_err_ratio': 0.0,
                'bytes_mean': 0.0, 'bytes_n': 0.0, 'outcome_cov': 0.0}

    known = 0
    notfound = 0
    other_4xx = 0
    server_err = 0
    byte_values = []
    for row in rows:
        out = row.get('_out')
        if not isinstance(out, dict):
            continue
        try:
            status = int(out.get('st') or 0)
        except (TypeError, ValueError):
            continue
        if status <= 0:
            continue
        known += 1
        if status == 404:
            notfound += 1
        elif 400 <= status <= 499:
            other_4xx += 1
        elif status >= 500:
            server_err += 1
        size = out.get('by')
        if isinstance(size, (int, float)) and not isinstance(size, bool) and size >= 0:
            byte_values.append(float(size))

    if known == 0:
        return {'notfound_ratio': 0.0, 'err_ratio': 0.0, 'srv_err_ratio': 0.0,
                'bytes_mean': 0.0, 'bytes_n': 0.0, 'outcome_cov': 0.0}

    return {
        'notfound_ratio': float(notfound) / known,
        'err_ratio': float(other_4xx) / known,
        'srv_err_ratio': float(server_err) / known,
        'bytes_mean': _mean(byte_values),
        # Count of byte-known rows. bytes_mean is the mean over THESE rows, so
        # bytes_mean * bytes_n is the exact total bytes moved; peak_bytes used
        # n_req (all rows) and so over-estimated under partial coverage. Not in
        # FEATURE_ORDER, so this does not change any serialized feature vector.
        'bytes_n': float(len(byte_values)),
        'outcome_cov': float(known) / total,
    }


def session_features(session, path_listing=None, path_detail=None):
    """Return the numeric feature dict for one session."""
    rows = session.get('rows') or []
    n_req = len(rows)
    if n_req == 0:
        base = dict((name, 0.0) for name in FEATURE_ORDER)
        base['bytes_n'] = 0.0     # not a FEATURE_ORDER column; kept for peak_bytes
        return base

    stamps = []
    for row in rows:
        try:
            stamps.append(float(row.get('ts', 0)))
        except (TypeError, ValueError):
            stamps.append(0.0)
    stamps.sort()

    gaps = [stamps[i + 1] - stamps[i] for i in range(len(stamps) - 1)]
    paths = [str(row.get('p') or '') for row in rows]
    scores = []
    for row in rows:
        try:
            scores.append(float(row.get('sc', 0)))
        except (TypeError, ValueError):
            scores.append(0.0)

    navs = sum(1 for row in rows if int(row.get('nav') or 0) == 1)

    out = {
        'n_req': float(n_req),
        'dur_s': float(stamps[-1] - stamps[0]),
        'gap_mean': _mean(gaps),
        'gap_std': _std(gaps),
        'gap_min': float(min(gaps)) if gaps else 0.0,
        'nav_ratio': float(navs) / n_req,
        'path_uniq_ratio': float(len(set(paths))) / n_req,
        'score_mean': _mean(scores),
        'script_ratio': float(sum(1 for r in rows if _has_reason(r, 'UA_SCRIPT'))) / n_req,
        'few_hdr_ratio': float(sum(1 for r in rows if _has_reason(r, 'FEW_HDR'))) / n_req,
        'no_al_ratio': float(sum(1 for r in rows if _has_reason(r, 'NO_AL'))) / n_req,
        'detail_no_listing_ratio': detail_no_listing_ratio(rows, path_listing, path_detail),
    }
    out.update(outcome_features(rows))
    return out


HP_HIST_SCORE = 40          # what the guard adds to the static score of a request from a client that tripped the honeypot before


def is_honeypot_row(row):
    """The request that tripped the honeypot (the guard answers it with act 404_hp and sets hp)."""
    try:
        return int(row.get('hp') or 0) == 1 or str(row.get('act') or '') == '404_hp'
    except (TypeError, ValueError):
        return False


def clf_features(features, session):
    """The feature dict the SUPERVISED CLASSIFIER learns from and scores with: `features` with score_mean and notfound_ratio
    recomputed so they no longer encode the event that labels an identity a bot.

    The classifier's positive label is a honeypot hit. That same event inflated two of its inputs: every later request of the
    device carries HP_HIST (+40 in the logged static score, averaged into score_mean), and the honeypot request itself is an
    answered 404 (counted in notfound_ratio). A model that sees them partly re-derives the label it is trained on and looks more
    precise than it is. Here the honeypot request is left out of both, and the HP_HIST contribution is taken out of each row's
    score. Every other feature, the anomaly model's vector and the reputation formula are untouched. Pure.
    """
    out = dict(features)
    rows = [r for r in (session.get('rows') or []) if not is_honeypot_row(r)]
    scores = []
    for row in rows:
        try:
            value = float(row.get('sc', 0))
        except (TypeError, ValueError):
            value = 0.0
        if _has_reason(row, 'HP_HIST'):
            value = max(0.0, value - HP_HIST_SCORE)
        scores.append(value)
    out['score_mean'] = _mean(scores)
    out['notfound_ratio'] = outcome_features(rows)['notfound_ratio']
    return out


def clf_vector(features, session):
    """feature_vector() of clf_features(): the classifier's input for one session."""
    return feature_vector(clf_features(features, session))


def feature_vector(features):
    """Flatten a feature dict into the fixed order the model expects."""
    return [float(features.get(name, 0.0)) for name in FEATURE_ORDER]


def session_labels(session, device_history=None):
    """Return the outcome labels for a session, widened by the device's window.

    hp_any             the session or the device tripped the honeypot
    challenge_unsolved the device was actually served a challenge or a 403 and
                       never completed a handshake. Shadow rows (sh == 1) do not
                       count: nothing was served, so nothing could be solved.
    solved_challenge   the device completed a handshake at least once
    """
    rows = list(session.get('rows') or [])
    if device_history:
        rows = rows + list(device_history)

    hp_any = 0
    served_gate = 0
    solved = 0
    for row in rows:
        if int(row.get('hp') or 0) == 1:
            hp_any = 1
        act = str(row.get('act') or '')
        shadow = int(row.get('sh') or 0) == 1
        if act == 'token_issued':      # deliberately NOT token_was_issued(): a shadowed
            solved = 1                 # handshake (proof of work skipped) is no human evidence
        elif act in ('challenge', '403') and not shadow:
            served_gate = 1

    return {
        'hp_any': hp_any,
        'challenge_unsolved': 1 if (served_gate and not solved) else 0,
        'solved_challenge': solved,
    }
