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


def session_features(session, path_listing=None, path_detail=None):
    """Return the numeric feature dict for one session."""
    rows = session.get('rows') or []
    n_req = len(rows)
    if n_req == 0:
        return dict((name, 0.0) for name in FEATURE_ORDER)

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

    return {
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
        if act == 'token_issued':
            solved = 1
        elif act in ('challenge', '403') and not shadow:
            served_gate = 1

    return {
        'hp_any': hp_any,
        'challenge_unsolved': 1 if (served_gate and not solved) else 0,
        'solved_challenge': solved,
    }
