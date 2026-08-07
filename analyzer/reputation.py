"""Behavioural reputation: a transparent additive formula, not a black box.

Sign convention matches the guard: POSITIVE is suspicious and pushes a device
toward challenge or block, NEGATIVE is trustworthy and can rescue a borderline
session. Every weight and threshold below is a named constant so an operator
can tune the formula without reading any logic.
"""

# --- positive weights: evidence of automation -----------------------------
W_HONEYPOT = 40            # followed a link no human can see
W_CHALLENGE_UNSOLVED = 20  # was actually served a gate and never completed it
W_METRONOMIC = 15          # request gaps too regular to be hand-driven
W_FAST_RATE = 15           # sustained request rate above a human ceiling
W_SCRIPT_UA = 15           # self-identifying HTTP client library
W_COLD_DETAIL = 10         # jumps into detail pages without browsing a listing

# --- negative weights: evidence of a real person --------------------------
W_SOLVED_HUMAN = -20       # completed the JS/cookie handshake and browsed plausibly
W_VARIED_BROWSING = -10    # wide path spread with irregular, human-like timing

# --- thresholds -----------------------------------------------------------
EPS_GAP_STD = 0.15         # seconds of gap jitter below which timing is metronomic
MIN_REQ_METRONOMIC = 5     # need this many requests before flat timing means anything
MAX_HUMAN_RATE = 2.0       # requests per second a real browser session stays under
COLD_DETAIL_RATIO = 0.7    # share of detail hits with no preceding listing
# Plausible share of top-level navigations. The upper bound is 1.0 on purpose:
# on a server-rendered site almost every logged request IS a navigation, so
# only a session that is nearly all non-navigation traffic is excluded here.
NAV_RATIO_HUMAN = (0.2, 1.0)
MIN_HUMAN_DWELL_S = 20.0   # a real visit lasts at least this long
HIGH_PATH_UNIQ = 0.6       # share of distinct paths that reads as exploring
IRREGULAR_GAP_STD = 1.0    # gap jitter above which timing looks hand-driven


def _median(values):
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return float(ordered[middle])
    return (float(ordered[middle - 1]) + float(ordered[middle])) / 2.0


def _median_of(sessions, name):
    return _median([float(s.get(name, 0.0)) for s in sessions])


def peak_rate(sessions):
    """Highest sustained requests-per-second across a device's sessions."""
    best = 0.0
    for features in sessions:
        n_req = float(features.get('n_req', 0.0))
        rate = n_req / max(float(features.get('dur_s', 0.0)), 1.0)
        if rate > best:
            best = rate
    return best


def device_reputation(sessions, labels, clamp, max_human_rate=MAX_HUMAN_RATE):
    """Score one device from its session feature dicts and aggregated labels.

    sessions: list of feature dicts produced by features.session_features
    labels:   dict with hp_any, challenge_unsolved, solved_challenge
    clamp:    [low, high] bounds applied to the sum
    """
    if not sessions:
        return 0

    labels = labels or {}
    score = 0

    if int(labels.get('hp_any') or 0) == 1:
        score += W_HONEYPOT
    if int(labels.get('challenge_unsolved') or 0) == 1:
        score += W_CHALLENGE_UNSOLVED

    gap_std = _median_of(sessions, 'gap_std')
    n_req = _median_of(sessions, 'n_req')
    if gap_std < EPS_GAP_STD and n_req >= MIN_REQ_METRONOMIC:
        score += W_METRONOMIC

    if peak_rate(sessions) > max_human_rate:
        score += W_FAST_RATE

    if _median_of(sessions, 'script_ratio') > 0:
        score += W_SCRIPT_UA

    # Only meaningful once the operator has configured path patterns; the
    # feature is a flat 0.0 otherwise, so this rule stays inert by default.
    if _median_of(sessions, 'detail_no_listing_ratio') > COLD_DETAIL_RATIO:
        score += W_COLD_DETAIL

    nav_ratio = _median_of(sessions, 'nav_ratio')
    dur_s = _median_of(sessions, 'dur_s')
    if (int(labels.get('solved_challenge') or 0) == 1
            and NAV_RATIO_HUMAN[0] <= nav_ratio <= NAV_RATIO_HUMAN[1]
            and dur_s >= MIN_HUMAN_DWELL_S):
        score += W_SOLVED_HUMAN

    if _median_of(sessions, 'path_uniq_ratio') >= HIGH_PATH_UNIQ and gap_std >= IRREGULAR_GAP_STD:
        score += W_VARIED_BROWSING

    low, high = int(clamp[0]), int(clamp[1])
    return max(low, min(high, int(score)))


def aggregate_labels(per_session_labels):
    """Fold a device's per-session labels into one dict (any-of semantics)."""
    result = {'hp_any': 0, 'challenge_unsolved': 0, 'solved_challenge': 0}
    for labels in per_session_labels:
        for name in result:
            if int(labels.get(name) or 0) == 1:
                result[name] = 1
    # A device that solved a handshake at some point in the window is not an
    # unsolved-challenge case, whatever an individual session looked like.
    if result['solved_challenge'] == 1:
        result['challenge_unsolved'] = 0
    return result
