"""Training-label derivation, and the circularity guard.

WHY challenge_unsolved IS NOT A TRAINING LABEL
----------------------------------------------
challenge_unsolved records that the guard served a gate and got no answer. It
is the guard's own decision handed back as ground truth. A model trained on it
learns to reproduce the rules that produced it - it will score brilliantly
offline, agree with the existing rules almost perfectly, and add nothing
whatsoever in production, because everything it flags was already flagged.
Worse, it inherits every bias of those rules, including their false positives:
a real customer on a locked-down browser who could not run the challenge script
is labelled a bot and teaches the model to block people like them.

It stays a reputation input, where its circularity is visible, bounded by a
fixed weight, and easy to reason about. It never becomes a label.

The positives below are all independent of the guard's gating decisions: a
honeypot hit is a link no human can see, a botv=='bad' verdict comes from
reverse DNS the guard never consults in band, and ground truth comes from the
operator. The negatives require evidence of a person, not merely the absence of
evidence of a bot.
"""

from __future__ import print_function

import os
import sys

# A negative needs all of these. Deliberately strict: a wrong negative teaches
# the model that a scraper is a customer, which is the expensive direction.
MIN_HUMAN_DWELL_S = 20.0    # median session dwell that reads as a real visit
MIN_HUMAN_SESSIONS = 2      # one session is not a browsing history


def load_ground_truth(path):
    """Read an operator label file into {identity: 0|1}.

    Format: one `key,label` per line; blank lines and # comments ignored.
    A missing or unreadable file yields an empty dict - ground truth is
    optional, and its absence must never be an error.

    This is how real labels enter the system: run a scraper you control against
    a staging copy, then list those device ids or addresses as positives.
    """
    truth = {}
    if not path or not os.path.isfile(path):
        return truth
    try:
        with open(path, 'r') as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ',' not in line:
                    continue
                key, _, label = line.partition(',')
                key = key.strip()
                label = label.strip()
                if not key or label not in ('0', '1'):
                    continue
                truth[key] = int(label)
    except Exception as exc:
        print('WARN: could not read ground truth from %s: %s' % (path, exc), file=sys.stderr)
        return {}
    return truth


def bot_labels(session, labels, rows, ground_truth=None, session_count=1,
               median_dwell=None):
    """Return 1 (bot), 0 (human) or None (excluded from training).

    session: a session dict from logs.sessionize
    labels:  the outcome labels from features.session_labels
    rows:    the rows to inspect for independent evidence
    ground_truth: optional {identity: 0|1} from the operator
    session_count: how many sessions this identity has in the window
    median_dwell: median dur_s across the identity's sessions
    """
    session = session or {}
    labels = labels or {}
    rows = rows or []
    ground_truth = ground_truth or {}

    # Operator ground truth wins over everything inferred.
    for identity in (session.get('dev') or '', session.get('key') or '',
                     session.get('ip') or ''):
        if identity and identity in ground_truth:
            return int(ground_truth[identity])

    # Positive: a link no human can see.
    if int(labels.get('hp_any') or 0) == 1:
        return 1

    # Positive: reverse DNS refuted a known-bot claim. The guard never does
    # this lookup in band, so the label owes nothing to its decisions.
    for row in rows:
        if str(row.get('botv') or '') == 'bad':
            return 1

    # Negative: evidence of a person. Solved the handshake, browsed for a
    # while, came back more than once, and never announced itself as a client
    # library. challenge_unsolved is deliberately absent from this test.
    script_ratio = 0.0
    try:
        script_ratio = float((session.get('features') or {}).get('script_ratio', 0.0))
    except (TypeError, ValueError):
        script_ratio = 0.0
    if median_dwell is None:
        median_dwell = 0.0

    if (int(labels.get('solved_challenge') or 0) == 1
            and float(median_dwell) >= MIN_HUMAN_DWELL_S
            and int(session_count) >= MIN_HUMAN_SESSIONS
            and script_ratio == 0.0):
        return 0

    # Everything else, including challenge_unsolved on its own.
    return None


def holdout_outcomes(sessions):
    """Aggregate counts over holdout sessions only, for the false-negative
    estimate in the report.

    The holdout is the one slice this system has not already shaped with its
    own enforcement, so it is the only place where "how much did we miss?" has
    an answer. Counts are aggregate on purpose: a holdout identity is never
    challenged, so it never gets a token and has no stable device id.
    """
    out = {
        'sessions': 0,
        'requests': 0,
        'honeypot_sessions': 0,
        'would_challenge': 0,
        'would_403': 0,
        'identities': 0,
    }
    seen = set()
    for session in sessions or []:
        rows = [r for r in (session.get('rows') or []) if int(r.get('hold') or 0) == 1]
        if not rows:
            continue
        out['sessions'] += 1
        out['requests'] += len(rows)
        key = session.get('key') or ''
        if key and key not in seen:
            seen.add(key)
        if any(int(r.get('hp') or 0) == 1 for r in rows):
            out['honeypot_sessions'] += 1
        for row in rows:
            act = str(row.get('act') or '')
            if act == 'challenge':
                out['would_challenge'] += 1
            elif act == '403':
                out['would_403'] += 1
    out['identities'] = len(seen)
    return out
