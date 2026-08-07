"""Pure Python mirror of the guard's scoring fold and decision.

This module mirrors exactly two PHP functions and nothing else:
gv_effective_score and gv_decide. Keeping decision logic in two languages is a
maintenance hazard; scripts/decision-parity.php plus the parity assertions in
selftest.py are what make it acceptable. If you change either function here or
there, the parity test fails until both match again. Do not add behaviour to
this module that the guard does not have.
"""

import math


def php_round(value):
    """Round half away from zero, the way PHP's round() does.

    Python's built-in round() is banker's rounding: round(0.5) is 0 and
    round(1.5) is 2. PHP returns 1 and 2. An ml level of 5 at weight 0.1 is
    exactly 0.5, so this is not a theoretical difference - it is the first
    case that breaks a naive port, and the parity matrix tests it directly.
    """
    value = float(value)
    if value >= 0:
        return int(math.floor(value + 0.5))
    return int(math.ceil(value - 0.5))


def effective_score(sc, rep, ml, clf, cfg):
    """Mirror of gv_effective_score.

    Shadow-first: each signal contributes only when its toggle is on. rep == 0,
    ml == -1 and clf == -1 are the absent-verdict sentinels and never
    contribute; a level of 0 is a real verdict that happens to be worth zero.
    """
    signals = (cfg or {}).get('signals') or {}
    esc = int(sc)
    if signals.get('reputation') and int(rep) != 0:
        esc += int(rep)
    if signals.get('ml') and int(ml) >= 0:
        esc += php_round(int(ml) * float(cfg.get('ml_weight', 0.4)))
    if signals.get('clf') and int(clf) >= 0:
        esc += php_round(int(clf) * float(cfg.get('clf_weight', 0.5)))
    return esc


def decide(esc, over, nav, tok, hard_block_score, ovr):
    """Mirror of gv_decide. First match wins."""
    if ovr == 'deny':
        return '403'
    if int(esc) >= int(hard_block_score) and nav:
        return '403'
    if over:
        return '429'
    # Only navigations reach this rule, so POST, XHR and REST clients are never
    # challenged.
    if nav and tok != 'v':
        return 'challenge'
    return 'allow'
