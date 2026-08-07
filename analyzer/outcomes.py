"""Outcome line parsing and the decision/outcome join.

The guard writes two kinds of line into the same daily file: the wide decision
line, written before the host application runs, and a tiny outcome line written
at shutdown. They are correlated by `rid`.

JOIN SCOPE: PER FILE, NOT PER WINDOW.
Both lines for a request are written by the same process, at most seconds or
minutes apart, so they land in the same daily file except for requests that
straddle midnight. Joining file by file keeps memory flat on a busy site -
holding a whole week's rid index would be the single largest allocation in the
analyzer - and loses only those few midnight requests, which then simply carry
no outcome. logs.py performs the split, index and attach for each file before
yielding, so every consumer above it sees decision rows with `_out` already
populated and never has to know outcome lines exist at all.

All three functions are pure.
"""


def split_rows(rows):
    """Partition rows into (decision_rows, outcome_rows) on one cheap key test."""
    decisions = []
    outcomes = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        if row.get('o') == 1:
            outcomes.append(row)
        else:
            decisions.append(row)
    return decisions, outcomes


def index_outcomes(outcome_rows):
    """Map rid -> outcome. Returns (index, collisions).

    A 12-hex-character id collides at a negligible rate, so a collision almost
    always means something is wrong - a log file concatenated twice, a rid
    reused by a broken deployment. The first wins and the count is returned, so
    that is visible rather than silent.
    """
    index = {}
    collisions = 0
    for row in outcome_rows or []:
        rid = row.get('rid')
        if not rid or not isinstance(rid, str):
            continue
        if rid in index:
            collisions += 1
            continue
        index[rid] = row
    return index, collisions


def attach(decision_rows, index):
    """Set `_out` on each decision row to its outcome dict, or None.

    The underscore marks a derived field that was never in the log, so nothing
    downstream mistakes it for something the guard wrote.
    """
    index = index or {}
    for row in decision_rows or []:
        rid = row.get('rid')
        row['_out'] = index.get(rid) if isinstance(rid, str) else None
    return decision_rows


def join(rows):
    """split -> index -> attach in one call. Returns (decision_rows, collisions)."""
    decisions, outcomes = split_rows(rows)
    index, collisions = index_outcomes(outcomes)
    return attach(decisions, index), collisions


def status_class(outcome):
    """Coarse status bucket for one outcome dict, or None when unknown."""
    if not outcome:
        return None
    try:
        status = int(outcome.get('st') or 0)
    except (TypeError, ValueError):
        return None
    if status <= 0:
        return None
    if status == 404:
        return '404'
    if 500 <= status <= 599:
        return '5xx'
    if 400 <= status <= 499:
        return '4xx'
    if 300 <= status <= 399:
        return '3xx'
    if 200 <= status <= 299:
        return '2xx'
    return 'other'
