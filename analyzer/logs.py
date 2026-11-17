"""Reading Phase 1 JSONL logs and turning them into sessions.

Both functions here are pure: read_lines only touches the filesystem it is
given, sessionize is arithmetic over a row list. Neither raises on malformed
input - a truncated or corrupt line is skipped, because a half-written log line
must never take down a nightly job.
"""

import datetime
import gzip
import io
import json
import os

from analyzer import outcomes as outcomes_mod


# Handshake outcomes. The guard logs exactly one line per handshake POST:
#   token_issued                                   a token was issued
#   nonce_bad / nonce_replay / pow_bad (sh=0)      refused with 403
#   mint_limited (sh=0)                            refused with 429
#   nonce_replay / pow_bad / mint_limited (sh=1)   would have been refused, but
#       enforcement is off, so the token WAS issued (shadow-first).
# The challenge funnel therefore counts a shadowed rejection as an issued token
# and a non-shadow rejection as a failed handshake. Shadowed rejections are NOT
# human evidence (see features.py / labels): a token that skipped its proof of
# work proves nothing about who asked for it.
HANDSHAKE_REJECTIONS = ('nonce_bad', 'nonce_replay', 'pow_bad', 'mint_limited')
HANDSHAKE_SHADOW_ACTS = ('nonce_replay', 'pow_bad', 'mint_limited')


def token_was_issued(row):
    """True when this handshake line ended with a token in the client's hands."""
    act = str(row.get('act') or '')
    if act == 'token_issued':
        return True
    return act in HANDSHAKE_SHADOW_ACTS and int(row.get('sh') or 0) == 1


def handshake_rejected(row):
    """True when this handshake line ended with a refusal."""
    act = str(row.get('act') or '')
    if act == 'nonce_bad':
        return True
    return act in HANDSHAKE_REJECTIONS and int(row.get('sh') or 0) == 0


def _read_file(path, opener):
    """Read one log file into a row list. A corrupt line is skipped, never fatal."""
    rows = []
    try:
        handle = opener(path, 'rt', encoding='utf-8', errors='replace')
    except Exception:
        return rows
    try:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue                  # skip the bad line, keep the file
            if isinstance(row, dict) and _clean(row):
                rows.append(row)
    except Exception:
        pass
    finally:
        try:
            handle.close()
        except Exception:
            pass
    return rows


def read_lines(log_dir, window_days, today=None, join_outcomes=True):
    """Yield decision rows from the last window_days of guard-YYYYMMDD.jsonl[.gz].

    Phase 4 writes two line kinds into the same file. This joins them file by
    file and yields only decision rows, each carrying `_out` - the matched
    outcome dict, or None. Callers above this point never see outcome lines and
    do not have to know they exist.

    Set join_outcomes=False to get the raw rows of both kinds, which is what the
    report needs when it wants to count outcome lines directly.
    """
    if today is None:
        today = datetime.date.today()
    for offset in range(int(window_days)):
        day = today - datetime.timedelta(days=offset)
        stem = os.path.join(log_dir, 'guard-%s.jsonl' % day.strftime('%Y%m%d'))
        for path, opener in ((stem, io.open), (stem + '.gz', gzip.open)):
            if not os.path.isfile(path):
                continue
            rows = _read_file(path, opener)
            if not join_outcomes:
                for row in rows:
                    yield row
                continue
            joined, _collisions = outcomes_mod.join(rows)
            for row in joined:
                yield row


def session_key(row):
    """Return (key, is_device). The stable device_id wins; ip|uah is the fallback."""
    dev = str(row.get('dev') or '')
    if dev:
        return dev, True
    return '%s|%s' % (row.get('ip') or '', row.get('uah') or ''), False


def sessionize(rows, gap_s):
    """Group rows into sessions. An idle gap larger than gap_s starts a new one."""
    buckets = {}
    for row in rows:
        try:
            ts = float(row.get('ts', 0))
        except (TypeError, ValueError):
            continue
        key, is_device = session_key(row)
        if key in ('', '|'):
            continue
        buckets.setdefault(key, {'is_device': is_device, 'rows': []})
        buckets[key]['rows'].append((ts, row))

    sessions = []
    for key in sorted(buckets):
        bucket = buckets[key]
        ordered = [row for _, row in sorted(bucket['rows'], key=lambda pair: pair[0])]
        current = []
        previous_ts = None
        for row in ordered:
            ts = float(row.get('ts', 0))
            if previous_ts is not None and (ts - previous_ts) > gap_s:
                sessions.append(_make_session(key, bucket['is_device'], current))
                current = []
            current.append(row)
            previous_ts = ts
        if current:
            sessions.append(_make_session(key, bucket['is_device'], current))
    return sessions


def _make_session(key, is_device, rows):
    last = rows[-1]
    return {
        'key': key,
        'is_device': is_device,
        'dev': str(last.get('dev') or '') if is_device else '',
        'ip': str(last.get('ip') or ''),
        'uah': str(last.get('uah') or ''),
        'rows': rows,
    }


def device_history(sessions):
    """Map every session key to the flat list of its rows across the window."""
    history = {}
    for session in sessions:
        history.setdefault(session['key'], []).extend(session['rows'])
    return history


# Fields every consumer reads with int(). The guard always writes numbers, but a
# log can be hand-edited or damaged, and one row with a string or a list in one
# of these used to raise in whichever job read it first: nightly, snapshot,
# report and replay all died on it, and under cron nobody saw why.
_INT_FIELDS = ('nav', 'gate', 'aj', 'al', 'hc', 'sc', 'esc', 'cd', 'cdh', 'cdd', 'ciu', 'ci',
               'rd', 'hp', 'rep', 'ml', 'clf', 'hold', 'sh', 'st', 'by')


def _clean(row):
    """Coerce the integer fields of a row in place; False drops the row."""
    for name in _INT_FIELDS:
        value = row.get(name)
        if value is None or (isinstance(value, int) and not isinstance(value, bool)):
            continue
        try:
            if isinstance(value, (list, dict)):
                return False
            row[name] = int(float(value))
        except (TypeError, ValueError, OverflowError):
            return False
    return True
