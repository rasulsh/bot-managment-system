"""Reading Phase 1 JSONL logs and turning them into sessions.

The readers here only touch the filesystem they are given and sessionize is
arithmetic over a row list. None of them raises on malformed input - a truncated
or corrupt line is skipped, because a half-written log line must never take down
a nightly job. read_lines is a generator; analyzer/ingest.py keeps the incremental
store the 15-minute jobs read instead of the logs.
"""

import datetime
import gzip
import io
import json
import os
import sys



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


def _open_text(path, gz):
    opener = gzip.open if gz else io.open
    return opener(path, 'rt', encoding='utf-8', errors='replace')


def _iter_file(path, gz):
    """Yield the clean rows of one log file, one at a time. A corrupt line is skipped, never fatal."""
    try:
        handle = _open_text(path, gz)
    except Exception:
        return
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
                yield row
    except Exception:
        pass
    finally:
        try:
            handle.close()
        except Exception:
            pass


def _read_file(path, opener):
    """Read one log file into a row list (for callers and tests that want the list)."""
    return list(_iter_file(path, opener is gzip.open))


def day_files(log_dir, day):
    """The files that hold one day of the log, oldest content first: [(path, is_gz)].

    A finished day is gzipped by scripts/guard-logrotate.sh, which writes the archive under a temporary name, renames it
    and only then removes the plain file. Both names can therefore exist for a moment (or after an interruption), and then
    the archive holds the same rows as the plain file: reading both counted every row twice. The rule:
      only one of them exists                  -> that one;
      both exist, the archive is not older     -> the plain file only (it is complete, the archive is a copy of it);
      both exist, the archive is OLDER than the plain file -> the archive, then the plain file. That is a day that was
          compressed and then written to again (a guard whose time zone differs from the host's): the two are disjoint.
    """
    stem = os.path.join(log_dir, 'guard-%s.jsonl' % day.strftime('%Y%m%d'))
    plain = os.path.isfile(stem)
    gz = os.path.isfile(stem + '.gz')
    if plain and gz:
        try:
            if os.path.getmtime(stem + '.gz') < os.path.getmtime(stem):
                return [(stem + '.gz', True), (stem, False)]
        except OSError:
            pass
        return [(stem, False)]
    if plain:
        return [(stem, False)]
    if gz:
        return [(stem + '.gz', True)]
    return []


def iter_day(files, join_outcomes=True, fields=None):
    """Yield one day's rows from its files (see day_files). Memory stays flat: a decision row is not held back for its outcome.

    The outcome lines of the day (about one per decision, tiny) are indexed in a first pass that parses only lines that
    contain the key "o"; the second pass yields decision rows with `_out` set. join_outcomes=False yields every row of both
    kinds in file order. `fields` keeps only those keys of each decision row (plus `_out`): a consumer that reads a dozen
    keys does not pay for fifty.
    """
    if not join_outcomes:
        for path, gz in files:
            for row in _iter_file(path, gz):
                yield row
        return
    index = {}
    for path, gz in files:
        try:
            handle = _open_text(path, gz)
        except Exception:
            continue
        try:
            for line in handle:
                if '"o"' not in line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if isinstance(row, dict) and row.get('o') == 1 and _clean(row):
                    rid = row.get('rid')
                    if rid and isinstance(rid, str) and rid not in index:
                        index[rid] = row
        except Exception:
            pass
        finally:
            try:
                handle.close()
            except Exception:
                pass
    for path, gz in files:
        for row in _iter_file(path, gz):
            if row.get('o') == 1:
                continue
            rid = row.get('rid')
            out = index.get(rid) if isinstance(rid, str) else None
            if fields is not None:
                row = dict((k, row[k]) for k in fields if k in row)
                for k in _INTERNED:                 # the same few thousand strings, once each instead of once per row
                    v = row.get(k)
                    if v.__class__ is str:
                        row[k] = sys.intern(v)
                if row.get('rs') == []:
                    row['rs'] = _NO_REASONS         # one shared empty list-like instead of a list per row
                if out is not None:                 # only what the readers use (status class, bytes), not the whole outcome line
                    out = {'st': out.get('st'), 'by': out.get('by')}
            row['_out'] = out
            yield row


def read_lines(log_dir, window_days, today=None, join_outcomes=True, fields=None):
    """Yield decision rows from the last window_days of guard-YYYYMMDD.jsonl[.gz].

    Phase 4 writes two line kinds into the same file. This joins them file by
    file and yields only decision rows, each carrying `_out` - the matched
    outcome dict, or None. Callers above this point never see outcome lines and
    do not have to know they exist.

    Set join_outcomes=False to get the raw rows of both kinds, which is what the
    report needs when it wants to count outcome lines directly.

    A generator, one day at a time: a caller that only aggregates holds one row; one that needs the whole window (sessions)
    keeps the rows it needs. See day_files() for which files make up a day.
    """
    if today is None:
        today = datetime.date.today()
    for offset in range(int(window_days)):
        day = today - datetime.timedelta(days=offset)
        for row in iter_day(day_files(log_dir, day), join_outcomes, fields):
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


# The keys of a decision row each job actually reads (found by reading the code, kept by a test that runs the job on a fixture
# with and without the projection). A job that passes `fields` to read_lines holds a dozen keys per row instead of fifty, which is
# what lets a week of a busy site's rows fit in memory. `_out` (the outcome) is always attached.
SESSION_FIELDS = ('ts', 'ip', 'dev', 'uah', 'p', 'sc', 'esc', 'nav', 'rs', 'hp', 'act', 'sh', 'hold', 'botv', 'clf', 'ml', 'rep', 'tok')
REPLAY_FIELDS = SESSION_FIELDS + ('gate', 'ovr', 'ua', 'bot')
REPORT_FIELDS = REPLAY_FIELDS + ('ms', 'rd', 'q', 'cc', 'asn')
_NO_REASONS = ()
_INTERNED = ('ip', 'dev', 'uah', 'p', 'act', 'tok', 'botv', 'ua', 'bot', 'cc')


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
