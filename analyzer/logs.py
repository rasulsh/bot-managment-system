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


def read_lines(log_dir, window_days, today=None):
    """Yield row dicts from the last window_days of guard-YYYYMMDD.jsonl[.gz]."""
    if today is None:
        today = datetime.date.today()
    for offset in range(int(window_days)):
        day = today - datetime.timedelta(days=offset)
        stem = os.path.join(log_dir, 'guard-%s.jsonl' % day.strftime('%Y%m%d'))
        for path, opener in ((stem, io.open), (stem + '.gz', gzip.open)):
            if not os.path.isfile(path):
                continue
            try:
                handle = opener(path, 'rt', encoding='utf-8', errors='replace')
            except Exception:
                continue
            try:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue          # skip the bad line, keep the file
                    if isinstance(row, dict):
                        yield row
            except Exception:
                continue
            finally:
                handle.close()


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
