"""Incremental reading of the guard logs: each byte is parsed once.

The snapshot (every 15 minutes) and the bot verification (every 10 minutes) used to parse 9 and 7 days of JSONL on every run,
about 700 MB on a site that logs 80 MB a day. This module reads only what was appended since the last run and keeps the result
in a small store next to the model file (the analyzer directory), so every later run reads a few megabytes instead:

    .ingest-state.json            one cursor per day file: byte offset into the (uncompressed) log, a fingerprint of its head
    rowstore/d-<day>-<hour>.dat   the decision rows of one source day and one clock hour, reduced to the fields the dashboard
                                  reads (ROW_FIELDS), zlib-compressed JSON frames, appended as the log grows
    rowstore/o-<day>-<hour>.dat   the outcome lines (request id -> status) of the same
    rowstore/h-<day>.dat          the rows that matched an access rule or an IP list (the Rules / readiness numbers need 7 days)
    daily/<day>.json              a summary of one source day: the hourly buckets of hours that left the row store (the 7-day
                                  chart), and the crawler claims per address (bot verification)

The store is DERIVED DATA. Deleting it, or any part of it, costs one slow run that rebuilds it from the logs; nothing here
is read by the guard or the panel, and an older release ignores it (so a rollback through the Update page is safe, and so is
an update again afterwards: the cursors are checked against the files, never trusted).

What a reader gets back is the same rows, in the same order, with the same `_out` as logs.read_lines() would yield for the
same files (newest day first, file order inside a day; an outcome joins a decision of the same day file). The pure functions in
snapshot.py run on them unchanged. A test compares both on a multi-day fixture, including midnight, a gzipped day, a shrunk
file and a missing summary.

Concurrency: update() holds an exclusive flock on .ingest.lock, readers a shared one. A run that dies half-way leaves a
`pending` marker in the state; the next run discards that day's files and reads the day again from byte 0.
Failure policy: callers wrap this in try/except and fall back to reading the logs directly (fail open).
"""

from __future__ import print_function

import datetime
import fcntl
import hashlib
import io
import gzip
import json
import os
import struct
import time
import zlib

from analyzer import fsmode
from analyzer import logs as logs_mod

STORE_VERSION = 1
HOUR = 3600
INGEST_DAYS = 9                  # log days kept in the store: the 7-day dashboard, plus the two the old 9-day read covered
DEFAULT_ROWSTORE_HOURS = 50      # hours of slim rows kept: the 24 h window and the 24 h before it, plus a boundary hour
FINGERPRINT_BYTES = 4096
CHUNK_BYTES = 8 * 1024 * 1024
FLUSH_ROWS = 100000              # rows buffered in memory before they are written out
FUTURE_SLACK_S = 86400           # a row stamped further ahead than this is garbage and is not stored

# The keys of a decision row that snapshot.py's functions read (build, kpi_counts, top_lists, top_mix, funnel_by_level,
# hour_buckets, readiness). A missing key and a null are the same to every reader.
ROW_FIELDS = ('ts', 'ip', 'dev', 'act', 'sh', 'hold', 'rd', 'rs', 'sc', 'esc', 'rep', 'ml', 'clf', 'hp', 'cap', 'ct',
              'cc', 'asn', 'ua', 'p', 'tok', 'rid')
HIT_FIELDS = ('ts', 'ip', 'dev', 'tok', 'rs')


# ---------------------------------------------------------------------------------------------------------------- paths

def base_dir(cfg):
    """The analyzer directory of this install: where the model, the markers and the status files live."""
    return os.path.dirname(os.path.abspath(cfg['model_path']))


def _paths(cfg):
    base = base_dir(cfg)
    return {'base': base, 'state': os.path.join(base, '.ingest-state.json'), 'lock': os.path.join(base, '.ingest.lock'),
            'rows': os.path.join(base, 'rowstore'), 'daily': os.path.join(base, 'daily')}


def _ensure_dirs(p):
    for key in ('rows', 'daily'):
        if not os.path.isdir(p[key]):
            os.makedirs(p[key], 0o755)


# ---------------------------------------------------------------------------------------------------------------- frames

def _frame(obj):
    payload = zlib.compress(json.dumps(obj, separators=(',', ':')).encode('utf-8'), 1)
    return struct.pack('<II', len(payload), zlib.crc32(payload) & 0xffffffff) + payload


def _append_frames(path, frames):
    if not frames:
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, fsmode.FILE_MODE)
    try:
        os.write(fd, b''.join(frames))
    finally:
        os.close(fd)


def _iter_frames(path):
    """Yield the objects of a frame file. A torn or corrupt tail ends the file; it never raises."""
    try:
        handle = open(path, 'rb')
    except OSError:
        return
    try:
        while True:
            head = handle.read(8)
            if len(head) < 8:
                return
            length, crc = struct.unpack('<II', head)
            payload = handle.read(length)
            if len(payload) < length or (zlib.crc32(payload) & 0xffffffff) != crc:
                return
            try:
                yield json.loads(zlib.decompress(payload).decode('utf-8'))
            except Exception:
                return
    finally:
        handle.close()


# ---------------------------------------------------------------------------------------------------------------- state

def _load_json(path, default):
    try:
        with open(path, 'r') as handle:
            data = json.load(handle)
        return data if isinstance(data, type(default)) else default
    except Exception:
        return default


def _write_json(path, data):
    tmp = path + '.tmp%d' % os.getpid()
    with fsmode.open_text(tmp) as handle:
        json.dump(data, handle, separators=(',', ':'))
    os.replace(tmp, path)


def _load_state(p):
    state = _load_json(p['state'], {})
    if state.get('v') != STORE_VERSION or not isinstance(state.get('days'), dict):
        state = {'v': STORE_VERSION, 'days': {}, 'pending': '', 'edge': 0}
    state.setdefault('pending', '')
    state.setdefault('edge', 0)
    return state


class _Lock(object):
    """flock on .ingest.lock: exclusive for the writer, shared for readers. timeout in seconds; None = do not wait."""

    def __init__(self, path, exclusive, timeout):
        self.path, self.exclusive, self.timeout, self.fd = path, exclusive, timeout, None

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, fsmode.FILE_MODE)
        flag = fcntl.LOCK_EX if self.exclusive else fcntl.LOCK_SH
        deadline = time.time() + (self.timeout or 0)
        while True:
            try:
                fcntl.flock(self.fd, flag | fcntl.LOCK_NB)
                return self
            except (IOError, OSError):
                if time.time() >= deadline:
                    os.close(self.fd)
                    self.fd = None
                    raise IOError('the ingest store is busy')
                time.sleep(0.2)

    def __exit__(self, *exc):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
        return False


# ---------------------------------------------------------------------------------------------------------------- sources

class _Chain(object):
    """The uncompressed bytes of a day's files (logs.day_files) as one stream: read(n) and skip(n)."""

    def __init__(self, files):
        self.files = list(files)
        self.cur = None
        self.i = 0
        self.single_plain = len(self.files) == 1 and not self.files[0][1]

    def _next(self):
        if self.cur is not None:
            self.cur.close()
            self.cur = None
        if self.i >= len(self.files):
            return False
        path, gz = self.files[self.i]
        self.i += 1
        try:
            self.cur = gzip.open(path, 'rb') if gz else io.open(path, 'rb')
        except Exception:
            return self._next()
        return True

    def read(self, n):
        while True:
            if self.cur is None and not self._next():
                return b''
            try:
                data = self.cur.read(n)
            except (OSError, EOFError, zlib.error):     # a truncated gzip: what was decoded is all there is
                data = b''
            if data:
                return data
            self.cur.close()
            self.cur = None

    def skip(self, n):
        if n <= 0:
            return 0
        if self.single_plain and self.cur is None and self._next():
            self.cur.seek(n)
            return n
        left = n
        while left > 0:
            data = self.read(min(left, CHUNK_BYTES))
            if not data:
                break
            left -= len(data)
        return n - left

    def head(self, n):
        data = b''
        while len(data) < n:
            part = self.read(n - len(data))
            if not part:
                break
            data += part
        return data

    def close(self):
        if self.cur is not None:
            self.cur.close()
            self.cur = None


def _signature(files):
    sig = []
    for path, gz in files:
        try:
            st = os.stat(path)
            sig.append([os.path.basename(path), st.st_size, int(st.st_mtime)])
        except OSError:
            sig.append([os.path.basename(path), -1, 0])
    return sig


def _fingerprint(files, upto):
    chain = _Chain(files)
    try:
        return hashlib.sha256(chain.head(min(upto, FINGERPRINT_BYTES))).hexdigest()[:32]
    finally:
        chain.close()


def _logical_size(files):
    """Bytes of the plain files (a gzip's uncompressed length is only known by reading it): used to spot a shrunk file."""
    if len(files) == 1 and not files[0][1]:
        try:
            return os.path.getsize(files[0][0])
        except OSError:
            return -1
    return None


# ---------------------------------------------------------------------------------------------------------------- the store

def _parse(line):
    """One log line to a dict, or None. Invalid UTF-8 is replaced, as logs.py (text mode, errors='replace') does."""
    try:
        return json.loads(line)
    except UnicodeDecodeError:
        try:
            return json.loads(line.decode('utf-8', 'replace'))
        except Exception:
            return None
    except Exception:
        return None


def _row_ts(row):
    try:
        return float(row.get('ts') or 0)
    except (TypeError, ValueError):
        return 0.0


def _day_files_for(log_dir, day):
    return logs_mod.day_files(log_dir, day)


def _daystr(day):
    return day.strftime('%Y%m%d')


def _purge_day(p, daystr):
    """Forget everything the store holds for one source day (the next run reads it again from byte 0)."""
    try:
        names = os.listdir(p['rows'])
    except OSError:
        names = []
    for name in names:
        parts = name[:-4].split('-') if name.endswith('.dat') else []
        if (len(parts) == 3 and parts[0] in ('d', 'o') and parts[1] == daystr) or (len(parts) == 2 and parts[0] == 'h' and parts[1] == daystr):
            _unlink(os.path.join(p['rows'], name))
    _unlink(os.path.join(p['daily'], daystr + '.json'))


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _hit_fns():
    from analyzer import snapshot as snapshot_mod       # lazy: snapshot imports this module
    return snapshot_mod.rule_ids, snapshot_mod.list_ids


class _DayWriter(object):
    """Buffers one source day's new rows and writes them out in frames."""

    def __init__(self, p, daystr, now):
        self.p, self.daystr, self.now = p, daystr, now
        self.dec, self.out, self.hits = {}, {}, []
        self.count = 0
        self.rule_ids, self.list_ids = _hit_fns()

    def add_decision(self, row):
        ts = _row_ts(row)
        if ts > 0 and ts <= self.now + FUTURE_SLACK_S:
            hour = int(ts) // HOUR
            self.dec.setdefault(hour, []).append(_slim(row, ROW_FIELDS))
            self.count += 1
        if self.rule_ids(row) or self.list_ids(row):
            try:
                float(row.get('ts') or 0)
            except (TypeError, ValueError):
                return
            self.hits.append(_slim(row, HIT_FIELDS))

    def add_outcome(self, row):
        rid = row.get('rid')
        if rid and isinstance(rid, str):
            ts = _row_ts(row)
            hour = int(ts) // HOUR if ts > 0 else 0
            self.out.setdefault(hour, []).append([rid, row.get('st')])

    def flush(self):
        for hour, rows in self.dec.items():
            _append_frames(os.path.join(self.p['rows'], 'd-%s-%d.dat' % (self.daystr, hour)), [_frame(rows)])
        for hour, pairs in self.out.items():
            _append_frames(os.path.join(self.p['rows'], 'o-%s-%d.dat' % (self.daystr, hour)), [_frame(pairs)])
        if self.hits:
            _append_frames(os.path.join(self.p['rows'], 'h-%s.dat' % self.daystr), [_frame(self.hits)])
        self.dec, self.out, self.hits = {}, {}, []
        self.count = 0


def _ingest_day(p, state, log_dir, day, now, stats):
    """Bring one source day up to date. Returns nothing; state and the store are updated in place."""
    daystr = _daystr(day)
    files = _day_files_for(log_dir, day)
    cur = state['days'].get(daystr)
    if not files:
        if cur is not None and not os.path.isfile(os.path.join(p['daily'], daystr + '.json')):
            state['days'].pop(daystr, None)
        return
    sig = _signature(files)
    summary_path = os.path.join(p['daily'], daystr + '.json')
    off = 0
    claims, last, cells = {}, {}, {}
    if cur is not None:
        summary = _load_json(summary_path, {})
        if summary.get('off') != cur.get('off') or summary.get('v') != STORE_VERSION:
            cur = None                      # the summary is missing, from another version or half-written: rebuild the day once
            stats['rebuilt'].append(daystr)
        elif cur.get('sig') == sig:
            return                          # nothing changed since the last run: no byte is read
        else:
            size = _logical_size(files)
            fp_ok = cur.get('off', 0) == 0 or _fingerprint(files, cur['off']) == cur.get('fp')
            if (size is not None and size < cur['off']) or not fp_ok:
                cur = None                  # the file shrank or is not the file we read: start the day over
                stats['reset'].append(daystr)
            else:
                off = cur['off']
                claims, last, cells = summary.get('claims', {}), summary.get('last', {}), summary.get('cells', {})
    if cur is None:
        _purge_day(p, daystr)
        state['days'].pop(daystr, None)
    state['pending'] = daystr
    _write_json(p['state'], state)

    chain = _Chain(files)
    writer = _DayWriter(p, daystr, now)
    try:
        if off:
            skipped = chain.skip(off)
            if skipped < off:               # the stream is shorter than the cursor: it is not the file we read (or it shrank just now)
                chain.close()
                _purge_day(p, daystr)
                state['days'].pop(daystr, None)
                state['pending'] = ''
                _write_json(p['state'], state)
                stats['reset'].append(daystr)
                return                      # the next run reads the day from byte 0
        pos = off
        tail = b''
        done = False
        while not done:
            data = chain.read(CHUNK_BYTES)
            if not data:
                break
            data = tail + data
            cut = data.rfind(b'\n')
            if cut < 0:
                tail = data
                continue
            tail = data[cut + 1:]
            block = data[:cut + 1]
            pos += len(block)
            for line in block.split(b'\n'):
                line = line.strip()
                if not line:
                    continue
                row = _parse(line)
                if not isinstance(row, dict) or not logs_mod._clean(row):
                    continue
                if row.get('o') == 1:
                    writer.add_outcome(row)
                    continue
                bot = str(row.get('bot') or '').lower()
                ip = str(row.get('ip') or '')
                if bot and ip:
                    slot = claims.setdefault(ip, {})
                    slot[bot] = slot.get(bot, 0) + 1
                    last[ip] = max(float(last.get(ip, 0)), _row_ts(row))
                writer.add_decision(row)
            stats['bytes'] += len(block)
            if writer.count >= FLUSH_ROWS:
                writer.flush()
        writer.flush()
    finally:
        chain.close()

    stats['rows_days'].append(daystr)
    _write_json(summary_path, {'v': STORE_VERSION, 'off': pos, 'claims': claims, 'last': last, 'cells': cells})
    state['days'][daystr] = {'off': pos, 'fp': _fingerprint(files, pos), 'sig': _signature(files)}
    state['pending'] = ''
    _write_json(p['state'], state)


def _recover(p, state):
    """A previous run died while writing a day: discard that day, it is read again."""
    daystr = state.get('pending')
    if daystr:
        _purge_day(p, daystr)
        state['days'].pop(daystr, None)
        state['pending'] = ''
        _write_json(p['state'], state)
        return daystr
    return ''


def _day_of(name):
    parts = name[:-4].split('-') if name.endswith('.dat') else []
    if len(parts) == 3 and parts[0] in ('d', 'o'):
        return parts[1], int(parts[2]) if parts[2].isdigit() else None
    return None, None


def _prune(p, state, now, rowstore_hours, ingest_days):
    """Hours older than the row store keep only their bucket (daily/<day>.json); days older than the ingest window go entirely."""
    from analyzer import snapshot as snapshot_mod
    edge = int(now) // HOUR - int(rowstore_hours) + 1
    state['edge'] = edge
    try:
        names = sorted(os.listdir(p['rows']))
    except OSError:
        names = []
    keep_from = _daystr(datetime.date.fromtimestamp(now) - datetime.timedelta(days=ingest_days - 1))
    for name in names:
        path = os.path.join(p['rows'], name)
        if name.endswith('.dat') and name.startswith('h-'):
            if name[2:-4] < keep_from:
                _unlink(path)
            continue
        daystr, hour = _day_of(name)
        if daystr is None or hour is None:
            continue
        if daystr < keep_from:
            _unlink(path)
        elif name.startswith('d-') and hour < edge:
            summary_path = os.path.join(p['daily'], daystr + '.json')
            summary = _load_json(summary_path, {})
            if summary.get('v') == STORE_VERSION:
                rows = []
                for frame in _iter_frames(path):
                    rows.extend(frame)
                bucket = snapshot_mod.hour_buckets(rows, hour * HOUR, 1)[0]
                cells = summary.setdefault('cells', {})
                old = cells.get(str(hour * HOUR))
                if old:                     # rows of this hour that arrived after it was folded: the counts add up
                    for k, v in bucket.items():
                        if k != 't':
                            old[k] = old.get(k, 0) + v
                else:
                    cells[str(hour * HOUR)] = bucket
                _write_json(summary_path, summary)
                _unlink(path)
        elif name.startswith('o-') and hour < edge - 1:
            _unlink(path)
    for name in os.listdir(p['daily']) if os.path.isdir(p['daily']) else []:
        if name.endswith('.json') and name[:-5] < keep_from:
            _unlink(os.path.join(p['daily'], name))
    for daystr in list(state['days']):
        if daystr < keep_from:
            state['days'].pop(daystr, None)


def _slim(row, fields):
    """The keys of `row` that `fields` names and that carry a value (a missing key and a null read the same everywhere)."""
    out = {}
    for f in fields:
        v = row.get(f)
        if v is not None:
            out[f] = v
    return out


def update(cfg, now=None, ingest_days=None, rowstore_hours=None, wait=300):
    """Read what was appended to the logs since the last run into the store. Returns a stats dict.

    Raises IOError when the store stays locked for `wait` seconds or cannot be written: the caller falls back to reading
    the logs directly.
    """
    now = time.time() if now is None else now
    ingest_days = int(ingest_days or max(INGEST_DAYS, int(cfg.get('window_days', 7)) + 2))
    # Never fewer than the 24 h window and the 24 h before it (plus a boundary hour): the store must hold what the snapshot reads.
    rowstore_hours = max(DEFAULT_ROWSTORE_HOURS, int(rowstore_hours or cfg.get('rowstore_hours') or DEFAULT_ROWSTORE_HOURS))
    p = _paths(cfg)
    _ensure_dirs(p)
    stats = {'bytes': 0, 'rebuilt': [], 'reset': [], 'rows_days': [], 'recovered': ''}
    with _Lock(p['lock'], True, wait):
        state = _load_state(p)
        stats['recovered'] = _recover(p, state)
        today = datetime.date.fromtimestamp(now)
        for offset in range(ingest_days - 1, -1, -1):          # oldest first: a first run prunes as it goes
            _ingest_day(p, state, cfg['log_dir'], today - datetime.timedelta(days=offset), now, stats)
        _prune(p, state, now, rowstore_hours, ingest_days)
        _write_json(p['state'], state)
    return stats


# ---------------------------------------------------------------------------------------------------------------- reading

class Reader(object):
    """Reads the store under a shared lock. Use as `with reader(cfg) as store:`."""

    def __init__(self, cfg, wait=60):
        self.p = _paths(cfg)
        self.lock = _Lock(self.p['lock'], False, wait)
        self.state = None

    def __enter__(self):
        _ensure_dirs(self.p)
        self.lock.__enter__()
        self.state = _load_state(self.p)
        return self

    def __exit__(self, *exc):
        return self.lock.__exit__(*exc)

    @property
    def edge(self):
        """Hours before this one only have their bucket (cells()); rows exist from here on."""
        return int(self.state.get('edge') or 0)

    def _files(self, kind):
        out = {}
        try:
            names = os.listdir(self.p['rows'])
        except OSError:
            names = []
        for name in names:
            daystr, hour = _day_of(name)
            if daystr is not None and hour is not None and name.startswith(kind + '-'):
                out.setdefault(daystr, []).append((hour, os.path.join(self.p['rows'], name)))
        for daystr in out:
            out[daystr].sort()
        return out

    def rows(self, since, until=None):
        """Decision rows with since <= ts (< until), as logs.read_lines yields them: newest day first, file order inside."""
        first_hour = int(since) // HOUR
        decisions = self._files('d')
        outcomes = self._files('o')
        for daystr in sorted(decisions, reverse=True):
            index = {}
            for hour, path in outcomes.get(daystr, []):
                for frame in _iter_frames(path):
                    for rid, st in frame:
                        if rid not in index:
                            index[rid] = {'st': st} if st is not None else {}
            for hour, path in decisions[daystr]:
                if hour < first_hour:
                    continue
                for frame in _iter_frames(path):
                    for row in frame:
                        ts = _row_ts(row)
                        if ts < since or (until is not None and ts >= until):
                            continue
                        rid = row.get('rid')
                        row['_out'] = index.get(rid) if isinstance(rid, str) else None
                        yield row

    def hit_days(self):
        """{day: iterator factory} of the rows that matched a rule or an IP list, per source day, newest first."""
        out = []
        try:
            names = sorted(os.listdir(self.p['rows']), reverse=True)
        except OSError:
            names = []
        for name in names:
            if name.startswith('h-') and name.endswith('.dat'):
                out.append((name[2:-4], os.path.join(self.p['rows'], name)))
        return out

    def hit_rows(self, daystr):
        for path_day, path in self.hit_days():
            if path_day == daystr:
                for frame in _iter_frames(path):
                    for row in frame:
                        yield row

    def cells(self):
        """{hour_start: bucket} of the hours that left the row store, summed over the source days that contributed."""
        out = {}
        try:
            names = sorted(os.listdir(self.p['daily']))
        except OSError:
            names = []
        for name in names:
            if not name.endswith('.json'):
                continue
            summary = _load_json(os.path.join(self.p['daily'], name), {})
            for key, bucket in (summary.get('cells') or {}).items():
                t = int(key)
                if t not in out:
                    out[t] = dict(bucket)
                    continue
                cur = out[t]                    # an hour split between two day files (a time-zone mismatch): counts add up
                for k, v in bucket.items():
                    if k != 't':
                        cur[k] = cur.get(k, 0) + v
        return out

    def claims(self, window_days, today, known_bots):
        """({ip: first bot seen}, {ip: claim count}) over the last window_days source days, exactly as run_verify counts them.

        Newest day first and, inside a day, the first matching bot of the address wins (logs.read_lines order).
        """
        known = set(str(b).lower() for b in known_bots or [])
        claims, counts = {}, {}
        for offset in range(int(window_days)):
            daystr = _daystr(today - datetime.timedelta(days=offset))
            summary = _load_json(os.path.join(self.p['daily'], daystr + '.json'), {})
            for ip, bots in (summary.get('claims') or {}).items():
                for bot, n in bots.items():
                    if known and bot not in known:
                        continue
                    counts[ip] = counts.get(ip, 0) + int(n)
                    claims.setdefault(ip, bot)
        return claims, counts


def reader(cfg, wait=60):
    return Reader(cfg, wait)


def storage_bytes(cfg):
    """Bytes the store occupies (the Log storage card shows it): the row store, the summaries and the state file."""
    p = _paths(cfg)
    total = 0
    for directory in (p['rows'], p['daily']):
        try:
            for name in os.listdir(directory):
                try:
                    total += os.path.getsize(os.path.join(directory, name))
                except OSError:
                    pass
        except OSError:
            pass
    return total
