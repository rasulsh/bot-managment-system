#!/usr/bin/env python3
"""IP list compile step: lists/<id>.txt  ->  lists/allow.bin, lists/block.bin.

Offline only. The panel keeps each list as plain text (lists/<id>.txt) plus the
metadata in lists/lists.json; this module builds ONE compiled range file per list
type from every ENABLED list of that type. The request path only binary-searches
those files (guard/iplist.php). Small lists are compiled by the panel itself
(panel/iplists.php, the same algorithm); this is the same step for the big ones,
run as the panel's `iplist_compile` job.

Compiled file layout: guard/geo.php (kind 3). Value of a range = uint16, bit 15
monitor mode, bits 0-14 the list index. Where lists overlap the SMALLER value
wins: an enforced list beats a monitor list, then the lower index.

SAFETY CAPS, applied to every entry here (a file copied over SFTP never went through the panel form;
panel/iplists.php gp_ipl_refusal() is the PHP mirror and a test compares the output byte for byte):
  * 0.0.0.0/0 and ::/0 are ALWAYS dropped, even for a forced list,
  * an allow entry wider than /16 (IPv4) or /32 (IPv6) is dropped,
  * a block entry wider than /8 (IPv4) or /32 (IPv6) is dropped,
  * a block entry covering private, loopback, link-local space or an address in lists.json "own" (the
    server's own addresses, recorded by the panel) is dropped.
The list's "force" flag (set only from the panel, audit-logged) keeps everything except 0/0. Dropped
entries and unparseable lines are counted per list and reason in lists-status.json, with samples.

A type with no enabled list that has entries gets its file DELETED: the guard
opens a list file only while an enabled list needs it. A type whose source
cannot be read keeps its old file and the error is reported.

Source text: one IPv4/IPv6 address or CIDR per line, `#` comments, blank lines,
CRLF, an optional CSV first column. A line that does not parse is skipped here
(the panel reports it by line number when the list is saved).

Writes lists/lists-status.json (what was built, per-list counts, errors).
"""

from __future__ import print_function

import argparse
import calendar
import datetime
import hashlib
import heapq
import ipaddress
import json
import os
import re
import sys
import time

try:
    import fcntl
except ImportError:                     # not on Windows; the lock is best effort
    fcntl = None

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import geo  # noqa: E402

STATUS_FILE = 'lists-status.json'
META_FILE = 'lists.json'
MONITOR = 0x8000
WIDE_V4 = 8                             # a block entry wider than /8 ...
WIDE_V6 = 32                            # ... or /32 (IPv6) is dropped unless the list is forced
ALLOW_WIDE_V4 = 16                      # an allow entry wider than /16 ...
ALLOW_WIDE_V6 = 32                      # ... or /32 (IPv6) likewise
MAX_LINES = 300000
SAMPLES = 10                            # dropped entries / invalid lines kept per list in the status
REASONS = ('all', 'allow_wide', 'wide', 'protected')
PRIVATE = ('0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
           '::/128', '::1/128', 'fc00::/7', 'fe80::/10')


def default_dir():
    env = os.environ.get('GV_LISTS_DIR')
    if env:
        return env
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lists')


# --------------------------------------------------------------------------
# Source text
# --------------------------------------------------------------------------

def parse_entry(token):
    """(version, start, end, prefix) for one address / CIDR token, or None. Pure.

    Host bits are masked (192.168.1.5/24 is 192.168.1.0/24). An IPv4-mapped IPv6
    address is the IPv4 address it carries (prefix counted from /96).
    """
    if not token or '%' in token or ' ' in token:
        return None
    addr, slash, tail = token.partition('/')
    if slash and (not tail.isdigit() or not tail.isascii()):
        return None
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    bits = 128 if ip.version == 6 else 32
    prefix = int(tail) if slash else bits
    if prefix > bits:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        if prefix < 96:
            return None
        ip = ip.ipv4_mapped
        bits, prefix = 32, prefix - 96
    host = bits - prefix
    start = (int(ip) >> host) << host
    return (ip.version, start, start + (1 << host) - 1, prefix)


EXPIRES_RE = re.compile(r'\bexpires\s*=\s*(\S*)(?:[ T](\d{2}:\d{2}))?', re.I)
EXPIRES_VALUE_RE = re.compile(r'^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}))?$')


def expiry(comment):
    """(timestamp, ok) for a `# expires=2026-11-30` comment (valid through the END of that day, UTC) or
    `# expires=2026-11-30T14:30` / `2026-11-30 14:30` (UTC, to the minute). 0 = no expiry; ok False = an `expires=` that is not a
    real date (the line is refused: a typo must not make a temporary entry permanent). Mirrors gp_ipl_expiry() in panel/iplists.php."""
    m = EXPIRES_RE.search(comment or '')
    if not m:
        return 0, True
    d = EXPIRES_VALUE_RE.match(m.group(1))
    if not d:
        return 0, False
    try:
        day = datetime.datetime(int(d.group(1)), int(d.group(2)), int(d.group(3)))
    except ValueError:
        return 0, False
    hh, mm = d.group(4), d.group(5)
    if hh is None and m.group(2):
        hh, mm = m.group(2)[:2], m.group(2)[3:5]
    base = calendar.timegm(day.timetuple())
    if hh is None:
        return base + 86400, True
    if int(hh) > 23 or int(mm) > 59:
        return 0, False
    return base + int(hh) * 3600 + int(mm) * 60, True


def parse_text(text, with_expiry=False):
    """([(version, start, end, prefix)], [(line number, text)]) from a source text. Pure.

    with_expiry=True: each entry is (version, start, end, prefix, expires) with the `# expires=` timestamp (0 = none)."""
    if text.startswith('﻿'):
        text = text[1:]
    entries, bad = [], []
    for number, line in enumerate(text.replace('\r\n', '\n').replace('\r', '\n').split('\n'), 1):
        comment = line.split('#', 1)[1] if '#' in line else ''
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        token = line.split(',', 1)[0].strip().strip('"\'').strip()
        parsed = parse_entry(token)
        exp = expiry(comment)
        if parsed is None or not exp[1]:
            bad.append((number, line[:80]))
        else:
            entries.append(parsed + (exp[0],) if with_expiry else parsed)
        if number >= MAX_LINES:
            break
    return entries, bad


def has_expired(lists_dir, now=None):
    """Whether an enabled list source still holds an entry whose `# expires=` time has passed (the nightly job recompiles then)."""
    now = int(time.time() if now is None else now)
    try:
        meta = read_meta(lists_dir)
    except Exception:
        return False
    for item in meta:
        if not item.get('enabled'):
            continue
        try:
            with open(os.path.join(lists_dir, item['id'] + '.txt'), 'rb') as handle:
                text = handle.read().decode('utf-8', 'replace')
        except OSError:
            continue
        if any(e[4] and e[4] <= now for e in parse_text(text, True)[0]):
            return True
    return False


def prune_expired(path, raw, now):
    """Remove the lines whose `# expires=` time has passed from a list source. `raw` is what the compile read: a file that changed
    since is left alone (the next compile does it). Atomic replace, same mode. Returns the number of lines removed."""
    keep, gone = [], 0
    for line in re.findall(r'[^\r\n]*(?:\r\n|\n|\r)|[^\r\n]+', raw):
        if '#' in line:
            body, comment = line.split('#', 1)
            exp = expiry(comment)
            if body.strip() and exp[1] and 0 < exp[0] <= now:
                gone += 1
                continue
        keep.append(line)
    try:
        with open(path, 'rb') as handle:
            if handle.read().decode('utf-8', 'replace') != raw:
                return 0
        if not gone:
            return 0
        tmp = '%s.tmp%d' % (path, os.getpid())
        mode = os.stat(path).st_mode & 0o777
        with open(tmp, 'wb') as handle:
            handle.write(''.join(keep).encode('utf-8'))
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except OSError:
        return 0
    return gone


# --------------------------------------------------------------------------
# Range arithmetic
# --------------------------------------------------------------------------

def union(ranges):
    """Sorted, merged (start, end) pairs. Overlapping and adjacent ranges join. Pure."""
    out = []
    for start, end in sorted(ranges):
        if out and start <= out[-1][1] + 1:
            if end > out[-1][1]:
                out[-1] = (out[-1][0], end)
        else:
            out.append((start, end))
    return out


def sweep(ranges):
    """Sorted, non-overlapping (start, end, value) from possibly overlapping ones.

    At every address the SMALLEST value among the ranges covering it wins (an
    enforced list beats a monitor one, then the lower list index), whatever the
    widths. Adjacent pieces with the same value are merged. Pure.
    """
    ranges = sorted(ranges, key=lambda r: (r[0], r[2], r[1]))
    out = []
    heap = []
    i, n = 0, len(ranges)
    pos = 0

    def emit(start, end, value):
        if out and out[-1][2] == value and out[-1][1] + 1 == start:
            out[-1] = (out[-1][0], end, value)
        else:
            out.append((start, end, value))

    while i < n or heap:
        if not heap:
            pos = ranges[i][0]
        while i < n and ranges[i][0] <= pos:
            heapq.heappush(heap, (ranges[i][2], ranges[i][1]))
            i += 1
        while heap and heap[0][1] < pos:
            heapq.heappop(heap)
        if not heap:
            continue
        value, end = heap[0]
        if i < n and ranges[i][0] - 1 < end:
            end = ranges[i][0] - 1
        emit(pos, end, value)
        pos = end + 1
    return out


# --------------------------------------------------------------------------
# Compile
# --------------------------------------------------------------------------

def read_meta(lists_dir):
    """The list records of lists.json ([] when missing or unusable). Never raises."""
    try:
        with open(os.path.join(lists_dir, META_FILE), 'r') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    lists = data.get('lists') if isinstance(data, dict) else None
    out = []
    for item in (lists if isinstance(lists, list) else []):
        if (isinstance(item, dict) and isinstance(item.get('id'), str) and item.get('type') in ('allow', 'block')
                and isinstance(item.get('idx'), int) and 0 < item['idx'] <= 0x7FFF):
            out.append(item)
    return out


def protected_ranges(own=()):
    """(version, start, end) of the space a block entry must not cover: private, loopback, link-local,
    unspecified, plus the server's own addresses. Pure."""
    out = []
    for token in list(PRIVATE) + [str(x) for x in own]:
        parsed = parse_entry(token)
        if parsed is not None:
            out.append(parsed[:3])
    return out


def refusal(entry, kind, protected, force=False):
    """Why an entry of a list of this type is dropped, or ''. Mirror of gp_ipl_refusal() in panel/iplists.php. Pure."""
    version, start, end, prefix = entry
    if prefix == 0:
        return 'all'
    if force:
        return ''
    if kind == 'allow':
        return 'allow_wide' if prefix < (ALLOW_WIDE_V4 if version == 4 else ALLOW_WIDE_V6) else ''
    if prefix < (WIDE_V4 if version == 4 else WIDE_V6):
        return 'wide'
    for pv, ps, pe in protected:
        if pv == version and start <= pe and end >= ps:
            return 'protected'
    return ''


def entry_text(entry):
    """Canonical text of a parsed entry, as the panel stores it: 203.0.113.0/24, 198.51.100.7, 2001:db8::/32."""
    version, start, _end, prefix = entry
    full = 32 if version == 4 else 128
    addr = str(ipaddress.ip_address(start) if version == 4 else ipaddress.IPv6Address(start))
    return addr if prefix == full else '%s/%d' % (addr, prefix)


def read_own(lists_dir):
    """The server's own addresses recorded in lists.json ("own"). Never raises."""
    try:
        with open(os.path.join(lists_dir, META_FILE), 'r') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    own = data.get('own') if isinstance(data, dict) else None
    return [x for x in (own if isinstance(own, list) else []) if isinstance(x, str) and parse_entry(x) is not None][:16]


def compile_lists(lists_dir, now=None):
    """Build allow.bin / block.bin. Returns the status dict (also written to lists-status.json)."""
    now = int(time.time() if now is None else now)
    status = {'v': 1, 'time': now, 'by': 'python', 'ok': True, 'errors': [], 'types': {'allow': None, 'block': None}, 'lists': {}}
    lock = None
    if fcntl is not None:
        try:
            lock = open(os.path.join(lists_dir, '.compile.lock'), 'a')
            try:
                os.chmod(os.path.join(lists_dir, '.compile.lock'), 0o644)
            except OSError:
                pass                    # the panel's web user may own it: not ours to change, and not a reason to drop the lock
            fcntl.flock(lock, fcntl.LOCK_EX)
        except OSError:
            lock = None
    try:
        meta = sorted(read_meta(lists_dir), key=lambda l: l['idx'])
        protected = protected_ranges(read_own(lists_dir))
        for kind in ('allow', 'block'):
            _compile_type(lists_dir, kind, [l for l in meta if l['type'] == kind and l.get('enabled')], now, status, protected)
        status['ok'] = not status['errors']
        try:
            geo._write_json_atomic(os.path.join(lists_dir, STATUS_FILE), status)
        except OSError as exc:
            status['ok'] = False
            status['errors'].append('cannot write %s: %s' % (STATUS_FILE, exc))
    finally:
        if lock is not None:
            lock.close()
    return status


def _compile_type(lists_dir, kind, lists, now, status, protected=()):
    path = os.path.join(lists_dir, kind + '.bin')
    ranges4, ranges6 = [], []
    digest = hashlib.sha256()
    failed = False
    for item in lists:
        value = item['idx'] | (MONITOR if item.get('mode') == 'monitor' else 0)
        try:
            with open(os.path.join(lists_dir, item['id'] + '.txt'), 'rb') as handle:
                raw = handle.read()
        except OSError as exc:
            status['errors'].append('%s: cannot read the source: %s' % (item['id'], exc))
            failed = True
            continue
        digest.update(('%d:%s:' % (item['idx'], item.get('mode'))).encode('ascii') + raw)
        # The same checks as a panel upload, for a file that never went through the form: lines that do not
        # parse are counted and shown, entries over a cap are dropped. Nothing here is fatal.
        text = raw.decode('utf-8', 'replace')
        entries, bad = parse_text(text, True)
        live = [e[:4] for e in entries if not (e[4] and e[4] <= now)]
        expired = len(entries) - len(live)
        entries = live
        dropped = dict((reason, 0) for reason in REASONS)
        samples = []
        huge = 0
        own4, own6 = [], []
        for entry in entries:
            why = refusal(entry, kind, protected, bool(item.get('force')))
            if why:
                dropped[why] += 1
                if kind == 'allow' and entry[3] < 8:
                    huge += 1
                if len(samples) < SAMPLES:
                    samples.append([entry_text(entry), why])
                continue
            (own4 if entry[0] == 4 else own6).append((entry[1], entry[2]))
        u4, u6 = union(own4), union(own6)
        status['lists'][item['id']] = {'entries': len(entries) - sum(dropped.values()), 'v4': len(u4), 'v6': len(u6),
                                       'addresses': sum(e - s + 1 for s, e in u4), 'invalid': len(bad),
                                       'invalid_samples': [[n, t] for n, t in bad[:SAMPLES]], 'dropped': dropped,
                                       'dropped_n': sum(dropped.values()), 'dropped_huge': huge, 'dropped_samples': samples,
                                       'expired': expired}
        if expired:
            prune_expired(os.path.join(lists_dir, item['id'] + '.txt'), text, now)
        ranges4.extend((s, e, value) for s, e in u4)
        ranges6.extend((s, e, value) for s, e in u6)
    if failed:
        return                                  # keep the file the guard has
    if not ranges4 and not ranges6:
        for stale in (path,):
            if os.path.exists(stale):
                os.unlink(stale)
        return
    v4, v6 = sweep(ranges4), sweep(ranges6)
    sha = digest.hexdigest()
    geo.swap_in(path, geo.pack(geo.KIND_IPLIST, v4, v6, now, 'iplists-' + kind, sha))
    status['types'][kind] = {'built': now, 'v4': len(v4), 'v6': len(v6), 'sha': sha, 'lists': [l['id'] for l in lists]}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Compile lists/ into allow.bin / block.bin')
    parser.add_argument('--dir', default=None, help='lists directory (default: GV_LISTS_DIR or <repo>/lists)')
    parser.add_argument('--config', default=None, help='accepted for worker compatibility; unused')
    args = parser.parse_args(argv)
    lists_dir = args.dir or default_dir()
    if not os.path.isdir(lists_dir):
        print('ERROR: lists directory not found: %s' % lists_dir, file=sys.stderr)
        return 1
    status = compile_lists(lists_dir)
    for kind in ('allow', 'block'):
        info = status['types'][kind]
        print('%s: %s' % (kind, ('%d IPv4 ranges, %d IPv6 ranges from %s' % (info['v4'], info['v6'], ', '.join(info['lists']))) if info else 'no enabled list with entries'))
    for err in status['errors']:
        print('ERROR: ' + err, file=sys.stderr)
    print('GV_JOB_RESULT: ' + json.dumps({'allow': status['types']['allow'] and status['types']['allow']['v4'],
                                         'block': status['types']['block'] and status['types']['block']['v4'],
                                         'errors': len(status['errors'])}, sort_keys=True), file=sys.stderr)
    print('iplist compile: ' + ('ok' if status['ok'] else 'FAILED'))
    return 0 if status['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
