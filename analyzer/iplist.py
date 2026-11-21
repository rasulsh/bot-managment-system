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
import hashlib
import heapq
import ipaddress
import json
import os
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
WIDE_V6 = 32                            # ... or /32 (IPv6) is refused unless the list is forced
MAX_LINES = 300000


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


def parse_text(text):
    """([(version, start, end, prefix)], [(line number, text)]) from a source text. Pure."""
    if text.startswith('﻿'):
        text = text[1:]
    entries, bad = [], []
    for number, line in enumerate(text.replace('\r\n', '\n').replace('\r', '\n').split('\n'), 1):
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        token = line.split(',', 1)[0].strip().strip('"\'').strip()
        parsed = parse_entry(token)
        if parsed is None:
            bad.append((number, line[:80]))
        else:
            entries.append(parsed)
        if number >= MAX_LINES:
            break
    return entries, bad


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


def _wide(version, prefix):
    return prefix < (WIDE_V4 if version == 4 else WIDE_V6)


def compile_lists(lists_dir, now=None):
    """Build allow.bin / block.bin. Returns the status dict (also written to lists-status.json)."""
    now = int(time.time() if now is None else now)
    status = {'v': 1, 'time': now, 'by': 'python', 'ok': True, 'errors': [], 'types': {'allow': None, 'block': None}, 'lists': {}}
    lock = None
    if fcntl is not None:
        try:
            lock = open(os.path.join(lists_dir, '.compile.lock'), 'a')
            fcntl.flock(lock, fcntl.LOCK_EX)
        except OSError:
            lock = None
    try:
        meta = sorted(read_meta(lists_dir), key=lambda l: l['idx'])
        for kind in ('allow', 'block'):
            _compile_type(lists_dir, kind, [l for l in meta if l['type'] == kind and l.get('enabled')], now, status)
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


def _compile_type(lists_dir, kind, lists, now, status):
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
        entries, bad = parse_text(raw.decode('utf-8', 'replace'))
        wide = 0
        own4, own6 = [], []
        for version, start, end, prefix in entries:
            if kind == 'block' and not item.get('force') and _wide(version, prefix):
                wide += 1
                continue
            (own4 if version == 4 else own6).append((start, end))
        u4, u6 = union(own4), union(own6)
        status['lists'][item['id']] = {'entries': len(entries) - wide, 'v4': len(u4), 'v6': len(u6),
                                       'addresses': sum(e - s + 1 for s, e in u4), 'invalid': len(bad), 'wide': wide}
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
