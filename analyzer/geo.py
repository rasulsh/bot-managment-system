#!/usr/bin/env python3
"""GeoIP compile step: .mmdb / geoip.dat  ->  geo/country.bin, geo/asn.bin.

Offline only. The guard never parses a source database: it binary-searches the
compiled range files this module writes (guard/geo.php reads them). Run it as
the panel's `geo_compile` job, or from cron: scripts/analyzer-cron.sh geo.

Sources, placed in geo/ (uploaded from the panel or copied over SFTP):
  * *.mmdb   MaxMind DB: GeoLite2-Country / GeoLite2-ASN, DB-IP "IP to Country
             Lite" / "IP to ASN Lite", IPinfo Lite. Needs the optional
             `maxminddb` package; without it these files are reported and skipped.
  * *.dat    V2Ray/Xray geoip.dat (protobuf GeoIPList). Only entries whose tag is
             a 2-letter country code are used; every other tag (private,
             cloudflare, telegram, ...) is listed as ignored. A minimal reader
             (varint + length-delimited fields), no protobuf dependency.

Per kind the NEWEST source file that yields data wins; the others are listed as
unused in geo/geo-status.json. A compile only replaces the live file when the
new one passes the sanity checks (minimum range count, IR present for the
country table, the known addresses of geo/known.json when that file exists).
The previous file is kept as <name>.prev for the panel's one-click rollback.

Compiled file layout: see guard/geo.php (one format for geo and the IP lists).
"""

from __future__ import print_function

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import struct
import sys
import time

MAGIC = b'GVRG'
VERSION = 1
HEADER = 128
KIND_COUNTRY = 1
KIND_ASN = 2
KIND_IPLIST = 3
MIN_RANGES = 1000            # a real country or ASN table has far more
STATUS_FILE = 'geo-status.json'


class GeoError(Exception):
    pass


def default_dir():
    env = os.environ.get('GV_GEO_DIR')
    if env:
        return env
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'geo')


# --------------------------------------------------------------------------
# Range arithmetic
# --------------------------------------------------------------------------

def normalize(ranges):
    """Sorted, non-overlapping ranges from (start, end, value) triples. Pure.

    Overlaps come from nested CIDRs (geoip.dat lists a block and a smaller block
    inside it): the NARROWER range wins inside the overlap, the wider one keeps
    the rest. Identical ranges with different values: the smaller value wins
    (deterministic). Adjacent ranges with the same value are merged.
    """
    ranges = sorted(ranges, key=lambda r: r[2], reverse=True)
    ranges.sort(key=lambda r: (r[0], -r[1]))
    out = []
    stack = []
    pos = 0

    def emit(start, end, value):
        if start > end:
            return
        if out and out[-1][2] == value and out[-1][1] + 1 == start:
            out[-1] = (out[-1][0], end, value)
        else:
            out.append((start, end, value))

    for start, end, value in ranges:
        while stack and stack[-1][1] < start:
            top = stack.pop()
            emit(pos, top[1], top[2])
            pos = max(pos, top[1] + 1)
        if stack:
            emit(pos, start - 1, stack[-1][2])
        pos = start
        stack.append((start, end, value))
    while stack:
        top = stack.pop()
        emit(pos, top[1], top[2])
        pos = max(pos, top[1] + 1)
    return out


def split_family(items):
    """[(start, end, value)] from ip_network objects, split by family."""
    v4, v6 = [], []
    for net, value in items:
        start = int(net.network_address)
        end = int(net.broadcast_address)
        if net.version == 4:
            v4.append((start, end, value))
        else:
            mapped = net.network_address.ipv4_mapped
            if mapped is not None:
                # ::ffff:a.b.c.d/N is the IPv4 range it carries
                v4.append((int(mapped), int(mapped) + (end - start), value))
            else:
                v6.append((start, end, value))
    return v4, v6


# --------------------------------------------------------------------------
# Compiled file: write, read, look up (the PHP reader is the one that matters;
# the lookup here exists to verify what was just written and to test parity)
# --------------------------------------------------------------------------

def _pack_value(kind, value):
    if kind == KIND_COUNTRY:
        return value.encode('ascii')
    if kind == KIND_ASN:
        return struct.pack('>I', value)
    return b''


def _value_size(kind):
    return {KIND_COUNTRY: 2, KIND_ASN: 4}.get(kind, 0)


def pack(kind, v4, v6, built, source, sha256_hex):
    """The bytes of a compiled file from normalised ranges. Pure."""
    head = struct.pack('>4sHBBIIII', MAGIC, VERSION, kind, _value_size(kind), int(built), len(v4), len(v6), 0)
    head += bytes(bytearray.fromhex(sha256_hex)) if sha256_hex else b'\0' * 32
    head += source.encode('utf-8', 'replace')[:72].ljust(72, b'\0')
    assert len(head) == HEADER
    parts = [head]
    for s, e, v in v4:
        parts.append(struct.pack('>II', s, e) + _pack_value(kind, v))
    for s, e, v in v6:
        parts.append(s.to_bytes(16, 'big') + e.to_bytes(16, 'big') + _pack_value(kind, v))
    return b''.join(parts)


def parse_header(data):
    """Header fields of a compiled file, or None when it is not one."""
    if len(data) < HEADER or data[:4] != MAGIC:
        return None
    ver, kind, vsize, built, n4, n6, _res = struct.unpack('>HBBIIII', data[4:24])
    if ver != VERSION:
        return None
    rec4, rec6 = 8 + vsize, 32 + vsize
    if len(data) < HEADER + n4 * rec4 + n6 * rec6:
        return None
    return {'kind': kind, 'vsize': vsize, 'built': built, 'v4': n4, 'v6': n6,
            'sha': data[24:56].hex(), 'source': data[56:128].rstrip(b'\0').decode('utf-8', 'replace'),
            'o4': HEADER, 'o6': HEADER + n4 * rec4}


def lookup(data, ip):
    """Value for an address in compiled-file bytes: str / int, or None. Binary search."""
    h = parse_header(data)
    if h is None:
        raise GeoError('not a compiled range file')
    addr = ipaddress.ip_address(ip)
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.version == 4:
        klen, off, count = 4, h['o4'], h['v4']
    else:
        klen, off, count = 16, h['o6'], h['v6']
    key = int(addr).to_bytes(klen, 'big')
    rec = 2 * klen + h['vsize']
    lo, hi = 0, count - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        at = off + mid * rec
        if key < data[at:at + klen]:
            hi = mid - 1
        elif key > data[at + klen:at + 2 * klen]:
            lo = mid + 1
        else:
            raw = data[at + 2 * klen:at + rec]
            if h['kind'] == KIND_COUNTRY:
                return raw.decode('ascii')
            if h['kind'] == KIND_ASN:
                return struct.unpack('>I', raw)[0]
            return ''
    return None


def read_ranges(data):
    """(v4, v6) lists of (start, end, value) back out of compiled bytes."""
    h = parse_header(data)
    if h is None:
        raise GeoError('not a compiled range file')
    vs = h['vsize']

    def val(raw):
        if h['kind'] == KIND_COUNTRY:
            return raw.decode('ascii')
        if h['kind'] == KIND_ASN:
            return struct.unpack('>I', raw)[0]
        return ''
    v4, v6 = [], []
    for i in range(h['v4']):
        at = h['o4'] + i * (8 + vs)
        s, e = struct.unpack('>II', data[at:at + 8])
        v4.append((s, e, val(data[at + 8:at + 8 + vs])))
    for i in range(h['v6']):
        at = h['o6'] + i * (32 + vs)
        v6.append((int.from_bytes(data[at:at + 16], 'big'), int.from_bytes(data[at + 16:at + 32], 'big'),
                   val(data[at + 32:at + 32 + vs])))
    return v4, v6


# --------------------------------------------------------------------------
# geoip.dat (V2Ray / Xray): protobuf GeoIPList, varint + length-delimited only
# --------------------------------------------------------------------------

def _varint(buf, pos):
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise GeoError('truncated varint')
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise GeoError('varint too long')


def _fields(buf):
    """(field_number, wire_type, value) of one message. Value: int (varint) or bytes."""
    pos = 0
    while pos < len(buf):
        key, pos = _varint(buf, pos)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _varint(buf, pos)
        elif wire == 2:
            length, pos = _varint(buf, pos)
            if pos + length > len(buf):
                raise GeoError('truncated field')
            value = buf[pos:pos + length]
            pos += length
        elif wire == 1:
            value, pos = None, pos + 8
        elif wire == 5:
            value, pos = None, pos + 4
        else:
            raise GeoError('unsupported wire type %d' % wire)
        if pos > len(buf):
            raise GeoError('truncated field')
        yield field, wire, value


def read_dat(path):
    """Country ranges out of a geoip.dat: {'v4': [...], 'v6': [...], 'ignored': {tag: networks}}.

    Entries tagged with a 2-letter country code become country ranges. Any other
    tag, and any entry marked reverse_match, is counted under 'ignored'.
    """
    with open(path, 'rb') as handle:
        buf = handle.read()
    v4, v6, ignored = [], [], {}
    for field, wire, entry in _fields(buf):
        if field != 1 or wire != 2:
            continue
        tag = ''
        reverse = False
        cidrs = []
        for f2, w2, v2 in _fields(entry):
            if f2 == 1 and w2 == 2:
                tag = v2.decode('utf-8', 'replace')
            elif f2 == 2 and w2 == 2:
                cidrs.append(v2)
            elif f2 == 3 and w2 == 0:
                reverse = bool(v2)
        low = tag.lower()
        if reverse or len(low) != 2 or not low.isalpha() or not low.isascii():
            ignored[tag] = ignored.get(tag, 0) + len(cidrs)
            continue
        cc = low.upper()
        for raw in cidrs:
            ip = b''
            prefix = 0
            for f3, w3, v3 in _fields(raw):
                if f3 == 1 and w3 == 2:
                    ip = v3
                elif f3 == 2 and w3 == 0:
                    prefix = v3
            if len(ip) not in (4, 16) or prefix > len(ip) * 8:
                raise GeoError('bad CIDR in tag %s' % tag)
            bits = len(ip) * 8
            host = bits - prefix
            start = (int.from_bytes(ip, 'big') >> host) << host
            end = start + (1 << host) - 1
            (v4 if len(ip) == 4 else v6).append((start, end, cc))
    return {'v4': v4, 'v6': v6, 'ignored': ignored}


# --------------------------------------------------------------------------
# .mmdb (optional maxminddb package)
# --------------------------------------------------------------------------

def _record_country(rec):
    if not isinstance(rec, dict):
        return ''
    value = None
    country = rec.get('country')
    if isinstance(country, dict):
        value = country.get('iso_code')
    elif isinstance(country, str) and len(country) == 2:
        value = country
    if not value:
        value = rec.get('country_code')
    if isinstance(value, str) and len(value) == 2 and value.isalpha() and value.isascii():
        return value.upper()
    return ''


def _record_asn(rec):
    if not isinstance(rec, dict):
        return 0
    value = rec.get('autonomous_system_number', rec.get('asn'))
    if isinstance(value, str) and value.upper().startswith('AS'):
        value = value[2:]
    try:
        value = int(value)
    except (TypeError, ValueError):
        return 0
    return value if 0 < value <= 4294967295 else 0


def read_mmdb(path):
    """{'country': {'v4', 'v6'}, 'asn': {'v4', 'v6'}} out of a MaxMind DB."""
    try:
        import maxminddb
    except ImportError:
        raise GeoError('the maxminddb package is not installed (pip install maxminddb); cannot read %s' % os.path.basename(path))
    cc_items, asn_items = [], []
    try:
        reader = maxminddb.open_database(path)
    except Exception as exc:
        raise GeoError('not a readable MaxMind DB: %s' % exc)
    try:
        for net, rec in reader:
            cc = _record_country(rec)
            if cc:
                cc_items.append((net, cc))
            asn = _record_asn(rec)
            if asn:
                asn_items.append((net, asn))
    finally:
        reader.close()
    out = {}
    for name, items in (('country', cc_items), ('asn', asn_items)):
        v4, v6 = split_family(items)
        out[name] = {'v4': v4, 'v6': v6}
    return out


# --------------------------------------------------------------------------
# Compile
# --------------------------------------------------------------------------

def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_atomic(path, obj):
    tmp = path + '.tmp%d' % os.getpid()
    with open(tmp, 'w') as handle:
        json.dump(obj, handle, sort_keys=True)
    os.replace(tmp, path)


def swap_in(path, data):
    """Write `data` to `path` atomically; keep the file it replaces as <path>.prev."""
    tmp = path + '.tmp%d' % os.getpid()
    with open(tmp, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        if os.path.exists(path):
            shutil.copyfile(path, path + '.prev.tmp%d' % os.getpid())
            os.replace(path + '.prev.tmp%d' % os.getpid(), path + '.prev')
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def sanity(kind, v4, v6, known, min_ranges):
    """Reasons a freshly built table must not replace the live one. [] = fine."""
    errors = []
    if len(v4) < min_ranges:
        errors.append('only %d IPv4 ranges (minimum %d)' % (len(v4), min_ranges))
    if kind == KIND_COUNTRY and not any(v == 'IR' for _, _, v in v4 + v6):
        errors.append('no range for IR')
    return errors


def check_known(data, known):
    """Known addresses must resolve as listed: [(ip, expected)]. Returns error strings."""
    errors = []
    for ip, expected in known:
        try:
            got = lookup(data, ip)
        except Exception as exc:
            errors.append('%s: %s' % (ip, exc))
            continue
        if got != expected:
            errors.append('%s resolved to %r, expected %r' % (ip, got, expected))
    return errors


def load_known(path):
    """geo/known.json: {"country": {"ip": "CC"}, "asn": {"ip": 123}}. Optional."""
    if not os.path.isfile(path):
        return {'country': [], 'asn': []}
    with open(path, 'r') as handle:
        raw = json.load(handle)
    out = {'country': [], 'asn': []}
    for kind in out:
        entries = raw.get(kind) if isinstance(raw, dict) else None
        if isinstance(entries, dict):
            out[kind] = [(str(ip), val) for ip, val in entries.items()]
    return out


def compile_geo(geo_dir, known=None, min_ranges=MIN_RANGES, now=None):
    """Compile every source in geo_dir. Returns the status dict (also written to
    geo/geo-status.json). 'ok' is False when nothing could be compiled; a kind that
    fails its sanity checks keeps its old file and adds to 'errors'."""
    now = int(time.time() if now is None else now)
    known = known if known is not None else load_known(os.path.join(geo_dir, 'known.json'))
    status = {'v': 1, 'time': now, 'ok': False, 'errors': [], 'sources': [], 'ignored_tags': {},
              'country': None, 'asn': None, 'countries': []}
    try:
        names = sorted(n for n in os.listdir(geo_dir)
                       if n.lower().endswith(('.mmdb', '.dat')) and os.path.isfile(os.path.join(geo_dir, n)))
    except OSError as exc:
        status['errors'].append('cannot read %s: %s' % (geo_dir, exc))
        return status
    names.sort(key=lambda n: os.path.getmtime(os.path.join(geo_dir, n)), reverse=True)
    if not names:
        status['errors'].append('no .mmdb or geoip.dat source file in %s' % geo_dir)
        return status

    candidates = {'country': None, 'asn': None}      # kind -> (name, v4, v6)
    for name in names:
        path = os.path.join(geo_dir, name)
        entry = {'name': name, 'size': os.path.getsize(path), 'mtime': int(os.path.getmtime(path)), 'provides': [], 'used': []}
        try:
            if name.lower().endswith('.dat'):
                dat = read_dat(path)
                found = {'country': {'v4': dat['v4'], 'v6': dat['v6']}}
                for tag, count in dat['ignored'].items():
                    status['ignored_tags'][tag] = status['ignored_tags'].get(tag, 0) + count
            else:
                found = read_mmdb(path)
        except (GeoError, OSError, ValueError) as exc:
            status['errors'].append('%s: %s' % (name, exc))
            entry['error'] = str(exc)
            status['sources'].append(entry)
            continue
        for kind, ranges in found.items():
            if ranges['v4'] or ranges['v6']:
                entry['provides'].append(kind)
                if candidates[kind] is None:           # newest file first
                    candidates[kind] = (name, ranges['v4'], ranges['v6'], _sha256(path))
                    entry['used'].append(kind)
        status['sources'].append(entry)

    swapped = 0
    for kind_name, kind, filename in (('country', KIND_COUNTRY, 'country.bin'), ('asn', KIND_ASN, 'asn.bin')):
        cand = candidates[kind_name]
        if cand is None:
            continue
        name, raw4, raw6, sha = cand
        v4, v6 = normalize(raw4), normalize(raw6)
        errs = sanity(kind, v4, v6, known, min_ranges)
        data = pack(kind, v4, v6, now, name, sha)
        errs += check_known(data, known.get(kind_name, []))
        if errs:
            status['errors'].append('%s table not replaced: %s' % (kind_name, '; '.join(errs)))
            continue
        swap_in(os.path.join(geo_dir, filename), data)
        swapped += 1
        status[kind_name] = {'source': name, 'sha256': sha, 'built': now, 'v4': len(v4), 'v6': len(v6)}
        if kind == KIND_COUNTRY:
            status['countries'] = sorted(set(v for _, _, v in v4 + v6))
    # A table that was not rebuilt keeps describing the file that is still live.
    old = _read_status(geo_dir)
    for kind_name in ('country', 'asn'):
        if status[kind_name] is None and old and isinstance(old.get(kind_name), dict):
            status[kind_name] = old[kind_name]
            if kind_name == 'country' and not status['countries']:
                status['countries'] = old.get('countries') or []
    status['ok'] = swapped > 0
    if swapped == 0 and not status['errors']:
        status['errors'].append('no usable data in the source files')
    try:
        _write_json_atomic(os.path.join(geo_dir, STATUS_FILE), status)
    except OSError as exc:
        status['errors'].append('cannot write %s: %s' % (STATUS_FILE, exc))
    return status


def _read_status(geo_dir):
    try:
        with open(os.path.join(geo_dir, STATUS_FILE), 'r') as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description='Compile geo/ sources into country.bin / asn.bin')
    parser.add_argument('--dir', default=None, help='geo directory (default: GV_GEO_DIR or <repo>/geo)')
    # GV_GEO_MIN_RANGES is a test knob: the pipeline test compiles a two-entry fixture.
    parser.add_argument('--min-ranges', type=int, default=int(os.environ.get('GV_GEO_MIN_RANGES', MIN_RANGES)))
    parser.add_argument('--config', default=None, help='accepted for worker compatibility; unused')
    args = parser.parse_args(argv)
    geo_dir = args.dir or default_dir()
    status = compile_geo(geo_dir, min_ranges=args.min_ranges)
    for kind in ('country', 'asn'):
        info = status[kind]
        if info:
            print('%s: %s  (%d IPv4 ranges, %d IPv6 ranges)' % (kind, info['source'], info['v4'], info['v6']))
    if status['ignored_tags']:
        print('ignored geoip.dat tags: ' + ', '.join(sorted(status['ignored_tags'])))
    for err in status['errors']:
        print('ERROR: ' + err, file=sys.stderr)
    print('geo compile: ' + ('ok' if status['ok'] else 'FAILED'))
    return 0 if status['ok'] and not status['errors'] else 1


if __name__ == '__main__':
    sys.exit(main())
