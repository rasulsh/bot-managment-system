"""Thin redis-py wrapper for the verdict contract.

Every key carries the gv: prefix and a TTL, so a stopped analyzer cannot pin a
stale verdict forever. Every call is wrapped: a Redis outage warns on stderr
and returns False rather than raising, because a failed verdict write must
never take down a nightly job. The analyzer only ever writes these keys - it
never blocks, challenges, or serves a request.
"""

from __future__ import print_function

import sys

try:
    import redis as redis_py
    REDIS_AVAILABLE = True
    REDIS_ERROR = ''
except Exception as exc:                      # pragma: no cover - env dependent
    REDIS_AVAILABLE = False
    REDIS_ERROR = str(exc)


def warn(message):
    print('WARN: ' + str(message), file=sys.stderr)


def connect(cfg):
    """Return a live client, or None when Redis is unavailable."""
    if not REDIS_AVAILABLE:
        warn('redis-py not installed: ' + REDIS_ERROR)
        return None
    settings = (cfg or {}).get('redis') or {}
    try:
        client = redis_py.Redis(
            host=settings.get('host', '127.0.0.1'),
            port=int(settings.get('port', 6379)),
            db=int(settings.get('db', 0)),
            socket_timeout=float(settings.get('socket_timeout', 0.2)),
            socket_connect_timeout=float(settings.get('socket_timeout', 0.2)),
            decode_responses=True,
        )
        client.ping()
        return client
    except Exception as exc:
        warn('redis unavailable: %s' % exc)
        return None


def _setex(client, key, ttl, value):
    if client is None:
        return False
    try:
        client.setex(key, int(ttl), str(value))
        return True
    except Exception as exc:
        warn('write failed for %s: %s' % (key, exc))
        return False


def _get(client, key):
    if client is None:
        return None
    try:
        return client.get(key)
    except Exception as exc:
        warn('read failed for %s: %s' % (key, exc))
        return None


def set_botv(client, ip, verdict, ttl):
    """Write gv:botok:{ip} or gv:botbad:{ip} and clear the opposite verdict."""
    if verdict not in ('ok', 'bad'):
        warn('ignoring unknown bot verdict: %r' % (verdict,))
        return False
    key = 'gv:botok:' + str(ip) if verdict == 'ok' else 'gv:botbad:' + str(ip)
    other = 'gv:botbad:' + str(ip) if verdict == 'ok' else 'gv:botok:' + str(ip)
    written = _setex(client, key, ttl, '1')
    if written and client is not None:
        try:
            client.delete(other)      # a re-verified IP must not stay flagged
        except Exception as exc:
            warn('delete failed for %s: %s' % (other, exc))
    return written


def get_botv(client, ip):
    """Return 'bad', 'ok' or None. A bad verdict wins if both somehow exist."""
    if _get(client, 'gv:botbad:' + str(ip)) is not None:
        return 'bad'
    if _get(client, 'gv:botok:' + str(ip)) is not None:
        return 'ok'
    return None


def set_rep(client, dev, value, ttl):
    return _setex(client, 'gv:rep:' + str(dev), ttl, int(value))


def get_rep(client, dev):
    raw = _get(client, 'gv:rep:' + str(dev))
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def set_ml(client, dev, level, ttl):
    level = max(0, min(100, int(level)))
    return _setex(client, 'gv:ml:' + str(dev), ttl, level)


def get_ml(client, dev):
    raw = _get(client, 'gv:ml:' + str(dev))
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def set_clf(client, dev, level, ttl):
    level = max(0, min(100, int(level)))
    return _setex(client, 'gv:clf:' + str(dev), ttl, level)


def get_clf(client, dev):
    raw = _get(client, 'gv:clf:' + str(dev))
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


# --- operator overrides ---------------------------------------------------
# Written by ctl.py, read by the guard. The TTL is the operator's, not ours:
# an override without an expiry is a config change in disguise, and it will be
# forgotten.

def set_override(client, kind, identity, ttl):
    if kind not in ('allow', 'deny'):
        warn('ignoring unknown override kind: %r' % (kind,))
        return False
    return _setex(client, 'gv:%s:%s' % (kind, identity), ttl, '1')


def get_override(client, identity):
    """Return {'allow': ttl|None, 'deny': ttl|None} for one identity."""
    out = {}
    for kind in ('allow', 'deny'):
        key = 'gv:%s:%s' % (kind, identity)
        if _get(client, key) == '1':
            out[kind] = ttl_of(client, key)
        else:
            out[kind] = None
    return out


def clear_override(client, identity):
    """Delete both override keys for an identity. Returns how many were removed."""
    if client is None:
        return 0
    removed = 0
    for kind in ('allow', 'deny'):
        try:
            removed += int(client.delete('gv:%s:%s' % (kind, identity)) or 0)
        except Exception as exc:
            warn('delete failed for %s override: %s' % (kind, exc))
    return removed


def ttl_of(client, key):
    if client is None:
        return None
    try:
        value = int(client.ttl(key))
    except Exception:
        return None
    return value if value >= 0 else None


def list_overrides(client, kind=None, limit=500):
    """Return [(kind, identity, ttl)] for the override keys currently set."""
    if client is None:
        return []
    kinds = ('allow', 'deny') if kind is None else (kind,)
    out = []
    for one in kinds:
        prefix = 'gv:%s:' % one
        try:
            for key in client.scan_iter(match=prefix + '*', count=100):
                out.append((one, str(key)[len(prefix):], ttl_of(client, key)))
                if len(out) >= limit:
                    return out
        except Exception as exc:
            warn('scan failed for %s overrides: %s' % (one, exc))
    return out


def identity_verdicts(client, identity):
    """Every gv: verdict touching one identity - the first thing to look at
    when a customer reports being blocked."""
    return {
        'reputation': get_rep(client, identity),
        'ml': get_ml(client, identity),
        'clf': get_clf(client, identity),
        'botok': _get(client, 'gv:botok:' + str(identity)) == '1',
        'botbad': _get(client, 'gv:botbad:' + str(identity)) == '1',
        'honeypot': _get(client, 'gv:hp:' + str(identity)) == '1',
        'overrides': get_override(client, identity),
    }
