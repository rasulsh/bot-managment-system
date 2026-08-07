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
