"""Thin redis-py wrapper for the verdict contract.

Every key goes through key()/gp_key(), which add the namespace prefix from the
guard's redis block, and carries a TTL, so a stopped analyzer cannot pin a
stale verdict forever. Every call is wrapped: a Redis outage warns on stderr
and returns False rather than raising, because a failed verdict write must
never take down a nightly job. The analyzer only ever writes these keys - it
never blocks, challenges, or serves a request.
"""

from __future__ import print_function

import re
import sys

try:
    import redis as redis_py
    REDIS_AVAILABLE = True
    REDIS_ERROR = ''
except Exception as exc:                      # pragma: no cover - env dependent
    REDIS_AVAILABLE = False
    REDIS_ERROR = str(exc)


PREFIX_RE = re.compile(r'^[A-Za-z0-9_.:-]{0,32}$')
NO_PASSWORD_RE = re.compile(r'without any password|no password is set', re.I)

# The key namespace of the connection opened last. key() is the ONLY place a
# 'gv:' literal is built; with an empty prefix the names are exactly the legacy
# ones, so an upgrade changes nothing.
_PREFIX = ''
# Credentials in use, scrubbed from anything warn() prints: a job's captured
# output is shown in the panel.
_SECRETS = []


def key(name):
    """Namespaced gv: key. Mirrors gv_key() in guard/redis.php."""
    return _PREFIX + 'gv:' + str(name)


def gp_key(name):
    """Namespaced gp: (panel) key. Mirrors gp_key() in guard/redis.php."""
    return _PREFIX + 'gp:' + str(name)


def unavailable_reason(cfg, what='verdicts were computed but not stored'):
    """The job warning for "no Redis client": a PHP bridge that failed (the guard's Redis settings could not be read, so
    nothing was even tried) is a different problem from a Redis that refused the connection. Pure."""
    if (cfg or {}).get('redis_confirmed') is False:
        return ('Redis settings not confirmed (the PHP bridge failed: %s): %s. Fix the php binary: add PATH=/usr/local/bin:/usr/bin:/bin to the crontab or set GV_PHP'
                % ((cfg or {}).get('redis_bridge_error') or 'unknown error', what))
    return 'Redis unavailable: %s' % what


def warn(message):
    text = str(message)
    for secret in _SECRETS:
        if secret:
            text = text.replace(secret, '***')
    print('WARN: ' + text, file=sys.stderr)


def connect(cfg, write=False):
    """Return a live client, or None when Redis is unavailable.

    write=True is for callers that change Redis: they get None (and an explicit
    ERROR) unless the Redis settings were confirmed - read from the guard's config
    or stated explicitly - because writing under guessed settings means writing
    into the wrong namespace and reporting success.

    Settings come from cfg['redis'], which config.load() already resolved
    (defaults < the guard's redis block < an explicit analyzer override).
    """
    global _PREFIX
    if not REDIS_AVAILABLE:
        warn('redis-py not installed: ' + REDIS_ERROR)
        return None
    settings = (cfg or {}).get('redis') or {}
    if write and (cfg or {}).get('redis_confirmed') is False:
        print('ERROR: the Redis settings are not confirmed (the guard\'s config could not be read), '
              'so nothing is written.', file=sys.stderr)
        return None
    prefix = str(settings.get('prefix') or '')
    if not PREFIX_RE.match(prefix):
        # Same rule as the guard: an invalid prefix is a configuration error,
        # never silently altered.
        warn('redis.prefix is invalid (allowed: [A-Za-z0-9_.:-], max 32): Redis disabled')
        return None
    _PREFIX = prefix
    password = str(settings.get('password') or '')
    username = str(settings.get('username') or '')
    _SECRETS[:] = [x for x in (password, username) if x]

    def build(use_password):
        timeout = float(settings.get('socket_timeout', 0.2))
        kwargs = dict(db=int(settings.get('db', 0)), socket_timeout=timeout,
                      socket_connect_timeout=timeout, decode_responses=True)
        socket_path = str(settings.get('socket') or '')
        if socket_path:
            kwargs['unix_socket_path'] = socket_path
        else:
            kwargs['host'] = settings.get('host', '127.0.0.1')
            kwargs['port'] = int(settings.get('port', 6379))
        if use_password and password:
            kwargs['password'] = password
            if username:
                kwargs['username'] = username
        # RESP2 on purpose: redis-py >= 5 defaults to RESP3 (a HELLO 3 handshake),
        # which Redis 5 does not understand. Older redis-py has no such argument.
        try:
            return redis_py.Redis(protocol=2, **kwargs)
        except TypeError:
            return redis_py.Redis(**kwargs)

    try:
        client = build(True)
        try:
            client.ping()
        except Exception as exc:
            # A password configured for a server that has none is harmless
            # (the wording differs by Redis version); carry on without AUTH.
            if password and NO_PASSWORD_RE.search(str(exc)):
                warn('a Redis password is configured but the server has none')
                client = build(False)
                client.ping()
            else:
                raise
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
    key_ = key('botok:' + str(ip)) if verdict == 'ok' else key('botbad:' + str(ip))
    other = key('botbad:' + str(ip)) if verdict == 'ok' else key('botok:' + str(ip))
    written = _setex(client, key_, ttl, '1')
    if written and client is not None:
        try:
            client.delete(other)      # a re-verified IP must not stay flagged
        except Exception as exc:
            warn('delete failed for %s: %s' % (other, exc))
    return written


def get_botv(client, ip):
    """Return 'bad', 'ok' or None. A bad verdict wins if both somehow exist."""
    if _get(client, key('botbad:' + str(ip))) is not None:
        return 'bad'
    if _get(client, key('botok:' + str(ip))) is not None:
        return 'ok'
    return None


def set_rep(client, dev, value, ttl):
    return _setex(client, key('rep:' + str(dev)), ttl, int(value))


def get_rep(client, dev):
    raw = _get(client, key('rep:' + str(dev)))
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def set_ml(client, dev, level, ttl):
    level = max(0, min(100, int(level)))
    return _setex(client, key('ml:' + str(dev)), ttl, level)


def get_ml(client, dev):
    raw = _get(client, key('ml:' + str(dev)))
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def set_clf(client, dev, level, ttl):
    level = max(0, min(100, int(level)))
    return _setex(client, key('clf:' + str(dev)), ttl, level)


def get_clf(client, dev):
    raw = _get(client, key('clf:' + str(dev)))
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


# --- operator overrides ---------------------------------------------------
# Written by ctl.py, read by the guard. The TTL is the operator's, not ours:
# an override without an expiry is a config change in disguise, and it will be
# forgotten.

# Temporary challenge overrides live in ONE key family, chal:<identity>; the value says which: '1' = the proof-of-work challenge,
# 'c' = the CAPTCHA. The guard reads it in its existing pipeline (guard/guard.php gv_override_from).
CHAL_VALUES = {'challenge': '1', 'captcha': 'c'}


def set_override(client, kind, identity, ttl):
    if kind in CHAL_VALUES:
        return _setex(client, key('chal:%s' % identity), ttl, CHAL_VALUES[kind])
    if kind not in ('allow', 'deny'):
        warn('ignoring unknown override kind: %r' % (kind,))
        return False
    return _setex(client, key('%s:%s' % (kind, identity)), ttl, '1')


def get_override(client, identity):
    """Return {'allow': ttl|None, 'deny': ttl|None, 'challenge': ttl|None, 'captcha': ttl|None} for one identity."""
    out = {}
    for kind in ('allow', 'deny'):
        full = key('%s:%s' % (kind, identity))
        if _get(client, full) == '1':
            out[kind] = ttl_of(client, full)
        else:
            out[kind] = None
    full = key('chal:%s' % identity)
    value = _get(client, full)
    for kind, want in CHAL_VALUES.items():
        out[kind] = ttl_of(client, full) if value == want else None
    return out


def clear_override(client, identity):
    """Delete both override keys for an identity. Returns how many were removed."""
    if client is None:
        return 0
    removed = 0
    for kind in ('allow', 'deny', 'chal'):
        try:
            removed += int(client.delete(key('%s:%s' % (kind, identity))) or 0)
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
    kinds = ('allow', 'deny', 'chal') if kind is None else (('chal',) if kind in CHAL_VALUES else (kind,))
    out = []
    for one in kinds:
        head = key('%s:' % one)                   # prefix + family, e.g. shop1:gv:allow:
        try:
            # The prefix contains no glob characters (see PREFIX_RE), so it can
            # go into the MATCH pattern as is.
            for full in client.scan_iter(match=head + '*', count=100):
                name = one
                if one == 'chal':
                    name = 'captcha' if _get(client, full) == 'c' else 'challenge'
                    if kind in CHAL_VALUES and name != kind:
                        continue
                out.append((name, str(full)[len(head):], ttl_of(client, full)))
                if len(out) >= limit:
                    return out
        except Exception as exc:
            warn('scan failed for %s overrides: %s' % (one, exc))
    return out


def ip_net(identity):
    """The guard's gv_ip_net(): an IPv4 address as it is, an IPv6 address as its /64 ('2001:db8::/64'); anything else (a device id) as it is."""
    ident = str(identity)
    if ':' not in ident:
        return ident
    try:
        import ipaddress
        addr = ipaddress.ip_address(ident)
    except ValueError:
        return ident
    if addr.version != 6:
        return ident
    return '%s/64' % ipaddress.ip_network('%s/64' % ident, strict=False).network_address.compressed


def honeypot_mark(client, identity):
    """Whether the guard holds a honeypot history for this identity: per device (hpd:<device>), per IPv6 /64 or IPv4 address (hpn:<net>),
    or the hp:<ip> that releases before 2026.11.39 wrote. The same three keys the panel's Identity page reads."""
    ident = str(identity)
    return (_get(client, key('hpd:' + ident)) == '1' or _get(client, key('hpn:' + ip_net(ident))) == '1'
            or _get(client, key('hp:' + ident)) == '1')


def identity_verdicts(client, identity):
    """Every gv: verdict touching one identity - the first thing to look at
    when a customer reports being blocked."""
    return {
        'reputation': get_rep(client, identity),
        'ml': get_ml(client, identity),
        'clf': get_clf(client, identity),
        'botok': _get(client, key('botok:' + str(identity))) == '1',
        'botbad': _get(client, key('botbad:' + str(identity))) == '1',
        'honeypot': honeypot_mark(client, identity),
        'overrides': get_override(client, identity),
    }
