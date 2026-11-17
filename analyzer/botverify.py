"""Forward-confirmed reverse DNS for known-bot claims.

Phase 1 gives any UA matching known_bots a fast in-band pass with no DNS
lookup, because DNS latency does not belong in the request path. This module
does that verification out of band and lets the guard read a single cheap key.

Verification is THREE-state, because "could not verify" and "refuted" are not
the same thing and a wrong 'bad' costs a real crawler a 403 on every page:

    ok       a PTR hostname matches a registered suffix AND forward-resolves
             back to the address.
    bad      a DEFINITIVE refutation only: the PTR lookup succeeded and no
             hostname matches a suffix; the address has no PTR record; or a
             matching hostname forward-resolved and the address is not in the
             answer (or the hostname does not exist).
    unknown  everything else: timeouts, TRY_AGAIN / SERVFAIL, an unreachable
             resolver, any unexpected exception, and a claimed bot with no
             configured suffix list (cannot be verified is not impersonator).

The caller writes nothing for 'unknown' and retries the address next run.

The resolver is injectable so every branch can be tested without real DNS.
An injected resolver reports a lookup outcome by raising DnsNotFound (a
definitive negative answer) or DnsTransient (could not tell); any other
exception counts as transient.
"""

import socket
import time

try:
    import ipaddress
except ImportError:                              # pragma: no cover - py2 only
    ipaddress = None


class DnsNotFound(Exception):
    """The resolver gave a definitive negative answer (NXDOMAIN / no record)."""


class DnsTransient(Exception):
    """The lookup could not be completed: timeout, SERVFAIL, resolver down."""


# netdb.h h_errno values, as raised by socket.herror (verified on glibc).
HOST_NOT_FOUND = 1
TRY_AGAIN = 2
NO_RECOVERY = 3
NO_DATA = 4

# A name that must resolve on any working resolver. See DefaultResolver.healthy.
DEFAULT_CANARY = 'www.google.com'
CANARY_TTL_S = 30


class DefaultResolver(object):
    """Thin wrapper over the standard library, so tests can swap it out."""

    def __init__(self, canary=DEFAULT_CANARY):
        self.canary = canary
        self._health = None                      # (checked_at, bool)

    def ptr(self, ip):
        """Reverse lookup: return every hostname the address claims.

        Raises DnsNotFound for HOST_NOT_FOUND / NO_DATA and DnsTransient for
        everything else (TRY_AGAIN, NO_RECOVERY, timeouts, odd errors).
        """
        try:
            hostname, aliases, _addresses = socket.gethostbyaddr(ip)
        except socket.herror as exc:
            code = exc.args[0] if exc.args else None
            if code in (HOST_NOT_FOUND, NO_DATA):
                raise DnsNotFound('no PTR record for %s' % ip)
            raise DnsTransient('PTR lookup failed (h_errno %r)' % (code,))
        except Exception as exc:                 # gaierror, timeout, OSError, ...
            raise DnsTransient('PTR lookup failed: %s' % exc)
        return [hostname] + list(aliases)

    def forward(self, hostname):
        """Forward lookup: return every address the hostname resolves to (v4 and v6).

        gethostbyname_ex() returns IPv4 addresses only, so a genuine IPv6
        Googlebot/Bingbot whose PTR matched would never forward-confirm.
        getaddrinfo() covers both families. EAI_NONAME / EAI_NODATA are a
        definitive "no such name"; EAI_AGAIN, EAI_FAIL and the rest are not.
        """
        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            code = exc.args[0] if exc.args else None
            if code in (socket.EAI_NONAME, getattr(socket, 'EAI_NODATA', None)):
                raise DnsNotFound('no such host %s' % hostname)
            raise DnsTransient('forward lookup failed (EAI %r)' % (code,))
        except Exception as exc:
            raise DnsTransient('forward lookup failed: %s' % exc)
        out = []
        for info in infos:
            addr = info[4][0]          # sockaddr; [0] is the address string
            if addr not in out:
                out.append(addr)
        return out

    def healthy(self, fresh=False):
        """True when the resolver demonstrably works right now.

        fresh=True ignores the cached answer. verify_ip asks for that after a
        NEGATIVE reply: a resolver that worked half a minute ago and has died
        since answers "not found" for everything, and a cached "healthy" would
        turn each of those into a 'bad' verdict for a real crawler.

        glibc reports an UNREACHABLE resolver as HOST_NOT_FOUND on some systems
        (observed: gethostbyaddr answers herror(1) in milliseconds when UDP/53
        is refused), which is indistinguishable from a real NXDOMAIN through the
        standard library. So a negative answer only counts as a refutation when
        a canary name resolves in the same breath.
        """
        now = time.time()
        if (not fresh and self._health is not None
                and (now - self._health[0]) < CANARY_TTL_S):
            return self._health[1]
        try:
            alive = bool(socket.getaddrinfo(self.canary, None))
        except Exception:
            alive = False
        self._health = (now, alive)
        return alive


default_resolver = DefaultResolver()


def matches_suffix(hostname, suffixes):
    """True when hostname ends with one of the operator-listed suffixes."""
    lowered = str(hostname or '').lower().rstrip('.')
    for suffix in suffixes or []:
        if lowered.endswith(str(suffix).lower()):
            return True
    return False


def _same_address(a, b):
    """Compare two textual addresses, tolerating IPv6 spelling differences."""
    a, b = str(a), str(b)
    if a == b:
        return True
    if ipaddress is None:
        return False
    try:
        return _unmapped(ipaddress.ip_address(a)) == _unmapped(ipaddress.ip_address(b))
    except ValueError:
        return False


def _unmapped(addr):
    """::ffff:1.2.3.4 is the IPv4 address 1.2.3.4 written as IPv6."""
    mapped = getattr(addr, 'ipv4_mapped', None)
    return mapped if mapped is not None else addr


def _resolver_works(resolver):
    """An injected resolver without healthy() is assumed to be working.

    Always asks for a FRESH check: this is only called after a negative answer,
    and that answer is worth nothing unless the resolver is alive right now.
    """
    check = getattr(resolver, 'healthy', None)
    if check is None:
        return True
    try:
        try:
            return bool(check(fresh=True))
        except TypeError:
            return bool(check())                 # an injected resolver without the flag
    except Exception:
        return False


def verify_ip(ip, claimed_bot, bot_suffixes, resolver=default_resolver):
    """Return 'ok', 'bad' or 'unknown' for a bot claim made from ip.

    1. PTR the address.
    2. At least one hostname must end with a suffix registered for the claimed
       bot - anyone can put "Googlebot" in a User-Agent, nobody else can hold
       PTR records under googlebot.com.
    3. That hostname must forward-resolve back to the original address, which
       is what defeats a forged PTR record.

    Only a definitive refutation returns 'bad'. A 'bad' verdict revokes the
    guard's free pass and adds BOT_FAKE (+35), which for a smartphone Googlebot
    is enough to cross hard_block_score - so it must never be a guess.
    """
    suffixes = (bot_suffixes or {}).get(claimed_bot) or []
    if not ip or not claimed_bot or not suffixes:
        return 'unknown'

    try:
        hostnames = resolver.ptr(ip)
    except DnsNotFound:
        # A negative answer only refutes the claim from a resolver that works.
        return 'bad' if _resolver_works(resolver) else 'unknown'
    except Exception:
        return 'unknown'
    if not hostnames:
        return 'bad' if _resolver_works(resolver) else 'unknown'

    matching = [h for h in hostnames if matches_suffix(h, suffixes)]
    if not matching:
        return 'bad'                             # the PTR answer itself refutes it

    transient = False
    for hostname in matching:
        try:
            addresses = resolver.forward(hostname)
        except DnsNotFound:
            if _resolver_works(resolver):
                continue                         # the PTR name does not exist: refuted
            transient = True
            continue
        except Exception:
            transient = True
            continue
        if any(_same_address(ip, a) for a in (addresses or [])):
            return 'ok'
    return 'unknown' if transient else 'bad'
