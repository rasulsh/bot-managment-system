"""Forward-confirmed reverse DNS for known-bot claims.

Phase 1 gives any UA matching known_bots a fast in-band pass with no DNS
lookup, because DNS latency does not belong in the request path. This module
does that verification out of band and lets the guard read a single cheap key.

The resolver is injectable so every branch can be tested without real DNS.
"""

import socket


class DefaultResolver(object):
    """Thin wrapper over the standard library, so tests can swap it out."""

    def ptr(self, ip):
        """Reverse lookup: return every hostname the address claims."""
        hostname, aliases, _addresses = socket.gethostbyaddr(ip)
        return [hostname] + list(aliases)

    def forward(self, hostname):
        """Forward lookup: return every address the hostname resolves to (v4 and v6).

        gethostbyname_ex() returns IPv4 addresses only, so a genuine IPv6
        Googlebot/Bingbot whose PTR matched would never forward-confirm and was
        always flagged 'bad'. getaddrinfo() covers both families; like
        gethostbyname_ex it may raise on failure, which verify_ip already
        catches (fail-closed on the verification only).
        """
        infos = socket.getaddrinfo(hostname, None)
        out = []
        for info in infos:
            addr = info[4][0]          # sockaddr; [0] is the address string
            if addr not in out:
                out.append(addr)
        return out


default_resolver = DefaultResolver()


def matches_suffix(hostname, suffixes):
    """True when hostname ends with one of the operator-listed suffixes."""
    lowered = str(hostname or '').lower().rstrip('.')
    for suffix in suffixes or []:
        if lowered.endswith(str(suffix).lower()):
            return True
    return False


def verify_ip(ip, claimed_bot, bot_suffixes, resolver=default_resolver):
    """Return 'ok' when the bot claim is forward-confirmed, else 'bad'.

    1. PTR the address.
    2. At least one hostname must end with a suffix registered for the claimed
       bot - anyone can put "Googlebot" in a User-Agent, nobody else can hold
       PTR records under googlebot.com.
    3. That hostname must forward-resolve back to the original address, which
       is what defeats a forged PTR record.

    Any resolver failure yields 'bad'. That is deliberately fail-closed on
    verification only: a 'bad' verdict never blocks anything by itself, it just
    revokes the free pass and sends the request through normal scoring.
    """
    suffixes = (bot_suffixes or {}).get(claimed_bot) or []
    if not ip or not claimed_bot or not suffixes:
        return 'bad'

    try:
        hostnames = resolver.ptr(ip)
    except Exception:
        return 'bad'
    if not hostnames:
        return 'bad'

    for hostname in hostnames:
        if not matches_suffix(hostname, suffixes):
            continue
        try:
            addresses = resolver.forward(hostname)
        except Exception:
            continue
        if ip in [str(a) for a in (addresses or [])]:
            return 'ok'
    return 'bad'
