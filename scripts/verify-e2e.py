#!/usr/bin/env python3
"""End-to-end check of three-state bot verification against a running guard.

    python3 scripts/verify-e2e.py http://127.0.0.1:8080 /tmp/gv-logs

A genuine Googlebot smartphone request must stay 200 across a simulated
resolver outage, and a forged one (definitive forward mismatch) must still be
caught. Prints one line: "<before> <after_outage> <after_forged>" (HTTP codes).
Needs the dev router's config (enforce.block on) and a local Redis.
"""
import contextlib
import io
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import botverify, redis_io, run_verify  # noqa: E402

UA = ('Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36 '
      '(compatible; Googlebot/2.1; +http://www.google.com/bot.html)')


def fetch(base, query):
    req = urllib.request.Request(base + '/?' + query, headers={
        'User-Agent': UA, 'Accept': 'text/html,application/xhtml+xml'})
    try:
        return urllib.request.urlopen(req, timeout=5).getcode()
    except urllib.error.HTTPError as exc:
        return exc.code


class Stub(object):
    def __init__(self, ptr, forward, exc=None):
        self.ptr_map, self.forward_map, self.exc = ptr, forward, exc

    def ptr(self, ip):
        if self.exc:
            raise self.exc
        return self.ptr_map.get(ip, [])

    def forward(self, host):
        return self.forward_map.get(host, [])

    def healthy(self):
        return True


def main():
    base, log_dir = sys.argv[1].rstrip('/'), sys.argv[2]
    ip = os.environ.get('GV_CLIENT_IP', '127.0.0.1')
    cfg = {'log_dir': log_dir, 'model_path': os.path.join(log_dir, 'model.joblib')}
    client = redis_io.connect({'redis': {}})
    client.delete('gv:botok:' + ip, 'gv:botbad:' + ip, 'gv:hp:' + ip)
    before = fetch(base, 'v=before')                       # logs the bot claim
    cfg_path = os.path.join(log_dir, 'verify-e2e.json')
    import json
    with open(cfg_path, 'w') as fh:
        json.dump(cfg, fh)
    run_verify.DNS_SLEEP_S = 0
    quiet = io.StringIO()
    with contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
        run_verify.main(['--config', cfg_path, '--log-dir', log_dir, '--recheck'],
                        resolver=Stub({}, {}, exc=botverify.DnsTransient('outage')))
    after_outage = fetch(base, 'v=outage')
    with contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
        run_verify.main(['--config', cfg_path, '--log-dir', log_dir, '--recheck'],
                        resolver=Stub({ip: ['fake.googlebot.com']}, {'fake.googlebot.com': ['203.0.113.250']}))
    after_forged = fetch(base, 'v=forged')
    client.delete('gv:botok:' + ip, 'gv:botbad:' + ip)
    os.unlink(cfg_path)
    print(before, after_outage, after_forged)


if __name__ == '__main__':
    main()
