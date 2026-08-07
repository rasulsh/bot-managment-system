#!/usr/bin/env python3
"""Analyzer self-test. Run: python3 analyzer/selftest.py

Plain PASS/FAIL/SKIP output, exit 0 when every non-SKIP assertion passes.
The core assertions build synthetic sessions in memory: no real log files, no
real DNS, no Redis required. The Redis and scikit-learn sections SKIP cleanly
when those are not installed.
"""

from __future__ import print_function

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import botverify
from analyzer import config as config_mod
from analyzer import features as features_mod
from analyzer import logs as logs_mod
from analyzer import model as model_mod
from analyzer import redis_io
from analyzer import reputation as reputation_mod

PASS = 0
FAIL = 0
SKIP = 0


def ok(name, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print('PASS  ' + name)
    else:
        FAIL += 1
        print('FAIL  ' + name)


def skip(name, why):
    global SKIP
    SKIP += 1
    print('SKIP  %s (%s)' % (name, why))


def section(name):
    print('\n-- ' + name)


def row(ts, dev='', ip='10.0.0.1', uah='aaaaaaaaaaaa', p='/', nav=1, sc=0,
        rs=None, act='allow', sh=0, hp=0, bot=''):
    """One synthetic Phase 1 log row."""
    return {'ts': ts, 'ip': ip, 'ua': 'x', 'uah': uah, 'm': 'GET', 'p': p, 'q': '',
            'aj': 0, 'nav': nav, 'tok': 'v' if dev else 'm', 'dev': dev, 'sf': '',
            'al': 1, 'hc': 10, 'sc': sc, 'rs': rs or [], 'cd': 0, 'ciu': 0, 'ci': 0,
            'rd': 0, 'hp': hp, 'bot': bot, 'ref': '', 'act': act, 'sh': sh, 'ms': 1.0}


# ---------------------------------------------------------------------------
section('Configuration')

cfg = config_mod.load()
ok('defaults load and validate', isinstance(cfg, dict) and cfg['window_days'] >= 1)
ok('rep_clamp is a two-element range', len(cfg['rep_clamp']) == 2
   and cfg['rep_clamp'][0] < cfg['rep_clamp'][1])
ok('known_bots matches the documented pair', cfg['known_bots'] == ['googlebot', 'bingbot'])
ok('bot_suffixes carries googlebot and bingbot',
   set(cfg['bot_suffixes']) == set(['googlebot', 'bingbot']))
ok('path patterns are empty by default: no platform coupling',
   cfg['path_listing'] == [] and cfg['path_detail'] == [])

try:
    config_mod.validate(dict(cfg, rep_clamp=[80, -50]))
    ok('an inverted rep_clamp is rejected', False)
except ValueError:
    ok('an inverted rep_clamp is rejected', True)

try:
    config_mod.load('/nonexistent/analyzer-config.json')
    ok('a missing config path is rejected', False)
except ValueError:
    ok('a missing config path is rejected', True)

handle, json_path = tempfile.mkstemp(suffix='.json')
with os.fdopen(handle, 'w') as fh:
    fh.write('{"window_days": 3, "redis": {"port": 6399}}')
override = config_mod.load(json_path)
ok('a json override replaces a scalar', override['window_days'] == 3)
ok('a json override merges nested redis settings',
   override['redis']['port'] == 6399 and override['redis']['host'] == '127.0.0.1')
os.unlink(json_path)

# ---------------------------------------------------------------------------
section('Sessionization')

rows = [
    row(1000.0, dev='devA', p='/a'),
    row(1010.0, dev='devA', p='/b'),
    row(1020.0, dev='devA', p='/c'),
    row(9000.0, dev='devA', p='/d'),          # far beyond the gap: new session
    row(1005.0, dev='devB', p='/a'),
    row(1015.0, dev='devB', p='/b'),
    row(1002.0, dev='', ip='10.0.0.9', uah='bbbbbbbbbbbb', p='/x'),
]
sessions = logs_mod.sessionize(rows, 1800)
ok('a mid-window gap splits one device into two sessions', len(sessions) == 4)

by_key = {}
for session in sessions:
    by_key.setdefault(session['key'], []).append(session)
ok('devA produced two sessions', len(by_key.get('devA', [])) == 2)
ok('devB produced one session', len(by_key.get('devB', [])) == 1)
ok('an empty dev falls back to the ip|uah key',
   '10.0.0.9|bbbbbbbbbbbb' in by_key)
ok('device sessions are marked is_device', by_key['devA'][0]['is_device'] is True)
ok('the ip|uah fallback is not marked is_device',
   by_key['10.0.0.9|bbbbbbbbbbbb'][0]['is_device'] is False)
ok('rows inside a session are ordered by ts',
   [r['p'] for r in by_key['devA'][0]['rows']] == ['/a', '/b', '/c'])
ok('an unparsable ts is dropped rather than raising',
   len(logs_mod.sessionize([{'ts': 'nonsense', 'dev': 'devZ'}], 1800)) == 0)
ok('device_history flattens every row of a key',
   len(logs_mod.device_history(sessions)['devA']) == 4)

# ---------------------------------------------------------------------------
section('Log reading')

log_dir = tempfile.mkdtemp(prefix='gv-selftest-logs-')
import datetime
import json as json_mod

today = datetime.date.today()
log_file = os.path.join(log_dir, 'guard-%s.jsonl' % today.strftime('%Y%m%d'))
with open(log_file, 'w') as fh:
    fh.write(json_mod.dumps(row(1000.0, dev='devA')) + '\n')
    fh.write('{ this is not json\n')           # must be skipped, not fatal
    fh.write('\n')
    fh.write(json_mod.dumps(row(1010.0, dev='devA')) + '\n')

read = list(logs_mod.read_lines(log_dir, 1))
ok('valid lines are read and the corrupt line is skipped', len(read) == 2)
ok('an absent day is simply not read', list(logs_mod.read_lines(log_dir, 1,
   today=today - datetime.timedelta(days=5))) == [])

import gzip as gzip_mod
gz_file = os.path.join(log_dir, 'guard-%s.jsonl.gz'
                       % (today - datetime.timedelta(days=1)).strftime('%Y%m%d'))
with gzip_mod.open(gz_file, 'wt') as fh:
    fh.write(json_mod.dumps(row(900.0, dev='devB')) + '\n')
ok('a gzipped day is read too', len(list(logs_mod.read_lines(log_dir, 2))) == 3)

os.unlink(log_file)
os.unlink(gz_file)
os.rmdir(log_dir)

# ---------------------------------------------------------------------------
section('Features')

# Metronomic scraper: exactly 0.25 s apart, scripted UA, every path distinct.
bot_rows = [row(1000.0 + i * 0.25, dev='botdev', p='/p%d' % i, nav=1, sc=30,
                rs=['UA_SCRIPT', 'FEW_HDR']) for i in range(40)]
bot_session = logs_mod.sessionize(bot_rows, 1800)[0]
bot_f = features_mod.session_features(bot_session)

# Human: irregular gaps, some repeat visits, clean score.
human_stamps = [0, 7, 19, 24, 48, 55, 91, 140, 168, 240]
human_paths = ['/', '/a', '/a', '/b', '/', '/c', '/c', '/d', '/', '/e']
human_rows = [row(1000.0 + t, dev='humandev', p=p, nav=1, sc=0, act='allow')
              for t, p in zip(human_stamps, human_paths)]
human_session = logs_mod.sessionize(human_rows, 1800)[0]
human_f = features_mod.session_features(human_session)

ok('the scraper counts every request', bot_f['n_req'] == 40.0)
ok('metronomic timing gives a near-zero gap_std', bot_f['gap_std'] < 0.01)
ok('human timing gives a clearly larger gap_std', human_f['gap_std'] > 1.0)
ok('the scraper is fully scripted', bot_f['script_ratio'] == 1.0)
ok('the human is not scripted at all', human_f['script_ratio'] == 0.0)
ok('the scraper never repeats a path', bot_f['path_uniq_ratio'] == 1.0)
ok('the human revisits pages', human_f['path_uniq_ratio'] < 1.0)
ok('few_hdr_ratio tracks the reason code', bot_f['few_hdr_ratio'] == 1.0)
ok('score_mean averages the static score', bot_f['score_mean'] == 30.0)
ok('nav_ratio is 1.0 when every row is a navigation', human_f['nav_ratio'] == 1.0)
ok('dur_s spans first to last row', human_f['dur_s'] == 240.0)
ok('gap_min picks the tightest gap', human_f['gap_min'] == 5.0)

vector = features_mod.feature_vector(bot_f)
ok('the vector length matches FEATURE_ORDER',
   len(vector) == len(features_mod.FEATURE_ORDER) == 12)
ok('the vector follows FEATURE_ORDER exactly',
   vector == [bot_f[name] for name in features_mod.FEATURE_ORDER])
ok('an empty session yields a zero vector of the right shape',
   features_mod.feature_vector(features_mod.session_features({'rows': []}))
   == [0.0] * len(features_mod.FEATURE_ORDER))

ok('detail_no_listing_ratio is inert without path patterns',
   bot_f['detail_no_listing_ratio'] == 0.0)

cold_rows = [row(1000.0, p='/item/1'), row(1001.0, p='/item/2'),
             row(1002.0, p='/category/x'), row(1003.0, p='/item/3')]
ok('detail hits before any listing are counted',
   abs(features_mod.detail_no_listing_ratio(cold_rows, [r'^/category/'], [r'^/item/'])
       - (2.0 / 3.0)) < 1e-9)
ok('an invalid operator regex is ignored rather than fatal',
   features_mod.detail_no_listing_ratio(cold_rows, ['['], [r'^/item/']) == 0.0)

# ---------------------------------------------------------------------------
section('Labels')

hp_rows = [row(1000.0, dev='hpdev', p='/old-archive', hp=1, act='404_hp')]
hp_session = logs_mod.sessionize(hp_rows, 1800)[0]
ok('a honeypot hit sets hp_any',
   features_mod.session_labels(hp_session)['hp_any'] == 1)

gate_rows = [row(1000.0, dev='gdev', act='challenge', sh=0),
             row(1005.0, dev='gdev', act='challenge', sh=0)]
gate_session = logs_mod.sessionize(gate_rows, 1800)[0]
ok('a served challenge with no handshake is challenge_unsolved',
   features_mod.session_labels(gate_session)['challenge_unsolved'] == 1)

shadow_rows = [row(1000.0, dev='sdev', act='challenge', sh=1)]
shadow_session = logs_mod.sessionize(shadow_rows, 1800)[0]
ok('a shadow challenge is not held against the device',
   features_mod.session_labels(shadow_session)['challenge_unsolved'] == 0)

solved_rows = [row(1000.0, dev='odev', act='challenge', sh=0),
               row(1002.0, dev='odev', act='token_issued', sh=0),
               row(1004.0, dev='odev', act='allow')]
solved_session = logs_mod.sessionize(solved_rows, 1800)[0]
solved_labels = features_mod.session_labels(solved_session)
ok('completing the handshake clears challenge_unsolved',
   solved_labels['challenge_unsolved'] == 0 and solved_labels['solved_challenge'] == 1)

ok('aggregate_labels takes any-of across sessions',
   reputation_mod.aggregate_labels([{'hp_any': 0}, {'hp_any': 1}])['hp_any'] == 1)
ok('aggregate_labels lets a later solve clear an earlier unsolved gate',
   reputation_mod.aggregate_labels(
       [{'challenge_unsolved': 1}, {'solved_challenge': 1}])['challenge_unsolved'] == 0)

# ---------------------------------------------------------------------------
section('Reputation')

clamp = cfg['rep_clamp']

hp_rep = reputation_mod.device_reputation(
    [features_mod.session_features(hp_session)],
    {'hp_any': 1, 'challenge_unsolved': 0, 'solved_challenge': 0}, clamp)
ok('a honeypot device scores strongly positive', hp_rep >= 40)

bot_rep = reputation_mod.device_reputation(
    [bot_f], {'hp_any': 0, 'challenge_unsolved': 1, 'solved_challenge': 0}, clamp)
ok('a metronomic scripted scraper scores strongly positive', bot_rep >= 50)

human_rep = reputation_mod.device_reputation(
    [human_f], {'hp_any': 0, 'challenge_unsolved': 0, 'solved_challenge': 1}, clamp)
ok('a human who solved the challenge scores negative', human_rep < 0)

ok('reputation respects the upper clamp',
   reputation_mod.device_reputation(
       [bot_f], {'hp_any': 1, 'challenge_unsolved': 1, 'solved_challenge': 0},
       [-50, 30]) == 30)
ok('reputation respects the lower clamp',
   reputation_mod.device_reputation(
       [human_f], {'hp_any': 0, 'challenge_unsolved': 0, 'solved_challenge': 1},
       [-5, 80]) == -5)
ok('a device with no sessions scores neutral',
   reputation_mod.device_reputation([], {'hp_any': 1}, clamp) == 0)
ok('peak_rate reports the fastest session',
   reputation_mod.peak_rate([{'n_req': 10.0, 'dur_s': 100.0},
                             {'n_req': 40.0, 'dur_s': 10.0}]) == 4.0)

# ---------------------------------------------------------------------------
section('Reverse DNS verification')


class StubResolver(object):
    def __init__(self, ptr_map, forward_map, raise_on_ptr=False, raise_on_forward=False):
        self.ptr_map = ptr_map
        self.forward_map = forward_map
        self.raise_on_ptr = raise_on_ptr
        self.raise_on_forward = raise_on_forward

    def ptr(self, ip):
        if self.raise_on_ptr:
            raise OSError('simulated PTR failure')
        return self.ptr_map.get(ip, [])

    def forward(self, hostname):
        if self.raise_on_forward:
            raise OSError('simulated forward failure')
        return self.forward_map.get(hostname, [])


suffixes = cfg['bot_suffixes']
GOOD_IP = '66.249.66.1'

happy = StubResolver({GOOD_IP: ['crawl-66-249-66-1.googlebot.com']},
                     {'crawl-66-249-66-1.googlebot.com': [GOOD_IP]})
ok('a forward-confirmed googlebot verifies ok',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes, happy) == 'ok')

wrong_suffix = StubResolver({GOOD_IP: ['host.evil-crawler.net']},
                            {'host.evil-crawler.net': [GOOD_IP]})
ok('a hostname outside the registered suffixes is bad',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes, wrong_suffix) == 'bad')

forged_ptr = StubResolver({GOOD_IP: ['fake.googlebot.com']},
                          {'fake.googlebot.com': ['203.0.113.9']})
ok('a forged PTR that does not forward-confirm is bad',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes, forged_ptr) == 'bad')

ok('a PTR resolver exception is bad',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes,
                       StubResolver({}, {}, raise_on_ptr=True)) == 'bad')
ok('a forward resolver exception is bad',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes,
                       StubResolver({GOOD_IP: ['x.googlebot.com']}, {},
                                    raise_on_forward=True)) == 'bad')
ok('an empty PTR result is bad',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes, StubResolver({}, {})) == 'bad')
ok('an unknown claimed bot is bad',
   botverify.verify_ip(GOOD_IP, 'notabot', suffixes, happy) == 'bad')
ok('an empty ip is bad', botverify.verify_ip('', 'googlebot', suffixes, happy) == 'bad')

multi = StubResolver({GOOD_IP: ['other.example.com', 'crawl.googlebot.com']},
                     {'crawl.googlebot.com': ['198.51.100.1', GOOD_IP]})
ok('a matching alias among several hostnames verifies ok',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes, multi) == 'ok')

bing = StubResolver({'40.77.1.1': ['msnbot-40-77-1-1.search.msn.com']},
                    {'msnbot-40-77-1-1.search.msn.com': ['40.77.1.1']})
ok('bingbot verifies against its own suffix',
   botverify.verify_ip('40.77.1.1', 'bingbot', suffixes, bing) == 'ok')
ok('a trailing dot in a PTR name is tolerated',
   botverify.matches_suffix('crawl.googlebot.com.', ['.googlebot.com']) is True)

# ---------------------------------------------------------------------------
section('Redis verdict round-trip')

client = redis_io.connect(cfg) if redis_io.REDIS_AVAILABLE else None
if client is None:
    skip('redis verdict round-trip', 'no reachable local Redis'
         if redis_io.REDIS_AVAILABLE else 'redis-py not installed')
else:
    dev = 'selftestdev%d' % os.getpid()
    ip = '198.51.100.%d' % (os.getpid() % 200 + 1)
    ok('set_rep writes a reputation', redis_io.set_rep(client, dev, -20, 60) is True)
    ok('get_rep reads it back signed', redis_io.get_rep(client, dev) == -20)
    ok('set_ml writes an anomaly level', redis_io.set_ml(client, dev, 77, 60) is True)
    ok('get_ml reads it back', redis_io.get_ml(client, dev) == 77)
    ok('set_ml clamps an out-of-range level',
       redis_io.set_ml(client, dev, 999, 60) and redis_io.get_ml(client, dev) == 100)
    ok('set_botv writes an ok verdict', redis_io.set_botv(client, ip, 'ok', 60) is True)
    ok('get_botv reads ok', redis_io.get_botv(client, ip) == 'ok')
    ok('a bad verdict clears the previous ok verdict',
       redis_io.set_botv(client, ip, 'bad', 60)
       and redis_io.get_botv(client, ip) == 'bad'
       and client.get('gv:botok:' + ip) is None)
    ok('an unknown verdict is refused', redis_io.set_botv(client, ip, 'maybe', 60) is False)
    ok('every verdict key carries a TTL',
       client.ttl('gv:rep:' + dev) > 0 and client.ttl('gv:ml:' + dev) > 0
       and client.ttl('gv:botbad:' + ip) > 0)
    ok('writes against a dead client return False rather than raising',
       redis_io.set_rep(None, dev, 1, 60) is False)
    ok('reads against a dead client return None',
       redis_io.get_rep(None, dev) is None)
    for key in ('gv:rep:' + dev, 'gv:ml:' + dev, 'gv:botok:' + ip, 'gv:botbad:' + ip):
        client.delete(key)

# ---------------------------------------------------------------------------
section('Isolation Forest')

if not model_mod.SKLEARN_AVAILABLE:
    skip('isolation forest train/score', 'scikit-learn not installed: ' + model_mod.SKLEARN_ERROR)
else:
    import random
    random.seed(0)

    def normal_vector():
        """A plausible human session: modest volume, irregular gaps, real dwell."""
        n_req = random.uniform(5, 20)
        dur = random.uniform(60, 400)
        return [n_req, dur, dur / n_req, random.uniform(4, 12), random.uniform(1, 4),
                random.uniform(0.7, 1.0), random.uniform(0.5, 0.9), random.uniform(0, 8),
                0.0, random.uniform(0, 0.1), random.uniform(0, 0.1), 0.0]

    clean = [normal_vector() for _ in range(400)]
    probe = normal_vector()
    model_path = os.path.join(tempfile.mkdtemp(prefix='gv-selftest-model-'), 'model.joblib')

    ok('training refuses below ml_min_train',
       model_mod.train(clean[:10], 0.05, model_path, min_train=200) is False)
    ok('nothing was written when training was refused', not os.path.isfile(model_path))
    ok('training succeeds with enough clean sessions',
       model_mod.train(clean, 0.05, model_path, min_train=200) is True)

    bundle = model_mod.load(model_path)
    ok('the trained bundle loads', bundle is not None)
    ok('the bundle records FEATURE_ORDER',
       bundle['feature_order'] == list(features_mod.FEATURE_ORDER))

    normal_level = model_mod.score(bundle, probe)
    # A metronomic 400-request burst: nothing like the training distribution.
    anomalous_level = model_mod.score(bundle, [400.0, 100.0, 0.25, 0.001, 0.2,
                                               1.0, 1.0, 30.0, 1.0, 1.0, 1.0, 0.0])
    ok('scores are integers inside 0..100',
       isinstance(normal_level, int) and 0 <= normal_level <= 100
       and 0 <= anomalous_level <= 100)
    ok('the anomalous session scores higher than the normal one (%d > %d)'
       % (anomalous_level, normal_level), anomalous_level > normal_level)
    ok('the normal session lands on the trustworthy side of the midpoint',
       normal_level < 50)
    ok('scoring the same vector twice is deterministic',
       model_mod.score(bundle, probe) == normal_level)
    ok('the clean-session filter accepts a human session',
       model_mod.is_clean_session({'hp_any': 0, 'challenge_unsolved': 0}, human_f) is True)
    ok('the clean-session filter rejects a scripted session',
       model_mod.is_clean_session({'hp_any': 0, 'challenge_unsolved': 0}, bot_f) is False)
    ok('the clean-session filter rejects a honeypot session',
       model_mod.is_clean_session({'hp_any': 1, 'challenge_unsolved': 0}, human_f) is False)
    ok('loading a missing model returns None',
       model_mod.load('/nonexistent/model.joblib') is None)

    os.unlink(model_path)
    os.rmdir(os.path.dirname(model_path))

# ---------------------------------------------------------------------------
print('')
print('PASS %d  FAIL %d  SKIP %d' % (PASS, FAIL, SKIP))
sys.exit(0 if FAIL == 0 else 1)
