#!/usr/bin/env python3
"""Analyzer self-test. Run: python3 analyzer/selftest.py

Plain PASS/FAIL/SKIP output, exit 0 when every non-SKIP assertion passes.
The core assertions build synthetic sessions in memory: no real log files, no
real DNS, no Redis required. The Redis and scikit-learn sections SKIP cleanly
when those are not installed.
"""

from __future__ import print_function

import os
import re
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import botverify
from analyzer import bridge
from analyzer import config as config_mod
from analyzer import decision
from analyzer import features as features_mod
from analyzer import labels as labels_mod
from analyzer import logs as logs_mod
from analyzer import model as model_mod
from analyzer import redis_io
from analyzer import replay as replay_mod
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
        rs=None, act='allow', sh=0, hp=0, bot='', botv='', rep=0, ml=-1, clf=-1,
        hold=0, ovr='', tok=None):
    """One synthetic guard log row."""
    return {'ts': ts, 'ip': ip, 'ua': 'x', 'uah': uah, 'm': 'GET', 'p': p, 'q': '',
            'aj': 0, 'nav': nav, 'tok': tok if tok else ('v' if dev else 'm'),
            'dev': dev, 'sf': '', 'al': 1, 'hc': 10, 'sc': sc, 'esc': sc,
            'rs': rs or [], 'cd': 0, 'ciu': 0, 'ci': 0, 'rd': 0, 'hp': hp, 'bot': bot,
            'ref': '', 'botv': botv, 'rep': rep, 'ml': ml, 'clf': clf, 'hold': hold,
            'ovr': ovr, 'act': act, 'sh': sh, 'ms': 1.0}


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
   len(vector) == len(features_mod.FEATURE_ORDER) == 17)
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
section('Phase 4 outcome join')

from analyzer import outcomes as outcomes_mod


def orow(rid, st=200, by=None, dur=1.0, ts=1.0):
    """One synthetic outcome line."""
    return {'o': 1, 'rid': rid, 'st': st, 'by': by, 'dur': dur, 'ts': ts}


mixed = [
    dict(row(1000.0, dev='joindev', p='/a'), rid='r1', v=4),
    orow('r1', st=200, by=4096),
    dict(row(1001.0, dev='joindev', p='/b'), rid='r2', v=4),
    orow('r2', st=404),
    dict(row(1002.0, dev='joindev', p='/c'), rid='r3', v=4),      # no outcome
    orow('r9', st=500),                                           # no decision
]
dec_rows, out_rows = outcomes_mod.split_rows(mixed)
ok('split separates decision rows from outcome rows',
   len(dec_rows) == 3 and len(out_rows) == 3)
ok('split keys on o == 1 only', all(r.get('o') != 1 for r in dec_rows))

index, collisions = outcomes_mod.index_outcomes(out_rows)
ok('outcomes index by rid', set(index) == set(['r1', 'r2', 'r9']))
ok('a clean index reports no collisions', collisions == 0)

dup_index, dup_collisions = outcomes_mod.index_outcomes(
    [orow('dup', st=200), orow('dup', st=500), orow('other', st=200)])
ok('a duplicate rid is counted rather than silently overwriting', dup_collisions == 1)
ok('the first outcome wins on a duplicate rid', dup_index['dup']['st'] == 200)
ok('an outcome line without a rid is ignored',
   outcomes_mod.index_outcomes([{'o': 1, 'st': 200}])[0] == {})

attached = outcomes_mod.attach(dec_rows, index)
by_rid = dict((r['rid'], r) for r in attached)
ok('a matched decision row carries its outcome', by_rid['r1']['_out']['st'] == 200)
ok('an unmatched decision row carries None', by_rid['r3']['_out'] is None)
ok('an unmatched outcome simply has no decision to attach to',
   'r9' not in by_rid)
ok('the derived field is underscore-prefixed', '_out' in by_rid['r1'])

joined, join_collisions = outcomes_mod.join(mixed)
ok('join does split, index and attach in one call',
   len(joined) == 3 and joined[0]['_out']['by'] == 4096 and join_collisions == 0)

ok('status_class buckets a 404', outcomes_mod.status_class(orow('x', st=404)) == '404')
ok('status_class buckets other 4xx separately',
   outcomes_mod.status_class(orow('x', st=403)) == '4xx')
ok('status_class buckets 5xx', outcomes_mod.status_class(orow('x', st=502)) == '5xx')
ok('status_class buckets 2xx', outcomes_mod.status_class(orow('x', st=204)) == '2xx')
ok('status_class returns None for a missing outcome',
   outcomes_mod.status_class(None) is None)
ok('status_class returns None for a zero status',
   outcomes_mod.status_class(orow('x', st=0)) is None)

# read_lines joins per file, so callers above it never see outcome lines.
join_dir = tempfile.mkdtemp(prefix='gv-selftest-join-')
join_file = os.path.join(join_dir, 'guard-%s.jsonl' % today.strftime('%Y%m%d'))
with open(join_file, 'w') as fh:
    for entry in mixed:
        fh.write(json_mod.dumps(entry) + '\n')
read_joined = list(logs_mod.read_lines(join_dir, 1))
ok('read_lines yields only decision rows', len(read_joined) == 3)
ok('read_lines attaches outcomes per file',
   sum(1 for r in read_joined if r.get('_out')) == 2)
read_raw = list(logs_mod.read_lines(join_dir, 1, join_outcomes=False))
ok('read_lines can still yield both kinds when asked', len(read_raw) == 6)
os.unlink(join_file)
os.rmdir(join_dir)

# ---------------------------------------------------------------------------
section('Phase 4 outcome features')

ok('FEATURE_ORDER gained exactly five names',
   len(features_mod.FEATURE_ORDER) == 17)
ok('the new names are appended, never inserted',
   features_mod.FEATURE_ORDER[:12] == [
       'n_req', 'dur_s', 'gap_mean', 'gap_std', 'gap_min', 'nav_ratio',
       'path_uniq_ratio', 'score_mean', 'script_ratio', 'few_hdr_ratio',
       'no_al_ratio', 'detail_no_listing_ratio']
   and features_mod.FEATURE_ORDER[12:] == [
       'notfound_ratio', 'err_ratio', 'srv_err_ratio', 'bytes_mean', 'outcome_cov'])

# A scraper walking a stale URL list: 6 of 8 known outcomes are 404s, and two
# rows have no outcome at all, so coverage is 8/10.
stale_rows = []
for i in range(6):
    stale_rows.append(dict(row(3000.0 + i, dev='staledev', p='/gone%d' % i),
                           rid='s%d' % i, _out=orow('s%d' % i, st=404, by=512)))
for i in range(6, 8):
    stale_rows.append(dict(row(3000.0 + i, dev='staledev', p='/ok%d' % i),
                           rid='s%d' % i, _out=orow('s%d' % i, st=200, by=20000)))
for i in range(8, 10):
    stale_rows.append(dict(row(3000.0 + i, dev='staledev', p='/unknown%d' % i),
                           rid='s%d' % i, _out=None))
stale_f = features_mod.session_features({'rows': stale_rows})
ok('notfound_ratio counts 404s over outcome-known rows only',
   abs(stale_f['notfound_ratio'] - 0.75) < 1e-9)
ok('outcome_cov reports the share of rows with any outcome',
   abs(stale_f['outcome_cov'] - 0.8) < 1e-9)
ok('bytes_mean averages only the declared sizes',
   abs(stale_f['bytes_mean'] - ((6 * 512 + 2 * 20000) / 8.0)) < 1e-9)
ok('err_ratio excludes 404 from the other-4xx bucket', stale_f['err_ratio'] == 0.0)
ok('srv_err_ratio is zero without any 5xx', stale_f['srv_err_ratio'] == 0.0)

mixed_status = [
    dict(row(4000.0, dev='mixdev'), rid='m1', _out=orow('m1', st=403)),
    dict(row(4001.0, dev='mixdev'), rid='m2', _out=orow('m2', st=500)),
    dict(row(4002.0, dev='mixdev'), rid='m3', _out=orow('m3', st=404)),
    dict(row(4003.0, dev='mixdev'), rid='m4', _out=orow('m4', st=200)),
]
mix_f = features_mod.session_features({'rows': mixed_status})
ok('each status bucket lands in its own feature',
   mix_f['notfound_ratio'] == 0.25 and mix_f['err_ratio'] == 0.25
   and mix_f['srv_err_ratio'] == 0.25)
ok('a full-coverage session reports coverage 1.0', mix_f['outcome_cov'] == 1.0)
ok('an undeclared size is excluded from bytes_mean rather than counted as zero',
   mix_f['bytes_mean'] == 0.0)

# A session recorded before capture was enabled: all five stay 0.0.
pre4 = features_mod.session_features(human_session)
ok('a session with no outcome data scores 0.0 on all five new features',
   all(pre4[name] == 0.0 for name in features_mod.FEATURE_ORDER[12:]))
ok('the pre-capture session is otherwise unchanged',
   pre4['n_req'] == human_f['n_req'] and pre4['gap_std'] == human_f['gap_std'])

ok('a session with rows but zero coverage reports coverage 0.0',
   features_mod.outcome_features(
       [dict(row(1.0, dev='d'), _out=None)])['outcome_cov'] == 0.0)
ok('an empty session yields zeroed outcome features',
   features_mod.outcome_features([])['outcome_cov'] == 0.0)
ok('a malformed status is ignored rather than counted',
   features_mod.outcome_features(
       [dict(row(1.0, dev='d'), _out={'o': 1, 'rid': 'x', 'st': 'nonsense'})])
   ['outcome_cov'] == 0.0)
ok('a boolean is not mistaken for a byte count',
   features_mod.outcome_features(
       [dict(row(1.0, dev='d'), _out=orow('x', st=200, by=True))])['bytes_mean'] == 0.0)
ok('the feature vector still matches FEATURE_ORDER after the extension',
   features_mod.feature_vector(stale_f)
   == [stale_f[name] for name in features_mod.FEATURE_ORDER])

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
section('Decision mirror parity with PHP')

import json as json_parity
import subprocess

PARITY_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             'scripts', 'decision-parity.php')
php_bin = shutil.which('php') if hasattr(shutil, 'which') else None
if not php_bin:
    skip('decision parity against the PHP matrix', 'php not available in this environment')
elif not os.path.isfile(PARITY_SCRIPT):
    skip('decision parity against the PHP matrix', 'decision-parity.php not found')
else:
    try:
        raw = subprocess.check_output([php_bin, PARITY_SCRIPT, '--emit'],
                                      stderr=subprocess.PIPE)
        matrix = json_parity.loads(raw.decode('utf-8', 'replace'))
    except Exception as exc:
        matrix = None
        skip('decision parity against the PHP matrix', 'could not run the emitter: %s' % exc)
    if matrix is not None:
        ok('the PHP matrix carries at least 40 cases', len(matrix) >= 40)
        esc_bad = []
        dec_bad = []
        for index, case in enumerate(matrix):
            got_esc = decision.effective_score(case['sc'], case['rep'], case['ml'],
                                               case['clf'], case['cfg'])
            got_dec = decision.decide(got_esc, case['over'], case['nav'], case['tok'],
                                      case['hard_block_score'], case['ovr'])
            if got_esc != case['esc']:
                esc_bad.append((index, got_esc, case['esc']))
            if got_dec != case['decision']:
                dec_bad.append((index, got_dec, case['decision']))
        ok('every effective score matches PHP exactly (%d cases)' % len(matrix), not esc_bad)
        if esc_bad:
            print('      first mismatch: case %d python=%s php=%s' % esc_bad[0])
        ok('every decision matches PHP exactly (%d cases)' % len(matrix), not dec_bad)
        if dec_bad:
            print('      first mismatch: case %d python=%s php=%s' % dec_bad[0])
        branches = set(c['decision'] for c in matrix)
        ok('the matrix exercises every decision branch',
           branches == set(['allow', 'challenge', '403', '429']))
        ok('the matrix exercises both override values',
           set(c['ovr'] for c in matrix) == set(['', 'allow', 'deny']))

ok('php_round rounds half away from zero like PHP',
   decision.php_round(0.5) == 1 and decision.php_round(1.5) == 2
   and decision.php_round(2.5) == 3)
ok('php_round handles negatives symmetrically',
   decision.php_round(-0.5) == -1 and decision.php_round(-1.5) == -2)
ok('absent verdicts never contribute with every signal on',
   decision.effective_score(25, 0, -1, -1, {
       'signals': {'reputation': True, 'ml': True, 'clf': True},
       'ml_weight': 0.4, 'clf_weight': 0.5}) == 25)

# ---------------------------------------------------------------------------
section('Config bridge')

bridged = bridge.guard_config(cfg)
ok('the bridge returns a threshold set', isinstance(bridged, dict)
   and 'hard_block_score' in bridged)
ok('the bridge never carries the secret or the salt',
   'secret' not in bridged and 'holdout_salt' not in bridged)
ok('the bridge reports where the thresholds came from',
   bridged.get('source') in ('guard', 'defaults'))
if php_bin:
    ok('with php present the thresholds come from the guard itself',
       bridged.get('source') == 'guard')
else:
    skip('thresholds come from the guard itself', 'php not available')

fallback = bridge.guard_config(cfg, php='/nonexistent/php-binary')
ok('a missing php falls back instead of raising',
   fallback.get('source') == 'defaults' and fallback['hard_block_score'] == 60)

dcfg = bridge.decision_config(bridged, {'hard_block_score': 45, 'signals.clf': True,
                                        'ml_weight': 0.9})
ok('dotted overrides are applied to the decision config',
   dcfg['hard_block_score'] == 45 and dcfg['signals']['clf'] is True
   and dcfg['ml_weight'] == 0.9)
ok('every signal key is present after building a decision config',
   set(dcfg['signals']) >= set(['reputation', 'ml', 'clf']))

# ---------------------------------------------------------------------------
section('Training labels and the circularity guard')

hp_sess = logs_mod.sessionize([row(1000.0, dev='hpdev', p='/old-archive', hp=1,
                                   act='404_hp')], 1800)[0]
ok('a honeypot session is labelled bot',
   labels_mod.bot_labels(hp_sess, {'hp_any': 1}, hp_sess['rows']) == 1)

bad_rows = [row(1000.0, ip='192.0.2.1', botv='bad', bot='googlebot', act='403')]
bad_sess = logs_mod.sessionize(bad_rows, 1800)[0]
ok('a refuted bot claim is labelled bot',
   labels_mod.bot_labels(bad_sess, {'hp_any': 0}, bad_rows) == 1)

# The circularity guard: an unsolved challenge is the guard's own decision fed
# back as truth, so it must never produce a label on its own.
unsolved_rows = [row(1000.0, dev='', ip='10.9.9.9', act='challenge'),
                 row(1005.0, dev='', ip='10.9.9.9', act='challenge')]
unsolved = logs_mod.sessionize(unsolved_rows, 1800)[0]
ok('challenge_unsolved alone produces no label',
   labels_mod.bot_labels(unsolved, {'hp_any': 0, 'challenge_unsolved': 1,
                                    'solved_challenge': 0}, unsolved_rows) is None)
ok('a 403 the guard served produces no label either',
   labels_mod.bot_labels(unsolved, {'hp_any': 0, 'challenge_unsolved': 1,
                                    'solved_challenge': 0},
                         [row(1000.0, act='403')]) is None)

human_sess = dict(logs_mod.sessionize(
    [row(1000.0, dev='hdev', act='token_issued'),
     row(1040.0, dev='hdev', p='/a'),
     row(1090.0, dev='hdev', p='/b')], 1800)[0])
human_sess['features'] = {'script_ratio': 0.0}
human_lbl = {'hp_any': 0, 'challenge_unsolved': 0, 'solved_challenge': 1}
ok('a solved, dwelling, returning identity is labelled human',
   labels_mod.bot_labels(human_sess, human_lbl, human_sess['rows'],
                         session_count=2, median_dwell=90.0) == 0)
ok('one session is not enough for a human label',
   labels_mod.bot_labels(human_sess, human_lbl, human_sess['rows'],
                         session_count=1, median_dwell=90.0) is None)
ok('too little dwell is not enough for a human label',
   labels_mod.bot_labels(human_sess, human_lbl, human_sess['rows'],
                         session_count=3, median_dwell=2.0) is None)
scripted = dict(human_sess)
scripted['features'] = {'script_ratio': 1.0}
ok('a scripted user agent blocks the human label',
   labels_mod.bot_labels(scripted, human_lbl, scripted['rows'],
                         session_count=3, median_dwell=90.0) is None)
ok('a honeypot hit beats every human signal',
   labels_mod.bot_labels(human_sess, {'hp_any': 1, 'solved_challenge': 1},
                         human_sess['rows'], session_count=5, median_dwell=500.0) == 1)

gt_handle, gt_path = tempfile.mkstemp(suffix='.txt')
with os.fdopen(gt_handle, 'w') as fh:
    fh.write('# operator ground truth\n')
    fh.write('scraperdev,1\n')
    fh.write('realuser,0\n')
    fh.write('malformed line without a comma\n')
    fh.write('baddev,7\n')
    fh.write('\n')
truth = labels_mod.load_ground_truth(gt_path)
ok('ground truth parses valid lines', truth == {'scraperdev': 1, 'realuser': 0})
ok('a missing ground truth file is not an error',
   labels_mod.load_ground_truth('/nonexistent/ground-truth.txt') == {})
ok('ground truth overrides an inferred label',
   labels_mod.bot_labels(dict(human_sess, dev='realuser'), {'hp_any': 1},
                         human_sess['rows'], truth) == 0)
os.unlink(gt_path)

hold_rows = [row(1000.0 + i, dev='', ip='198.18.0.1', hold=1, sh=1, act='challenge')
             for i in range(5)]
hold_rows.append(row(1010.0, dev='', ip='198.18.0.1', hold=1, sh=1, hp=1, act='404_hp'))
hold_sessions = logs_mod.sessionize(hold_rows, 1800)
outcomes = labels_mod.holdout_outcomes(hold_sessions)
ok('holdout outcomes count only held-out rows', outcomes['requests'] == 6)
ok('holdout outcomes count suppressed challenges', outcomes['would_challenge'] == 5)
ok('holdout outcomes notice a honeypot hit', outcomes['honeypot_sessions'] == 1)
ok('holdout outcomes ignore enforced traffic',
   labels_mod.holdout_outcomes(logs_mod.sessionize(
       [row(1000.0, dev='enforced', act='challenge')], 1800))['requests'] == 0)

# ---------------------------------------------------------------------------
section('Counterfactual replay')

# 6 humans, each with two sessions far enough apart to split, a solved
# handshake and real dwell; 3 honeypot bots; one holdout row; and three rows
# that never reach the decision step.
replay_rows_in = []
for d in range(6):
    dev = 'rhuman%d' % d
    base_ts = 2000.0 + d * 100000
    replay_rows_in.append(row(base_ts, dev=dev, act='token_issued'))
    for i in range(4):
        replay_rows_in.append(row(base_ts + 40 + i * 30, dev=dev, p='/p%d' % i,
                                  sc=10, rep=-20, ml=15, clf=5))
    for i in range(4):                       # second session, well past the gap
        replay_rows_in.append(row(base_ts + 9000 + i * 30, dev=dev, p='/s%d' % i,
                                  sc=10, rep=-20, ml=15, clf=5))
for d in range(3):
    dev = 'rbot%d' % d
    base_ts = 800000.0 + d * 1000
    replay_rows_in.append(row(base_ts, dev=dev, p='/old-archive', hp=1, act='404_hp'))
    for i in range(4):
        replay_rows_in.append(row(base_ts + 10 + i, dev=dev, p='/q%d' % i,
                                  sc=45, rep=60, ml=90, clf=88))
replay_rows_in.append(row(900000.0, dev='', ip='198.18.9.9', sc=45, hold=1, sh=1,
                          act='challenge'))
replay_rows_in.append(row(900100.0, dev='', ip='10.1.1.1', act='exempt'))
replay_rows_in.append(row(900200.0, dev='', ip='10.1.1.1', act='allow_bot', bot='googlebot'))

# 6 token_issued + 3 404_hp + 1 exempt + 1 allow_bot never reach the decision.
EXPECT_SKIPPED = 11
EXPECT_HUMAN_ROWS = 6 * 8
EXPECT_BOT_ROWS = 3 * 4

replay_sessions = logs_mod.sessionize(replay_rows_in, 1800)
label_map = replay_mod.identity_label_map(replay_sessions)
ok('replay labels the honeypot identities as bots',
   all(label_map.get('rbot%d' % d) == 1 for d in range(3)))
ok('replay labels the returning solved identities as human',
   all(label_map.get('rhuman%d' % d) == 0 for d in range(6)))

base_cfg = {'hard_block_score': 60, 'signals': {'reputation': False, 'ml': False,
                                                'clf': False},
            'ml_weight': 0.4, 'clf_weight': 0.5}
same = replay_mod.replay_rows(replay_rows_in, base_cfg, base_cfg, label_map)
ok('replaying a config against itself moves nothing', same['movement'] == {})
ok('replay skips rows that never reached the decision step',
   same['skipped_non_decision'] == EXPECT_SKIPPED)
ok('replay considers every remaining row',
   same['considered'] == len(replay_rows_in) - EXPECT_SKIPPED)

cand = dict(base_cfg, signals={'reputation': True, 'ml': False, 'clf': False})
moved = replay_mod.replay_rows(replay_rows_in, base_cfg, cand, label_map)
ok('enabling reputation moves bot rows into 403',
   moved['movement'].get('allow->403', 0) == EXPECT_BOT_ROWS)
ok('the movement is credited to the bot-labelled subset',
   moved['bot_newly_caught'] == EXPECT_BOT_ROWS and moved['bot_rows'] == EXPECT_BOT_ROWS)
ok('no human-labelled row is newly restricted',
   moved['human_newly_restricted'] == 0 and moved['human_rows'] == EXPECT_HUMAN_ROWS)
ok('the holdout row is counted separately', moved['holdout_rows'] == 1)
ok('replay reports how many effective scores moved', moved['esc_changed'] > 0)

lower = replay_mod.replay_rows(replay_rows_in, base_cfg,
                               dict(base_cfg, hard_block_score=40), label_map)
ok('lowering the block score restricts more rows',
   lower['candidate']['403'] > lower['baseline']['403'])
ok('a threshold change alone does not move any effective score',
   lower['esc_changed'] == 0)

ok('replay parses a boolean signal override',
   replay_mod.parse_set(['signals.clf=true'])['signals.clf'] is True)
ok('replay parses an integer override',
   replay_mod.parse_set(['hard_block_score=45'])['hard_block_score'] == 45)
ok('replay parses a float override',
   replay_mod.parse_set(['ml_weight=0.6'])['ml_weight'] == 0.6)
try:
    replay_mod.parse_set(['nonsense'])
    ok('a malformed override is rejected', False)
except ValueError:
    ok('a malformed override is rejected', True)

ok('replay renders a report containing the movement table',
   'Movement table' in replay_mod.format_report(moved, base_cfg, cand,
                                                {'signals.reputation': True},
                                                'threshold', 'guard'))
ok('the replay report names the deciding number',
   'the number that decides this change' in replay_mod.format_report(
       moved, base_cfg, cand, {}, 'threshold', 'guard'))

# Read-only by construction: the module must not import redis at all.
replay_source = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'replay.py')).read()
ok('replay never imports redis_io', 'redis_io' not in replay_source)
ok('replay never opens a file for writing',
   "'w'" not in replay_source and '"w"' not in replay_source)

# ---------------------------------------------------------------------------
section('Period report')

from analyzer import report as report_mod

report_rows = list(replay_rows_in)
report_rows.append(row(950000.0, dev='', ip='10.2.2.2', act='nonce_bad'))
report_rows.append(row(950100.0, dev='rhuman0', act='allow', ovr='allow',
                       tok='v'))
report_stats = report_mod.collect(report_rows, cfg, {'source': 'defaults',
                                                     'holdout_pct': 5})

ok('the report counts every request', report_stats['requests'] == len(report_rows))
ok('the report counts unique devices', len(report_stats['devices']) == 9)
ok('the report separates enforced from holdout requests',
   report_stats['holdout_requests'] == 1
   and report_stats['enforced_requests'] == len(report_rows) - 1)
ok('the report counts the challenge funnel',
   report_stats['token_issued'] == 6 and report_stats['challenge_served'] == 0)
ok('the report notices operator overrides',
   report_stats['overrides'].get('allow') == 1)
ok('the report tracks verdict coverage',
   report_stats['has_rep'] > 0 and report_stats['has_clf'] > 0)
ok('the report records no divergence when esc equals sc',
   report_stats['diverged'] == 0)

text = report_mod.render_text(report_stats, 7)
for heading in ('1. Traffic', '2. Decisions', '3. Challenge funnel',
                '4. Score distribution', '5. Verdict coverage',
                '6. Holdout comparison', '7. Top offenders',
                '8. Anomalies worth a look'):
    ok('the text report contains section "%s"' % heading, heading in text)
ok('the text report names the false-negative estimate',
   'false-negative estimate' in text)

disabled = report_mod.collect([row(1000.0, dev='d1')], cfg,
                              {'source': 'defaults', 'holdout_pct': 0})
ok('the report says so when holdout is disabled',
   'holdout disabled' in report_mod.render_text(disabled, 7))

low_funnel = report_mod.collect(
    [row(1000.0 + i, dev='', ip='10.3.3.3', act='challenge') for i in range(20)]
    + [row(2000.0, dev='d9', act='token_issued')], cfg,
    {'source': 'defaults', 'holdout_pct': 0})
ok('a poor challenge funnel is called out in words',
   'BELOW TARGET' in report_mod.render_text(low_funnel, 7))

html = report_mod.render_html(report_stats, 7)
ok('the html report starts with a doctype', html.startswith('<!doctype html>'))
ok('the html report closes cleanly', html.rstrip().endswith('</html>'))
ok('the html report contains no script tag', '<script' not in html.lower())
ok('the html report references no external asset',
   not re.search(r'(?:src|href)\s*=', html) and 'http://' not in html
   and 'https://' not in html)
ok('the html report has no inline event handler',
   not re.search(r'\son[a-z]+\s*=', html))
ok('the html report loads no remote font or image',
   '@import' not in html and 'url(' not in html)
try:
    import xml.etree.ElementTree as ElementTree
    ElementTree.fromstring(html[html.index('<main'):html.rindex('</main>') + 7])
    ok('the html body is well-formed markup', True)
except Exception as exc:
    ok('the html body is well-formed markup: %s' % exc, False)

ok('html escaping neutralises markup in an identity',
   '&lt;script&gt;' in report_mod._esc_html('<script>'))

spiky = {'2026-01-01': {'nonce_bad': 1, 'botv_bad': 0, 'block': 0, 'degraded': 0},
         '2026-01-02': {'nonce_bad': 40, 'botv_bad': 0, 'block': 0, 'degraded': 0}}
ok('a day-over-day jump is reported',
   any('failed handshakes' in line for line in report_mod.anomalies(spiky)))
ok('a single day produces no anomaly', report_mod.anomalies(
    {'2026-01-01': {'nonce_bad': 99}}) == [])

report_source = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'report.py')).read()
ok('the report never imports redis_io', 'redis_io' not in report_source)

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
                0.0, random.uniform(0, 0.1), random.uniform(0, 0.1), 0.0,
                # Phase 4 outcomes: a person mostly gets pages that exist.
                random.uniform(0, 0.05), 0.0, 0.0,
                random.uniform(8000, 60000), random.uniform(0.8, 1.0)]

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
                                               1.0, 1.0, 30.0, 1.0, 1.0, 1.0, 0.0,
                                               0.6, 0.05, 0.0, 350000.0, 0.95])
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
section('Supervised classifier')

from analyzer import classifier as clf_mod

if not clf_mod.SKLEARN_AVAILABLE:
    skip('supervised classifier train/score',
         'scikit-learn not installed: ' + clf_mod.SKLEARN_ERROR)
else:
    import random
    random.seed(5)

    def human_vector():
        n_req = random.uniform(5, 20)
        dur = random.uniform(60, 400)
        return [n_req, dur, dur / n_req, random.uniform(4, 12), random.uniform(1, 4),
                random.uniform(0.7, 1.0), random.uniform(0.4, 0.8), random.uniform(0, 8),
                0.0, random.uniform(0, 0.1), random.uniform(0, 0.1), 0.0,
                random.uniform(0, 0.05), 0.0, 0.0,
                random.uniform(8000, 60000), random.uniform(0.8, 1.0)]

    def bot_vector():
        n_req = random.uniform(60, 400)
        dur = n_req * random.uniform(0.15, 0.3)
        return [n_req, dur, dur / n_req, random.uniform(0.0, 0.05),
                random.uniform(0.05, 0.2), 1.0, random.uniform(0.95, 1.0),
                random.uniform(25, 45), 1.0, 1.0, random.uniform(0.5, 1.0), 0.0,
                # Phase 4 outcomes: a stale URL list walks into 404s and moves
                # far more bytes than a person reading pages.
                random.uniform(0.3, 0.7), random.uniform(0, 0.1), 0.0,
                random.uniform(100000, 400000), random.uniform(0.8, 1.0)]

    clf_dir = tempfile.mkdtemp(prefix='gv-selftest-clf-')
    clf_path = os.path.join(clf_dir, 'clf.joblib')

    X_small = [human_vector() for _ in range(60)] + [bot_vector() for _ in range(10)]
    y_small = [0] * 60 + [1] * 10
    ok('training refuses below min_positive',
       clf_mod.train(X_small, y_small, clf_path, min_positive=50) is False)
    ok('nothing was written when training was refused', not os.path.isfile(clf_path))

    X_one = [human_vector() for _ in range(200)]
    ok('training refuses when the bot class is missing entirely',
       clf_mod.train(X_one, [0] * 200, clf_path, min_positive=1) is False)
    ok('training refuses when the human class is missing entirely',
       clf_mod.train([bot_vector() for _ in range(200)], [1] * 200, clf_path,
                     min_positive=1) is False)

    X = [human_vector() for _ in range(300)] + [bot_vector() for _ in range(120)]
    y = [0] * 300 + [1] * 120
    ok('training succeeds with enough labelled examples of both classes',
       clf_mod.train(X, y, clf_path, min_positive=50) is True)

    clf_bundle = clf_mod.load(clf_path)
    ok('the trained classifier loads', clf_bundle is not None)
    ok('the bundle records FEATURE_ORDER',
       clf_bundle['feature_order'] == list(features_mod.FEATURE_ORDER))
    ok('the bundle carries an operating threshold',
       0.0 <= float(clf_bundle['threshold']) <= 1.0)

    metrics = clf_bundle.get('metrics') or {}
    ok('metrics report precision and recall, not accuracy',
       'precision' in metrics and 'recall' in metrics and 'accuracy' not in metrics)
    ok('metrics include PR-AUC and a confusion matrix',
       'pr_auc' in metrics and set(metrics.get('confusion') or {})
       == set(['tn', 'fp', 'fn', 'tp']))
    ok('metrics record which target precision was asked for',
       metrics.get('target_precision') == 0.98)
    ok('the held-out precision is usable (%.3f)' % metrics.get('precision', 0.0),
       metrics.get('precision', 0.0) >= 0.9)
    ok('the metrics block renders as English',
       'precision' in clf_mod.format_metrics(metrics))

    bot_level = clf_mod.score(clf_bundle, bot_vector())
    human_level = clf_mod.score(clf_bundle, human_vector())
    ok('levels are integers inside 0..100',
       isinstance(bot_level, int) and 0 <= bot_level <= 100 and 0 <= human_level <= 100)
    ok('a bot-shaped vector scores above a human-shaped one (%d > %d)'
       % (bot_level, human_level), bot_level > human_level)
    probe = bot_vector()
    ok('scoring the same vector twice is deterministic',
       clf_mod.score(clf_bundle, probe) == clf_mod.score(clf_bundle, probe))
    ok('loading a missing classifier returns None',
       clf_mod.load(os.path.join(clf_dir, 'absent.joblib')) is None)

    # Threshold choice on deliberately overlapping scores, where the answer is
    # not trivially 1.0 and the precision/recall trade-off is real.
    over_y, over_s = [], []
    for _ in range(400):
        over_y.append(0)
        over_s.append(random.betavariate(2, 8))
    for _ in range(120):
        over_y.append(1)
        over_s.append(random.betavariate(6, 3))
    strict = clf_mod.choose_threshold(over_y, over_s, 0.98)
    loose = clf_mod.choose_threshold(over_y, over_s, 0.70)
    ok('a strict precision target is met', strict['reached_target']
       and strict['precision'] >= 0.98)
    ok('a looser target gives a lower threshold and more recall',
       loose['threshold'] < strict['threshold'] and loose['recall'] > strict['recall'])
    ok('an unreachable target is reported rather than faked',
       clf_mod.choose_threshold(over_y, over_s, 1.01)['reached_target'] is False)
    ok('an unreachable target warns against enabling the signal',
       'Do not enable' in clf_mod.format_metrics(
           {'precision': 0.4, 'recall': 0.9, 'reached_target': False,
            'confusion': {'tn': 1, 'fp': 1, 'fn': 1, 'tp': 1}}))

    if os.path.isfile(clf_path):
        os.unlink(clf_path)
    os.rmdir(clf_dir)

# ---------------------------------------------------------------------------
print('')
print('PASS %d  FAIL %d  SKIP %d' % (PASS, FAIL, SKIP))
sys.exit(0 if FAIL == 0 else 1)
