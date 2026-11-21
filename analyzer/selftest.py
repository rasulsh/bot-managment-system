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
ok('known_bots carries the Google and Bing crawler families',
   set(['googlebot', 'adsbot-google', 'bingbot']) <= set(cfg['known_bots']))
ok('every known bot has a suffix list, so none is left unverifiable',
   set(cfg['known_bots']) == set(cfg['bot_suffixes']))
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

# Settings saved in the admin panel (guard overlay analyzer.*).
pan = config_mod.apply_panel(dict(cfg), {
    'window_days': 14, 'contamination': 0.1, 'clf_target_precision': 1,
    'path_listing': ['^/category/', '(unclosed'], 'worker_max_jobs': True,
    'model_path': '/tmp/evil', 'session_gap_s': '60'})
ok('panel settings: typed values apply, an int is accepted for a float',
   pan['window_days'] == 14 and pan['contamination'] == 0.1 and pan['clf_target_precision'] == 1.0)
ok('panel settings: a pattern Python cannot compile is dropped, the rest kept',
   pan['path_listing'] == ['^/category/'])
ok('panel settings: wrong types, bools and keys outside PANEL_KEYS are ignored',
   pan['worker_max_jobs'] == cfg['worker_max_jobs'] and pan['model_path'] == cfg['model_path']
   and pan['session_gap_s'] == cfg['session_gap_s'])

# End to end through PHP: a value written to the overlay reaches config.load(),
# over an explicit analyzer config file (defaults < file < panel).
overlay_path = os.path.join(config_mod.REPO_ROOT, 'guard', 'config.local.json')
saved_overlay = open(overlay_path).read() if os.path.isfile(overlay_path) else None
try:
    with open(overlay_path, 'w') as fh:
        fh.write('{"analyzer.window_days": 21, "analyzer.report_top_n": 5, "analyzer.window_days_typo": 1}')
    config_mod.bridge._REDIS_CACHE.clear()
    config_mod.bridge._PANEL_CACHE.clear()
    handle, json_path = tempfile.mkstemp(suffix='.json')
    with os.fdopen(handle, 'w') as fh:
        fh.write('{"window_days": 3, "report_days": 9}')
    via_php = config_mod.load(json_path)
    os.unlink(json_path)
    if config_mod.bridge.last_error:
        skip('panel settings reach the analyzer through PHP', 'php not available: ' + config_mod.bridge.last_error)
    else:
        ok('panel settings reach the analyzer through PHP and win over the analyzer file',
           via_php['window_days'] == 21 and via_php['report_top_n'] == 5 and via_php['report_days'] == 9)
finally:
    if saved_overlay is None:
        os.unlink(overlay_path)
    else:
        with open(overlay_path, 'w') as fh:
            fh.write(saved_overlay)
    config_mod.bridge._REDIS_CACHE.clear()
    config_mod.bridge._PANEL_CACHE.clear()

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
section('Phase 4 outcome reputation rules')

NEUTRAL_LABELS = {'hp_any': 0, 'challenge_unsolved': 0, 'solved_challenge': 0}


def out_feats(**over):
    """A deliberately unremarkable session, so only the rule under test fires."""
    base = {'n_req': 40.0, 'dur_s': 600.0, 'gap_mean': 15.0, 'gap_std': 6.0,
            'gap_min': 2.0, 'nav_ratio': 1.0, 'path_uniq_ratio': 0.5,
            'score_mean': 0.0, 'script_ratio': 0.0, 'few_hdr_ratio': 0.0,
            'no_al_ratio': 0.0, 'detail_no_listing_ratio': 0.0,
            'notfound_ratio': 0.0, 'err_ratio': 0.0, 'srv_err_ratio': 0.0,
            'bytes_mean': 10000.0, 'outcome_cov': 1.0}
    base.update(over)
    # Fully byte-covered unless a test says otherwise: bytes_n tracks the count
    # of byte-known rows that bytes_mean is averaged over (FIX #16).
    base.setdefault('bytes_n', base['n_req'])
    return base


baseline_rep = reputation_mod.device_reputation([out_feats()], NEUTRAL_LABELS, clamp)
ok('the neutral outcome session is a clean baseline', baseline_rep == 0)

stale_rep = reputation_mod.device_reputation(
    [out_feats(notfound_ratio=0.6)], NEUTRAL_LABELS, clamp)
ok('a stale URL list walking into 404s adds W_NOTFOUND',
   stale_rep - baseline_rep == reputation_mod.W_NOTFOUND)

ok('a 404 share below the threshold does not fire',
   reputation_mod.device_reputation(
       [out_feats(notfound_ratio=0.2)], NEUTRAL_LABELS, clamp) == baseline_rep)
ok('too few requests makes a 404 share meaningless',
   reputation_mod.device_reputation(
       [out_feats(notfound_ratio=0.9, n_req=5.0)], NEUTRAL_LABELS, clamp) == baseline_rep)
ok('sparse outcome coverage suppresses the 404 rule',
   reputation_mod.device_reputation(
       [out_feats(notfound_ratio=0.9, outcome_cov=0.2)], NEUTRAL_LABELS, clamp)
   == baseline_rep)

# The bulk rule needs a wide path spread, which by itself also earns the
# Phase 2 varied-browsing credit. Compare against a baseline carrying the same
# spread so only the bulk rule differs between the two.
spread_baseline = reputation_mod.device_reputation(
    [out_feats(path_uniq_ratio=0.9)], NEUTRAL_LABELS, clamp)
bulk_rep = reputation_mod.device_reputation(
    [out_feats(bytes_mean=2 * 1024 * 1024, n_req=40.0, path_uniq_ratio=0.9)],
    NEUTRAL_LABELS, clamp)
ok('moving 80 MB in one session adds W_BULK',
   bulk_rep - spread_baseline == reputation_mod.W_BULK)
ok('bulk transfer without path spread does not fire',
   reputation_mod.device_reputation(
       [out_feats(bytes_mean=2 * 1024 * 1024, n_req=40.0, path_uniq_ratio=0.2)],
       NEUTRAL_LABELS, clamp) == baseline_rep)
ok('a normal amount of content does not fire the bulk rule',
   reputation_mod.device_reputation(
       [out_feats(bytes_mean=50000.0, path_uniq_ratio=0.9)], NEUTRAL_LABELS, clamp)
   == spread_baseline)
ok('sparse coverage suppresses the bulk rule too',
   reputation_mod.device_reputation(
       [out_feats(bytes_mean=2 * 1024 * 1024, n_req=40.0, path_uniq_ratio=0.9,
                  outcome_cov=0.2)], NEUTRAL_LABELS, clamp) == spread_baseline)
# FIX #16: bytes_mean is the mean over byte-known rows only. With partial byte
# coverage the true bytes moved is bytes_mean * bytes_n, not bytes_mean * n_req.
# Here 2 MiB * 10 rows = 20 MiB is under BULK_BYTES even though 2 MiB * 40 rows
# (the old estimate) would exceed it, so W_BULK must NOT fire.
ok('partial byte coverage does not over-estimate the bulk rule (FIX #16)',
   reputation_mod.device_reputation(
       [out_feats(bytes_mean=2 * 1024 * 1024, n_req=40.0, bytes_n=10.0,
                  path_uniq_ratio=0.9)], NEUTRAL_LABELS, clamp) == spread_baseline)
# The same bytes_mean fully covered (bytes_n == n_req) does fire, confirming it
# is the coverage-corrected total and not the rule itself that changed.
ok('fully byte-covered bulk transfer still fires W_BULK',
   reputation_mod.device_reputation(
       [out_feats(bytes_mean=2 * 1024 * 1024, n_req=40.0, bytes_n=40.0,
                  path_uniq_ratio=0.9)], NEUTRAL_LABELS, clamp) - spread_baseline
   == reputation_mod.W_BULK)

srv_rep = reputation_mod.device_reputation(
    [out_feats(srv_err_ratio=0.4)], NEUTRAL_LABELS, clamp)
ok('driving the application into 5xx adds W_SRV_ERR',
   srv_rep - baseline_rep == reputation_mod.W_SRV_ERR)
ok('an occasional 5xx below the threshold does not fire',
   reputation_mod.device_reputation(
       [out_feats(srv_err_ratio=0.05)], NEUTRAL_LABELS, clamp) == baseline_rep)

all_three = reputation_mod.device_reputation(
    [out_feats(notfound_ratio=0.6, srv_err_ratio=0.4,
               bytes_mean=2 * 1024 * 1024, path_uniq_ratio=0.9)],
    NEUTRAL_LABELS, clamp)
ok('the three outcome rules add together',
   all_three - spread_baseline == (reputation_mod.W_NOTFOUND + reputation_mod.W_BULK
                                   + reputation_mod.W_SRV_ERR))

# The migration guarantee: a pre-capture session must score exactly as it did
# before Phase 4, because every outcome feature is 0.0 and coverage gates each
# rule.
zero_cov = out_feats(notfound_ratio=0.0, srv_err_ratio=0.0, bytes_mean=0.0,
                     outcome_cov=0.0)
ok('a session with zero outcome coverage is scored exactly as before Phase 4',
   reputation_mod.device_reputation([zero_cov], NEUTRAL_LABELS, clamp) == baseline_rep)
ok('the existing human session reputation is unchanged by Phase 4',
   reputation_mod.device_reputation(
       [human_f], {'hp_any': 0, 'challenge_unsolved': 0, 'solved_challenge': 1},
       clamp) == human_rep)
ok('the existing scraper reputation is unchanged by Phase 4',
   reputation_mod.device_reputation(
       [bot_f], {'hp_any': 0, 'challenge_unsolved': 1, 'solved_challenge': 0},
       clamp) == bot_rep)

ok('peak_bytes reports the heaviest session',
   reputation_mod.peak_bytes([{'bytes_mean': 1000.0, 'n_req': 10.0},
                              {'bytes_mean': 5000.0, 'n_req': 100.0}]) == 500000.0)
ok('peak_bytes is zero without any byte data',
   reputation_mod.peak_bytes([{'n_req': 100.0}]) == 0.0)
ok('peak_bytes multiplies the mean by the byte-known count, not all requests',
   reputation_mod.peak_bytes(
       [{'bytes_mean': 2.0 * 1024 * 1024, 'n_req': 40.0, 'bytes_n': 10.0}])
   == 2.0 * 1024 * 1024 * 10.0)
ok('peak_bytes falls back to n_req when bytes_n is absent',
   reputation_mod.peak_bytes([{'bytes_mean': 1000.0, 'n_req': 10.0}]) == 10000.0)

# ---------------------------------------------------------------------------
section('Per-device holdout exclusion keys off sh, not hold (FIX #12 pt2)')

from analyzer import run_nightly as run_nightly_mod

# hold marks holdout membership for every request, but an enforced 429 logs
# hold=1 with sh=0. A device is only truly held out when a row was actually
# suppressed (hold=1 AND sh=1); a rate-limited device must keep its reputation.
enforced_rows = [row(3000.0 + i, dev='enfdev', act='429', hold=1, sh=0) for i in range(3)]
enforced_sessions = logs_mod.sessionize(enforced_rows, 1800)
enforced_view = run_nightly_mod.build_device_view(enforced_sessions, cfg)
ok('a device with only hold=1,sh=0 (enforced 429) rows is not marked holdout',
   enforced_view[enforced_sessions[0]['key']]['holdout'] is False)

shadow_rows = [row(4000.0 + i, dev='shaddev', act='403', hold=1, sh=1) for i in range(3)]
shadow_sessions = logs_mod.sessionize(shadow_rows, 1800)
shadow_view = run_nightly_mod.build_device_view(shadow_sessions, cfg)
ok('a device with a hold=1,sh=1 (shadowed) row is still marked holdout',
   shadow_view[shadow_sessions[0]['key']]['holdout'] is True)

mixed_rows = ([row(5000.0 + i, dev='mixdev', act='429', hold=1, sh=0) for i in range(3)]
              + [row(5100.0, dev='mixdev', act='403', hold=1, sh=1)])
mixed_sessions = logs_mod.sessionize(mixed_rows, 1800)
mixed_view = run_nightly_mod.build_device_view(mixed_sessions, cfg)
ok('a device with any shadowed row among enforced ones is marked holdout',
   mixed_view[mixed_sessions[0]['key']]['holdout'] is True)

# ---------------------------------------------------------------------------
section('Reverse DNS verification')


class StubResolver(object):
    """raise_on_* take True (an unclassified OSError, i.e. transient) or an
    exception class/instance to raise (DnsNotFound, DnsTransient, ...)."""

    def __init__(self, ptr_map, forward_map, raise_on_ptr=False, raise_on_forward=False,
                 healthy=True):
        self.ptr_map = ptr_map
        self.forward_map = forward_map
        self.raise_on_ptr = raise_on_ptr
        self.raise_on_forward = raise_on_forward
        self._healthy = healthy

    @staticmethod
    def _raise(spec, text):
        if spec is True:
            raise OSError(text)
        raise spec

    def ptr(self, ip):
        if self.raise_on_ptr:
            self._raise(self.raise_on_ptr, 'simulated PTR failure')
        return self.ptr_map.get(ip, [])

    def forward(self, hostname):
        if self.raise_on_forward:
            self._raise(self.raise_on_forward, 'simulated forward failure')
        return self.forward_map.get(hostname, [])

    def healthy(self):
        return self._healthy


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

ok('a transient PTR failure is unknown, not bad',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes, StubResolver({}, {}, raise_on_ptr=True)) == 'unknown')
ok('a PTR TRY_AGAIN / timeout (DnsTransient) is unknown',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes,
                       StubResolver({}, {}, raise_on_ptr=botverify.DnsTransient('servfail'))) == 'unknown')
ok('an address with no PTR record (NXDOMAIN, working resolver) is bad',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes,
                       StubResolver({}, {}, raise_on_ptr=botverify.DnsNotFound('nx'))) == 'bad')
ok('a negative PTR answer from a resolver that fails its canary is unknown',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes,
                       StubResolver({}, {}, raise_on_ptr=botverify.DnsNotFound('nx'),
                                    healthy=False)) == 'unknown')
ok('PTR ok but forward lookup transiently failing is unknown',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes,
                       StubResolver({GOOD_IP: ['x.googlebot.com']}, {}, raise_on_forward=True)) == 'unknown')
ok('PTR ok but forward lookup failing with TRY_AGAIN is unknown',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes,
                       StubResolver({GOOD_IP: ['x.googlebot.com']}, {},
                                    raise_on_forward=botverify.DnsTransient('again'))) == 'unknown')
ok('PTR ok but the forward name does not exist is bad (working resolver)',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes,
                       StubResolver({GOOD_IP: ['x.googlebot.com']}, {},
                                    raise_on_forward=botverify.DnsNotFound('nx'))) == 'bad')
ok('an empty PTR result from a working resolver is bad',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes, StubResolver({}, {})) == 'bad')
ok('a claimed bot with no suffix list is unknown, never bad',
   botverify.verify_ip(GOOD_IP, 'notabot', suffixes, happy) == 'unknown')
ok('a bot whose suffix list is empty is unknown, never bad',
   botverify.verify_ip(GOOD_IP, 'googlebot', {'googlebot': []}, happy) == 'unknown')
ok('an empty ip is unknown', botverify.verify_ip('', 'googlebot', suffixes, happy) == 'unknown')
ok('one transient forward failure does not hide a later confirming hostname',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes,
                       StubResolver({GOOD_IP: ['a.googlebot.com', 'crawl.googlebot.com']},
                                    {'crawl.googlebot.com': [GOOD_IP]})) == 'ok')

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

# FIX #5: IPv6 crawlers. verify_ip compares the original ip against the
# forward-resolved set as strings, so an injected resolver returning the IPv6
# address confirms the claim end to end for both families.
V6_IP = '2001:4860:4860::1'
v6 = StubResolver({V6_IP: ['crawl-v6.googlebot.com']},
                  {'crawl-v6.googlebot.com': [V6_IP]})
ok('an IPv6 googlebot forward-confirms ok',
   botverify.verify_ip(V6_IP, 'googlebot', suffixes, v6) == 'ok')
v6_mixed = StubResolver({V6_IP: ['crawl-v6.googlebot.com']},
                        {'crawl-v6.googlebot.com': ['66.249.66.2', V6_IP]})
ok('an IPv6 address confirms even when IPv4 addresses are also returned',
   botverify.verify_ip(V6_IP, 'googlebot', suffixes, v6_mixed) == 'ok')
ok('IPv4 verification is unchanged by the widened forward lookup',
   botverify.verify_ip(GOOD_IP, 'googlebot', suffixes, happy) == 'ok')

# The real DefaultResolver.forward now resolves both families. Monkeypatch
# getaddrinfo so the test needs no DNS, and assert both families survive,
# de-duplicated and in order - gethostbyname_ex used to drop the IPv6 entry.
_orig_gai = botverify.socket.getaddrinfo
try:
    botverify.socket.getaddrinfo = lambda host, port: [
        (botverify.socket.AF_INET, 0, 0, '', ('66.249.66.1', 0)),
        (botverify.socket.AF_INET6, 0, 0, '', ('2001:4860:4860::8888', 0, 0, 0)),
        (botverify.socket.AF_INET, 0, 0, '', ('66.249.66.1', 0)),
    ]
    _resolved = botverify.DefaultResolver().forward('crawl.googlebot.com')
finally:
    botverify.socket.getaddrinfo = _orig_gai
ok('DefaultResolver.forward returns both v4 and v6 addresses, de-duplicated',
   _resolved == ['66.249.66.1', '2001:4860:4860::8888'])

# Map the real stdlib errors (codes verified on Linux/glibc).
def _raises(exc):
    def thrower(*args, **kwargs):
        raise exc
    return thrower


_orig_gha = botverify.socket.gethostbyaddr
_orig_gai2 = botverify.socket.getaddrinfo
dr = botverify.DefaultResolver()
try:
    def ptr_outcome(exc):
        botverify.socket.gethostbyaddr = _raises(exc)
        try:
            dr.ptr('192.0.2.1')
        except botverify.DnsNotFound:
            return 'notfound'
        except botverify.DnsTransient:
            return 'transient'
        return 'returned'

    def fwd_outcome(exc):
        botverify.socket.getaddrinfo = _raises(exc)
        try:
            dr.forward('x.googlebot.com')
        except botverify.DnsNotFound:
            return 'notfound'
        except botverify.DnsTransient:
            return 'transient'
        return 'returned'

    ok('herror HOST_NOT_FOUND maps to NotFound', ptr_outcome(botverify.socket.herror(1, 'Unknown host')) == 'notfound')
    ok('herror NO_DATA maps to NotFound', ptr_outcome(botverify.socket.herror(4, 'No data')) == 'notfound')
    ok('herror TRY_AGAIN maps to Transient', ptr_outcome(botverify.socket.herror(2, 'again')) == 'transient')
    ok('herror NO_RECOVERY maps to Transient', ptr_outcome(botverify.socket.herror(3, 'fail')) == 'transient')
    ok('a PTR socket.timeout maps to Transient', ptr_outcome(botverify.socket.timeout('t')) == 'transient')
    ok('a PTR OSError maps to Transient', ptr_outcome(OSError('x')) == 'transient')
    ok('a PTR gaierror maps to Transient',
       ptr_outcome(botverify.socket.gaierror(botverify.socket.EAI_NONAME, 'x')) == 'transient')
    ok('gaierror EAI_NONAME maps to NotFound',
       fwd_outcome(botverify.socket.gaierror(botverify.socket.EAI_NONAME, 'x')) == 'notfound')
    ok('gaierror EAI_AGAIN maps to Transient',
       fwd_outcome(botverify.socket.gaierror(botverify.socket.EAI_AGAIN, 'x')) == 'transient')
    ok('gaierror EAI_FAIL maps to Transient',
       fwd_outcome(botverify.socket.gaierror(botverify.socket.EAI_FAIL, 'x')) == 'transient')
    ok('a forward socket.timeout maps to Transient', fwd_outcome(botverify.socket.timeout('t')) == 'transient')

    # glibc reports an unreachable resolver as HOST_NOT_FOUND: without the canary
    # that would be an instant false 'bad'.
    botverify.socket.gethostbyaddr = _raises(botverify.socket.herror(1, 'Unknown host'))
    botverify.socket.getaddrinfo = _raises(botverify.socket.gaierror(-3, 'again'))
    ok('NXDOMAIN while the canary cannot resolve is unknown (resolver down)',
       botverify.verify_ip(GOOD_IP, 'googlebot', suffixes, botverify.DefaultResolver()) == 'unknown')
    botverify.socket.getaddrinfo = lambda host, port: [(botverify.socket.AF_INET, 0, 0, '', ('1.2.3.4', 0))]
    ok('NXDOMAIN while the canary resolves is bad',
       botverify.verify_ip(GOOD_IP, 'googlebot', suffixes, botverify.DefaultResolver()) == 'bad')
finally:
    botverify.socket.gethostbyaddr = _orig_gha
    botverify.socket.getaddrinfo = _orig_gai2

v6_alt = StubResolver({V6_IP: ['crawl-v6.googlebot.com']},
                      {'crawl-v6.googlebot.com': ['2001:4860:4860:0:0:0:0:1']})
ok('IPv6 spelling differences do not defeat confirmation',
   botverify.verify_ip(V6_IP, 'googlebot', suffixes, v6_alt) == 'ok')
v6_forged = StubResolver({V6_IP: ['crawl-v6.googlebot.com']}, {'crawl-v6.googlebot.com': ['2001:db8::1']})
ok('an IPv6 forward mismatch is bad', botverify.verify_ip(V6_IP, 'googlebot', suffixes, v6_forged) == 'bad')

# ---------------------------------------------------------------------------
section('run_verify: unknown writes nothing, bad is still caught')

from analyzer import run_verify as run_verify_mod
import contextlib
import io as io_mod
import json as json_rv

rv_client = redis_io.connect(cfg) if redis_io.REDIS_AVAILABLE else None
if rv_client is None:
    skip('run_verify end to end', 'no reachable local Redis')
else:
    rv_dir = tempfile.mkdtemp(prefix='gv-selftest-rv-')
    rv_logs = os.path.join(rv_dir, 'logs')
    os.makedirs(rv_logs)
    rv_ip = '198.51.100.%d' % (os.getpid() % 100 + 100)
    rv_row = {'ts': 1.0, 'ip': rv_ip, 'bot': 'googlebot', 'ua': 'Googlebot', 'act': 'allow_bot'}
    with open(os.path.join(rv_logs, 'guard-%s.jsonl' % datetime.date.today().strftime('%Y%m%d')), 'w') as fh:
        fh.write(json_rv.dumps(rv_row) + '\n')
    rv_cfg = os.path.join(rv_dir, 'cfg.json')
    with open(rv_cfg, 'w') as fh:
        json_rv.dump({'log_dir': rv_logs, 'model_path': os.path.join(rv_dir, 'model.joblib'),
                      'redis': cfg['redis']}, fh)
    run_verify_mod.DNS_SLEEP_S = 0

    def run_rv(resolver, *extra):
        out, err = io_mod.StringIO(), io_mod.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = run_verify_mod.main(['--config', rv_cfg] + list(extra), resolver=resolver)
        return code, out.getvalue(), err.getvalue()

    def rv_clear():
        rv_client.delete(redis_io.key('botok:' + rv_ip), redis_io.key('botbad:' + rv_ip))

    def rv_botbad_keys():
        return list(rv_client.scan_iter(match=redis_io.key('botbad:*'), count=500))

    rv_clear()
    before = set(rv_botbad_keys())
    outage = StubResolver({}, {}, raise_on_ptr=botverify.DnsTransient('resolver outage'))
    code, out, _err = run_rv(outage)
    ok('a simulated resolver outage writes zero gv:botbad keys',
       code == 0 and set(rv_botbad_keys()) == before and rv_client.get(redis_io.key('botok:' + rv_ip)) is None)
    ok('the outage run reports the address as unknown', 'unknown 1' in out and 'could not be verified' in out)
    ok('the outage is recorded for the panel and report',
       run_verify_mod.snapshot_mod.read_stats(config_mod.load(rv_cfg), 'run_verify').get('unknown') == 1)

    # An existing ok verdict survives an outage even when the address is re-checked.
    redis_io.set_botv(rv_client, rv_ip, 'ok', 600)
    run_rv(outage, '--recheck')
    ok('an existing ok verdict stays ok through a transient failure',
       rv_client.get(redis_io.key('botok:' + rv_ip)) == '1' and rv_client.get(redis_io.key('botbad:' + rv_ip)) is None)

    # A forged claim: PTR resolves under googlebot.com but forward does not confirm.
    forged = StubResolver({rv_ip: ['fake.googlebot.com']}, {'fake.googlebot.com': ['203.0.113.250']})
    run_rv(forged, '--recheck')
    ok('a definitive mismatch still flips ok to bad', rv_client.get(redis_io.key('botbad:' + rv_ip)) == '1'
       and rv_client.get(redis_io.key('botok:' + rv_ip)) is None)
    ok('a bad verdict uses the short botbad_ttl so it self-heals',
       0 < rv_client.ttl(redis_io.key('botbad:' + rv_ip)) <= 3600)
    genuine = StubResolver({rv_ip: ['crawl.googlebot.com']}, {'crawl.googlebot.com': [rv_ip]})
    run_rv(genuine, '--recheck')
    ok('a confirmed address flips bad back to ok with the long TTL',
       rv_client.get(redis_io.key('botok:' + rv_ip)) == '1' and rv_client.get(redis_io.key('botbad:' + rv_ip)) is None
       and rv_client.ttl(redis_io.key('botok:' + rv_ip)) > 3600)
    rv_clear()
    run_rv(forged, '--dry-run')
    ok('--dry-run writes nothing', rv_client.get(redis_io.key('botbad:' + rv_ip)) is None)
    rv_clear()
    # Without --recheck a fresh verdict is not re-resolved.
    redis_io.set_botv(rv_client, rv_ip, 'ok', 600)
    run_rv(forged)
    ok('a fresh verdict is not re-resolved without --recheck', rv_client.get(redis_io.key('botok:' + rv_ip)) == '1')
    rv_clear()

    # A known bot with no suffix list: one warning, never bad.
    with open(rv_cfg, 'w') as fh:
        json_rv.dump({'log_dir': rv_logs, 'model_path': os.path.join(rv_dir, 'model.joblib'),
                      'redis': cfg['redis'], 'bot_suffixes': {'googlebot': []}}, fh)
    code, out, err = run_rv(forged)
    ok('a bot without a suffix list warns by name and writes nothing',
       "'googlebot'" in err and 'no entry in bot_suffixes' in err
       and rv_client.get(redis_io.key('botbad:' + rv_ip)) is None and 'unknown 1' in out)
    rv_clear()
    shutil.rmtree(rv_dir, ignore_errors=True)

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
       and client.get(redis_io.key('botok:' + ip)) is None)
    ok('an unknown verdict is refused', redis_io.set_botv(client, ip, 'maybe', 60) is False)
    ok('every verdict key carries a TTL',
       client.ttl(redis_io.key('rep:' + dev)) > 0 and client.ttl(redis_io.key('ml:' + dev)) > 0
       and client.ttl(redis_io.key('botbad:' + ip)) > 0)
    ok('writes against a dead client return False rather than raising',
       redis_io.set_rep(None, dev, 1, 60) is False)
    ok('reads against a dead client return None',
       redis_io.get_rep(None, dev) is None)
    for key in (redis_io.key('rep:' + dev), redis_io.key('ml:' + dev), redis_io.key('botok:' + ip), redis_io.key('botbad:' + ip)):
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

# FIX #15: a timed-out config dump must kill and reap the child, not leak it.
# A fake Popen times out on the first communicate(), then returns on the reap.
class _FakeTimeoutProc(object):
    def __init__(self):
        self.killed = False
        self._calls = 0

    def communicate(self, timeout=None):
        self._calls += 1
        if self._calls == 1:
            raise subprocess_mod.TimeoutExpired(cmd='php', timeout=timeout)
        return (b'', b'')           # the post-kill reap

    def kill(self):
        self.killed = True

import subprocess as subprocess_mod
_fake_proc = _FakeTimeoutProc()
_orig_popen = bridge.subprocess.Popen
try:
    bridge.subprocess.Popen = lambda *a, **k: _fake_proc
    _timeout_result = bridge.dump_config(php='php', timeout=1)
finally:
    bridge.subprocess.Popen = _orig_popen
ok('a timed-out config dump returns None', _timeout_result is None)
ok('a timed-out config dump kills the child rather than leaking it',
   _fake_proc.killed is True)

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
section('Handshake acts: funnel, replay and old logs')

from analyzer import snapshot as snapshot_hs
from analyzer import replay as replay_hs
from analyzer import report as report_hs

hs_rows = [
    row(100.0, dev='', ip='10.9.9.1', act='challenge'),
    row(100.5, dev='h1', ip='10.9.9.1', act='token_issued'),
    row(101.0, dev='', ip='10.9.9.2', act='challenge'),
    row(101.2, dev='', ip='10.9.9.2', act='pow_bad', sh=0),          # refused
    row(102.0, dev='', ip='10.9.9.3', act='challenge'),
    row(102.2, dev='', ip='10.9.9.3', act='nonce_replay', sh=0),     # refused
    row(103.0, dev='', ip='10.9.9.4', act='challenge'),
    row(103.2, dev='h4', ip='10.9.9.4', act='mint_limited', sh=1),   # shadow: token WAS issued
    row(104.0, dev='', ip='10.9.9.5', act='mint_limited', sh=0),     # refused (429)
    row(105.0, dev='', ip='10.9.9.6', act='nonce_bad'),              # refused
    row(106.0, dev='h7', ip='10.9.9.7', act='pow_bad', sh=1),        # shadow: token issued
]
ok('token_was_issued: issued and shadowed rows count',
   [logs_mod.token_was_issued(r) for r in hs_rows if r['act'] in ('token_issued', 'mint_limited', 'pow_bad')]
   == [True, False, True, False, True])
ok('handshake_rejected: only non-shadow rejections count',
   [logs_mod.handshake_rejected(r) for r in hs_rows if r['act'] in
    ('pow_bad', 'nonce_replay', 'mint_limited', 'nonce_bad')] == [True, True, False, True, True, False])
hs_snap = snapshot_hs.build(hs_rows, cfg, {'source': 'defaults'})
ok('the snapshot funnel counts shadow-issued tokens as issued (3) and rejections (4)',
   hs_snap['funnel']['token_issued'] == 3 and hs_snap['funnel']['handshake_rejected'] == 4)
hs_stats = report_hs.collect(hs_rows, cfg, {'source': 'defaults'})
ok('the report funnel agrees with the snapshot', hs_stats['token_issued'] == 3)
ok('the report counts every refused handshake in its day bucket',
   sum(b['nonce_bad'] for b in hs_stats['by_day'].values()) == 4)
ok('the report renders with the new acts (text and html)',
   bool(report_hs.render_text(hs_stats, 7)) and bool(report_hs.render_html(hs_stats, 7)))
ok('replay treats the new handshake acts as non-decisions',
   all(a in replay_hs.NON_DECISION_ACTS for a in ('nonce_replay', 'pow_bad', 'mint_limited')))
old_rows = [row(1.0, dev='o1', act='token_issued'), row(2.0, dev='', act='nonce_bad'),
            row(3.0, dev='o2', act='allow'), {'act': 'challenge', 'ts': 4.0, 'v': 2}]
ok('pre-change rows (old action names, missing fields) still aggregate',
   snapshot_hs.build(old_rows, cfg, {'source': 'defaults'})['funnel']['token_issued'] == 1)

# ---------------------------------------------------------------------------
section('Panel replay and analyzer replay agree (including the new acts)')

import json as json_rp

rp_dir = tempfile.mkdtemp(prefix='gv-selftest-replay-parity-')
rp_acts = ['allow', 'challenge', '403', '429', 'exempt', 'allow_bot', '404_hp', 'token_issued',
           'nonce_bad', 'nonce_replay', 'pow_bad', 'mint_limited', 'allow_override', 'allow',
           'allow_preview']
rp_rows = []
for i in range(84):
    act = rp_acts[i % len(rp_acts)]
    rp_rows.append(row(1000.0 + i, dev=('d%d' % (i % 7)), ip='10.7.0.%d' % (i % 5), sc=(i * 7) % 90,
                       act=act, sh=(i % 3 == 0 and act in ('nonce_replay', 'pow_bad', 'mint_limited')) and 1 or 0,
                       rep=(i % 5) * 6 - 6, ml=(i * 11) % 100 if i % 4 else -1, clf=(i * 13) % 100 if i % 6 else -1,
                       nav=1 if i % 3 else 0, ovr='deny' if act == '403' and i % 2 else ''))
    # Schema 5: most rows carry the gate, and on some it differs from nav (a GET
    # that did not ask for HTML). Every fourth row is left as an old, gate-less row.
    if i % 4:
        rp_rows[-1]['gate'] = 0 if i % 5 == 0 else 1
        if i % 2:
            rp_rows[-1]['tok'] = 'm'
with open(os.path.join(rp_dir, 'guard-%s.jsonl' % datetime.date.today().strftime('%Y%m%d')), 'w') as fh:
    for r in rp_rows:
        fh.write(json_rp.dumps(r) + '\n')
rp_php = shutil.which('php')
if not rp_php:
    skip('panel/analyzer replay parity', 'php not available')
else:
    rp_script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts', 'replay-parity.php')
    rp_out = json_rp.loads(subprocess.check_output([rp_php, rp_script, rp_dir, '45', 'reputation,ml']).decode())
    rp_base = {'hard_block_score': 60, 'signals': {'reputation': False, 'ml': False, 'clf': False},
               'ml_weight': 0.4, 'clf_weight': 0.5}
    rp_cand = {'hard_block_score': 45, 'signals': {'reputation': True, 'ml': True, 'clf': False},
               'ml_weight': 0.4, 'clf_weight': 0.5}
    rp_py = replay_hs.replay_rows(rp_rows, rp_base, rp_cand)
    ok('both replays consider the same rows (%d) and skip the same non-decisions (%d)'
       % (rp_py['considered'], rp_py['skipped_non_decision']),
       rp_out['considered'] == rp_py['considered'] and rp_out['skipped'] == rp_py['skipped_non_decision'])
    ok('...and every handshake act is a non-decision on both sides',
       rp_py['skipped_non_decision'] >= 4 * 6)
    ok('both replays agree on the baseline and candidate action counts',
       rp_out['baseline'] == rp_py['baseline'] and rp_out['candidate'] == rp_py['candidate'])
    ok('...and on how many rows changed score', rp_out['esc_changed'] == rp_py['esc_changed'])
    ok('...and the rows in play include a gated non-navigation and a gate-less old row',
       any(r.get('gate') == 1 and r['nav'] == 0 for r in rp_rows)
       and any('gate' not in r for r in rp_rows))
rp_cfg = {'hard_block_score': 60, 'signals': {'reputation': False, 'ml': False, 'clf': False},
          'ml_weight': 0.4, 'clf_weight': 0.5}
rp_gated = row(1.0, nav=0, tok='m')
rp_gated['gate'] = 1
ok('replay re-decides a schema 5 row on its gate: a token-less non-HTML GET is a challenge',
   replay_hs.row_decision(rp_gated, rp_cfg)[1] == 'challenge')
ok('replay re-decides an old row on nav, as the guard did when it was written',
   replay_hs.row_decision(row(1.0, nav=0, tok='m'), rp_cfg)[1] == 'allow'
   and replay_hs.row_decision(row(1.0, nav=1, tok='m'), rp_cfg)[1] == 'challenge')
rp_post = row(1.0, nav=0, tok='m')
rp_post['gate'] = 0
ok('a schema 5 row with gate 0 (a POST) is never challenged on replay',
   replay_hs.row_decision(rp_post, rp_cfg)[1] == 'allow')
ok('replay treats the preview pass as a non-decision', 'allow_preview' in replay_hs.NON_DECISION_ACTS)
shutil.rmtree(rp_dir, ignore_errors=True)

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
                '6. Response outcomes', '7. Holdout comparison',
                '8. Top offenders', '9. Anomalies worth a look'):
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
# --- Phase 4 outcomes section ---------------------------------------------
outcome_report_rows = []
for i in range(10):
    r = 'ro%d' % i
    outcome_report_rows.append(dict(row(6000.0 + i, dev='rephuman', p='/p%d' % i),
                                    rid=r, _out=orow(r, st=200, by=12000)))
for i in range(10, 20):
    r = 'ro%d' % i
    outcome_report_rows.append(dict(row(6000.0 + i, dev='', ip='198.18.5.5',
                                        p='/gone%d' % i, hold=1, sh=1),
                                    rid=r, _out=orow(r, st=404, by=300)))
outcome_report_rows.append(dict(row(6100.0, dev='repnoout', p='/x'), rid='ro-none',
                                _out=None))
out_stats = report_mod.collect(outcome_report_rows, cfg,
                               {'source': 'defaults', 'holdout_pct': 5})
ok('the report counts outcome-known rows', out_stats['outcome_known'] == 20)
ok('the report buckets statuses',
   out_stats['status'].get('2xx') == 10 and out_stats['status'].get('404') == 10)
ok('the report splits status by enforced and holdout',
   out_stats['status_enforced'].get('2xx') == 10
   and out_stats['status_holdout'].get('404') == 10)
ok('the report totals bytes served',
   out_stats['bytes_total'] == 10 * 12000 + 10 * 300)
ok('the report ranks identities by 404 count',
   out_stats['top_404'].get('198.18.5.5|aaaaaaaaaaaa') == 10)
ok('the report collects request durations', len(out_stats['dur']) == 20)

out_text = report_mod.render_text(out_stats, 7)
ok('the text report contains the outcomes section', '6. Response outcomes' in out_text)
ok('the outcomes section compares the non-holdout population against holdout',
   'Non-holdout population vs holdout' in out_text
   and 'Enforced population vs holdout' not in out_text)
ok('the outcomes section label reads correctly in monitor mode, not "enforced"',
   'would catch in monitor mode' in out_text)
ok('the later sections were renumbered',
   '7. Holdout comparison' in out_text and '8. Top offenders' in out_text
   and '9. Anomalies worth a look' in out_text)

no_out = report_mod.collect([row(1.0, dev='d1')], cfg,
                            {'source': 'defaults', 'holdout_pct': 0})
no_out_text = report_mod.render_text(no_out, 7)
ok('the report says so when there are no outcome lines',
   'No outcome lines in this window' in no_out_text)
ok('low coverage is explained rather than flagged as an error',
   'Coverage under' in report_mod.render_text(
       report_mod.collect(outcome_report_rows + [dict(row(7000.0 + i, dev='x'),
                                                      rid='rq%d' % i, _out=None)
                                                 for i in range(40)],
                          cfg, {'source': 'defaults', 'holdout_pct': 5}), 7))

out_html = report_mod.render_html(out_stats, 7)
ok('the html report contains the outcomes section',
   '6. Response outcomes' in out_html)
ok('the html outcomes section is still script-free',
   '<script' not in out_html.lower() and not re.search(r'(?:src|href)\s*=', out_html))

stale_stats = report_mod.collect(
    [dict(row(1.0, dev='d1'), rep=5)],
    dict(cfg, _models={'ml': {'exists': True, 'stale': True,
                              'error': 'feature order mismatch: bundle has 12 features'},
                       'clf': {'exists': False, 'stale': False}}),
    {'source': 'defaults', 'holdout_pct': 0})
stale_text = report_mod.render_text(stale_stats, 7)
ok('the report names a stale model in verdict coverage',
   'STALE ML MODEL' in stale_text)
ok('the report names a stale model as the likely cause of missing verdicts',
   'stale model after a feature-set change' in stale_text)

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
section('Phase 4 candidate models and promotion')

from analyzer import promote as promote_mod

ok('config carries both candidate paths',
   cfg['model_candidate_path'].endswith('.candidate')
   and cfg['clf_candidate_path'].endswith('.candidate'))
ok('a candidate path is not the live path',
   cfg['model_candidate_path'] != cfg['model_path']
   and cfg['clf_candidate_path'] != cfg['clf_path'])
ok('paths_for returns (live, candidate) for each kind',
   promote_mod.paths_for('ml', cfg) == (cfg['model_path'], cfg['model_candidate_path'])
   and promote_mod.paths_for('clf', cfg) == (cfg['clf_path'], cfg['clf_candidate_path']))
try:
    promote_mod.paths_for('nonsense', cfg)
    ok('an unknown model kind is rejected', False)
except ValueError:
    ok('an unknown model kind is rejected', True)

promo_dir = tempfile.mkdtemp(prefix='gv-selftest-promo-')
promo_cfg = dict(cfg,
                 model_path=os.path.join(promo_dir, 'model.joblib'),
                 model_candidate_path=os.path.join(promo_dir, 'model.joblib.candidate'),
                 clf_path=os.path.join(promo_dir, 'clf.joblib'),
                 clf_candidate_path=os.path.join(promo_dir, 'clf.joblib.candidate'))

missing = promote_mod.check('ml', promo_cfg)
ok('promotion refuses a missing candidate', missing['ok'] is False)
ok('the refusal names the command that produces one',
   '--candidate' in missing['reason'])
ok('promote() on a missing candidate is a no-op refusal',
   promote_mod.promote('ml', promo_cfg)['ok'] is False)

ok('an absent live model is reported as absent, not stale',
   model_mod.inspect(promo_cfg['model_path'])['exists'] is False)
ok('no warning is emitted for an absent model',
   promote_mod.stale_warning('ml', model_mod.inspect(promo_cfg['model_path'])) == '')

if not model_mod.SKLEARN_AVAILABLE:
    skip('candidate training and promotion round-trip',
         'scikit-learn not installed: ' + model_mod.SKLEARN_ERROR)
else:
    import random as promo_random
    promo_random.seed(17)

    def promo_vector():
        n_req = promo_random.uniform(5, 20)
        dur = promo_random.uniform(60, 400)
        return [n_req, dur, dur / n_req, promo_random.uniform(4, 12),
                promo_random.uniform(1, 4), promo_random.uniform(0.7, 1.0),
                promo_random.uniform(0.5, 0.9), promo_random.uniform(0, 8),
                0.0, 0.0, 0.0, 0.0,
                promo_random.uniform(0, 0.05), 0.0, 0.0,
                promo_random.uniform(8000, 60000), promo_random.uniform(0.8, 1.0)]

    vectors = [promo_vector() for _ in range(300)]

    # Training to the candidate path must not touch the live path at all.
    ok('candidate training writes the candidate',
       model_mod.train(vectors, 0.05, promo_cfg['model_candidate_path'],
                       min_train=200) is True)
    ok('candidate training left the live model untouched',
       not os.path.isfile(promo_cfg['model_path']))

    verdict = promote_mod.check('ml', promo_cfg)
    ok('a matching candidate passes the check', verdict['ok'] is True)

    result = promote_mod.promote('ml', promo_cfg)
    ok('promotion moves the candidate into place', result['ok'] is True)
    ok('the live model now exists', os.path.isfile(promo_cfg['model_path']))
    ok('the candidate no longer exists after promotion',
       not os.path.isfile(promo_cfg['model_candidate_path']))
    ok('the promoted model loads', model_mod.load(promo_cfg['model_path']) is not None)

    # A bundle from before the feature extension must be refused, and must
    # produce the loud warning that names the fix.
    stale_bundle = model_mod.load(promo_cfg['model_path'])
    stale_bundle = dict(stale_bundle)
    stale_bundle['feature_order'] = list(features_mod.FEATURE_ORDER)[:12]
    import joblib as promo_joblib
    promo_joblib.dump(stale_bundle, promo_cfg['model_candidate_path'])
    stale_check = promote_mod.check('ml', promo_cfg)
    ok('promotion refuses a feature-order mismatch', stale_check['ok'] is False)
    ok('the mismatch refusal states both feature counts',
       '12 features' in stale_check['reason'] and '17' in stale_check['reason'])
    ok('the stale candidate was not moved into place',
       os.path.isfile(promo_cfg['model_candidate_path']))

    # FIX #19: a bundle with a correct feature_order and model but NO scaler
    # loads as None, so inspect() must report it not loadable and promotion must
    # refuse it - otherwise a candidate promotes and then yields no ML verdicts.
    scalerless = dict(model_mod.load(promo_cfg['model_path']))
    scalerless.pop('scaler', None)
    promo_joblib.dump(scalerless, promo_cfg['model_candidate_path'])
    scalerless_info = model_mod.inspect(promo_cfg['model_candidate_path'])
    ok('a scaler-less bundle is reported not loadable', scalerless_info['loadable'] is False)
    ok('a scaler-less bundle indeed loads as None', model_mod.load(promo_cfg['model_candidate_path']) is None)
    ok('promotion refuses a scaler-less candidate',
       promote_mod.check('ml', promo_cfg)['ok'] is False)

    promo_joblib.dump(stale_bundle, promo_cfg['model_path'])
    stale_info = model_mod.inspect(promo_cfg['model_path'])
    ok('a stale live model is detected as stale',
       stale_info['stale'] is True and stale_info['loadable'] is False)
    warning = promote_mod.stale_warning('ml', stale_info)
    ok('a stale live model produces a loud warning', warning.startswith('WARNING'))
    ok('the warning explains the silent-permissiveness risk',
       'silently dropped' in warning)
    ok('the warning names the promotion command',
       'promote-model ml' in warning and '--candidate' in warning)
    ok('live_status inspects both kinds',
       set(promote_mod.live_status(promo_cfg)) == set(['ml', 'clf']))

    # The classifier gate: a candidate below target precision is refused, so a
    # false-positive problem cannot be promoted into production.
    def promo_bot_vector():
        n_req = promo_random.uniform(60, 400)
        dur = n_req * promo_random.uniform(0.15, 0.3)
        return [n_req, dur, dur / n_req, promo_random.uniform(0.0, 0.05),
                promo_random.uniform(0.05, 0.2), 1.0, promo_random.uniform(0.95, 1.0),
                promo_random.uniform(25, 45), 1.0, 1.0, promo_random.uniform(0.5, 1.0), 0.0,
                promo_random.uniform(0.3, 0.7), 0.0, 0.0,
                promo_random.uniform(100000, 400000), promo_random.uniform(0.8, 1.0)]

    clf_X = [promo_vector() for _ in range(300)] + [promo_bot_vector() for _ in range(120)]
    clf_y = [0] * 300 + [1] * 120
    ok('a classifier candidate trains to the candidate path',
       clf_mod.train(clf_X, clf_y, promo_cfg['clf_candidate_path'], min_positive=50) is True)
    ok('classifier candidate training left the live classifier untouched',
       not os.path.isfile(promo_cfg['clf_path']))
    ok('a classifier candidate meeting its target may be promoted',
       promote_mod.check('clf', promo_cfg)['ok'] is True)

    weak = dict(clf_mod.load(promo_cfg['clf_candidate_path']))
    weak['metrics'] = dict(weak['metrics'], precision=0.42)
    promo_joblib.dump(weak, promo_cfg['clf_candidate_path'])
    weak_check = promote_mod.check('clf', promo_cfg)
    ok('promotion refuses a classifier below target precision', weak_check['ok'] is False)
    ok('the precision refusal explains the cost',
       'restrict real users' in weak_check['reason'])

    no_metrics = dict(clf_mod.load(promo_cfg['clf_candidate_path']))
    no_metrics['metrics'] = None
    promo_joblib.dump(no_metrics, promo_cfg['clf_candidate_path'])
    ok('promotion refuses a classifier carrying no metrics',
       promote_mod.check('clf', promo_cfg)['ok'] is False)

for name in os.listdir(promo_dir):
    os.unlink(os.path.join(promo_dir, name))
os.rmdir(promo_dir)

# ---------------------------------------------------------------------------
section('Worker forwards the config path to child jobs')

from analyzer import worker as worker_mod

# Capture the argv each child entry point is called with, without running it.
_captured_argv = {}


def _capturing(name):
    def fake(argv=None):
        _captured_argv[name] = list(argv or [])
        return 0
    return fake


_worker_orig = {
    'run_verify': worker_mod.run_verify.main,
    'run_nightly': worker_mod.run_nightly.main,
    'replay': worker_mod.replay_mod.main,
    'snapshot': worker_mod.snapshot_mod.main,
}
try:
    worker_mod.run_verify.main = _capturing('run_verify')
    worker_mod.run_nightly.main = _capturing('run_nightly')
    worker_mod.replay_mod.main = _capturing('replay')
    worker_mod.snapshot_mod.main = _capturing('snapshot')

    CFG_PATH = '/etc/guard/analyzer.json'
    cfg_with_path = {'_config_path': CFG_PATH}
    worker_mod.HANDLERS['verify'](cfg_with_path, {})
    ok('job_verify forwards --config to run_verify',
       _captured_argv['run_verify'] == ['--config', CFG_PATH])
    worker_mod.HANDLERS['nightly'](cfg_with_path, {})
    ok('job_nightly forwards --config to run_nightly',
       _captured_argv['run_nightly'] == ['--config', CFG_PATH])
    worker_mod.HANDLERS['train'](cfg_with_path, {})
    ok('job_train forwards --config before its own flags',
       _captured_argv['run_nightly'] == ['--config', CFG_PATH, '--train', '--candidate'])
    worker_mod.HANDLERS['train_clf'](cfg_with_path, {})
    ok('job_train_clf forwards --config before its own flags',
       _captured_argv['run_nightly'] == ['--config', CFG_PATH, '--train-clf', '--candidate'])
    worker_mod.HANDLERS['replay_full'](cfg_with_path, {'days': 3})
    ok('job_replay_full forwards --config ahead of the mode flags',
       _captured_argv['replay'] == ['--config', CFG_PATH, '--mode', 'full', '--days', '3'])
    worker_mod.HANDLERS['snapshot'](cfg_with_path, {})
    ok('job_snapshot forwards --config to snapshot',
       _captured_argv['snapshot'] == ['--config', CFG_PATH])

    # With no config path, no --config flag is injected: the child re-resolves
    # from env/defaults exactly as the worker did.
    _captured_argv.clear()
    cfg_no_path = {'_config_path': None}
    worker_mod.HANDLERS['nightly'](cfg_no_path, {})
    ok('a worker without a config path passes no --config to the child',
       _captured_argv['run_nightly'] == [])
    worker_mod.HANDLERS['train'](cfg_no_path, {})
    ok('job_train with no config path passes only its own flags',
       _captured_argv['run_nightly'] == ['--train', '--candidate'])
finally:
    worker_mod.run_verify.main = _worker_orig['run_verify']
    worker_mod.run_nightly.main = _worker_orig['run_nightly']
    worker_mod.replay_mod.main = _worker_orig['replay']
    worker_mod.snapshot_mod.main = _worker_orig['snapshot']

# job_promote reads paths from cfg rather than shelling out, so it is left as
# is: confirm it passes the cfg straight through to promote() and never builds
# an argv from _config_path.
_promo_seen = {}
_promo_orig = worker_mod.promote_mod.promote
try:
    def _fake_promote(kind, cfg):
        _promo_seen['kind'] = kind
        _promo_seen['cfg'] = cfg
        return {'ok': True, 'reason': 'stub'}
    worker_mod.promote_mod.promote = _fake_promote
    worker_mod.HANDLERS['promote_ml']({'_config_path': CFG_PATH}, {})
    ok('job_promote passes cfg straight to promote() (no argv shelling)',
       _promo_seen.get('kind') == 'ml' and _promo_seen.get('cfg') == {'_config_path': CFG_PATH})
finally:
    worker_mod.promote_mod.promote = _promo_orig

# ---------------------------------------------------------------------------
section('Redis auth, db, socket and key prefix (Python side)')

import hmac as hmac_mod
import hashlib
import json as json_x2
import subprocess as sp_x
import time as time_x

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_redis_bin = os.environ.get('GV_REDIS_BIN') or shutil.which('redis-server')
_rtmp = tempfile.mkdtemp(prefix='gv-selftest-redis-matrix-')
_started = []


def start_redis(port, extra=(), sock=''):
    cmd = [_redis_bin, '--port', str(port), '--bind', '127.0.0.1', '--save', '', '--appendonly', 'no',
           '--daemonize', 'yes', '--pidfile', os.path.join(_rtmp, 'r%d.pid' % port), '--dir', _rtmp]
    if sock:
        cmd += ['--unixsocket', sock, '--unixsocketperm', '700']
    cmd += list(extra)
    sp_x.call(cmd, stdout=sp_x.DEVNULL, stderr=sp_x.DEVNULL)
    import socket as socket_x
    for _ in range(50):
        try:
            probe = socket_x.create_connection(('127.0.0.1', port), 0.2)
            probe.close()
            _started.append(port)
            return True
        except OSError:
            time_x.sleep(0.1)
    return False


def raw_client(**kw):
    # Same RESP2 choice as redis_io.connect(): redis-py 8 would send HELLO 3,
    # which Redis 5 rejects.
    try:
        return redis_io.redis_py.Redis(protocol=2, **kw)
    except TypeError:
        return redis_io.redis_py.Redis(**kw)


def rcfg(**redis_over):
    c = {'redis': dict(config_mod.DEFAULTS['redis'])}
    c['redis'].update(redis_over)
    return c


if not _redis_bin or not redis_io.REDIS_AVAILABLE:
    skip('python redis matrix', 'redis-server or redis-py not available')
else:
    P_PLAIN, P_AUTH, P_ACL, P_UNIX = 63810, 63811, 63812, 63813
    sock_path = os.path.join(_rtmp, 'py.sock')
    up = [start_redis(P_PLAIN), start_redis(P_AUTH, ['--requirepass', 's3cret']),
          start_redis(P_ACL), start_redis(P_UNIX, sock=sock_path)]
    ok('the throwaway redis servers started', all(up))
    admin = raw_client(port=P_PLAIN, decode_responses=True)
    acl_ok = True
    try:
        raw_client(port=P_ACL).execute_command('ACL', 'SETUSER', 'gvuser', 'on', '>aclpass', '~*', '+@all')
    except Exception:
        acl_ok = False

    c = redis_io.connect(rcfg(port=P_PLAIN))
    ok('no auth server, no password: connects', c is not None)
    ok('...and an empty prefix keeps the legacy key names',
       redis_io.key('rep:abc') == 'gv:rep:abc' and redis_io.gp_key('jobs') == 'gp:jobs')
    c = redis_io.connect(rcfg(port=P_AUTH, password='s3cret'))
    ok('requirepass + correct password: connects', c is not None and c.ping())
    _err = io_mod.StringIO()
    with contextlib.redirect_stderr(_err):
        c = redis_io.connect(rcfg(port=P_AUTH, password='WRONG-PW-XYZ'))
    ok('requirepass + wrong password: no client, and the password is never printed',
       c is None and 'WRONG-PW-XYZ' not in _err.getvalue())
    with contextlib.redirect_stderr(io_mod.StringIO()):
        c = redis_io.connect(rcfg(port=P_AUTH))
    ok('requirepass + no password: no client', c is None)
    with contextlib.redirect_stderr(io_mod.StringIO()) as _e2:
        c = redis_io.connect(rcfg(port=P_PLAIN, password='unneeded'))
    ok('no auth server + a password configured: still connects', c is not None and c.ping())
    if acl_ok:
        c = redis_io.connect(rcfg(port=P_ACL, username='gvuser', password='aclpass'))
        ok('ACL user + password: connects and writes', c is not None and c.set('acl:k', '1'))
        with contextlib.redirect_stderr(io_mod.StringIO()):
            ok('ACL user + wrong password: no client',
               redis_io.connect(rcfg(port=P_ACL, username='gvuser', password='bad')) is None)
    else:
        skip('python ACL user', 'Redis < 6')
    c = redis_io.connect(rcfg(socket=sock_path, port=1))
    ok('unix socket: connects (host/port ignored)', c is not None and c.ping())
    c1 = redis_io.connect(rcfg(port=P_PLAIN, db=1))
    redis_io.set_rep(c1, 'dbdev', 5, 60)
    c0 = redis_io.connect(rcfg(port=P_PLAIN))
    ok('db = 1: keys land in db 1 and not in db 0',
       redis_io.get_rep(c1, 'dbdev') == 5 and redis_io.get_rep(c0, 'dbdev') is None)
    with contextlib.redirect_stderr(io_mod.StringIO()):
        ok('an invalid prefix disables Redis instead of being altered',
           redis_io.connect(rcfg(port=P_PLAIN, prefix='bad prefix')) is None
           and redis_io.connect(rcfg(port=P_PLAIN, prefix='x*')) is None)

    # Prefix isolation across every family the analyzer touches.
    admin.flushall()
    a = redis_io.connect(rcfg(port=P_PLAIN, prefix='shop1:'))
    redis_io.set_rep(a, 'd1', 11, 60)
    redis_io.set_ml(a, 'd1', 22, 60)
    redis_io.set_clf(a, 'd1', 33, 60)
    redis_io.set_botv(a, '198.51.100.7', 'ok', 60)
    redis_io.set_override(a, 'allow', 'ident1', 600)
    ok('a prefixed write lands under the prefix',
       admin.get('shop1:gv:rep:d1') == '11' and admin.get('shop1:gv:botok:198.51.100.7') == '1'
       and admin.get('gv:rep:d1') is None)
    b = redis_io.connect(rcfg(port=P_PLAIN, prefix='shop2:'))
    ok('another prefix sees nothing of it',
       redis_io.get_rep(b, 'd1') is None and redis_io.get_botv(b, '198.51.100.7') is None
       and redis_io.list_overrides(b) == [])
    a = redis_io.connect(rcfg(port=P_PLAIN, prefix='shop1:'))
    ok('list_overrides strips the prefix from what it shows',
       redis_io.list_overrides(a)[0][:2] == ('allow', 'ident1'))
    ok('clear_override removes only its own namespace',
       redis_io.clear_override(a, 'ident1') == 1)
    ok('the job queue key is namespaced', redis_io.gp_key('jobs') == 'shop1:gp:jobs')
    # ctl.py show / identity_verdicts read every family back through key().
    redis_io.set_override(a, 'allow', 'ident9', 600)
    redis_io.set_rep(a, 'ident9', 7, 60)
    iv = redis_io.identity_verdicts(a, 'ident9')
    ok('identity_verdicts reads overrides and verdicts back under the prefix',
       iv['reputation'] == 7 and iv['overrides']['allow'] is not None and iv['overrides']['deny'] is None)
    ok('get_override reports the remaining ttl', 0 < redis_io.get_override(a, 'ident9')['allow'] <= 600)

    # PHP guard <-> Python analyzer under one non-empty prefix.
    php_bin_x = shutil.which('php')
    if not php_bin_x:
        skip('PHP/Python cross-language prefix check', 'php not available')
    else:
        admin.flushall()
        secret = 'xl-secret'
        guard_cfg_path = os.path.join(_rtmp, 'guard-cfg.php')
        guard_log = os.path.join(_rtmp, 'guardlogs')
        guard_cfg = {
            'secret': secret, 'enforce': {'block': False, 'challenge': False, 'ratelimit': False},
            'signals': {'reputation': True, 'ml': True, 'clf': True},
            'redis': {'host': '127.0.0.1', 'port': P_AUTH, 'password': 's3cret', 'prefix': 'xl:',
                      'db': 2, 'timeout': 0.25},
            'log_dir': guard_log, 'known_bots': ['googlebot'],
        }
        _escaped = json_x2.dumps(guard_cfg).replace("\\", "\\\\").replace("'", "\\'")
        with open(guard_cfg_path, 'w') as fh:
            fh.write('<?php if (!defined("GV_BOOT")) { exit; } return json_decode(\'' + _escaped + '\', true);')

        # (1) The analyzer resolves its Redis settings from the GUARD's config,
        # credentials included, through the bridge - and prints none of it.
        an_cfg_path = os.path.join(_rtmp, 'an.json')
        with open(an_cfg_path, 'w') as fh:
            json_x2.dump({'guard_config_path': guard_cfg_path, 'log_dir': guard_log,
                          'model_path': os.path.join(_rtmp, 'model.joblib')}, fh)
        an = config_mod.load(an_cfg_path)
        ok('the analyzer takes host/port/db/prefix/password from the guard block',
           an['redis']['port'] == P_AUTH and an['redis']['password'] == 's3cret'
           and an['redis']['prefix'] == 'xl:' and an['redis']['db'] == 2
           and an['redis']['socket_timeout'] >= 0.25)
        an_override = os.path.join(_rtmp, 'an2.json')
        with open(an_override, 'w') as fh:
            json_x2.dump({'guard_config_path': guard_cfg_path, 'log_dir': guard_log,
                          'model_path': os.path.join(_rtmp, 'model.joblib'),
                          'redis': {'prefix': 'override:'}}, fh)
        an2 = config_mod.load(an_override)
        ok('an explicit analyzer override beats the guard block, key by key',
           an2['redis']['prefix'] == 'override:' and an2['redis']['port'] == P_AUTH)
        dump_default = sp_x.check_output([php_bin_x, os.path.join(REPO, 'scripts', 'config-dump.php'),
                                          '--config', guard_cfg_path]).decode()
        ok('the default config dump never prints the Redis password or username',
           's3cret' not in dump_default and '"password"' not in dump_default)
        ok('...but still shows the safe parts (host, db, prefix)',
           '"prefix": "xl:"' in dump_default and '"db": 2' in dump_default)

        # (2) Python writes a reputation; the PHP guard reads it under the prefix.
        pc = redis_io.connect(an)
        ok('the analyzer connects with the guard\'s credentials', pc is not None)
        devid = 'cafe' * 6
        redis_io.set_rep(pc, devid, 42, 120)
        issued = str(int(time_x.time()))
        sig = hmac_mod.new(secret.encode(), ('%s.%s' % (devid, issued)).encode(), hashlib.sha256).hexdigest()
        token = '%s.%s.%s' % (devid, issued, sig)
        probe_in = json_x2.dumps({'config': guard_cfg_path, 'cookie': {'_gv': token},
                                  'server': {'HTTP_USER_AGENT': 'Mozilla/5.0 Chrome/126.0', 'HTTP_ACCEPT': 'text/html',
                                             'HTTP_ACCEPT_LANGUAGE': 'en', 'HTTP_SEC_FETCH_MODE': 'navigate',
                                             'HTTP_A': '1', 'HTTP_B': '2', 'HTTP_C': '3', 'HTTP_D': '4'}})
        proc = sp_x.run([php_bin_x, os.path.join(REPO, 'scripts', 'request-probe.php')],
                        input=probe_in.encode(), stdout=sp_x.PIPE, stderr=sp_x.PIPE)
        rows = []
        for fn in sorted(os.listdir(guard_log)) if os.path.isdir(guard_log) else []:
            if fn.endswith('.jsonl'):
                with open(os.path.join(guard_log, fn)) as fh:
                    rows = [json_x2.loads(line) for line in fh if line.strip()]
        ok('a rep written from Python is read by the PHP guard under the same prefix/db/auth',
           bool(rows) and rows[-1].get('rep') == 42 and rows[-1].get('rd') == 0)

        # (3) A panel-style override (PHP) is visible to ctl.py (Python).
        php_code = ("define('GV_BOOT',1);define('GP_BOOT',1);putenv('GV_CONFIG=%s');"
                    "require '%s/guard/guard.php';require '%s/panel/config_io.php';require '%s/panel/data.php';"
                    "echo gp_override_set('deny','xl-ident',600) ? 'set' : 'fail';" % (guard_cfg_path, REPO, REPO, REPO))
        out = sp_x.check_output([php_bin_x, '-d', 'display_errors=0', '-r', php_code]).decode()
        listed = sp_x.check_output([sys.executable, os.path.join(REPO, 'analyzer', 'ctl.py'),
                                    '--config', an_cfg_path, 'list']).decode()
        ok('a panel override is listed by ctl.py (prefix stripped, credentials from the bridge)',
           out == 'set' and 'xl-ident' in listed and 'xl:' not in listed)
        redis_io.connect(rcfg(port=P_PLAIN))      # reset the module prefix for later tests

    for port in _started:
        try:
            with open(os.path.join(_rtmp, 'r%d.pid' % port)) as pid_fh:
                os.kill(int(pid_fh.read().strip()), 15)
        except Exception:
            pass
    shutil.rmtree(_rtmp, ignore_errors=True)

# ---------------------------------------------------------------------------
section('A failed PHP bridge is loud and nothing is written against unconfirmed settings')

from analyzer import ctl as ctl_mod
if not (redis_io.REDIS_AVAILABLE and shutil.which('php')):
    skip('bridge failure handling', 'redis-py or php missing')
else:
    bf_dir = tempfile.mkdtemp(prefix='gv-selftest-bridge-')
    bf_guard = os.path.join(bf_dir, 'guard.php')
    with open(bf_guard, 'w') as fh:
        fh.write('<?php if (!defined("GV_BOOT")) { exit; } return array("secret" => "x", '
                 '"redis" => array("prefix" => "shopA:"));')
    bf_cfg = os.path.join(bf_dir, 'an.json')
    with open(bf_cfg, 'w') as fh:
        json_x2.dump({'guard_config_path': bf_guard, 'php_bin': '/nonexistent/php', 'log_dir': bf_dir,
                      'model_path': os.path.join(bf_dir, 'model.joblib')}, fh)
    probe = redis_io.connect(config_mod.DEFAULTS)
    if probe is None:
        skip('bridge failure handling', 'no local Redis on 6379')
    else:
        for k in list(probe.scan_iter(match='*203.0.113.77*')):
            probe.delete(k)
        err = io_mod.StringIO()
        with contextlib.redirect_stderr(err):
            bf = config_mod.load(bf_cfg)
        ok('a failed bridge is reported on stderr, not swallowed',
           'could not read the guard' in err.getvalue() and '/nonexistent/php' in err.getvalue())
        ok('...and the settings are marked unconfirmed', bf.get('redis_confirmed') is False)
        out, err = io_mod.StringIO(), io_mod.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ctl_mod.main(['--config', bf_cfg, 'allow', '203.0.113.77', '--ttl', '600'])
        ok('ctl allow refuses to write against unconfirmed settings (non-zero exit, no success claim)',
           code != 0 and 'Allow override set' not in out.getvalue() and 'not confirmed' in err.getvalue())
        ok('...and no key at all was written (neither prefixed nor legacy)',
           not list(probe.scan_iter(match='*203.0.113.77*')))
        err = io_mod.StringIO()
        with contextlib.redirect_stderr(err):
            code = ctl_mod.main(['--config', bf_cfg, 'list'])
        ok('a read-only command still runs but warns again on every run', code == 0 and 'could not read the guard' in err.getvalue())
        # An explicit, complete redis override is an operator decision: no bridge, no warning, writes allowed.
        with open(bf_cfg, 'w') as fh:
            json_x2.dump({'guard_config_path': bf_guard, 'php_bin': '/nonexistent/php', 'log_dir': bf_dir,
                          'model_path': os.path.join(bf_dir, 'model.joblib'),
                          'redis': {'host': '127.0.0.1', 'port': 6379, 'prefix': 'shopA:'}}, fh)
        err = io_mod.StringIO()
        with contextlib.redirect_stdout(io_mod.StringIO()), contextlib.redirect_stderr(err):
            code = ctl_mod.main(['--config', bf_cfg, 'allow', '203.0.113.77', '--ttl', '600'])
        ok('an explicit redis override incl. prefix is confirmed: writes work, under the prefix',
           code == 0 and probe.get('shopA:gv:allow:203.0.113.77') == '1' and probe.get('gv:allow:203.0.113.77') is None
           and 'could not read' not in err.getvalue())
        probe.delete('shopA:gv:allow:203.0.113.77')
    shutil.rmtree(bf_dir, ignore_errors=True)

# ---------------------------------------------------------------------------
section('Source audit: Redis keys go through redis_io.key()/gp_key()')

_audit_bad = []
for _dir, _dirs, _files in os.walk(os.path.join(REPO, 'analyzer')):
    for _fn in _files:
        if _fn.endswith('.py') and _fn not in ('selftest.py', 'redis_io.py'):
            with open(os.path.join(_dir, _fn)) as _fh:
                for _n, _line in enumerate(_fh, 1):
                    if re.search(r"""['"]g[vp]:""", _line):
                        _audit_bad.append('%s:%d' % (_fn, _n))
ok('no raw gv:/gp: key literal in analyzer/ outside redis_io.py %s' % _audit_bad, not _audit_bad)
ok('every Redis consumer connects through redis_io.connect()',
   not [fn for fn in os.listdir(os.path.join(REPO, 'analyzer'))
        if fn.endswith('.py') and fn not in ('selftest.py', 'redis_io.py')
        and re.search(r'redis_py\.Redis\(|redis\.Redis\(|redis\.StrictRedis\(',
                      open(os.path.join(REPO, 'analyzer', fn)).read())])

# ---------------------------------------------------------------------------
print('')
# ---------------------------------------------------------------------------
section('Review hardening')

from analyzer import botverify as bv_h                       # noqa: E402
from analyzer import run_verify as rv_h                      # noqa: E402
from analyzer import decision as dec_h                       # noqa: E402
from analyzer import logs as logs_h                          # noqa: E402
from analyzer import model as model_h                        # noqa: E402
import json
import time


class DyingResolver(object):
    """Answered the canary a moment ago, dead now: every lookup is 'not found'."""
    def __init__(self):
        self.calls = []

    def ptr(self, ip):
        raise bv_h.DnsNotFound('nxdomain')

    def forward(self, host):
        raise bv_h.DnsNotFound('nxdomain')

    def healthy(self, fresh=False):
        self.calls.append(fresh)
        return (not fresh)                    # the cached answer says alive; a fresh check says dead


dying = DyingResolver()
ok('a negative answer from a resolver that died after its last health check is NOT a bad verdict',
   bv_h.verify_ip('66.249.66.1', 'googlebot', {'googlebot': ['.googlebot.com']}, dying) == 'unknown')
ok('...because the health check after a negative answer is always a fresh one', dying.calls == [True])


class OldStyleResolver(object):
    def ptr(self, ip):
        raise bv_h.DnsNotFound('nxdomain')

    def forward(self, host):
        return []

    def healthy(self):
        return True


ok('an injected resolver whose healthy() takes no argument still works',
   bv_h.verify_ip('203.0.113.9', 'googlebot', {'googlebot': ['.googlebot.com']}, OldStyleResolver()) == 'bad')
ok('an IPv4-mapped IPv6 spelling of the same address matches',
   bv_h._same_address('::ffff:66.249.66.1', '66.249.66.1') and not bv_h._same_address('::ffff:66.249.66.1', '66.249.66.2'))

hr_rows = ([{'bot': 'googlebot', 'ip': '10.0.0.%d' % i} for i in range(1, 60)]
           + [{'bot': 'googlebot', 'ip': '66.249.66.1'} for _ in range(40)]
           + [{'bot': 'unlisted', 'ip': '9.9.9.9'} for _ in range(99)])
hr_counts = rv_h.claim_counts(hr_rows, ['googlebot'])
hr_order = rv_h.lookup_order(rv_h.collect_bot_ips(hr_rows, ['googlebot']), hr_counts)
ok('verification looks at the busiest claimant first, not the lowest address',
   hr_order[0] == '66.249.66.1' and hr_counts['66.249.66.1'] == 40 and '9.9.9.9' not in hr_counts)
ok('ties keep a stable address order', hr_order[1:4] == ['10.0.0.1', '10.0.0.10', '10.0.0.11'])

ok('rounding matches PHP at the binary-fraction boundaries',
   dec_h.php_round(0.7 * 85) == 60 and dec_h.php_round(0.35 * 90) == 32
   and dec_h.php_round(0.5) == 1 and dec_h.php_round(1.5) == 2 and dec_h.php_round(-0.5) == -1
   and dec_h.php_round(59.4) == 59)
hr_php = shutil.which('php')
if hr_php:
    # The guard's own gv_round_int(), not PHP's round(): round() differs between PHP
    # versions (8.4 dropped its pre-rounding), the guard's function does not.
    hr_guard = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'guard', 'guard.php')
    hr_code = ('define("GV_BOOT",1);define("GV_NO_AUTORUN",1);require %s;'
               '$o=[];for($w=0;$w<=200;$w++){for($l=0;$l<=100;$l++){$o[]=gv_round_int($l*($w/100));}}'
               'echo implode(",",$o);') % json_mod.dumps(hr_guard)
    hr_out = subprocess.run([hr_php, '-r', hr_code], stdout=subprocess.PIPE, universal_newlines=True).stdout
    hr_php_vals = [int(x) for x in hr_out.split(',')]
    hr_py_vals = [dec_h.php_round(l * (w / 100.0)) for w in range(201) for l in range(101)]
    ok('...and for every weight 0.00-2.00 x level 0-100 (%d cases)' % len(hr_py_vals), hr_php_vals == hr_py_vals)

hr_dir = tempfile.mkdtemp(prefix='gv-hard-')
with open(os.path.join(hr_dir, 'guard-%s.jsonl' % time.strftime('%Y%m%d')), 'w') as fh:
    fh.write(json.dumps({'v': 5, 'ts': time.time(), 'nav': 1, 'hp': 0, 'act': 'allow'}) + '\n')
    fh.write(json.dumps({'v': 5, 'ts': time.time(), 'nav': '1', 'hp': 0.0, 'act': 'allow'}) + '\n')
    fh.write(json.dumps({'v': 5, 'ts': time.time(), 'nav': [1], 'hp': 0, 'act': 'allow'}) + '\n')
    fh.write(json.dumps({'v': 5, 'ts': time.time(), 'nav': 'yes', 'hp': 0, 'act': 'allow'}) + '\n')
hr_read = list(logs_h.read_lines(hr_dir, 1))
ok('a row with a wrong-typed integer field is coerced when it can be and dropped when it cannot',
   len(hr_read) == 2 and all(r['nav'] == 1 and isinstance(r['nav'], int) for r in hr_read))

hr_model = os.path.join(hr_dir, 'm.joblib')
model_h._dump_atomic({'a': 1}, hr_model)
ok('a model is written through a temp file and no temp file is left behind',
   os.path.isfile(hr_model) and [n for n in os.listdir(hr_dir) if '.tmp.' in n] == [])
shutil.rmtree(hr_dir, ignore_errors=True)
ok('reputation expires in two weeks, not a month', config_mod.DEFAULTS['rep_ttl'] == 1209600)


# ---------------------------------------------------------------------------
section('Access rules: hit counts from the logs')

import datetime as dt_rh
import gzip as gzip_rh
import json as json_rh
import time as time_rh
from analyzer import snapshot as snapshot_rh

rh_now = time_rh.time()
ok('rule_ids reads RULE: and SH_RULE: reasons, ignores everything else',
   snapshot_rh.rule_ids({'rs': ['UA_SCRIPT', 'RULE:r1', 'SH_RULE:st-curl', 'RULE:', 5, 'XRULE:z']}) == ['r1', 'st-curl'])
ok('rule_ids tolerates a missing or wrong-typed rs',
   snapshot_rh.rule_ids({}) == [] and snapshot_rh.rule_ids({'rs': None}) == [] and snapshot_rh.rule_ids({'rs': 'RULE:x'}) == [])
rh_rows = [{'ts': 100.0, 'rs': ['RULE:a']}, {'ts': 200.0, 'rs': ['SH_RULE:a', 'RULE:b']}, {'ts': 'bad', 'rs': ['RULE:a']},
           {'ts': 300.0, 'rs': []}]
rh_c = snapshot_rh.count_rule_hits(rh_rows)
ok('count_rule_hits counts monitor and enforced hits per id and the last timestamp',
   rh_c == {'a': [2, 200.0], 'b': [1, 200.0]})
ok('count_rule_hits honours the since window', snapshot_rh.count_rule_hits(rh_rows, since=150.0)['a'] == [1, 200.0])

rh_dir = tempfile.mkdtemp(prefix='gv-rules-')
rh_cache = os.path.join(rh_dir, 'cache.json')
rh_today = dt_rh.date.fromtimestamp(rh_now)


def rh_write(offset, rows, gz=False):
    day = rh_today - dt_rh.timedelta(days=offset)
    path = os.path.join(rh_dir, 'guard-%s.jsonl' % day.strftime('%Y%m%d'))
    opener = (lambda p: gzip_rh.open(p + '.gz', 'wt')) if gz else (lambda p: open(p, 'w'))
    with opener(path) as fh:
        for r in rows:
            fh.write(json_rh.dumps(r) + '\n')


rh_write(0, [{'ts': rh_now - 60, 'act': '403', 'rs': ['RULE:a']}, {'ts': rh_now - 30, 'act': 'allow', 'rs': ['SH_RULE:b']}])
rh_write(1, [{'ts': rh_now - 3600 * 30, 'act': '403', 'rs': ['RULE:a']}, {'ts': rh_now - 3600 * 20, 'act': '403', 'rs': ['RULE:a']}])
rh_write(3, [{'ts': rh_now - 86400 * 3, 'act': '403', 'rs': ['RULE:a']}], gz=True)
rh_write(9, [{'ts': rh_now - 86400 * 9, 'act': '403', 'rs': ['RULE:a']}])
rh_res = snapshot_rh.collect_rule_hits(rh_dir, rh_now, rh_cache)
ok('24 h counts reach back into yesterday but only as far as 24 hours', rh_res['a']['h24'] == 2 and rh_res['b']['h24'] == 1)
ok('7 d counts cover the week, gzipped days included, and skip older days', rh_res['a']['d7'] == 4 and rh_res['b']['d7'] == 1)
ok('last hit is the newest timestamp', abs(rh_res['a']['last'] - (rh_now - 60)) < 0.01)
ok('finished days are cached, today and yesterday are not',
   set(json_rh.load(open(rh_cache))['days']) == set((rh_today - dt_rh.timedelta(days=n)).strftime('%Y%m%d') for n in range(2, 7)))
os.remove(os.path.join(rh_dir, 'guard-%s.jsonl.gz' % (rh_today - dt_rh.timedelta(days=3)).strftime('%Y%m%d')))
ok('a cached day is not re-read (file gone, count stays)',
   snapshot_rh.collect_rule_hits(rh_dir, rh_now, rh_cache)['a']['d7'] == 4)
with open(rh_cache, 'w') as fh:
    fh.write('{broken')
ok('a corrupt cache is ignored and rebuilt',
   snapshot_rh.collect_rule_hits(rh_dir, rh_now, rh_cache)['a']['d7'] == 3)
ok('an empty log directory gives no hits', snapshot_rh.collect_rule_hits(tempfile.mkdtemp(prefix='gv-empty-'), rh_now, None) == {})
shutil.rmtree(rh_dir, ignore_errors=True)

# ---------------------------------------------------------------------------
section('GeoIP compile: ranges, geoip.dat, .mmdb, atomic swap, sanity checks, PHP parity')
import ipaddress as ip_geo
import json as json_geo
import struct as struct_geo
import subprocess as sp_geo
from analyzer import geo as geo_mod
from analyzer import worker as worker_geo


def g_net(cidr, value):
    n = ip_geo.ip_network(cidr)
    return (int(n.network_address), int(n.broadcast_address), value)


# -- range arithmetic
ok('normalize: nested ranges - the narrower one wins inside, the wider keeps both sides',
   geo_mod.normalize([g_net('10.0.0.0/8', 'AA'), g_net('10.1.0.0/16', 'BB')]) ==
   [(167772160, 167837695, 'AA'), (167837696, 167903231, 'BB'), (167903232, 184549375, 'AA')])
ok('normalize: adjacent ranges with the same value merge, different values do not',
   geo_mod.normalize([g_net('1.0.0.0/24', 'AA'), g_net('1.0.1.0/24', 'AA'), g_net('1.0.2.0/24', 'BB')]) ==
   [(16777216, 16777727, 'AA'), (16777728, 16777983, 'BB')])
ok('normalize: identical ranges with different values - the smaller value wins, deterministically',
   geo_mod.normalize([g_net('2.0.0.0/8', 'US'), g_net('2.0.0.0/8', 'IR')]) == [g_net('2.0.0.0/8', 'IR')]
   and geo_mod.normalize([g_net('2.0.0.0/8', 'IR'), g_net('2.0.0.0/8', 'US')]) == [g_net('2.0.0.0/8', 'IR')])
ok('normalize: input order does not matter and the output is sorted and non-overlapping',
   geo_mod.normalize([g_net('9.0.0.0/8', 'CC'), g_net('3.0.0.0/8', 'AA'), g_net('3.3.0.0/16', 'BB'), g_net('3.3.3.0/24', 'DD')]) ==
   geo_mod.normalize([g_net('3.3.3.0/24', 'DD'), g_net('3.0.0.0/8', 'AA'), g_net('9.0.0.0/8', 'CC'), g_net('3.3.0.0/16', 'BB')])
   and all(a[1] < b[0] for a, b in zip(geo_mod.normalize([g_net('9.0.0.0/8', 'CC'), g_net('3.0.0.0/8', 'AA'), g_net('3.3.3.0/24', 'DD')]),
                                       geo_mod.normalize([g_net('9.0.0.0/8', 'CC'), g_net('3.0.0.0/8', 'AA'), g_net('3.3.3.0/24', 'DD')])[1:])))
ok('normalize: three levels of nesting', [r[2] for r in geo_mod.normalize([g_net('3.0.0.0/8', 'AA'), g_net('3.3.0.0/16', 'BB'), g_net('3.3.3.0/24', 'DD')])] == ['AA', 'BB', 'DD', 'BB', 'AA'])
ok('normalize: empty input, and IPv6 (128-bit) ranges',
   geo_mod.normalize([]) == [] and geo_mod.normalize([g_net('2001:db8::/32', 'DE'), g_net('2001:db8:1::/48', 'FR')])[1][2] == 'FR'
   and len(geo_mod.normalize([g_net('2001:db8::/32', 'DE'), g_net('2001:db8:1::/48', 'FR')])) == 3)
ok('split_family: an IPv4-mapped IPv6 network becomes the IPv4 range it carries',
   geo_mod.split_family([(ip_geo.ip_network('::ffff:1.2.3.0/120'), 'AA'), (ip_geo.ip_network('2001:db8::/32'), 'DE')]) ==
   ([(16909056, 16909311, 'AA')], [g_net('2001:db8::/32', 'DE')]))

# -- the compiled file
gv4 = geo_mod.normalize([g_net('1.0.0.0/24', 'AA'), g_net('5.0.0.0/8', 'IR'), g_net('255.255.255.255/32', 'ZZ')])
gv6 = geo_mod.normalize([g_net('2001:db8::/32', 'DE'), g_net('2a00::/12', 'IR')])
gbin = geo_mod.pack(geo_mod.KIND_COUNTRY, gv4, gv6, 1700000000, 'x.dat', 'ab' * 32)
gh = geo_mod.parse_header(gbin)
ok('compiled file: header fields round-trip', gh and gh['kind'] == 1 and gh['vsize'] == 2 and gh['built'] == 1700000000 and gh['v4'] == 3 and gh['v6'] == 2
   and gh['source'] == 'x.dat' and gh['sha'] == 'ab' * 32 and len(gbin) == 128 + 3 * 10 + 2 * 34)
ok('compiled file: read_ranges returns what was written', geo_mod.read_ranges(gbin) == (gv4, gv6))
ok('compiled file: lookup of first / last / inside / gap / mapped IPv6',
   geo_mod.lookup(gbin, '1.0.0.0') == 'AA' and geo_mod.lookup(gbin, '1.0.0.255') == 'AA' and geo_mod.lookup(gbin, '5.9.9.9') == 'IR'
   and geo_mod.lookup(gbin, '255.255.255.255') == 'ZZ' and geo_mod.lookup(gbin, '4.0.0.0') is None and geo_mod.lookup(gbin, '::ffff:5.1.1.1') == 'IR'
   and geo_mod.lookup(gbin, '2001:db8::5') == 'DE' and geo_mod.lookup(gbin, '2a01::1') == 'IR' and geo_mod.lookup(gbin, '3000::') is None)
gasn = geo_mod.pack(geo_mod.KIND_ASN, geo_mod.normalize([g_net('1.0.0.0/24', 13335), g_net('2.0.0.0/24', 4200000000)]), [], 1, 'a.mmdb', '')
ok('compiled file: ASN values, including one above 2^31', geo_mod.lookup(gasn, '1.0.0.9') == 13335 and geo_mod.lookup(gasn, '2.0.0.1') == 4200000000 and geo_mod.lookup(gasn, '9.9.9.9') is None)
ok('compiled file: truncated or foreign bytes are not a compiled file',
   geo_mod.parse_header(gbin[:200]) is None and geo_mod.parse_header(b'x' * 200) is None and geo_mod.parse_header(b'') is None)

# -- geoip.dat (protobuf)
def pb_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def pb_field(num, wire, payload):
    key = pb_varint((num << 3) | wire)
    if wire == 2:
        return key + pb_varint(len(payload)) + payload
    return key + payload


def pb_cidr(cidr):
    n = ip_geo.ip_network(cidr)
    return pb_field(1, 2, n.network_address.packed) + pb_field(2, 0, pb_varint(n.prefixlen))


def pb_entry(tag, cidrs, reverse=False, extra=b''):
    body = pb_field(1, 2, tag.encode()) + b''.join(pb_field(2, 2, pb_cidr(c)) for c in cidrs)
    if reverse:
        body += pb_field(3, 0, pb_varint(1))
    return pb_field(1, 2, body + extra)


dat_bytes = (pb_entry('IR', ['5.0.0.0/8', '2a00::/12']) + pb_entry('us', ['5.1.0.0/16', '8.8.8.0/24']) + pb_entry('PRIVATE', ['10.0.0.0/8', '192.168.0.0/16'])
             + pb_entry('cloudflare', ['1.1.1.0/24']) + pb_entry('de', ['2001:db8::/32']) + pb_entry('geolocation-cn', ['9.9.9.0/24'])
             + pb_entry('fr', ['7.0.0.0/8'], reverse=True) + pb_entry('tr', ['6.0.0.0/8'], extra=pb_field(15, 5, b'\0\0\0\0')))
geo_work = tempfile.mkdtemp(prefix='gv-geo-selftest-')
dat_path = os.path.join(geo_work, 'fixture.dat')
with open(dat_path, 'wb') as fh:
    fh.write(dat_bytes)
dat = geo_mod.read_dat(dat_path)
ok('geoip.dat: 2-letter tags become country ranges (any case, upper-cased)', set(r[2] for r in dat['v4']) == {'IR', 'US', 'TR'} and [r[2] for r in dat['v6']] == ['IR', 'DE'])
ok('geoip.dat: private, cloudflare, longer tags and reverse_match entries are listed as ignored',
   dat['ignored'] == {'PRIVATE': 2, 'cloudflare': 1, 'geolocation-cn': 1, 'fr': 1})
ok('geoip.dat: an unknown field with a fixed-width wire type is skipped', 'TR' in set(r[2] for r in dat['v4']))
for label, blob in (('truncated', dat_bytes[:-3]), ('a bad prefix', pb_entry('ir', []) + pb_field(1, 2, pb_field(1, 2, b'ir') + pb_field(2, 2, pb_field(1, 2, b'\x05\0\0\0') + pb_field(2, 0, pb_varint(40)))))):
    bad_path = os.path.join(geo_work, 'bad.dat')
    with open(bad_path, 'wb') as fh:
        fh.write(blob)
    try:
        geo_mod.read_dat(bad_path)
        raised = False
    except geo_mod.GeoError:
        raised = True
    ok('geoip.dat: %s is an error, not a crash' % label, raised)
os.remove(os.path.join(geo_work, 'bad.dat'))
ok('geoip.dat: nested CIDRs from different countries compile to a narrower-wins table', (lambda t: (geo_mod.lookup(t, '5.1.2.3') == 'US' and geo_mod.lookup(t, '5.2.0.0') == 'IR' and geo_mod.lookup(t, '5.0.255.255') == 'IR'))(
    geo_mod.pack(1, geo_mod.normalize(dat['v4']), geo_mod.normalize(dat['v6']), 1, 'f.dat', '')))


# -- a minimal MaxMind DB writer (IPv4 tree, 24-bit records), enough to feed the reader
def mm_str(s):
    b = s.encode()
    return bytes([0x40 | len(b)]) + b


def mm_uint(typ, n):
    raw = n.to_bytes(max(1, (n.bit_length() + 7) // 8), 'big') if n else b''
    return bytes([(typ << 5) | len(raw)]) + raw


def mm_value(v):
    if isinstance(v, dict):
        return bytes([0xE0 | len(v)]) + b''.join(mm_str(k) + mm_value(x) for k, x in v.items())
    if isinstance(v, str):
        return mm_str(v)
    return mm_uint(6, v)


def mm_build(entries, dbtype):
    """entries: [(cidr, record dict)] -> MMDB bytes (IPv4 only)."""
    data = b''
    offsets = {}
    nodes = [[None, None]]
    for cidr, rec in sorted(entries, key=lambda e: ip_geo.ip_network(e[0]).prefixlen):
        key = json_geo.dumps(rec, sort_keys=True)
        if key not in offsets:
            offsets[key] = len(data)
            data += mm_value(rec)
        net = ip_geo.ip_network(cidr)
        bits = format(int(net.network_address), '032b')[:net.prefixlen]
        at = 0
        for i, bit in enumerate(bits):
            b = int(bit)
            if i == len(bits) - 1:
                nodes[at][b] = ('data', offsets[key])
            else:
                if not isinstance(nodes[at][b], int):
                    old = nodes[at][b]               # a wider network already ends here: both halves keep its data
                    nodes.append([old, old])
                    nodes[at][b] = len(nodes) - 1
                at = nodes[at][b]
    count = len(nodes)

    def rec_val(r):
        if r is None:
            return count
        if isinstance(r, int):
            return r
        return count + 16 + r[1]
    tree = b''.join(rec_val(n[0]).to_bytes(3, 'big') + rec_val(n[1]).to_bytes(3, 'big') for n in nodes)
    meta = {'binary_format_major_version': 2, 'binary_format_minor_version': 0, 'database_type': dbtype, 'ip_version': 4,
            'node_count': count, 'record_size': 24, 'build_epoch': 1700000000, 'description': {'en': 'fixture'}, 'languages': ['en']}
    md = bytes([0xE0 | len(meta)])
    for k, v in meta.items():
        md += mm_str(k)
        if k == 'build_epoch':
            md += bytes([4, 2]) + (1700000000).to_bytes(4, 'big')          # uint64: extended type 9
        elif k == 'languages':
            md += bytes([1, 4]) + mm_str('en')                            # array: extended type 11
        elif k == 'description':
            md += mm_value({'en': 'fixture'})
        elif isinstance(v, str):
            md += mm_str(v)
        elif k in ('ip_version', 'record_size', 'binary_format_major_version', 'binary_format_minor_version'):
            md += mm_uint(5, v)                                            # uint16
        else:
            md += mm_uint(6, v)
    return tree + b'\0' * 16 + data + b'\xab\xcd\xefMaxMind.com' + md


try:
    import maxminddb as mm_geo
except ImportError:
    mm_geo = None
if mm_geo is None:
    skip('.mmdb reader and compile', 'the optional maxminddb package is not installed')
else:
    mm_country = mm_build([('5.0.0.0/8', {'country': {'iso_code': 'IR'}}), ('5.1.0.0/16', {'country': {'iso_code': 'DE'}}), ('8.8.8.0/24', {'country': {'iso_code': 'us'}}),
                           ('9.0.0.0/8', {'country': {'names': {'en': 'nowhere'}}})], 'GeoLite2-Country')
    mm_asn = mm_build([('1.0.0.0/24', {'autonomous_system_number': 13335, 'org': 'Cloudflare'}),
                       ('1.0.1.0/24', {'autonomous_system_number': 13335, 'org': 'Cloudflare'}),
                       ('2.0.0.0/24', {'asn': 'AS15169', 'country_code': 'US'})], 'GeoLite2-ASN')
    mm_path = os.path.join(geo_work, 'c.mmdb')
    with open(mm_path, 'wb') as fh:
        fh.write(mm_country)
    r_cc = geo_mod.read_mmdb(mm_path)
    ok('.mmdb: country ranges (upper-cased), a record without an ISO code is skipped, no ASN data', geo_mod.normalize(r_cc['country']['v4']) ==
       geo_mod.normalize([g_net('5.0.0.0/8', 'IR'), g_net('5.1.0.0/16', 'DE'), g_net('8.8.8.0/24', 'US')]) and r_cc['asn']['v4'] == []
       and geo_mod.normalize(r_cc['country']['v4'])[1] == g_net('5.1.0.0/16', 'DE'))
    with open(mm_path, 'wb') as fh:
        fh.write(mm_asn)
    r_as = geo_mod.read_mmdb(mm_path)
    ok('.mmdb: ASN as a number (GeoLite2 style) and as "AS15169" (IPinfo style); an IPinfo-style record also gives a country',
       geo_mod.normalize(r_as['asn']['v4']) == [g_net('1.0.0.0/23', 13335), g_net('2.0.0.0/24', 15169)] and r_as['country']['v4'] == [g_net('2.0.0.0/24', 'US')])
    os.remove(mm_path)
    with open(mm_path, 'wb') as fh:
        fh.write(b'this is not a database')
    try:
        geo_mod.read_mmdb(mm_path)
        raised = False
    except geo_mod.GeoError:
        raised = True
    ok('.mmdb: a file that is not a MaxMind DB is an error, not a crash', raised)
    os.remove(mm_path)


# -- compile: atomic swap, rollback copy, sanity checks
def geo_dir(name):
    d = os.path.join(geo_work, name)
    os.makedirs(d)
    return d


def put(d, name, blob):
    with open(os.path.join(d, name), 'wb') as fh:
        fh.write(blob)


d1 = geo_dir('c1')
put(d1, 'geoip.dat', dat_bytes)
st1 = geo_mod.compile_geo(d1, known={'country': [('5.1.2.3', 'US'), ('5.9.9.9', 'IR')], 'asn': []}, min_ranges=2, now=1800000000)
cbin = open(os.path.join(d1, 'country.bin'), 'rb').read()
ok('compile: geoip.dat -> country.bin; the file passes its own lookups and has the source name and sha',
   st1['ok'] and st1['errors'] == [] and geo_mod.lookup(cbin, '5.1.2.3') == 'US' and geo_mod.lookup(cbin, '6.1.1.1') == 'TR'
   and geo_mod.parse_header(cbin)['source'] == 'geoip.dat' and geo_mod.parse_header(cbin)['built'] == 1800000000
   and geo_mod.parse_header(cbin)['sha'] == __import__('hashlib').sha256(dat_bytes).hexdigest())
ok('compile: no ASN source means no asn.bin and no error', not os.path.exists(os.path.join(d1, 'asn.bin')) and st1['asn'] is None)
ok('compile: geo-status.json records the sources, the ignored tags and the country list',
   json_geo.load(open(os.path.join(d1, 'geo-status.json')))['ignored_tags']['PRIVATE'] == 2 and st1['countries'] == ['DE', 'IR', 'TR', 'US']
   and st1['sources'][0]['used'] == ['country'])
ok('compile: no temp file and no .prev after the first compile', [n for n in os.listdir(d1) if '.tmp' in n or n.endswith('.prev')] == [])
st2 = geo_mod.compile_geo(d1, known={'country': [], 'asn': []}, min_ranges=2, now=1800000100)
ok('compile: a second compile keeps the file it replaced as country.bin.prev (rollback copy), byte for byte',
   open(os.path.join(d1, 'country.bin.prev'), 'rb').read() == cbin and geo_mod.parse_header(open(os.path.join(d1, 'country.bin'), 'rb').read())['built'] == 1800000100)
ok('compile: still no temp files', [n for n in os.listdir(d1) if '.tmp' in n] == [])

# sanity failures keep the live file
live = open(os.path.join(d1, 'country.bin'), 'rb').read()
put(d1, 'geoip.dat', pb_entry('us', ['8.8.8.0/24']) + pb_entry('de', ['2001:db8::/32']))
os.utime(os.path.join(d1, 'geoip.dat'), None)
st3 = geo_mod.compile_geo(d1, known={'country': [], 'asn': []}, min_ranges=1, now=1800000200)
ok('sanity: a table with no range for IR does not replace the live file', not st3['ok'] and any('no range for IR' in e for e in st3['errors']) and open(os.path.join(d1, 'country.bin'), 'rb').read() == live)
ok('sanity: a failed compile still describes the file that is live (status keeps the old country entry)', st3['country'] is not None and st3['country']['built'] == 1800000100)
put(d1, 'geoip.dat', dat_bytes)
st4 = geo_mod.compile_geo(d1, known={'country': [], 'asn': []}, min_ranges=100, now=1800000300)
ok('sanity: fewer IPv4 ranges than the minimum does not replace the live file', not st4['ok'] and any('IPv4 ranges' in e for e in st4['errors']) and open(os.path.join(d1, 'country.bin'), 'rb').read() == live)
st5 = geo_mod.compile_geo(d1, known={'country': [('5.1.2.3', 'IR')], 'asn': []}, min_ranges=1, now=1800000400)
ok('sanity: a known address that resolves differently blocks the swap and says which', not st5['ok'] and any('5.1.2.3' in e and "'US'" in e for e in st5['errors']) and open(os.path.join(d1, 'country.bin'), 'rb').read() == live)
known_file = os.path.join(d1, 'known.json')
with open(known_file, 'w') as fh:
    json_geo.dump({'country': {'5.9.9.9': 'IR', '6.0.0.1': 'TR'}, 'asn': {}}, fh)
ok('sanity: geo/known.json supplies the known addresses (none are hard-coded)', geo_mod.load_known(known_file)['country'] == [('5.9.9.9', 'IR'), ('6.0.0.1', 'TR')]
   and geo_mod.load_known(os.path.join(d1, 'missing.json')) == {'country': [], 'asn': []})
ok('sanity: sanity() flags an empty table and a missing IR', geo_mod.sanity(1, [], [], [], 1) and geo_mod.sanity(1, [(1, 2, 'US')], [], [], 1) == ['no range for IR'] and geo_mod.sanity(2, [(1, 2, 5)], [], [], 1) == [])

d2 = geo_dir('c2')
st6 = geo_mod.compile_geo(d2, known={'country': [], 'asn': []})
ok('compile: a directory with no source says so and writes nothing', not st6['ok'] and any('no .mmdb' in e for e in st6['errors']) and not os.path.exists(os.path.join(d2, 'country.bin')))
st7 = geo_mod.compile_geo(os.path.join(geo_work, 'missing-dir'), known={'country': [], 'asn': []})
ok('compile: a missing directory is a reported error, not an exception', not st7['ok'] and st7['errors'])
d3 = geo_dir('c3')
put(d3, 'broken.dat', dat_bytes[:-3])
put(d3, 'good.dat', dat_bytes)
os.utime(os.path.join(d3, 'broken.dat'), (1, 1))
st8 = geo_mod.compile_geo(d3, known={'country': [], 'asn': []}, min_ranges=1)
ok('compile: a broken source is reported and skipped; a good one still compiles', st8['ok'] and any('broken.dat' in e for e in st8['errors']) and os.path.exists(os.path.join(d3, 'country.bin')))
ok('compile: main() exits non-zero when anything went wrong, zero when nothing did',
   geo_mod.main(['--dir', d3, '--min-ranges', '1']) == 1 and geo_mod.main(['--dir', d1, '--min-ranges', '1']) == 0)

if mm_geo is not None:
    d4 = geo_dir('c4')
    put(d4, 'GeoLite2-Country.mmdb', mm_country)
    put(d4, 'GeoLite2-ASN.mmdb', mm_build([('1.0.0.0/24', {'autonomous_system_number': 13335}), ('1.0.1.0/24', {'autonomous_system_number': 13335}),
                                           ('2.0.0.0/24', {'autonomous_system_number': 15169})], 'GeoLite2-ASN'))
    st9 = geo_mod.compile_geo(d4, known={'country': [('5.1.1.1', 'DE'), ('5.200.0.0', 'IR')], 'asn': [('1.0.0.77', 13335), ('1.0.1.77', 13335)]}, min_ranges=1, now=1800000000)
    ok('compile: a country .mmdb and an ASN .mmdb give country.bin and asn.bin; adjacent same-AS networks merge',
       st9['ok'] and st9['errors'] == [] and st9['asn']['v4'] == 2 and geo_mod.lookup(open(os.path.join(d4, 'asn.bin'), 'rb').read(), '2.0.0.5') == 15169
       and geo_mod.parse_header(open(os.path.join(d4, 'asn.bin'), 'rb').read())['kind'] == 2)
    ok('compile: each kind comes from the file that holds it',
       st9['country']['source'] == 'GeoLite2-Country.mmdb' and st9['asn']['source'] == 'GeoLite2-ASN.mmdb')
    # Without the optional package the .mmdb files are reported and a geoip.dat still compiles.
    saved = sys.modules.get('maxminddb')
    sys.modules['maxminddb'] = None
    try:
        put(d4, 'geoip.dat', dat_bytes)
        st10 = geo_mod.compile_geo(d4, known={'country': [], 'asn': []}, min_ranges=1)
    finally:
        sys.modules['maxminddb'] = saved
    ok('compile: without the maxminddb package the .mmdb files are reported (with the install hint) and the geoip.dat still compiles',
       any('pip install maxminddb' in e for e in st10['errors']) and st10['country']['source'] == 'geoip.dat')

# -- worker, cron wrapper
ok('worker: geo_compile is a known job type with a handler', 'geo_compile' in worker_geo.HANDLERS and worker_geo.validate({'id': 'a1', 'type': 'geo_compile', 'params': {}})[0])
ok('worker: an unknown type is still refused', not worker_geo.validate({'id': 'a1', 'type': 'geo_compilex', 'params': {}})[0])
cron_src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts', 'analyzer-cron.sh')).read()
ok('cron wrapper: a geo mode that runs analyzer/geo.py', re.search(r'geo\)\s+SCRIPT="analyzer/geo\.py"', cron_src) is not None)
jobs_src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'panel', 'jobs.php')).read()
ok('the panel and the worker agree on the job type list', "'geo_compile'" in jobs_src)

# -- PHP reads what Python writes
php_geo = shutil.which('php')
if not php_geo:
    skip('PHP lookup parity', 'php not found')
else:
    ips = ['5.1.2.3', '5.0.0.0', '5.255.255.255', '4.255.255.255', '6.1.1.1', '8.8.8.8', '8.8.9.1', '2001:db8::1', '2a01::1', '2b00::1', '::ffff:5.1.2.3', '255.255.255.255', 'bad']
    d5 = geo_dir('c5')
    put(d5, 'geoip.dat', dat_bytes)
    geo_mod.compile_geo(d5, known={'country': [], 'asn': []}, min_ranges=1)
    code = ('define("GV_BOOT", 1); define("GV_NO_AUTORUN", 1); require $argv[1] . "/guard/guard.php"; '
            'foreach (array_slice($argv, 2) as $ip) { echo gv_geo_country($ip, true), "\\n"; }')
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env['GV_GEO_DIR'] = d5
    out = sp_geo.run([php_geo, '-r', code, root] + ips, env=env, stdout=sp_geo.PIPE, stderr=sp_geo.PIPE, universal_newlines=True)
    php_vals = out.stdout.split('\n')[:len(ips)]
    data5 = open(os.path.join(d5, 'country.bin'), 'rb').read()

    def py_val(ip):
        try:
            return geo_mod.lookup(data5, ip) or ''
        except ValueError:
            return ''
    ok('PHP and Python resolve every probe address the same way (%d probes)' % len(ips), out.returncode == 0 and php_vals == [py_val(ip) for ip in ips])
    ok('...and the answers are the expected ones, not just equal', php_vals[:5] == ['US', 'IR', 'IR', '', 'TR'] and php_vals[7] == 'DE')
shutil.rmtree(geo_work, ignore_errors=True)

# ---------------------------------------------------------------------------
section('IP lists compile: parser, merge by value, kind-3 file, atomic swap, PHP parity, snapshot hit counts')
import random as rnd_il
import subprocess as sp_il
from analyzer import iplist as il_mod
from analyzer import snapshot as snap_il

IL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
il_work = tempfile.mkdtemp(prefix='gv-iplist-selftest-')

pe = il_mod.parse_entry
ok('parse_entry: addresses, CIDRs and masked host bits', pe('203.0.113.7') == (4, 3405803783, 3405803783, 32) and pe('203.0.113.0/24')[3] == 24
   and pe('192.0.2.77/24') == pe('192.0.2.0/24') and pe('2001:db8::/32')[0] == 6 and pe('1.2.3.4/0')[1:3] == (0, 4294967295))
ok('parse_entry: an IPv4-mapped IPv6 address is the IPv4 address it carries (counted from /96)',
   pe('::ffff:1.2.3.4') == pe('1.2.3.4') and pe('::ffff:1.2.3.0/120') == pe('1.2.3.0/24') and pe('::ffff:1.2.3.0/64') is None)
ok('parse_entry: everything that is not an address is refused',
   all(pe(t) is None for t in ('', '1.2.3', '300.1.1.1', '1.2.3.4/33', '2001:db8::/129', '1.2.3.4/', '1.2.3.4/a', 'fe80::1%eth0', '1.2.3.4 5.6.7.8', 'example.com', '1.2.3.4/-1')))
il_entries, il_bad = il_mod.parse_text('﻿ip,note\r\n# c\r\n\r\n203.0.113.0/24  # t\r\n"198.51.100.7",x\r\n\'192.0.2.1\' , y\r\n2001:db8::/32\n\t10.9.9.9\t\njunk line\r5.5.5.5')
ok('parse_text: BOM, CRLF, CR, comments, blank lines, CSV first column, quotes; bad lines with their number',
   len(il_entries) == 6 and il_bad == [(1, 'ip,note'), (9, 'junk line')])
ok('union: overlapping, nested and adjacent ranges merge',
   il_mod.union([(0, 9), (10, 19), (5, 6), (30, 40), (31, 32)]) == [(0, 19), (30, 40)] and il_mod.union([]) == [])
ok('sweep: the SMALLER value wins on an overlap whatever the widths; equal neighbours merge',
   il_mod.sweep([(0, 100, 5), (10, 20, 1), (15, 30, 9), (101, 110, 5), (200, 200, 0x8001)]) == [(0, 9, 5), (10, 20, 1), (21, 110, 5), (200, 200, 0x8001)])
ok('sweep: an enforced value (no bit 15) beats a monitor value on the same address',
   il_mod.sweep([(0, 99, 0x8001), (40, 49, 2)]) == [(0, 39, 0x8001), (40, 49, 2), (50, 99, 0x8001)])
rnd_il.seed(21)
il_bad_n = 0
il_in = []
for _ in range(80):
    a = rnd_il.randint(0, 200)
    il_in.append((a, a + rnd_il.randint(0, 60), rnd_il.randint(1, 6) | (0x8000 if rnd_il.random() < .5 else 0)))
il_sw = il_mod.sweep(il_in)
for a in range(0, 270):
    want = min([v for s_, e_, v in il_in if s_ <= a <= e_] or [None]) if any(s_ <= a <= e_ for s_, e_, v in il_in) else None
    got = [v for s_, e_, v in il_sw if s_ <= a <= e_]
    if (got[0] if got else None) != want:
        il_bad_n += 1
ok('sweep: 80 random overlapping ranges agree with a per-address minimum (%d wrong)' % il_bad_n, il_bad_n == 0
   and all(a[1] < b[0] for a, b in zip(il_sw, il_sw[1:])))
il_top = il_mod.sweep([(4294967290, 4294967295, 3)])
ok('sweep: the top of the address space does not overflow', il_top == [(4294967290, 4294967295, 3)])

il_bin = geo_mod.pack(geo_mod.KIND_IPLIST, [(1000, 1999, 7), (3000, 3000, 0x8002)], [(5, 9, 1)], 1700000000, 'iplists-block', 'cd' * 32)
il_h = geo_mod.parse_header(il_bin)
ok('kind-3 file: 2-byte values, counts, header; read_ranges and lookup give the value back',
   il_h['kind'] == 3 and il_h['vsize'] == 2 and il_h['v4'] == 2 and il_h['v6'] == 1 and geo_mod.read_ranges(il_bin) == ([(1000, 1999, 7), (3000, 3000, 0x8002)], [(5, 9, 1)])
   and geo_mod.lookup(il_bin, '0.0.3.232') == 7 and geo_mod.lookup(il_bin, '0.0.11.184') == 0x8002 and geo_mod.lookup(il_bin, '0.0.7.208') is None)

def il_dir(name, lists, sources):
    d = os.path.join(il_work, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'lists.json'), 'w') as handle:
        json_geo.dump({'v': 1, 'next_idx': 99, 'lists': lists}, handle)
    for key, text in sources.items():
        with open(os.path.join(d, key + '.txt'), 'w') as handle:
            handle.write(text)
    return d

def il_list(i, kind, mode='enforce', enabled=True, force=False, id_=None):
    return {'id': id_ or 'l%d' % i, 'idx': i, 'name': 'L%d' % i, 'type': kind, 'mode': mode, 'enabled': enabled, 'force': force}

d1 = il_dir('c1', [il_list(1, 'block'), il_list(2, 'block', 'monitor'), il_list(3, 'allow'), il_list(4, 'block', enabled=False)],
            {'l1': '203.0.113.0/24\n198.51.100.0/25\n2001:db8::/48\njunk\n', 'l2': '203.0.113.0/25\n192.0.2.0/24\n', 'l3': '203.0.113.64/26\n', 'l4': '8.8.8.0/24\n'})
st1 = il_mod.compile_lists(d1, now=1800000000)
blk = open(os.path.join(d1, 'block.bin'), 'rb').read()
alw = open(os.path.join(d1, 'allow.bin'), 'rb').read()
ok('compile: one file per type from the ENABLED lists; the disabled list is not in it', st1['ok'] and geo_mod.lookup(blk, '8.8.8.5') is None and geo_mod.lookup(alw, '203.0.113.70') == 3
   and st1['types']['block']['lists'] == ['l1', 'l2'] and st1['types']['allow']['lists'] == ['l3'])
ok('compile: the enforced list wins over the monitor list on an overlap (value 1, not 0x8002), the monitor-only part keeps bit 15',
   geo_mod.lookup(blk, '203.0.113.9') == 1 and geo_mod.lookup(blk, '192.0.2.9') == 0x8002 and geo_mod.lookup(blk, '2001:db8::1') == 1)
ok('compile: per-list counts (entries, ranges, addresses, skipped invalid lines)', st1['lists']['l1'] == {'entries': 3, 'v4': 2, 'v6': 1, 'addresses': 384, 'invalid': 1, 'wide': 0}
   and st1['lists']['l3']['addresses'] == 64 and 'l4' not in st1['lists'])
ok('compile: lists-status.json is written, atomically, with the time and no leftovers', json_geo.load(open(os.path.join(d1, 'lists-status.json')))['time'] == 1800000000
   and not [n for n in os.listdir(d1) if '.tmp' in n])
ok('compile: the header names the type and carries the build time and a sha256 of the sources', geo_mod.parse_header(blk)['built'] == 1800000000 and geo_mod.parse_header(blk)['source'] == 'iplists-block'
   and len(geo_mod.parse_header(blk)['sha']) == 64 and geo_mod.parse_header(blk)['sha'] != '0' * 64)
sha_before = geo_mod.parse_header(blk)['sha']
with open(os.path.join(d1, 'l1.txt'), 'a') as handle:
    handle.write('8.8.4.0/24\n')
il_mod.compile_lists(d1, now=1800000100)
blk2 = open(os.path.join(d1, 'block.bin'), 'rb').read()
ok('compile: a changed source gives a new file and a new sha; the previous file stays as block.bin.prev',
   geo_mod.parse_header(blk2)['sha'] != sha_before and geo_mod.lookup(blk2, '8.8.4.9') == 1 and open(os.path.join(d1, 'block.bin.prev'), 'rb').read() == blk)
# wide entries, force, nothing to compile, a missing source
d2 = il_dir('c2', [il_list(1, 'block'), il_list(2, 'block', force=True), il_list(3, 'allow')], {'l1': '64.0.0.0/4\n11.0.0.0/8\n2400::/31\n', 'l2': '96.0.0.0/3\n', 'l3': '64.0.0.0/4\n'})
st2 = il_mod.compile_lists(d2, now=1)
ok('compile: a block entry wider than /8 (IPv4) or /32 (IPv6) is dropped and counted unless the list is forced; an allow list is never limited',
   st2['lists']['l1'] == {'entries': 1, 'v4': 1, 'v6': 0, 'addresses': 16777216, 'invalid': 0, 'wide': 2} and st2['lists']['l2']['wide'] == 0 and st2['lists']['l3']['wide'] == 0
   and geo_mod.lookup(open(os.path.join(d2, 'block.bin'), 'rb').read(), '100.1.1.1') == 2 and geo_mod.lookup(open(os.path.join(d2, 'block.bin'), 'rb').read(), '70.1.1.1') is None)
d3 = il_dir('c3', [il_list(1, 'block'), il_list(2, 'allow', enabled=False)], {'l1': '203.0.113.0/24\n', 'l2': '1.2.3.4\n'})
il_mod.compile_lists(d3, now=1)
ok('compile: no enabled allow list: no allow.bin at all (the guard opens nothing)', os.path.exists(os.path.join(d3, 'block.bin')) and not os.path.exists(os.path.join(d3, 'allow.bin')))
with open(os.path.join(d3, 'l1.txt'), 'w') as handle:
    handle.write('# only a comment\n')
st3 = il_mod.compile_lists(d3, now=2)
ok('compile: a list left with no entries removes its type file', st3['ok'] and not os.path.exists(os.path.join(d3, 'block.bin')) and st3['types']['block'] is None)
il_mod.compile_lists(il_dir('c3b', [il_list(1, 'block')], {'l1': '203.0.113.0/24\n'}), now=1)
d4 = os.path.join(il_work, 'c3b')
keep4 = open(os.path.join(d4, 'block.bin'), 'rb').read()
os.unlink(os.path.join(d4, 'l1.txt'))
st4 = il_mod.compile_lists(d4, now=5)
ok('compile: an enabled list whose source is missing is an error, the previous file is kept untouched', not st4['ok'] and any('l1' in e for e in st4['errors']) and open(os.path.join(d4, 'block.bin'), 'rb').read() == keep4)
d5 = os.path.join(il_work, 'c5')
os.makedirs(d5)
ok('compile: no lists.json at all: nothing to do, no files, ok', il_mod.compile_lists(d5, now=1)['ok'] and not os.path.exists(os.path.join(d5, 'block.bin')))
with open(os.path.join(d5, 'lists.json'), 'w') as handle:
    handle.write('{not json')
ok('compile: a broken lists.json is "no lists", not an exception', il_mod.compile_lists(d5, now=1)['ok'])
with open(os.path.join(d5, 'lists.json'), 'w') as handle:
    json_geo.dump({'lists': [{'id': '../x', 'idx': 1, 'type': 'block', 'enabled': True}, {'id': 'ok', 'idx': 0, 'type': 'block'}, {'id': 'ok2', 'idx': 40000, 'type': 'block'}, {'id': 'a', 'idx': 1, 'type': 'bogus'}, 'x']}, handle)
ok('compile: records with a bad id, index or type are ignored (the id is never used as a path unvalidated)', il_mod.read_meta(d5) == [{'id': '../x', 'idx': 1, 'type': 'block', 'enabled': True}] and il_mod.compile_lists(d5, now=1)['ok'] is not None)
ok('main(): exit 0 on success, 1 on an error or a missing directory',
   il_mod.main(['--dir', d1]) == 0 and il_mod.main(['--dir', d4]) == 1 and il_mod.main(['--dir', os.path.join(il_work, 'nope')]) == 1)
ok('worker: iplist_compile is a known job type with a handler; panel and worker agree on the list',
   'iplist_compile' in worker_geo.HANDLERS and worker_geo.validate({'id': 'a1', 'type': 'iplist_compile', 'params': {}})[0]
   and "'iplist_compile'" in open(os.path.join(IL_ROOT, 'panel', 'jobs.php')).read())

# -- PHP and Python build the same bytes, and the guard reads what Python wrote
php_il = shutil.which('php')
if not php_il:
    skip('IP list PHP parity', 'php not found')
else:
    rnd_il.seed(3)

    def r4():
        a = rnd_il.getrandbits(32)
        return '%d.%d.%d.%d/%d' % (a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255, rnd_il.choice([8, 12, 16, 20, 24, 28, 32]))

    def r6():
        return '%s/%d' % (ip_geo.IPv6Address(rnd_il.getrandbits(128)), rnd_il.choice([32, 48, 64, 128]))
    lists_p = [il_list(1, 'allow'), il_list(2, 'block'), il_list(3, 'block', 'monitor'), il_list(4, 'allow', 'monitor'), il_list(5, 'block', force=True)]
    sources_p = {}
    for item in lists_p:
        lines = [r4() for _ in range(1500)] + [r6() for _ in range(150)] + ['::ffff:1.2.3.0/120', '# c', 'junk', '10.1.0.0/9', '0.0.0.0/0', '203.0.113.0/24', '203.0.113.64/26']
        sources_p[item['id']] = '\r\n'.join(lines) + '\r\n'
    dp1 = il_dir('p1', lists_p, sources_p)
    dp2 = il_dir('p2', lists_p, sources_p)
    stp = il_mod.compile_lists(dp1, now=1700000000)
    code = ('define("GV_BOOT", 1); define("GV_NO_AUTORUN", 1); define("GP_BOOT", 1); $r = $argv[1];'
            'require $r . "/guard/guard.php"; require $r . "/panel/config_io.php"; require $r . "/panel/jobs.php"; require $r . "/panel/iplists.php";'
            '$s = gp_iplists_compile(1700000000); echo json_encode($s["ok"]);')
    env_p = dict(os.environ)
    env_p['GV_LISTS_DIR'] = dp2
    out_p = sp_il.run([php_il, '-r', code, IL_ROOT], env=env_p, stdout=sp_il.PIPE, stderr=sp_il.PIPE, universal_newlines=True)
    same = all(open(os.path.join(dp1, n), 'rb').read() == open(os.path.join(dp2, n), 'rb').read() for n in ('allow.bin', 'block.bin'))
    ok('PHP (panel) and Python (worker) compile the SAME bytes from the same lists (allow and block, v4 + v6, monitor + enforce, wide, mapped, CRLF)', out_p.stdout.strip() == 'true' and same and stp['ok'])
    st_php = json_geo.load(open(os.path.join(dp2, 'lists-status.json')))
    ok('...and the same per-list counts and type summaries', st_php['lists'] == stp['lists'] and st_php['types']['block']['v4'] == stp['types']['block']['v4'] and st_php['types']['allow']['sha'] == stp['types']['allow']['sha'])
    probes = ['203.0.113.70', '203.0.113.5', '1.2.3.77', '10.1.2.3', '8.8.8.8', '2001:db8::1', '::ffff:203.0.113.5', '255.255.255.255', '0.0.0.0', 'bad']
    code2 = ('define("GV_BOOT", 1); define("GV_NO_AUTORUN", 1); require $argv[1] . "/guard/guard.php";'
             'foreach (array_slice($argv, 2) as $ip) { $c = gv_iplist_check($ip); echo json_encode(array(isset($c["allow"]["idx"]) ? $c["allow"]["idx"] . ($c["allow"]["monitor"] ? "m" : "") : "-", isset($c["block"]["idx"]) ? $c["block"]["idx"] . ($c["block"]["monitor"] ? "m" : "") : "-")), "\n"; }')
    env_p['GV_LISTS_DIR'] = dp1
    out2 = sp_il.run([php_il, '-r', code2, IL_ROOT] + probes, env=env_p, stdout=sp_il.PIPE, stderr=sp_il.PIPE, universal_newlines=True)
    php_res = [json_geo.loads(x) for x in out2.stdout.strip().split('\n')]

    def py_res(ip):
        out = []
        for kind in ('allow', 'block'):
            try:
                v = geo_mod.lookup(open(os.path.join(dp1, kind + '.bin'), 'rb').read(), ip)
            except (ValueError, geo_mod.GeoError):
                v = None
            out.append('-' if v is None else '%d%s' % (v & 0x7FFF, 'm' if v & 0x8000 else ''))
        return out
    ok('the PHP guard and the Python reader agree on every probe address of the Python-written files (%d probes)' % len(probes), out2.returncode == 0 and php_res == [py_res(ip) for ip in probes])
    ok('...and the probes really hit (not an all-miss agreement)', php_res[0] != ['-', '-'] and sum(1 for r in php_res if r != ['-', '-']) >= 4)
shutil.rmtree(il_work, ignore_errors=True)

# -- snapshot: hits of the lists
ok('snapshot: list_ids reads IPL_ALLOW / IPL_BLOCK and their SH_ forms, nothing else',
   snap_il.list_ids({'rs': ['IPL_BLOCK:scrapers', 'SH_IPL_ALLOW:partners', 'RULE:r1', 'IPL_BLOCK:', 'XIPL_BLOCK:z', 5, 'IPL_ALLOW:' + 'a' * 25]}) == ['block:scrapers', 'allow:partners']
   and snap_il.list_ids({}) == [] and snap_il.list_ids({'rs': None}) == [])
il_hits = snap_il.count_rule_hits([{'ts': 100.0, 'rs': ['IPL_BLOCK:x', 'RULE:a']}, {'ts': 200.0, 'rs': ['SH_IPL_BLOCK:x']}, {'ts': 300.0, 'rs': ['IPL_ALLOW:y']}])
ok('snapshot: list hits are counted next to rule hits under an "ipl:" key, per type and id', il_hits['ipl:block:x'] == [2, 200.0] and il_hits['ipl:allow:y'] == [1, 300.0] and il_hits['a'] == [1, 100.0])
ok('snapshot: split_list_hits separates them for the panel (iplists keyed type:id)',
   snap_il.split_list_hits(il_hits) == ({'a': [1, 100.0]}, {'block:x': [2, 200.0], 'allow:y': [1, 300.0]}))
ok('snapshot: a rule id that looks like a list key cannot collide (rule ids never start with "ipl:")', snap_il.split_list_hits({'r1': [1, 1.0]}) == ({'r1': [1, 1.0]}, {}))

# ---------------------------------------------------------------------------
section('Crontab check (scripts/cron-check.sh): parser, states, schedules, GV_PYTHON, CageFS, CRLF')
import importlib.util as ilu_cc
import json as json_cc
import subprocess as sp_cc

cc_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts', 'cron_check.py')
cc_spec = ilu_cc.spec_from_file_location('cron_check', cc_path)
cron_check = ilu_cc.module_from_spec(cc_spec)
cc_spec.loader.exec_module(cron_check)
CC_ROOT = '/home/u/bot-guard'
CC_PY = sys.executable
CC_FULL = '\n'.join([
    'GV_PYTHON=' + CC_PY,
    'MAILTO=""',
    '*/10 * * * * %s/scripts/analyzer-cron.sh verify    >/dev/null 2>&1' % CC_ROOT,
    '* * * * * %s/scripts/analyzer-cron.sh worker >/dev/null 2>&1' % CC_ROOT,
    '*/15 * * * * %s/scripts/analyzer-cron.sh snapshot >/dev/null 2>&1' % CC_ROOT,
    '17 4 * * * %s/scripts/analyzer-cron.sh nightly >/dev/null 2>&1' % CC_ROOT,
    '10 3 * * * %s/scripts/guard-logrotate.sh >/dev/null 2>&1' % CC_ROOT,
    '# reverse-DNS bot verification, frequent',
]) + '\n'


def cc_state(report, job):
    return [j for j in report['jobs'] if j['job'] == job][0]


full = cron_check.evaluate(CC_FULL, CC_ROOT, geo_used=False, now=1)
ok('a complete crontab: every required entry ok, exit-style ok flag, no problems', full['ok'] and full['problems'] == 0
   and all(cc_state(full, j)['state'] == 'ok' for j in ('verify', 'worker', 'snapshot', 'nightly', 'logrotate')))
ok('recommended entries (train, train-clf, report) are only informational when missing; geo is left out when GeoIP is unused',
   cc_state(full, 'train')['severity'] == 'info' and cc_state(full, 'report')['state'] == 'missing' and 'geo' not in [j['job'] for j in full['jobs']] and full['ok'])
ok('a prose comment is not an entry', all(cc_state(full, j)['state'] == 'ok' for j in ('verify',)))
ok('GV_PYTHON pointing at an executable file is ok', full['gv_python']['set'] and full['gv_python']['ok'])

empty = cron_check.evaluate('', CC_ROOT, geo_used=False)
ok('an empty crontab: every required entry missing (critical), not an error of the check', not empty['ok'] and empty['problems'] == 5
   and all(cc_state(empty, j)['severity'] == 'critical' for j in ('verify', 'worker', 'snapshot', 'nightly', 'logrotate')))
ok('missing entries come with the exact line for THIS install, and the GV_PYTHON hint', cc_state(empty, 'worker')['install_line'] == '* * * * * %s/scripts/analyzer-cron.sh worker >/dev/null 2>&1' % CC_ROOT
   and cc_state(empty, 'logrotate')['install_line'].endswith('/scripts/guard-logrotate.sh >/dev/null 2>&1') and empty['gv_python']['suggest'].startswith('GV_PYTHON=') and empty['editor'] == 'crontab -e')

commented = cron_check.evaluate(CC_FULL.replace('*/15 * * * * ', '#*/15 * * * * ').replace('17 4', '# 17 4'), CC_ROOT, geo_used=False)
ok('a commented-out entry counts as DISABLED (a warning, still a problem for the exit code), and its line is offered again',
   cc_state(commented, 'snapshot')['state'] == 'disabled' and cc_state(commented, 'nightly')['state'] == 'disabled' and cc_state(commented, 'snapshot')['severity'] == 'warning'
   and not commented['ok'] and 'snapshot' in cc_state(commented, 'snapshot')['install_line'])

dup = cron_check.evaluate(CC_FULL + '*/10 * * * * %s/scripts/analyzer-cron.sh verify\n' % CC_ROOT, CC_ROOT, geo_used=False)
ok('duplicates are reported (warning)', cc_state(dup, 'verify')['state'] == 'duplicate' and cc_state(dup, 'verify')['severity'] == 'warning' and dup['ok'])

wrong = cron_check.evaluate(CC_FULL.replace(CC_ROOT + '/scripts/guard-logrotate.sh', '/home/other/bot-guard/scripts/guard-logrotate.sh'), CC_ROOT, geo_used=False)
ok('an entry pointing at another install directory is "wrong path"', cc_state(wrong, 'logrotate')['state'] == 'wrong_path' and not wrong['ok'] and '/home/other' in cc_state(wrong, 'logrotate')['message'])
ok('a relative script path is "wrong path" too, a path through .. or a symlink to this install is fine',
   cron_check.evaluate('* * * * * scripts/analyzer-cron.sh worker\n', CC_ROOT, geo_used=False)['jobs'][1]['state'] == 'wrong_path'
   and cc_state(cron_check.evaluate('* * * * * %s/x/../scripts/analyzer-cron.sh worker\n' % CC_ROOT, CC_ROOT, geo_used=False), 'worker')['state'] == 'ok')

daily = cron_check.evaluate(CC_FULL.replace('17 4 * * *', '@daily').replace('10 3 * * *', '@midnight'), CC_ROOT, geo_used=False)
ok('@daily / @midnight style schedules are understood', cc_state(daily, 'nightly')['state'] == 'ok' and cc_state(daily, 'logrotate')['state'] == 'ok' and cc_state(daily, 'nightly')['period_min'] == 1440)
slow = cron_check.evaluate(CC_FULL.replace('*/10 * * * *', '*/30 * * * *').replace('17 4 * * *', '@weekly').replace('* * * * * %s/scripts/analyzer-cron.sh worker' % CC_ROOT, '@hourly %s/scripts/analyzer-cron.sh worker' % CC_ROOT), CC_ROOT, geo_used=False)
ok('a schedule that runs less often than the job needs is "wrong schedule" (verify */30, nightly @weekly, worker @hourly)',
   all(cc_state(slow, j)['state'] == 'wrong_schedule' for j in ('verify', 'nightly', 'worker')) and 'every 30' in cc_state(slow, 'verify')['message'] and not slow['ok'])
ok('@reboot never runs the job', cc_state(cron_check.evaluate(CC_FULL.replace('17 4 * * *', '@reboot'), CC_ROOT, geo_used=False), 'nightly')['state'] == 'wrong_schedule')
ok('period estimate: */10, every minute, hourly list, weekdays only, monthly, @yearly',
   cron_check.period_minutes('*/10 * * * *') == 10 and cron_check.period_minutes('* * * * *') == 1 and cron_check.period_minutes('0 * * * *') == 60
   and cron_check.period_minutes('0 0 * * 1-5') == 10080 / 5 and cron_check.period_minutes('23 3 1 * *') > 40000 and cron_check.period_minutes('@yearly') == 525600
   and cron_check.period_minutes('0,30 * * * *') == 30 and cron_check.period_minutes('nonsense') is None and cron_check.period_minutes('1 2 3') is None)
ok('weekly (41 5 * * 0) and monthly (23 3 1 * *) defaults satisfy their 7 d / 30 d expectations',
   all(cc_state(cron_check.evaluate('41 5 * * 0 %s/scripts/analyzer-cron.sh train\n23 3 1 * * %s/scripts/analyzer-cron.sh geo\n' % (CC_ROOT, CC_ROOT), CC_ROOT, geo_used=True), j)['state'] == 'ok' for j in ('train', 'geo')))

env_only = cron_check.parse_crontab('SHELL=/bin/bash\nPATH=/usr/bin:/bin\nGV_PYTHON="/x/py"\nMAILTO=\n')
ok('environment lines are read (quotes stripped) and are not entries', env_only[0]['GV_PYTHON'] == '/x/py' and env_only[0]['SHELL'] == '/bin/bash' and env_only[1] == [])
gp_bad = cron_check.evaluate(CC_FULL.replace('GV_PYTHON=' + CC_PY, 'GV_PYTHON=/nonexistent/venv/bin/python'), CC_ROOT, geo_used=False)
ok('a GV_PYTHON that is not an executable file is a problem; a missing one is only a warning', gp_bad['gv_python']['set'] and not gp_bad['gv_python']['ok'] and not gp_bad['ok']
   and cron_check.evaluate(CC_FULL.replace('GV_PYTHON=' + CC_PY + '\n', ''), CC_ROOT, geo_used=False)['ok'] and cron_check.evaluate(CC_FULL.replace('GV_PYTHON=' + CC_PY + '\n', ''), CC_ROOT, geo_used=False)['warnings'] >= 1)
crlf = cron_check.evaluate(CC_FULL.replace('\n', '\r\n'), CC_ROOT, geo_used=False)
ok('CRLF line endings (a crontab edited on Windows) give the same result', crlf['ok'] and crlf['gv_python']['ok'] and [j['state'] for j in crlf['jobs']] == [j['state'] for j in full['jobs']])

cage = ('# DO NOT EDIT THIS FILE - edit the master and reinstall.\n# (/tmp/crontab.XXXX installed on Fri Nov 20 10:00:00 2026)\n# (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)\n' + CC_FULL)
ok('CageFS / vixie-cron header comments are ignored', cron_check.evaluate(cage, CC_ROOT, geo_used=False)['ok'])
ok('the geo entry is required-looking only when GeoIP is used (recommended, warning level)', cc_state(cron_check.evaluate(CC_FULL, CC_ROOT, geo_used=True), 'geo')['state'] == 'missing')

# the live crontab: crontab.cagefs first, then crontab; "no crontab for user" is empty
cc_calls = []
real_run = cron_check.subprocess.run


def fake_run_factory(table):
    def fake_run(cmd, **kw):
        cc_calls.append(cmd[0])
        entry = table.get(cmd[0])
        if entry is None:
            raise OSError('not found')
        return sp_cc.CompletedProcess(cmd, entry[0], entry[1], entry[2])
    return fake_run


cron_check.subprocess.run = fake_run_factory({'/usr/bin/crontab.cagefs': (0, CC_FULL, ''), 'crontab': (0, 'wrong', '')})
text_cc, src_cc = cron_check.read_live()
ok('crontab.cagefs is tried first and wins', src_cc == 'crontab.cagefs' and text_cc == CC_FULL and cc_calls == ['/usr/bin/crontab.cagefs'])
cc_calls[:] = []
cron_check.subprocess.run = fake_run_factory({'crontab': (0, CC_FULL, '')})
ok('without crontab.cagefs the plain crontab -l is used', cron_check.read_live() == (CC_FULL, 'crontab') and cc_calls == ['/usr/bin/crontab.cagefs', 'crontab'])
cron_check.subprocess.run = fake_run_factory({'crontab': (1, '', 'no crontab for cloud')})
ok('"no crontab for user" is an empty crontab, not an error', cron_check.read_live() == ('', 'crontab'))
cron_check.subprocess.run = fake_run_factory({})
ok('no crontab command at all: unreadable (None), reported as such', cron_check.read_live() == (None, ''))
cron_check.subprocess.run = real_run

# the script itself: exit codes and JSON
cc_tmp = tempfile.mkdtemp(prefix='gv-cc-')
with open(os.path.join(cc_tmp, 'ok.txt'), 'w') as fh:
    fh.write(CC_FULL)
with open(os.path.join(cc_tmp, 'empty.txt'), 'w') as fh:
    fh.write('')
cc_script = os.path.join(os.path.dirname(cc_path), 'cron-check.sh')
r_ok = sp_cc.run(['bash', cc_script, '--file', os.path.join(cc_tmp, 'ok.txt'), '--root', CC_ROOT], stdout=sp_cc.PIPE, universal_newlines=True)
r_empty = sp_cc.run(['bash', cc_script, '--file', os.path.join(cc_tmp, 'empty.txt'), '--root', CC_ROOT], stdout=sp_cc.PIPE, universal_newlines=True)
r_json = sp_cc.run(['bash', cc_script, '--json', '--file', os.path.join(cc_tmp, 'empty.txt'), '--root', CC_ROOT], stdout=sp_cc.PIPE, universal_newlines=True)
ok('cron-check.sh exits 0 when all required entries are right and 1 when something is missing', r_ok.returncode == 0 and r_empty.returncode == 1)
ok('the report is English and names the fix; --json is valid JSON with the same verdict', 'RESULT:' in r_empty.stdout and 'crontab -e' in r_empty.stdout and json_cc.loads(r_json.stdout)['problems'] == 5
   and not re.search(r'[^\x00-\x7f]', r_empty.stdout))
shutil.rmtree(cc_tmp, ignore_errors=True)

# ---------------------------------------------------------------------------
section('Job reports, 24 h KPIs, top lists, time zone (PR 4)')
import io as io_p4
import contextlib as ctx_p4
from analyzer import jobreport as jr_p4
from analyzer import snapshot as snap_p4

buf_p4 = io_p4.StringIO()
with ctx_p4.redirect_stderr(buf_p4):
    jr_p4.warn('Redis unavailable:\n verdicts   not stored')
    jr_p4.result({'ml_trained': False, 'ml_samples': 12, 'clf_metrics': {'precision': 0.9}})
    jr_p4.warn('x' * 1000)
warns_p4, res_p4 = jr_p4.parse(buf_p4.getvalue() + 'ordinary output\nGV_JOB_RESULT: not json\n')
ok('jobreport: warnings are single-line and capped, the result round-trips, junk lines are ignored',
   warns_p4[0] == 'Redis unavailable: verdicts not stored' and len(warns_p4[1]) == 300 and res_p4 == {'ml_trained': False, 'ml_samples': 12, 'clf_metrics': {'precision': 0.9}})
ok('jobreport: an unserialisable result is dropped, not a crash; no markers = nothing', jr_p4.parse('plain') == ([], None))

now_p4 = 1_800_000_000.0
rows_p4 = [
    {'ts': now_p4 - 100, 'act': 'allow', 'ip': '1.1.1.1', 'ua': 'Mozilla', 'p': '/a', 'sh': 0, 'rs': []},
    {'ts': now_p4 - 90, 'act': '403', 'ip': '2.2.2.2', 'dev': 'd1', 'ua': 'curl/8', 'p': '/shop', 'sh': 0, 'rs': ['UA_SCRIPT', 'RULE:r1'], 'cc': 'IR'},
    {'ts': now_p4 - 80, 'act': '403', 'ip': '2.2.2.2', 'dev': 'd1', 'ua': 'curl/8', 'p': '/shop', 'sh': 0, 'rs': ['UA_SCRIPT', 'SH_RULE:r2'], 'cc': 'IR'},
    {'ts': now_p4 - 70, 'act': '429', 'ip': '3.3.3.3', 'ua': 'x', 'p': '/api', 'sh': 0, 'rs': [], 'cc': 'US'},
    {'ts': now_p4 - 60, 'act': 'challenge', 'ip': '4.4.4.4', 'sh': 0, 'rs': []},
    {'ts': now_p4 - 50, 'act': 'challenge', 'ip': '4.4.4.4', 'sh': 1, 'rs': []},
    {'ts': now_p4 - 40, 'act': 'token_issued', 'ip': '4.4.4.4', 'sh': 0, 'rs': []},
    {'ts': now_p4 - 30, 'act': '404_hp', 'hp': 1, 'ip': '5.5.5.5', 'sh': 0, 'rs': []},
    {'ts': now_p4 - 20, 'act': 'allow', 'rd': 1, 'ip': '6.6.6.6', 'sh': 0, 'rs': []},
]
kc_p4 = snap_p4.kpi_counts(rows_p4)
ok('kpi: requests, allowed (shadow rows count as allowed), blocked, limited, challenged (shadow excluded)',
   kc_p4['requests'] == 9 and kc_p4['blocked'] == 2 and kc_p4['limited'] == 1 and kc_p4['challenged'] == 1 and kc_p4['allowed'] == 3)
ok('kpi: rule hits count rows (RULE: and SH_RULE:), honeypot, degraded', kc_p4['rule_hits'] == 2 and kc_p4['honeypot'] == 1 and kc_p4['degraded'] == 1)
ok('kpi: challenge success rate = tokens issued / challenges served, None when none was served',
   kc_p4['token_issued'] == 1 and kc_p4['challenge_success'] == 100.0 and snap_p4.kpi_counts([])['challenge_success'] is None and snap_p4.kpi_counts([])['requests'] == 0)
tl_p4 = snap_p4.top_lists(rows_p4)
ok('top lists: rules (enforced and monitor ids), reasons without the rule ids', tl_p4['rules'] == [['r1', 1], ['r2', 1]] and tl_p4['reasons'] == [['UA_SCRIPT', 2]])
ok('top lists: ips, devices, UAs and paths of the clients being acted on (403 / 429 / challenge, not shadow), most first',
   tl_p4['ips'][0] == ['2.2.2.2', 2] and tl_p4['devices'] == [['d1', 2]] and tl_p4['uas'][0] == ['curl/8', 2] and tl_p4['paths'][0] == ['/shop', 2] and ['1.1.1.1', 1] not in tl_p4['ips'])
ok('top lists: countries over all rows that carry one; empty when none does', tl_p4['countries'] == [['IR', 2], ['US', 1]] and snap_p4.top_lists([{'act': 'allow'}])['countries'] == [])
ok('top lists are bounded (8 entries) and deterministic', len(snap_p4.top_lists([{'act': '403', 'ip': '10.0.0.%d' % i} for i in range(30)])['ips']) == 8
   and snap_p4.top_lists([{'act': '403', 'ip': 'b'}, {'act': '403', 'ip': 'a'}])['ips'] == [['a', 1], ['b', 1]])
tz_p4 = snap_p4.local_tz()
ok('the analyzer reports its time zone offset (daily logs, logrotate and "today" follow it)', isinstance(tz_p4['offset'], int) and abs(tz_p4['offset']) <= 14 * 3600 and 'name' in tz_p4)
ok('the worker records exit, warnings and the result of a job it ran', (lambda w: ('warnings' in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'analyzer', 'worker.py')).read() and 'jobreport.parse' in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'analyzer', 'worker.py')).read()))(0))

print('PASS %d  FAIL %d  SKIP %d' % (PASS, FAIL, SKIP))
sys.exit(0 if FAIL == 0 else 1)
