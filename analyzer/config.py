"""Analyzer settings.

Defaults live here. An operator can override any of them by pointing the
GV_ANALYZER_CONFIG environment variable (or the --config flag of the entry
points) at a .json file, or at a .py file exposing a CONFIG dict.

Two keys - known_bots and bot_suffixes - are duplicated in guard/config.php.
They describe the same contract seen from both sides and MUST be kept in sync;
the analyzer decides which IPs are impersonators, the guard honours the verdict.
"""

import copy
import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULTS = {
    # Where the Phase 1 guard writes its JSONL.
    'log_dir': os.path.join(REPO_ROOT, 'logs'),
    'redis': {'host': '127.0.0.1', 'port': 6379, 'db': 0, 'socket_timeout': 0.2},
    # How far back to read logs, and the idle gap that starts a new session.
    'window_days': 7,
    'session_gap_s': 1800,
    # Verdict lifetimes. Every write carries one so a stopped analyzer cannot
    # pin a stale verdict forever.
    'rep_ttl': 2592000,
    'ml_ttl': 86400,
    'botv_ttl': 86400,
    # Reputation is clamped so no single device can dominate the score.
    'rep_clamp': [-50, 80],
    # Below this many clean sessions the "normal" manifold is meaningless.
    'ml_min_train': 200,
    'contamination': 0.05,
    'model_path': os.path.join(REPO_ROOT, 'analyzer', 'model.joblib'),
    # Must match guard/config.php.
    'known_bots': ['googlebot', 'bingbot'],
    'bot_suffixes': {
        'googlebot': ['.googlebot.com', '.google.com'],
        'bingbot': ['.search.msn.com'],
    },
    # Operator-supplied regexes identifying listing and detail pages. Empty by
    # default: nothing here knows anything about any particular platform.
    'path_listing': [],
    'path_detail': [],

    # --- Phase 3 -----------------------------------------------------------
    # The supervised classifier. Its thresholds are chosen for precision, not
    # accuracy: the cost of a false positive is a paying customer who cannot
    # reach the site, and the classes are heavily imbalanced.
    'clf_path': os.path.join(REPO_ROOT, 'analyzer', 'clf.joblib'),
    'clf_min_positive': 50,
    'clf_test_size': 0.25,
    'clf_target_precision': 0.98,
    # Optional operator label file: one `identity,0|1` per line.
    'ground_truth_path': os.path.join(REPO_ROOT, 'analyzer', 'ground-truth.txt'),
    # How the bridge reaches the guard's effective config. guard_config_path
    # is passed to config-dump.php --config when set.
    'php_bin': 'php',
    'guard_config_path': '',
    # Report defaults.
    'report_days': 7,
    'report_top_n': 20,
    # Below this challenge->token_issued rate the report says so in words:
    # real users are burning on the challenge.
    'challenge_success_target': 0.95,
}

_NESTED = ('redis', 'bot_suffixes')


def _read_overrides(path):
    """Load an override mapping from a .json or .py file."""
    if path.endswith('.json'):
        with open(path, 'r') as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError('config file must contain a JSON object: ' + path)
        return data
    namespace = {}
    with open(path, 'r') as fh:
        source = fh.read()
    exec(compile(source, path, 'exec'), namespace)
    if isinstance(namespace.get('CONFIG'), dict):
        return namespace['CONFIG']
    return dict((k, v) for k, v in namespace.items() if k in DEFAULTS)


def _merge(base, overrides):
    for key, value in overrides.items():
        if key in _NESTED and isinstance(value, dict) and isinstance(base.get(key), dict):
            merged = dict(base[key])
            merged.update(value)
            base[key] = merged
        else:
            base[key] = value
    return base


def validate(cfg):
    """Raise ValueError on a configuration that cannot produce useful output."""
    if not isinstance(cfg.get('log_dir'), str) or not cfg['log_dir']:
        raise ValueError('log_dir must be a non-empty string')
    if int(cfg.get('window_days', 0)) < 1:
        raise ValueError('window_days must be >= 1')
    if int(cfg.get('session_gap_s', 0)) < 1:
        raise ValueError('session_gap_s must be >= 1')
    clamp = cfg.get('rep_clamp')
    if not isinstance(clamp, (list, tuple)) or len(clamp) != 2 or clamp[0] > clamp[1]:
        raise ValueError('rep_clamp must be [low, high] with low <= high')
    if not 0.0 < float(cfg.get('contamination', 0)) < 0.5:
        raise ValueError('contamination must be between 0 and 0.5')
    if not isinstance(cfg.get('bot_suffixes'), dict):
        raise ValueError('bot_suffixes must be a mapping of bot name to suffix list')
    for key in ('path_listing', 'path_detail'):
        if not isinstance(cfg.get(key), (list, tuple)):
            raise ValueError(key + ' must be a list of regex strings')
    if not 0.0 < float(cfg.get('clf_target_precision', 0)) <= 1.0:
        raise ValueError('clf_target_precision must be between 0 and 1')
    if not 0.0 < float(cfg.get('clf_test_size', 0)) < 1.0:
        raise ValueError('clf_test_size must be between 0 and 1')
    if int(cfg.get('clf_min_positive', 0)) < 1:
        raise ValueError('clf_min_positive must be >= 1')
    return cfg


def load(path=None):
    """Return the effective configuration dict."""
    cfg = copy.deepcopy(DEFAULTS)
    if path is None:
        path = os.environ.get('GV_ANALYZER_CONFIG', '')
    if path:
        if not os.path.isfile(path):
            raise ValueError('config file not found: ' + path)
        cfg = _merge(cfg, _read_overrides(path))
    return validate(cfg)
