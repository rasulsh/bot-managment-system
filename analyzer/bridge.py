"""Load the guard's effective configuration by shelling out to PHP.

Phase 2 duplicated known_bots and bot_suffixes between the two configs and
documented that they must be kept in sync. Phase 3 stops adding to that list:
thresholds - hard_block_score, the signal toggles, the weights - are read from
the guard itself through scripts/config-dump.php, so replay tunes against what
is actually in force rather than a copy that quietly drifted.

When PHP is missing or the dump fails this warns once and falls back to the
analyzer's own defaults. It never raises: an unavailable bridge must degrade to
"tune against the documented defaults", not take down a nightly job.
"""

from __future__ import print_function

import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP_SCRIPT = os.path.join(REPO_ROOT, 'scripts', 'config-dump.php')

# Only the keys the decision mirror actually reads. Anything else in the dump
# is informational; taking a narrow slice keeps the coupling small.
GUARD_KEYS = (
    'hard_block_score',
    'signals',
    'ml_weight',
    'clf_weight',
    'holdout_pct',
    'enforce',
    'known_bots',
    'bot_suffixes',
)

# Used when the bridge cannot reach PHP. Mirrors guard/config.php's shipped
# defaults; the guard's own gv_cfg_defaults remains the source of truth.
FALLBACK = {
    'hard_block_score': 60,
    'signals': {'reputation': False, 'ml': False, 'clf': False},
    'ml_weight': 0.4,
    'clf_weight': 0.5,
    'holdout_pct': 0,
    'enforce': {'block': False, 'challenge': False, 'ratelimit': False},
}

_warned = False
last_error = ''          # why the most recent dump_config() failed ('' = it did not)


def _warn_once(message):
    global _warned
    if not _warned:
        print('WARN: ' + str(message), file=sys.stderr)
        print('WARN: falling back to the analyzer defaults; replay results are '
              'only as accurate as those defaults.', file=sys.stderr)
        _warned = True


def dump_config(php='php', script=None, config_path=None, timeout=15, extra=None, quiet=False):
    """Run config-dump.php and return the parsed dict, or None on any failure.

    extra: additional argv for the script (the Redis credentials mode). quiet:
    stay silent on failure; used where a missing bridge is an ordinary state.
    """
    script = script or DUMP_SCRIPT
    def warn(message):
        global last_error
        last_error = str(message)
        if not quiet:
            _warn_once(message)
    if not os.path.isfile(script):
        warn('config dump script not found: %s' % script)
        return None
    cmd = [php, script] + list(extra or [])
    if config_path:
        cmd += ['--config', config_path]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # communicate(timeout=) does not kill the child; reap it or a hung PHP
        # binary leaks a process on the cron host for every timeout.
        proc.kill()
        try:
            proc.communicate(timeout=5)
        except Exception:
            pass
        warn('config dump timed out after %ss (%s)' % (timeout, ' '.join(cmd)))
        return None
    except Exception as exc:
        warn('could not run the config dump (%s): %s' % (' '.join(cmd), exc))
        return None
    if proc.returncode != 0:
        detail = (err or b'').decode('utf-8', 'replace').strip()
        warn('config dump exited %d: %s' % (proc.returncode, detail))
        return None
    try:
        data = json.loads((out or b'').decode('utf-8', 'replace'))
    except Exception as exc:
        warn('config dump did not produce valid JSON: %s' % exc)
        return None
    if not isinstance(data, dict):
        warn('config dump did not produce a JSON object')
        return None
    # Defence in depth: the dump strips these, and we refuse to carry them even
    # if a future edit forgets to.
    data.pop('secret', None)
    data.pop('holdout_salt', None)
    return data


_REDIS_CACHE = {}


def redis_block(php='php', config_path=None):
    """The guard's redis block INCLUDING credentials, or {} when unavailable.

    This is the one place the password crosses from PHP to Python: it is read
    from the dump process's stdout pipe, held in memory and handed to
    redis-py. It is never logged, never printed and never put in a snapshot;
    the default config dump (guard_config, the CLI) strips it. Cached per
    process so the PHP bridge is spawned once, not once per config load.
    """
    return dict(redis_block_status(php, config_path)[0])


def redis_block_status(php='php', config_path=None):
    """(block, error): the guard's redis block and, when it could not be read, why.

    A failure must never look like "the guard has default settings": the caller
    (config.resolve_redis) reports it loudly and refuses to write.
    """
    key = (php, config_path or '')
    if key not in _REDIS_CACHE:
        global last_error
        last_error = ''
        data = dump_config(php=php, config_path=config_path,
                           extra=['--redis-credentials'], quiet=True)
        block = data.get('redis') if isinstance(data, dict) else None
        if isinstance(block, dict):
            _REDIS_CACHE[key] = (dict(block), '')
        else:
            _REDIS_CACHE[key] = ({}, last_error or 'the config dump produced no redis block')
    block, err = _REDIS_CACHE[key]
    return dict(block), err


def guard_config(cfg=None, php=None, config_path=None):
    """Return the guard thresholds, from the dump when possible.

    cfg is the analyzer config; its 'php_bin' and 'guard_config_path' settings
    are used when present. The result always carries every GUARD_KEYS entry the
    dump provided, over the fallback defaults.
    """
    cfg = cfg or {}
    php = php or cfg.get('php_bin') or 'php'
    config_path = config_path or cfg.get('guard_config_path') or None

    merged = dict(FALLBACK)
    merged['known_bots'] = list(cfg.get('known_bots') or [])
    merged['bot_suffixes'] = dict(cfg.get('bot_suffixes') or {})

    dumped = dump_config(php=php, config_path=config_path)
    if dumped is None:
        merged['source'] = 'defaults'
        return merged

    for key in GUARD_KEYS:
        if key in dumped:
            merged[key] = dumped[key]
    merged['source'] = 'guard'
    return merged


def decision_config(guard_cfg, overrides=None):
    """Build the small dict decision.effective_score/decide consume.

    overrides is a flat mapping using dotted keys, e.g.
    {'hard_block_score': 50, 'signals.clf': True}, which is exactly what
    replay's --set flag produces.
    """
    out = {
        'hard_block_score': int(guard_cfg.get('hard_block_score', 60)),
        'signals': dict(guard_cfg.get('signals') or {}),
        'ml_weight': float(guard_cfg.get('ml_weight', 0.4)),
        'clf_weight': float(guard_cfg.get('clf_weight', 0.5)),
    }
    for name in ('reputation', 'ml', 'clf'):
        out['signals'].setdefault(name, False)

    for key, value in (overrides or {}).items():
        if key.startswith('signals.'):
            out['signals'][key.split('.', 1)[1]] = bool(value)
        elif key == 'hard_block_score':
            out['hard_block_score'] = int(value)
        elif key in ('ml_weight', 'clf_weight'):
            out[key] = float(value)
    return out
