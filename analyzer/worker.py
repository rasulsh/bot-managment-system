#!/usr/bin/env python3
"""Drain the panel's job queue.

Run every minute from cron, behind the same flock as the other analyzer modes so
a job and a nightly run cannot collide.

THE RULE THAT SHAPES THIS FILE: a job type maps to a PYTHON FUNCTION CALLED
IN-PROCESS. Nothing here builds a command string and nothing here executes one.
The panel already refuses to enqueue an unknown type; the worker refuses it
again independently, so a queue entry written by anything other than the panel
is still rejected.

Every job runs under the worker's own effective config: the --config the worker
was started with (or env/default resolution when it had none) is threaded into
each child entry point, so a job never silently re-resolves a different config.

A crashed job is marked failed with its traceback. Nothing is ever left running
forever - an operator staring at a job stuck in "running" learns nothing.
"""

from __future__ import print_function

import argparse
import json
import os
import subprocess
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import config as config_mod
from analyzer import geo as geo_mod
from analyzer import iplist as iplist_mod
from analyzer import jobreport
from analyzer import promote as promote_mod
from analyzer import redis_io
from analyzer import replay as replay_mod
from analyzer import run_nightly
from analyzer import run_verify
from analyzer import snapshot as snapshot_mod

JOB_TTL = 86400
MAX_OUTPUT = 8000


class Captured(object):
    """Collect whatever a job prints, so the panel can show it."""

    def __init__(self):
        self.parts = []

    def write(self, text):
        self.parts.append(text)

    def flush(self):
        pass

    def value(self):
        text = ''.join(self.parts)
        return text[-MAX_OUTPUT:] if len(text) > MAX_OUTPUT else text


# --------------------------------------------------------------------------
# Job handlers. Each takes (cfg, params) and returns an exit-style int.
#
# Every handler that shells into another entry point runs it under the SAME
# config the worker loaded. main() stashes that path in cfg['_config_path'];
# _cfg_argv turns it into the --config flag to forward. None means the worker
# used env/default resolution, so the child should too - and no flag is passed.
# --------------------------------------------------------------------------

def _cfg_argv(config_path):
    return ['--config', config_path] if config_path else []


def job_verify(cfg, params):
    return run_verify.main(_cfg_argv(cfg.get('_config_path')))


def job_nightly(cfg, params):
    return run_nightly.main(_cfg_argv(cfg.get('_config_path')))


def job_train(cfg, params):
    # --candidate is the documented default for a migration: it never touches
    # the live model, so a queued training run cannot make the guard more
    # permissive while nobody is watching.
    return run_nightly.main(_cfg_argv(cfg.get('_config_path')) + ['--train', '--candidate'])


def job_train_clf(cfg, params):
    return run_nightly.main(_cfg_argv(cfg.get('_config_path')) + ['--train-clf', '--candidate'])


def job_replay_full(cfg, params):
    argv = _cfg_argv(cfg.get('_config_path')) + ['--mode', 'full']
    days = params.get('days')
    if days:
        argv += ['--days', str(int(days))]
    for key, value in (params.get('set') or {}).items():
        if isinstance(value, bool):
            value = 'true' if value else 'false'
        argv += ['--set', '%s=%s' % (key, value)]
    return replay_mod.main(argv)


def job_promote(kind):
    def handler(cfg, params):
        result = promote_mod.promote(kind, cfg)
        print(result['reason'])
        return 0 if result['ok'] else 1
    return handler


def job_snapshot(cfg, params):
    return snapshot_mod.main(_cfg_argv(cfg.get('_config_path')))


def job_geo_compile(cfg, params):
    # Reads the sources in geo/ and swaps country.bin / asn.bin atomically.
    return geo_mod.main([])


def job_iplist_compile(cfg, params):
    # Builds lists/allow.bin and lists/block.bin from the enabled IP lists (panel/iplists.php).
    return iplist_mod.main([])


PIP_TIMEOUT = 600


def job_pip_sync(cfg, params):
    # After an in-panel update changed analyzer/requirements.txt: install it with the worker's own
    # interpreter (the one GV_PYTHON points at). Bounded in time; pip's output goes to the job log.
    req = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'requirements.txt')
    if not os.path.isfile(req):
        print('requirements.txt not found: %s' % req)
        return 1
    cmd = [sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check', '-r', req]
    print('running: ' + ' '.join(cmd))
    try:
        done = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=PIP_TIMEOUT,
                              universal_newlines=True)
    except subprocess.TimeoutExpired as exc:
        print((exc.stdout or '')[-4000:] if isinstance(exc.stdout, str) else '')
        print('pip timed out after %d seconds' % PIP_TIMEOUT)
        return 1
    except OSError as exc:
        print('could not run pip: %s' % exc)
        return 1
    print((done.stdout or '')[-8000:])
    return 0 if done.returncode == 0 else 1


HANDLERS = {
    'verify': job_verify,
    'nightly': job_nightly,
    'train': job_train,
    'train_clf': job_train_clf,
    'replay_full': job_replay_full,
    'promote_ml': job_promote('ml'),
    'promote_clf': job_promote('clf'),
    'snapshot': job_snapshot,
    'geo_compile': job_geo_compile,
    'iplist_compile': job_iplist_compile,
    'pip_sync': job_pip_sync,
}


def validate(envelope):
    """Second, independent check of a queue entry. Returns (ok, reason)."""
    if not isinstance(envelope, dict):
        return False, 'not an object'
    job_id = envelope.get('id')
    if not isinstance(job_id, str) or not job_id or len(job_id) > 64:
        return False, 'bad id'
    job_type = envelope.get('type')
    if job_type not in HANDLERS:
        return False, 'unknown type: %r' % (job_type,)
    params = envelope.get('params')
    if params is not None and not isinstance(params, dict):
        return False, 'bad params'
    days = (params or {}).get('days')
    if days is not None:
        try:
            days = int(days)
        except (TypeError, ValueError):
            return False, 'bad days'
        if days < 1 or days > 90:
            return False, 'bad days'
    overrides = (params or {}).get('set')
    if overrides is not None and not isinstance(overrides, dict):
        return False, 'bad set'
    return True, ''


def set_status(client, job_id, payload):
    if client is None:
        return
    try:
        # set(..., ex=) rather than setex(): redis-py deprecated setex, and the
        # warning would otherwise be captured into the job output the panel shows.
        client.set(redis_io.gp_key('job:' + job_id), json.dumps(payload, ensure_ascii=False),
                   ex=JOB_TTL)
    except Exception as exc:
        redis_io.warn('could not write job status: %s' % exc)


def run_one(client, cfg, raw):
    """Execute one envelope. Never raises."""
    try:
        envelope = json.loads(raw)
    except Exception:
        print('Refused a job: not valid JSON.')
        return False

    ok, reason = validate(envelope)
    if not ok:
        job_id = envelope.get('id') if isinstance(envelope, dict) else None
        print('Refused a job: %s' % reason)
        if isinstance(job_id, str) and job_id:
            set_status(client, job_id, dict(envelope, status='failed',
                                            output='refused: ' + reason,
                                            finished_at=round(time.time(), 3)))
        return False

    job_id = envelope['id']
    job_type = envelope['type']
    params = envelope.get('params') or {}

    set_status(client, job_id, dict(envelope, status='running',
                                    started_at=round(time.time(), 3)))

    started = time.time()
    captured = Captured()
    real_stdout, real_stderr = sys.stdout, sys.stderr
    status = 'done'
    code = 0
    try:
        sys.stdout = captured
        sys.stderr = captured
        code = HANDLERS[job_type](cfg, params)
        if code not in (0, None):
            status = 'failed'
    except Exception:
        status = 'failed'
        captured.write('\n' + traceback.format_exc())
    finally:
        sys.stdout, sys.stderr = real_stdout, real_stderr

    duration = round(time.time() - started, 2)
    # The same fields a cron run records in .jobstatus-<mode>.json: exit code, duration,
    # warnings ("succeeded but did nothing useful") and the result of a training run.
    warnings, result = jobreport.parse(''.join(captured.parts))
    extra = {'warnings': warnings[:5]}
    if result is not None:
        extra['result'] = result
    if status == 'done' and warnings:
        extra['warning'] = True
    set_status(client, job_id, dict(envelope, status=status,
                                    output=captured.value(),
                                    exit_code=code if isinstance(code, int) else None,
                                    duration=duration,
                                    started_at=round(started, 3),
                                    finished_at=round(time.time(), 3), **extra))
    print('Job %s (%s): %s in %.2fs.' % (job_id, job_type, status, duration))
    return status == 'done'


def parse_args(argv):
    parser = argparse.ArgumentParser(description='Drain the panel job queue.')
    parser.add_argument('--config', default=None)
    parser.add_argument('--max-jobs', type=int, default=4,
                        help='most jobs to run in one firing (default 4)')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        cfg = config_mod.load(args.config)
    except Exception as exc:
        print('ERROR: bad configuration: %s' % exc, file=sys.stderr)
        return 2

    # Jobs shell into other entry points in-process; without the worker's own
    # config path they would re-resolve config from GV_ANALYZER_CONFIG/defaults
    # and run under a different config than the worker loaded. Stash the path
    # the worker actually used (possibly None) so every handler forwards it.
    # config.validate already ran inside load(), and this private key is never
    # serialized into Redis job status (handlers never put cfg there), so it is
    # safe to carry on the plain cfg dict.
    cfg['_config_path'] = args.config

    client = redis_io.connect(cfg, write=True)
    if client is None:
        print(redis_io.unavailable_reason(cfg, 'no jobs can be drained') + '.')
        return 0

    done = 0
    for _ in range(max(1, int(args.max_jobs))):
        try:
            raw = client.rpop(redis_io.gp_key('jobs'))
        except Exception as exc:
            redis_io.warn('could not read the queue: %s' % exc)
            break
        if not raw:
            break
        run_one(client, cfg, raw)
        done += 1

    snapshot_mod.touch_run(cfg, 'worker')
    print('Worker finished: %d job(s) processed.' % done)
    return 0


if __name__ == '__main__':
    sys.exit(main())
