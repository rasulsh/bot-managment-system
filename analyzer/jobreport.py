"""Machine-readable job reports for the cron wrapper and the panel.

A job that "succeeds" while doing nothing (no input logs, Redis unreachable, no
model, nothing trained) must not look healthy. Such a job calls warn(); a job with a
result worth keeping (a training run: candidate written or not, sample counts,
metrics) calls result(). Both write ONE line to stderr:

    GV_JOB_WARN: <reason>
    GV_JOB_RESULT: {"key": value, ...}

scripts/analyzer-cron.sh captures stderr, turns the warnings into the job's
"warning" status and stores the result in .jobstatus-<mode>.json; the panel worker
copies the same fields into the job status of a job started from the panel. The lines
stay readable in plain cron mail, so nothing depends on the wrapper to be useful.
"""

import json
import sys

WARN_PREFIX = 'GV_JOB_WARN: '
RESULT_PREFIX = 'GV_JOB_RESULT: '


def _oneline(text):
    return ' '.join(str(text).split())[:300]


def warn(reason):
    """Mark this run as 'ok, but did nothing useful' with the reason."""
    print(WARN_PREFIX + _oneline(reason), file=sys.stderr)


def result(payload):
    """Attach a small dict of facts about this run (JSON-serialisable)."""
    try:
        text = json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str)
    except Exception:
        return
    print(RESULT_PREFIX + text[:2000], file=sys.stderr)


def parse(text):
    """(warnings list, result dict or None) from captured output. Pure."""
    warnings = []
    found = None
    for line in str(text).splitlines():
        if line.startswith(WARN_PREFIX):
            warnings.append(line[len(WARN_PREFIX):].strip())
        elif line.startswith(RESULT_PREFIX):
            try:
                value = json.loads(line[len(RESULT_PREFIX):])
                if isinstance(value, dict):
                    found = value
            except ValueError:
                pass
    return warnings, found
