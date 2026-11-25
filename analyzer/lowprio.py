"""Idle CPU priority for the analyzer's background jobs.

scripts/analyzer-cron.sh already starts every job under `nice -n 19` and `ionice -c3` when those tools exist. A job started by hand,
by the panel's worker or by a cron line that does not use the wrapper has neither, so each entry point also calls apply(): the
CPU part (os.nice) is available from Python everywhere; the I/O class is not, and stays the wrapper's business.

GV_LOWPRIO=0 turns it off (a benchmark, or an operator who wants a job to finish fast).
"""

import os


def apply():
    """Lower this process's CPU priority to nice 19. Returns True when it is (now) at 19; never raises."""
    if os.environ.get('GV_LOWPRIO', '1') == '0':
        return False
    try:
        current = os.nice(0)
        if current < 19:
            os.nice(19 - current)
        return True
    except (AttributeError, OSError):
        return False
