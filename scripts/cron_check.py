#!/usr/bin/env python3
"""Check the crontab of the current user against what Bot Guard needs.

Run through scripts/cron-check.sh (standard library only, no virtualenv needed).

  cron-check.sh            human report, exit 0 = every required entry is present and right
  cron-check.sh --json     the same as JSON (the panel reads this)
  cron-check.sh --file F   check the crontab text in file F instead of the live one (tests)
  cron-check.sh --root D   treat D as the install directory (tests)

Order of commands tried for the live crontab: /usr/bin/crontab.cagefs -l (CloudLinux /
CageFS), then crontab -l. "no crontab for <user>" is an empty crontab, not an error.

Both forms of an entry are accepted: through the shell ("bash /path/scripts/analyzer-cron.sh verify", the
recommended form, which does not depend on the execute bit) and direct ("/path/scripts/analyzer-cron.sh
verify"). A DIRECT entry whose script exists but is not executable is an ERROR: cron cannot run it and fails
silently. Fix: chmod 755 <script>, or use the bash form.

Parsing: blank lines and "#" comments are ignored, EXCEPT a commented-out cron entry for one of
our scripts, which counts as DISABLED. @hourly/@daily-style schedules are understood. An entry is
matched by script path + mode and its resolved path is compared with THIS install directory
(another directory = "wrong path"). Duplicates are reported. A schedule that runs less often than
the job needs is reported. A GV_PYTHON= line must name an existing executable.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time

# job -> (script, mode argument, expected interval in minutes, required, default schedule)
JOBS = [
    ('verify', 'analyzer-cron.sh', 'verify', 10, True, '*/10 * * * *'),
    ('worker', 'analyzer-cron.sh', 'worker', 1, True, '* * * * *'),
    ('snapshot', 'analyzer-cron.sh', 'snapshot', 15, True, '*/15 * * * *'),
    ('nightly', 'analyzer-cron.sh', 'nightly', 1440, True, '17 4 * * *'),
    ('logrotate', 'guard-logrotate.sh', '', 1440, True, '10 3 * * *'),
    ('train', 'analyzer-cron.sh', 'train', 10080, False, '41 5 * * 0'),
    ('train-clf', 'analyzer-cron.sh', 'train-clf', 10080, False, '11 6 * * 0'),
    ('geo', 'analyzer-cron.sh', 'geo', 43200, False, '23 3 1 * *'),
    ('feeds', 'analyzer-cron.sh', 'feeds', 1440, False, '27 3 * * *'),
    ('report', 'analyzer-cron.sh', 'report', 10080, False, '30 7 * * 1'),
]
MACROS = {'@hourly': 60, '@daily': 1440, '@midnight': 1440, '@weekly': 10080, '@monthly': 43200,
          '@yearly': 525600, '@annually': 525600}
SLACK = 1.05          # a period up to 5 % over the expected interval still counts as on schedule

ENTRY_RE = re.compile(r'(?P<path>\S*(?:analyzer-cron|guard-logrotate)\.sh)(?:\s+(?P<mode>train-clf|train|verify|nightly|snapshot|worker|report|geo|feeds)\b)?')
# What cron's own PATH is when the crontab sets none (Vixie cron: /usr/bin:/bin). On cPanel / CloudLinux the php found there can be a
# CGI build (php -v says "(cgi-fcgi)"), which prints HTTP headers first; the command-line build is /usr/local/bin/php.
DEFAULT_CRON_PATH = '/usr/bin:/bin'
PATH_LINE = 'PATH=/usr/local/bin:/usr/bin:/bin'
PHP_V_RE = re.compile(r'^PHP (\d+)\.(\d+)\.(\d+)\S*\s+\(([A-Za-z0-9_-]+)\)')
SHELLS = ('bash', 'sh', 'dash', 'ash', 'zsh')
ENV_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$')


def _field_count(spec, lo, hi):
    """How many values a cron field selects. Pure; unparseable fields count as 1."""
    total = set()
    for part in spec.split(','):
        step = 1
        if '/' in part:
            part, step_s = part.split('/', 1)
            try:
                step = max(1, int(step_s))
            except ValueError:
                return 1
        if part in ('*', '?'):
            a, b = lo, hi
        elif '-' in part:
            try:
                a_s, b_s = part.split('-', 1)
                a, b = int(a_s), int(b_s)
            except ValueError:
                return 1
        else:
            try:
                a = b = int(part)
            except ValueError:
                return 1
        total.update(range(a, b + 1, step))
    return max(1, len(total))


def period_minutes(schedule):
    """The average gap between runs of a cron schedule, in minutes (None = never, e.g. @reboot). Pure."""
    schedule = schedule.strip()
    if schedule.startswith('@'):
        if schedule in MACROS:
            return MACROS[schedule]
        return None
    f = schedule.split()
    if len(f) != 5:
        return None
    mins = _field_count(f[0], 0, 59)
    hours = _field_count(f[1], 0, 23)
    per_day = float(mins * hours)
    dom_all = f[2] in ('*', '?')
    mon_all = f[3] in ('*', '?')
    dow_all = f[4] in ('*', '?')
    days_per_week = 7.0
    if not dow_all:
        days_per_week = float(min(7, _field_count(f[4], 0, 7)))
    elif not dom_all:
        days_per_week = _field_count(f[2], 1, 31) * 7.0 / 31.0
    if not mon_all:
        days_per_week *= _field_count(f[3], 1, 12) / 12.0
    runs_per_week = per_day * days_per_week
    return 10080.0 / runs_per_week if runs_per_week > 0 else None


def parse_crontab(text):
    """(env dict, entries list). An entry: {'schedule','command','path','mode','script','disabled','line'}. Pure."""
    env = {}
    entries = []
    for raw in text.replace('\r\n', '\n').replace('\r', '\n').split('\n'):
        line = raw.strip()
        if not line:
            continue
        disabled = False
        if line.startswith('#'):
            line = line.lstrip('#').strip()
            disabled = True
        else:
            m = ENV_RE.match(line)
            if m:
                env[m.group(1)] = m.group(2).strip().strip('"\'')
                continue
        if line.startswith('@'):
            parts = line.split(None, 1)
            schedule, command = parts[0], (parts[1] if len(parts) > 1 else '')
        else:
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            schedule, command = ' '.join(parts[:5]), parts[5]
            if not re.match(r'^[\d*/,\-?]+$', ''.join(parts[:5]).replace(' ', '')):
                continue                       # a prose comment, not a schedule
        m = ENTRY_RE.search(command)
        if not m:
            continue
        script = os.path.basename(m.group('path'))
        mode = m.group('mode') or ''
        if script == 'analyzer-cron.sh' and not mode:
            continue
        before = command[:m.start()].split()
        via_shell = any(os.path.basename(t.strip('"\'')) in SHELLS for t in before)
        entries.append({'schedule': schedule, 'command': command.strip(), 'path': m.group('path').strip('"\''),
                        'mode': mode, 'script': script, 'disabled': disabled, 'line': raw.strip(), 'via_shell': via_shell})
    return env, entries


def _same_install(path, root):
    """Whether a script path from the crontab is THIS install's script. Resolves symlinks and .. ."""
    if not path.startswith('/'):
        return False
    try:
        return os.path.realpath(path) == os.path.realpath(os.path.join(root, 'scripts', os.path.basename(path)))
    except Exception:
        return False


def geo_in_use(root):
    d = os.path.join(root, 'geo')
    try:
        return any(n.endswith(('.mmdb', '.dat', '.bin')) for n in os.listdir(d))
    except OSError:
        return False


def feeds_scheduled(root):
    """Whether an enabled IP feed has a schedule (daily / weekly): only then is the `feeds` job recommended."""
    d = os.environ.get('GV_LISTS_DIR') or os.path.join(root, 'lists')
    try:
        with open(os.path.join(d, 'feeds.json')) as fh:
            data = json.load(fh)
        return any(isinstance(f, dict) and f.get('enabled') and f.get('schedule') in ('daily', 'weekly') for f in data.get('feeds', []))
    except (OSError, ValueError, AttributeError):
        return False


def check_php(env, default_path=None):
    """Which php would cron run, and is it the command-line build 8.0 or newer? Resolved with the crontab's OWN PATH (its PATH=
    line, else cron's default) or its GV_PHP= line. Never raises."""
    path = env.get('PATH') or default_path or DEFAULT_CRON_PATH
    binary = env.get('GV_PHP') or shutil.which('php', path=path) or ''
    info = {'binary': binary, 'search_path': path, 'path_set': 'PATH' in env, 'sapi': '', 'version': '', 'ok': False,
            'message': '', 'suggest': PATH_LINE}
    if not binary or not os.path.isfile(binary):
        info['message'] = 'no php was found on cron\'s PATH (%s): the jobs cannot read the guard\'s settings. Add the line %s' % (path, PATH_LINE)
        return info
    try:
        p = subprocess.run([binary, '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, universal_newlines=True,
                           env={'PATH': path})
        first = (p.stdout or '').strip().split('\n')[0]
    except (OSError, subprocess.SubprocessError):
        info['message'] = 'could not run %s -v' % binary
        return info
    m = PHP_V_RE.match(first)
    if not m:
        info['message'] = '%s -v did not say which PHP it is (%s)' % (binary, first[:80])
        return info
    info['version'] = '%s.%s.%s' % m.groups()[:3]
    info['sapi'] = m.group(4)
    if info['sapi'] != 'cli':
        info['message'] = ('cron would run %s, which is PHP %s (%s), not the command line build: it prints HTTP headers first, so the jobs cannot read the '
                           'guard\'s settings (Redis "not confirmed"). Add the line %s above the entries, or set GV_PHP=/usr/local/bin/php'
                           % (binary, info['version'], info['sapi'], PATH_LINE))
    elif (int(m.group(1)), int(m.group(2))) < (8, 0):
        info['message'] = 'cron would run %s, PHP %s: Bot Guard needs PHP 8.0 or newer. Point GV_PHP= (or a PATH= line) at a newer php, e.g. %s' % (binary, info['version'], PATH_LINE)
    else:
        info['ok'] = True
    return info


def evaluate(text, root, source='file', now=None, geo_used=None, default_path=None, feeds_used=None):
    """Compare a crontab with the install. Returns the report dict. Pure apart from path checks."""
    now = int(time.time() if now is None else now)
    env, entries = parse_crontab(text)
    geo_used = geo_in_use(root) if geo_used is None else geo_used
    feeds_used = feeds_scheduled(root) if feeds_used is None else feeds_used
    jobs = []
    problems = 0
    warnings = 0
    for name, script, mode, expected, required, default in JOBS:
        if name == 'geo' and not geo_used:
            continue
        if name == 'feeds' and not feeds_used:
            continue
        mine = [e for e in entries if e['script'] == script and e['mode'] == mode]
        live = [e for e in mine if not e['disabled']]
        off = [e for e in mine if e['disabled']]
        state, message, schedule, period, line = 'ok', '', '', None, ''
        if live:
            good = [e for e in live if _same_install(e['path'], root)]
            if not good:
                state = 'wrong_path'
                message = 'the entry points at %s, not at this install (%s)' % (live[0]['path'], os.path.join(root, 'scripts', script))
                schedule, line = live[0]['schedule'], live[0]['line']
            else:
                best = good[0]
                schedule, line = best['schedule'], best['line']
                period = period_minutes(schedule)
                if len(good) > 1:
                    state = 'duplicate'
                    message = '%d entries for the same job (the lock makes this harmless, but remove the extra ones)' % len(good)
                if period is None:
                    state = 'wrong_schedule'
                    message = 'the schedule %s never runs the job' % schedule
                elif period > expected * SLACK:
                    state = 'wrong_schedule'
                    message = 'runs about every %s min, the job needs every %s min or more often' % (_fmt(period), _fmt(expected))
                # A direct entry needs the execute bit; "bash <script>" does not. Only a script that exists is judged.
                direct = [e for e in good if not e['via_shell']]
                if direct and os.path.isfile(direct[0]['path']) and not os.access(direct[0]['path'], os.X_OK):
                    state = 'not_executable'
                    message = ('not executable — cron will fail silently. Fix: chmod 755 %s   (or use the bash form: bash %s)'
                               % (direct[0]['path'], direct[0]['path']))
        elif off:
            state = 'disabled'
            message = 'the entry is commented out'
            schedule, line = off[0]['schedule'], off[0]['line']
        else:
            state = 'missing'
            message = 'there is no entry for it'
        severity = 'ok'
        if state == 'not_executable':
            severity = 'critical'
        elif state == 'missing':
            severity = 'critical' if required else 'warning'
        elif state in ('disabled', 'wrong_path', 'wrong_schedule'):
            severity = 'warning'
        elif state == 'duplicate':
            severity = 'warning'
        if not required and state == 'missing':
            severity = 'warning' if name == 'feeds' else 'info'     # feeds is only checked when a scheduled feed exists: then a missing entry is worth a warning
        # not_executable is an error for every job, required or not: an enabled entry that cannot start is never what you want.
        bad_for_exit = state == 'not_executable' or (required and state in ('missing', 'disabled', 'wrong_path', 'wrong_schedule'))
        if bad_for_exit:
            problems += 1
        elif severity in ('warning',):
            warnings += 1
        jobs.append({'job': name, 'required': required, 'state': state, 'severity': severity, 'message': message,
                     'schedule': schedule, 'expected_min': expected, 'period_min': period, 'line': line,
                     'install_line': install_line(root, name, script, mode, default) if state not in ('ok', 'duplicate') else ''})
    gp = env.get('GV_PYTHON')
    py = {'set': gp is not None, 'value': gp or '', 'ok': False}
    if gp:
        py['ok'] = os.path.isfile(gp) and os.access(gp, os.X_OK)
        if not py['ok']:
            problems += 1
    else:
        warnings += 1
    php = check_php(env, default_path)
    if not php['ok']:
        warnings += 1
    venv = os.path.join(root, '.venv', 'bin', 'python')
    py['suggest'] = 'GV_PYTHON=' + (venv if os.path.isfile(venv) else '/path/to/virtualenv/bin/python')
    return {'v': 1, 'time': now, 'source': source, 'root': root, 'jobs': jobs, 'gv_python': py, 'php': php,
            'problems': problems, 'warnings': warnings, 'ok': problems == 0, 'editor': 'crontab -e',
            'unreadable': False}


def _fmt(n):
    return str(int(n)) if float(n).is_integer() else '%.1f' % n


def install_line(root, name, script, mode, default):
    """The recommended crontab line: through bash, so it never depends on the execute bit."""
    path = os.path.join(root, 'scripts', script)
    tail = (' ' + mode) if mode else ''
    if name == 'report':
        return '%s bash %s%s | mail -s "Bot Guard weekly" you@example.com' % (default, path, tail)
    return '%s bash %s%s >/dev/null 2>&1' % (default, path, tail)


def read_live():
    """(text, source). Tries crontab.cagefs then crontab; None text = unreadable."""
    for cmd, label in ((['/usr/bin/crontab.cagefs', '-l'], 'crontab.cagefs'), (['crontab', '-l'], 'crontab')):
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, universal_newlines=True)
        except (OSError, subprocess.SubprocessError):
            continue
        if p.returncode == 0:
            return p.stdout, label
        if 'no crontab' in (p.stderr or '').lower():
            return '', label
    return None, ''


def render(report):
    lines = ['Bot Guard cron check (%s)' % (report['source'] or 'unreadable'), 'Install: %s' % report['root'], '']
    if report.get('unreadable'):
        lines += ['The crontab could not be read (no crontab.cagefs or crontab command, or it is not allowed here).',
                  'Run this script over SSH as the user that owns the cron jobs.']
        return '\n'.join(lines) + '\n'
    for j in report['jobs']:
        tag = {'ok': 'OK      ', 'critical': 'ERROR   ' if j['state'] == 'not_executable' else 'MISSING ', 'warning': 'WARNING ', 'info': 'optional'}[j['severity']]
        label = j['job'] + ('' if j['required'] else ' (recommended)')
        lines.append('%s %-24s %s' % (tag, label, j['state'] if j['state'] != 'ok' else j['schedule']))
        if j['message']:
            lines.append('         %s' % j['message'])
    gp = report['gv_python']
    lines.append('')
    if not gp['set']:
        lines.append('WARNING  GV_PYTHON is not set in the crontab: the jobs use the system python3 (add "%s" above the entries if the packages live in a virtualenv)' % gp['suggest'])
    elif gp['ok']:
        lines.append('OK       GV_PYTHON=%s' % gp['value'])
    else:
        lines.append('PROBLEM  GV_PYTHON=%s is not an executable file' % gp['value'])
    php = report.get('php') or {}
    if php:
        if php.get('ok'):
            lines.append('OK       php: %s (PHP %s, %s)' % (php['binary'], php['version'], php['sapi']))
        else:
            lines.append('WARNING  php: ' + php['message'])
    need = [j['install_line'] for j in report['jobs'] if j['install_line'] and (j['required'] or j['state'] != 'missing')]
    if need or (php and not php.get('ok')):
        # The template starts with a PATH line: cron's default PATH may find a php that is not the command line build.
        head = [] if (php and php.get('path_set') and php.get('ok')) else [PATH_LINE]
        lines += ['', 'Add or fix these lines (open the editor with: crontab -e):'] + ['  ' + n for n in head + need]
    lines += ['', 'RESULT: ' + ('every required entry is present and correct' if report['ok'] else '%d problem(s)' % report['problems'])
              + ('; %d warning(s)' % report['warnings'] if report['warnings'] else '')]
    return '\n'.join(lines) + '\n'


def main(argv):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    as_json = False
    default_path = None
    text = None
    source = ''
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--json':
            as_json = True
        elif a == '--file' and i + 1 < len(argv):
            with open(argv[i + 1], 'r') as handle:
                text = handle.read()
            source = 'file'
            i += 1
        elif a == '--root' and i + 1 < len(argv):
            root = argv[i + 1]
            i += 1
        elif a == '--default-path' and i + 1 < len(argv):
            default_path = argv[i + 1]          # tests: what cron's PATH is when the crontab sets none
            i += 1
        elif a in ('-h', '--help'):
            print(__doc__)
            return 0
        i += 1
    if text is None:
        text, source = read_live()
    if text is None:
        report = {'v': 1, 'time': int(time.time()), 'source': '', 'root': root, 'jobs': [], 'gv_python': {'set': False, 'value': '', 'ok': False, 'suggest': ''},
                  'problems': 0, 'warnings': 0, 'ok': False, 'editor': 'crontab -e', 'unreadable': True}
        print(json.dumps(report, sort_keys=True) if as_json else render(report), end='' if not as_json else '\n')
        return 2
    report = evaluate(text, root, source, default_path=default_path)
    if as_json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(render(report), end='')
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
