"""File modes for what the analyzer writes.

Cron often runs with umask 002, which made every file a job created group-writable (model.joblib, the job status and state
files, the markers, the lock holder). A group-writable model file is a pickle somebody else on the host can replace. The wrappers
now set `umask 022`; the writers here do not depend on it: files are CREATED with an explicit mode, and an existing file that an
earlier version left group- or world-writable is corrected the next time the job runs.

    FILE_MODE    0644  data, status, markers, models (readable by the panel's web user, writable by the job's user only)
    SECRET_MODE  0600  anything that could carry a secret (none of the analyzer's own files does today; here for the next one)

Nothing here touches logs/: the guard and the wrappers give those their own modes.
"""

import os
import shutil
import stat

FILE_MODE = 0o644
SECRET_MODE = 0o600
WRITABLE_BY_OTHERS = 0o022          # group-write and other-write


def _fchmod(fd, mode):
    try:
        os.fchmod(fd, mode)
    except (AttributeError, OSError):
        pass


def open_text(path, mode=FILE_MODE):
    """open(path, 'w', encoding='utf-8') (never the locale's) that creates the file with `mode` whatever the umask says (and fixes the mode of one that exists)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    _fchmod(fd, mode)
    return os.fdopen(fd, 'w', encoding='utf-8')


def open_binary(path, mode=FILE_MODE):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    _fchmod(fd, mode)
    return os.fdopen(fd, 'wb')


def open_append(path, mode=FILE_MODE):
    """open(path, 'a') with an explicit creation mode (lock files)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, mode)
    _fchmod(fd, mode)
    return os.fdopen(fd, 'a', encoding='utf-8')


def set_mode(path, mode=FILE_MODE):
    """chmod, quietly (a file that belongs to another user cannot be changed, and that is not this job's problem)."""
    try:
        os.chmod(path, mode)
        return True
    except OSError:
        return False


def tighten(path):
    """Remove group- and other-write from an existing regular file this process owns. Returns True when something changed."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or not (st.st_mode & WRITABLE_BY_OTHERS):
        return False
    return set_mode(path, stat.S_IMODE(st.st_mode) & ~WRITABLE_BY_OTHERS)


def tighten_dir(directory, include_hidden=True):
    """tighten() for every regular file directly in `directory` (not subdirectories, not links). Returns the names changed.

    Run at the start of a job on the directory its files live in: a model, a status file or a marker that an earlier run created
    group-writable is corrected the next time the job that owns it runs.
    """
    changed = []
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return changed
    for name in names:
        if not include_hidden and name.startswith('.'):
            continue
        if tighten(os.path.join(directory, name)):
            changed.append(name)
    return changed


def remove_loose_pycache(code_dir):
    """Delete a __pycache__ in the analyzer's code directory that this user owns and that group or others can write.

    An earlier run under cron's umask 002 created it 0775, and the permission check reports it. The jobs no longer write bytecode
    (PYTHONDONTWRITEBYTECODE=1 in the wrappers, sys.dont_write_bytecode in the entry points), so the directory is only a cache: it is
    removed and Python never makes it again. Returns the paths removed.
    """
    removed = []
    for root in (code_dir, os.path.dirname(code_dir) + os.sep + 'scripts'):
        path = os.path.join(root, '__pycache__')
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and (st.st_mode & WRITABLE_BY_OTHERS):
            shutil.rmtree(path, ignore_errors=True)
            removed.append(path)
    return removed


def tidy_for(cfg):
    """The analyzer directory of this install (where the model, the snapshot, the markers and the status files live)."""
    try:
        remove_loose_pycache(os.path.dirname(os.path.abspath(__file__)))
    except Exception:
        pass
    try:
        return tighten_dir(os.path.dirname(os.path.abspath(cfg['model_path'])))
    except Exception:
        return []


def unsafe_to_load(path):
    """Why a model file must NOT be unpickled, or '' when it may be.

    joblib.load is pickle.load: whoever can write the file runs code as the analyzer. A model is only loaded when it is a regular
    file (not a link), owned by the user running this process, and not writable by group or others. A file an earlier version left
    group-writable is corrected first by tidy_for() / tighten() (when this user owns it); one that belongs to another user, for
    example the web server's, is refused and the job says so rather than trusting it.
    """
    try:
        st = os.lstat(path)
    except OSError as exc:
        return 'cannot stat %s: %s' % (path, exc)
    if not stat.S_ISREG(st.st_mode):
        return '%s is not a regular file' % path
    if st.st_uid != os.getuid():
        return '%s is owned by uid %d, not by the user running the analyzer (uid %d)' % (path, st.st_uid, os.getuid())
    if st.st_mode & WRITABLE_BY_OTHERS:
        return '%s is writable by group or others (mode %o)' % (path, stat.S_IMODE(st.st_mode))
    return ''
