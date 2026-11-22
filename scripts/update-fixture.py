#!/usr/bin/env python3
"""Build the two ZIPs the updater end-to-end tests upload (scripts/update-e2e.sh, scripts/update-web-e2e.sh).

  python3 scripts/update-fixture.py <install-dir> <out-dir> <good-version> <broken-version>

Writes <out-dir>/good.zip (the install's own files with VERSION and CHANGELOG.md bumped, docs/E2E-NEW.md added, one doc
changed) and <out-dir>/broken.zip (same tree, but guard/log.php redeclares a function: it parses, so the updater accepts it,
and then fails the health check with a fatal error). Like a GitHub download: one wrapper folder, only code files, no
modes (Python's zipfile gives 0600), nothing install-local. Standard library only.
"""
import os
import sys
import zipfile

EXTS = ('.php', '.py', '.sh', '.md', '.txt', '.json', '.css', '.js', '.woff2', '.ttf', '.png', '.tpl')
NAMES = ('.htaccess', '.gitkeep', '.gitignore', 'VERSION', 'LICENSE')
TOP = ('guard', 'panel', 'analyzer', 'scripts', 'docs', 'geo', 'lists', 'logs', 'updates')
LOCAL = ('panel/panel.config.php', 'panel/users.json', 'panel/audit.jsonl', 'guard/config.local.json', 'guard/rules.json', 'analyzer/snapshot.json', 'guard.off')
SKIP_DIRS = ('.git', '.github', '__pycache__', '.ratelimit', '.venv', 'node_modules')
DATA_DIRS = ('updates/', 'logs/', 'lists/', 'geo/')


def files(inst):
    for base, dirs, names in os.walk(inst):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for n in names:
            p = os.path.join(base, n)
            rel = os.path.relpath(p, inst).replace(os.sep, '/')
            if rel in LOCAL or rel.startswith('panel/users.json'):
                continue
            if rel.startswith(DATA_DIRS) and n not in ('.htaccess', '.gitkeep'):
                continue
            if n.startswith('.') and n not in NAMES:
                continue
            if not (n in NAMES or n.endswith(EXTS)):
                continue
            if '/' in rel and rel.split('/')[0] not in TOP:
                continue
            yield rel, p


def make(inst, out, name, version, extra):
    with zipfile.ZipFile(os.path.join(out, name), 'w', zipfile.ZIP_DEFLATED) as z:
        for rel, p in files(inst):
            with open(p, 'rb') as fh:
                data = fh.read()
            if rel == 'VERSION':
                data = (version + '\n').encode()
            elif rel == 'CHANGELOG.md':
                data = ('# Changelog\n\n## %s\n\n- e2e release\n\n' % version).encode()
            elif rel in extra:
                data = data + extra[rel].encode()
            z.writestr('bot-managment-system-master/' + rel, data)
        z.writestr('bot-managment-system-master/docs/E2E-NEW.md', '# added by the e2e update\n')


def main(argv):
    if len(argv) != 4:
        print(__doc__)
        return 2
    inst, out, good, broken = argv
    make(inst, out, 'good.zip', good, {'docs/09-ADMIN-PANEL.md': '\n<!-- e2e -->\n'})
    make(inst, out, 'broken.zip', broken, {'guard/log.php': '\nfunction gv_log_policy() {}\n'})
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
