# Changelog

Newest first. Each entry is one version, written as `## <version>` (the same string as the `VERSION` file).
The Update page of the panel shows the entries between the installed version and the one in the ZIP.
Older history and upgrade steps: [docs/10-UPGRADE-NOTES.md](docs/10-UPGRADE-NOTES.md).

## 2026.11.23

- **Updater sets file modes explicitly:** directories 0755, files 0644, every `scripts/*.sh` 0755, nothing group- or world-writable (GitHub ZIPs carry no reliable modes). Unchanged files are corrected too, so the first update repairs an install that was copied with 666 modes. The updater's own workspace is private (0600 / 0644).
- **The crontab goes through bash everywhere** (`bash /path/scripts/analyzer-cron.sh verify`): README, docs, the dashboard "Cron setup" card, `cron-check.sh` output. `cron-check.sh` accepts both forms and reports a direct entry whose script is not executable as an ERROR ("not executable — cron will fail silently", with the fix) and exits 1.
- **File permission health check** (dashboard alerts and a card on the Jobs page): group/world-writable files and directories, cron scripts without the execute bit, secret files readable by everybody, with the exact `chmod` / `find` commands. Cached for one hour, recomputed after an update.

## 2026.11.22

- New admin page **Update**: upload the GitHub ZIP of the repository, review what changes, apply it with your password,
  roll back with one click or from the shell. Protected install files (configuration, rules, lists, logs, models) are never touched.
- `VERSION` file and this changelog; the version is shown in the panel footer.
- New worker job `pip_sync` (installs `analyzer/requirements.txt` after an update that changed it).
- `panel/recover.php` and `updates/` (recovery and health-check scripts the updater writes).
