# Changelog

Newest first. Each entry is one version, written as `## <version>` (the same string as the `VERSION` file).
The Update page of the panel shows the entries between the installed version and the one in the ZIP.
Older history and upgrade steps: [docs/10-UPGRADE-NOTES.md](docs/10-UPGRADE-NOTES.md).

## 2026.11.22

- New admin page **Update**: upload the GitHub ZIP of the repository, review what changes, apply it with your password,
  roll back with one click or from the shell. Protected install files (configuration, rules, lists, logs, models) are never touched.
- `VERSION` file and this changelog; the version is shown in the panel footer.
- New worker job `pip_sync` (installs `analyzer/requirements.txt` after an update that changed it).
- `panel/recover.php` and `updates/` (recovery and health-check scripts the updater writes).
