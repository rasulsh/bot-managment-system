# Changelog

Newest first. Each entry is one version, written as `## <version>` (the same string as the `VERSION` file).
The Update page of the panel shows the entries between the installed version and the one in the ZIP.
Older history and upgrade steps: [docs/10-UPGRADE-NOTES.md](docs/10-UPGRADE-NOTES.md).

## 2026.11.25

- **Hotfix: the update health check was blocked by `panel/.htaccess`.** `recover.php` was allowed by the `FilesMatch` block but not by the `RewriteRule` allow-list, so mod_rewrite answered the web server's 403, the update stayed "Waiting for the check" and the guard stayed off. Fixed; an install that is stuck can be repaired with one `sed` line (docs/10-UPGRADE-NOTES.md).
- The check no longer depends on one web path: **Run the check now** runs it inside the panel request; `php updates/verify.php <stamp>` from the shell. An update waiting more than 2 minutes raises a critical alert (the guard is OFF, with the command).
- `exposure-check.sh` requires `recover.php` to answer the application's own bare 404. New `scripts/update-web-e2e.sh` runs the full update flow on real Apache and OpenLiteSpeed in CI.

## 2026.11.24

- **Several panel users, three roles:** Administrator, Monitoring operator (every report except secrets and user management; changes nothing) and Demo (aggregate numbers only). New pages **Users** and **My account**; the updater is administrator only.
- One deny-by-default permission map checked on the server for every GET and POST (HTTP 403 and an audit line on denial). The Demo page is built from a separate, data-minimised view model.
- `panel/users.json` (migrated automatically from `panel/panel.config.php`, nobody changes a password). Disabling a user, a role change and a password reset end their sessions at once. Per-username login limit. `panel/setpass.php` recovers admin access.

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
