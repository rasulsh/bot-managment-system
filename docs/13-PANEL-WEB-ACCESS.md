# Making the admin panel reachable from the web

This guide puts the admin panel on a URL such as `https://example.com/gv-admin/`.
It assumes the supported layout: the repository **outside** the web root, and only
the `panel/` directory exposed through a **symbolic link** (symlink).

Every command below was run against a real Apache 2.4 server in CI
(`.github/ci/webserver-test.sh`), in this exact layout. OpenLiteSpeed 1.9 is
tested by the same script. LiteSpeed Enterprise (the usual cPanel web server)
reads Apache's configuration and `.htaccess` files the same way.

Before you start, the guard itself should already be installed (README, Quick Start)
and `php panel/setpass.php` should already have been run (it creates the login).

---

## 1. The directory structure

```
/home/USER/                       <- your hosting account (cPanel user)
├── bot-guard/                    <- this repository. NOT reachable from the web
│   ├── prepend.php
│   ├── guard/                    <- config.php, config.local.json (panel writes here)
│   ├── logs/                     <- guard writes here
│   ├── panel/                    <- the panel. The ONLY part that is exposed
│   │   ├── index.php             <- the single entry point
│   │   ├── assets/               <- CSS and fonts
│   │   ├── .htaccess             <- allows index.php and assets, denies the rest
│   │   └── panel.config.php      <- login (created by setpass.php, mode 0600)
│   └── ...
└── public_html/                  <- your site's document root (web root)
    ├── index.php                 <- your application (WordPress, OpenCart, ...)
    ├── .user.ini                 <- auto_prepend_file=/home/USER/bot-guard/prepend.php
    └── gv-admin -> /home/USER/bot-guard/panel     <- the symlink you create
```

How it fits together:

- The web server only serves files below `public_html`.
- `public_html/gv-admin` is not a real directory. It is a pointer to
  `bot-guard/panel`. When a browser asks for `/gv-admin/`, the web server follows
  the pointer and runs `bot-guard/panel/index.php`.
- Nothing else of `bot-guard/` (configuration, logs, secrets) has a URL.
- `panel/.htaccess` still applies after the symlink is followed. It allows only
  `index.php`, `*.css` and `*.woff2`, and answers 403 for every other file.

Replace `USER` with your account name and `gv-admin` with a name of your choice in
every command below. Pick a name that is not obvious (not `admin`, not `panel`)
and that does not exist in `public_html` yet.

---

## 2. Create the symlink

Where: an SSH session **as the account user** (on cPanel: **cPanel → Advanced →
Terminal**, or SSH with the account's own login). Do not use `root`. The cPanel
File Manager cannot create symlinks.

```bash
cd /home/USER/public_html
ls -la gv-admin 2>/dev/null && echo "STOP: gv-admin already exists, pick another name"
ln -s /home/USER/bot-guard/panel /home/USER/public_html/gv-admin
ls -l /home/USER/public_html/gv-admin
```

Expected output of the last command (owner is your account, not `root`):

```
lrwxrwxrwx 1 USER USER 27 ... gv-admin -> /home/USER/bot-guard/panel
```

Why the owner matters: cPanel servers run with `Options SymLinksIfOwnerMatch`.
The web server follows a symlink only when the symlink and its target belong to
the same user. A symlink created by `root` answers **403 Forbidden**.

If you had to create it as `root`, fix the owner of the link itself (`-h`):

```bash
chown -h USER:USER /home/USER/public_html/gv-admin
```

To remove the panel from the web later, delete only the link (no trailing slash,
so the real directory is not touched):

```bash
rm /home/USER/public_html/gv-admin
```

---

## 3. Permissions and ownership

On cPanel with CloudLinux, PHP runs **as your account user** (suEXEC, LSAPI,
PHP-FPM). The account user must own the whole repository.

Where: SSH as the account user.

```bash
cd /home/USER/bot-guard
find . -type d -exec chmod 0755 {} +      # directories: owner writes, server traverses
chmod 0644 panel/index.php panel/assets/* # files the web server serves (git already checks them out 0644)
chmod 0600 guard/config.php               # holds the secret and the Redis password
chmod 0600 panel/panel.config.php         # holds the login hash (setpass.php sets this)
chmod 0755 scripts/*.sh                   # cron runs these directly
ls -ld /home/USER                         # must allow traversal: drwx--x--x (0711) or 0750 with the web server's group
```

What PHP must be able to **write** (all owned by the account user, so 0755 is
enough):

| Path | Written by | Why |
|---|---|---|
| `logs/` | guard | daily request logs |
| `guard/` | panel | `config.local.json`, its `.lock` and temp file (settings saved in the panel) |
| `panel/` | panel | `audit.jsonl` (audit trail), `.ratelimit/` (login limit when Redis is down) |
| `bot-guard/` (top) | panel | `guard.off` (the kill switch on the dashboard) |

**PHP runs as a different user** (a VPS with plain Apache and `mod_php`, where PHP
runs as `www-data` or `apache`): give the repository to that user instead.

```bash
# find the PHP user: the owner of the files the guard just wrote
ls -l /home/USER/bot-guard/logs/
sudo chown -R www-data:www-data /home/USER/bot-guard      # use the user you saw
sudo chown -h www-data:www-data /home/USER/public_html/gv-admin
```

With `SymLinksIfOwnerMatch`, the symlink must have the same owner as
`bot-guard/panel`, so change both.

---

## 4. Web server configuration

### cPanel / shared hosting (Apache or LiteSpeed Enterprise)

Nothing to configure. The defaults already allow what the panel needs:

- `.htaccess` files are read (`AllowOverride All`).
- Symlinks are followed when the owner matches (`SymLinksIfOwnerMatch`).

Do **not** add panel rules to `public_html/.htaccess`. `panel/.htaccess` ships
with the repository and is complete on its own.

### Your own Apache server (VPS / root access)

The document root needs these two settings. Without `AllowOverride`, the panel's
`.htaccess` is ignored. Without a symlink option, the link answers 403.

```apache
<Directory /home/USER/public_html>
	Options SymLinksIfOwnerMatch          # or FollowSymLinks
	AllowOverride All                     # or: AuthConfig Limit FileInfo
	Require all granted
</Directory>
```

`AllowOverride None` means nothing protects the panel's internal files. A partial
set (for example only `FileInfo`) makes the panel answer **500**, which fails
closed. `mod_rewrite` and `mod_headers` should be enabled
(`a2enmod rewrite headers`, then `systemctl reload apache2`).

If you prefer an `Alias` to a symlink (needs access to the server or vhost
configuration, so not on shared hosting):

```apache
Alias /gv-admin /home/USER/bot-guard/panel
<Directory /home/USER/bot-guard/panel>
	AllowOverride All
	Options FollowSymLinks
	Require all granted
	DirectoryIndex index.php
</Directory>
```

Keep `Options FollowSymLinks` in the `Alias` block: Apache evaluates the
`RewriteRule` in `panel/.htaccess` only when a symlink option is on. With
`Options None` every panel request answers 403.

### OpenLiteSpeed

OpenLiteSpeed does not read `.htaccess` unless you tell it to, and it ignores the
`Require` lines there (it relies on the `RewriteRule` fallback in
`panel/.htaccess`). In the WebAdmin console (port 7080), for your virtual host:

- **Basic → Follow Symbolic Link**: `Yes` (`allowSymbolLink 1`)
- **Rewrite → Enable Rewrite**: `Yes`, **Auto Load from .htaccess**: `Yes`
- Then **Graceful Restart**.

OpenLiteSpeed reads `.htaccess` when it starts. After a change to any `.htaccess`,
restart it again: `/usr/local/lsws/bin/lswsctrl restart`.

---

## 5. Exempt the panel from the guard

The guard runs on every PHP request in `public_html`, the panel included. Without
an exemption, your own guard can challenge or block you in your own panel once
enforcement is on.

Where: `/home/USER/bot-guard/guard/config.php`, in an editor.

```php
'exempt_paths' => array('/gv-admin/'),
```

Keep the paths that are already in the list. The value is the URL path with a
trailing slash. The panel has its own login, CSRF protection and login rate
limit, so the exemption does not open anything.

---

## 6. Check that it works

Where: SSH on the server, or any computer with `curl`.

**1. The panel URL loads the login page:**

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://example.com/gv-admin/
curl -s -o /dev/null -w '%{http_code}\n' -L https://example.com/gv-admin/
```

Expected: `303` (redirect to the login page), then `200` (with `-L`, the login
page itself).

**2. Internal files are refused (403 or 404, never 200):**

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://example.com/gv-admin/panel.config.php
curl -s -o /dev/null -w '%{http_code}\n' https://example.com/gv-admin/audit.jsonl
```

**3. The full exposure check:**

```bash
cd /home/USER/bot-guard
bash scripts/exposure-check.sh https://example.com /gv-admin
```

It ends with `OK: no sensitive path answered 200 ...` and exit code 0.

**4. Sign in.** Open `https://example.com/gv-admin/` in a browser and log in with
the user from `setpass.php`. The **Data pipeline** card on the dashboard should
say that requests are being logged.

Optional, on a **test install only** (it changes a setting and toggles the kill
switch): `bash scripts/panel-smoke.sh https://example.com /gv-admin USER PASSWORD`.

---

## 7. Troubleshooting

| What you see | Cause | Fix |
|---|---|---|
| **403** on `/gv-admin` (no trailing slash) | Apache checks the link name before it adds the slash | Open `/gv-admin/` with the slash |
| **403 Forbidden** on `/gv-admin/` | The symlink is owned by `root` (or another user) and the server uses `SymLinksIfOwnerMatch` | `chown -h USER:USER public_html/gv-admin` (section 2) |
| **403** on `/gv-admin/` | The web server cannot traverse a directory on the path | `chmod 0711 /home/USER`, `chmod 0755 bot-guard bot-guard/panel` |
| **403** on every panel URL, Apache `Alias` | `Options None` in the `Alias` block | Use `Options FollowSymLinks` (section 4) |
| **404 with an empty page** | `php panel/setpass.php` was not run, or PHP cannot read `panel/panel.config.php` | Run `setpass.php` as the PHP user; check the owner of `panel.config.php` |
| **404 with your site's 404 page** | The symlink is missing or has a different name | `ls -l public_html/` and compare with the URL |
| **500 Internal Server Error** | `.htaccess` directives not allowed (partial `AllowOverride`), or a PHP error | Section 4; read the server error log (cPanel → Metrics → Errors) and `bot-guard/logs/guard-errors.log` |
| Page loads **without styling** | `assets/*.css` is not readable by the web server | `chmod 0755 panel/assets` and `chmod 0644 panel/assets/*` |
| You see the **challenge page** or a 403 from the guard | The panel path is not in `exempt_paths` | Section 5 |
| **Login does not stick** (you land on the login page again) | The panel is opened under two different host names or paths (`www.` and without, or a symlink and an `Alias`) | Always use the same URL; the session cookie is scoped to one host and to `/gv-admin/` |
| "Access from this IP is not allowed" | `ip_allowlist` in `panel/panel.config.php` does not contain your address | Edit the list over SSH (docs/03-SETUP.md, Step 5) |
| "Too many attempts" | 5 failed logins in 15 minutes | Wait 15 minutes |
| Settings **cannot be saved** ("write to disk failed") | PHP cannot write in `guard/` | Section 3: the PHP user must own `guard/` |
| The kill switch does not change | PHP cannot create `bot-guard/guard.off` | Section 3: the PHP user must own the top directory |
| A change to `.htaccess` has no effect (OpenLiteSpeed) | OpenLiteSpeed reads `.htaccess` at start | `lswsctrl restart` |

Do not add the panel path to `robots.txt`. It would publish the URL. The panel
already sends `X-Robots-Tag: noindex` on every response.

---

## What was verified and what was not

- Verified in CI on Apache 2.4 (`mod_php`) and OpenLiteSpeed 1.9: the symlink
  layout, the `Alias` layout (Apache), `exposure-check.sh`, login, settings save,
  overrides and the kill switch (`panel-smoke.sh`), and that the guard logs the
  host application's requests through `auto_prepend_file`.
- Not verified: LiteSpeed Enterprise and cPanel's suEXEC/CageFS user separation.
  They follow the same rules as Apache, but no CI job runs them.
