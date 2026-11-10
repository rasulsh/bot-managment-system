#!/usr/bin/env bash
# CI: run scripts/exposure-check.sh and scripts/panel-smoke.sh against a REAL web
# server, in each supported layout:
#   docroot  the whole repository INSIDE the document root (worst case)
#   symlink  repository outside the docroot, panel exposed by a symlink
#   alias    repository outside the docroot, panel exposed by an Alias (Apache)
#
#   sudo bash .github/ci/webserver-test.sh apache
#   sudo bash .github/ci/webserver-test.sh ols
#
# Debian/Ubuntu only (apt), needs root. Installs the server if it is missing.
set -euo pipefail

SERVER="${1:-}"
case "$SERVER" in apache|ols) ;; *) echo "usage: $0 apache|ols"; exit 2 ;; esac
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${GV_CI_WORK:-/tmp/gv-ci}"
PORT=8088
PASSWORD='ci-smoke-password-12'
LSWS=/usr/local/lsws
mkdir -p "$WORK"
fail=0

log() { printf '\n==== %s\n' "$*"; }

install_apache() {
	command -v apache2 >/dev/null 2>&1 && ls /usr/lib/apache2/modules/libphp*.so >/dev/null 2>&1 && return 0
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apache2 libapache2-mod-php >/dev/null
}

install_ols() {
	[ -x "$LSWS/bin/openlitespeed" ] && return 0
	local tmp; tmp="$(mktemp -d)"
	curl -sSf https://rpms.litespeedtech.com/debian/lst_debian_repo.gpg -o "$tmp/a.gpg"
	curl -sSf https://rpms.litespeedtech.com/debian/lst_repo.gpg -o "$tmp/b.gpg"
	cat "$tmp/a.gpg" "$tmp/b.gpg" | gpg --dearmor > /usr/share/keyrings/litespeed.gpg
	echo "deb [signed-by=/usr/share/keyrings/litespeed.gpg] http://rpms.litespeedtech.com/debian/ $(lsb_release -sc) main" \
		> /etc/apt/sources.list.d/litespeed.list
	apt-get update -qq
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openlitespeed lsphp83 lsphp83-common >/dev/null
}

ensure_redis() {
	redis-cli ping >/dev/null 2>&1 && return 0
	command -v redis-server >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq redis-server >/dev/null
	redis-server --daemonize yes --save "" >/dev/null
	sleep 1
}

# deploy <dest>: copy the repository (with .git, so the .git/HEAD probe is real)
deploy() {
	rm -rf "$1"; mkdir -p "$1"
	rsync -a --exclude '__pycache__' "$REPO"/ "$1"/
	mkdir -p "$1/logs"
	chown -R www-data:www-data "$1"
}

install_panel_login() {   # <repo copy>
	(cd "$1" && printf 'admin\n%s\n%s\n' "$PASSWORD" "$PASSWORD" | runuser -u www-data -- php panel/setpass.php >/dev/null)
}

stop_server() {
	if [ "$SERVER" = apache ]; then
		[ -f "$WORK/apache.pid" ] && apache2 -f "$WORK/httpd.conf" -k stop >/dev/null 2>&1 || true
	else
		# The package starts OpenLiteSpeed (default config, user nobody) as a service
		# when it is installed, and its lsphp children outlive "lswsctrl stop". A stale
		# lsphp running as another user would keep answering and could neither read
		# panel/panel.config.php (0600) nor write logs/. Stop everything, for real.
		systemctl stop lsws lshttpd >/dev/null 2>&1 || true
		"$LSWS/bin/lswsctrl" stop >/dev/null 2>&1 </dev/null || true
		sleep 1
		for n in openlitespeed lshttpd lscgid lsphp; do pkill -9 -x "$n" >/dev/null 2>&1 || true; done
		rm -rf /tmp/lshttpd/* 2>/dev/null || true
	fi
	sleep 2
}

# OpenLiteSpeed only: the PHP worker must run as the web user, or the panel and the
# guard cannot read their 0600 config / write logs. Fail with evidence, not a mystery.
assert_php_user() {   # <path that makes PHP run>
	[ "$SERVER" = ols ] || return 0
	curl -s -o /dev/null "http://127.0.0.1:$PORT$1" || true
	local users; users="$(ps -C lsphp -o user= | sort -u | tr '\n' ' ')"
	echo "lsphp runs as: ${users:-<none>}"
	if [ "$users" != "www-data " ]; then
		echo "FAIL  lsphp is not running as www-data"
		ps -eo user,pid,args | grep -E 'litespeed|lsphp|lscgid' | grep -v grep || true
		grep -nE '^(user|group)' "$LSWS/conf/httpd_config.conf" || true
		tail -n 20 "$LSWS/gv/logs/error.log" 2>/dev/null || true
		fail=1
	fi
}

start_apache() {   # <docroot> <extra-config-file or ''>
	local mods=/usr/lib/apache2/modules phpmod
	phpmod="$(ls $mods/libphp*.so | head -1)"
	cat > "$WORK/httpd.conf" <<CONF
ServerRoot "$WORK"
ServerName localhost
Listen 127.0.0.1:$PORT
PidFile $WORK/apache.pid
ErrorLog $WORK/apache-error.log
LogLevel warn
LoadModule mpm_prefork_module $mods/mod_mpm_prefork.so
LoadModule authz_core_module $mods/mod_authz_core.so
LoadModule authz_host_module $mods/mod_authz_host.so
LoadModule access_compat_module $mods/mod_access_compat.so
LoadModule authn_core_module $mods/mod_authn_core.so
LoadModule dir_module $mods/mod_dir.so
LoadModule mime_module $mods/mod_mime.so
LoadModule rewrite_module $mods/mod_rewrite.so
LoadModule headers_module $mods/mod_headers.so
LoadModule alias_module $mods/mod_alias.so
LoadModule env_module $mods/mod_env.so
LoadModule php_module $phpmod
User www-data
Group www-data
TypesConfig /etc/mime.types
DirectoryIndex index.php index.html
AddType application/x-httpd-php .php
DocumentRoot "$1"
<Directory />
	AllowOverride None
	Require all denied
</Directory>
<Directory "$1">
	Options SymLinksIfOwnerMatch
	AllowOverride All
	Require all granted
</Directory>
<FilesMatch "^\.ht">
	Require all denied
</FilesMatch>
CONF
	# $2: a repository copy (guard it with auto_prepend_file) or a config fragment.
	if [ -d "${2:-}" ]; then
		echo "php_admin_value auto_prepend_file $2/prepend.php" >> "$WORK/httpd.conf"
	elif [ -f "${2:-}" ]; then
		cat "$2" >> "$WORK/httpd.conf"
	fi
	apache2 -f "$WORK/httpd.conf" -t
	apache2 -f "$WORK/httpd.conf" -k start
}

start_ols() {   # <docroot> <repo copy holding prepend.php or ''>
	[ -f "$LSWS/conf/httpd_config.conf.orig" ] || cp "$LSWS/conf/httpd_config.conf" "$LSWS/conf/httpd_config.conf.orig"
	cp "$LSWS/conf/httpd_config.conf.orig" "$LSWS/conf/httpd_config.conf"
	mkdir -p "$LSWS/conf/vhosts/gv" "$LSWS/gv/logs" /tmp/lshttpd
	python3 - "$LSWS" "$PORT" <<'PY'
import re, sys
lsws, port = sys.argv[1], sys.argv[2]
p = lsws + '/conf/httpd_config.conf'
s = open(p).read()
s = re.sub(r'(?m)^user\s+\S+', 'user                             www-data', s, count=1)
s = re.sub(r'(?m)^group\s+\S+', 'group                            www-data', s, count=1)
s = re.sub(r'virtualHost Example\{.*?\n\}\n', """virtualHost gv{
    vhRoot                   %s/gv/
    allowSymbolLink          1
    enableScript             1
    restrained               0
    setUIDMode               0
    configFile               conf/vhosts/gv/vhconf.conf
}
""" % lsws, s, flags=re.S)
s = re.sub(r'listener Default\{.*?\n\}\n', """listener Default{
    address                  *:%s
    secure                   0
    map                      gv *
}
""" % port, s, flags=re.S)
open(p, 'w').write(s)
PY
	cat > "$LSWS/conf/vhosts/gv/vhconf.conf" <<CONF
docRoot $1
enableGzip 0
index {
  indexFiles index.php, index.html
  autoIndex 0
  useServer 0
}
errorlog $LSWS/gv/logs/error.log {
  logLevel DEBUG
  useServer 0
}
accessLog $LSWS/gv/logs/access.log {
  useServer 0
}
rewrite {
  enable 1
  autoLoadHtaccess 1
}
scripthandler {
  add lsapi:lsphp php
}
phpIniOverride {
$( [ -n "${2:-}" ] && echo "  php_admin_value auto_prepend_file $2/prepend.php" )
}
CONF
	chown -R www-data:www-data "$LSWS/gv" "$LSWS/conf/vhosts/gv" /tmp/lshttpd
	"$LSWS/bin/lswsctrl" start >/dev/null 2>&1 </dev/null
	wait_http
}

wait_http() {   # until the listener answers (any status), at most ~40 s
	for _ in $(seq 1 40); do
		curl -s -o /dev/null -m 2 "http://127.0.0.1:$PORT/" && return 0
		sleep 1
	done
	echo "WARN: nothing answered on port $PORT"
}

start_server() { if [ "$SERVER" = apache ]; then start_apache "$@"; else start_ols "$@"; fi; }

run_checks() {   # <label> <panel path>
	assert_php_user "$2/index.php"
	log "$SERVER / $1: exposure-check.sh"
	bash "$REPO/scripts/exposure-check.sh" "http://127.0.0.1:$PORT" "$2" || fail=1
	log "$SERVER / $1: panel-smoke.sh"
	bash "$REPO/scripts/panel-smoke.sh" "http://127.0.0.1:$PORT" "$2" admin "$PASSWORD" || fail=1
}

ensure_redis
if [ "$SERVER" = apache ]; then install_apache; else install_ols; fi

# --- layout 1: the whole repository inside the document root --------------------
log "layout: docroot (worst case)"
stop_server
deploy /var/www/gv-docroot
install_panel_login /var/www/gv-docroot
start_server /var/www/gv-docroot ''
run_checks docroot /panel
stop_server

# --- layout 2: repository outside, panel by symlink -----------------------------
log "layout: symlink"
deploy /var/www/bot-guard
install_panel_login /var/www/bot-guard
rm -rf /var/www/site; mkdir -p /var/www/site
echo '<?php header("Content-Type: text/plain"); echo "host app OK\n";' > /var/www/site/index.php
chown -R www-data:www-data /var/www/site
runuser -u www-data -- ln -s /var/www/bot-guard/panel /var/www/site/gv-admin
start_server /var/www/site /var/www/bot-guard
body="$(curl -s "http://127.0.0.1:$PORT/")"
if [ "$body" = "host app OK" ]; then echo "PASS  host application still answers"; else echo "FAIL  host application: $body"; fail=1; fi
run_checks symlink /gv-admin
if ls /var/www/bot-guard/logs/guard-*.jsonl >/dev/null 2>&1; then echo "PASS  the guard (auto_prepend_file) logged the requests"; else echo "FAIL  no guard log was written"; fail=1; fi
stop_server

# --- layout 3: Alias (Apache; LiteSpeed has no Alias directive in .htaccess) ----
if [ "$SERVER" = apache ]; then
	log "layout: alias"
	rm -f /var/www/site/gv-admin
	cat > "$WORK/alias.conf" <<'CONF'
php_admin_value auto_prepend_file /var/www/bot-guard/prepend.php
Alias /gv-admin /var/www/bot-guard/panel
<Directory /var/www/bot-guard/panel>
	AllowOverride All
	Options FollowSymLinks
	Require all granted
	DirectoryIndex index.php
</Directory>
CONF
	start_server /var/www/site "$WORK/alias.conf"
	run_checks alias /gv-admin
	stop_server
fi

if [ "$fail" -ne 0 ]; then echo; echo "FAILED: see the output above."; exit 1; fi
echo; echo "All layouts passed on $SERVER."
