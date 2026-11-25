#!/usr/bin/env bash
# The first request after an update that moves the panel's data (2026.11.39: panel/ -> data/panel/): an administrator who is signed in
# STAYS signed in, the files are migrated with private modes, the old copies are left for a rollback, and a new login works. Also: a login
# page that was open too long gives a clear message, a fresh form and keeps the user name. A throw-away copy of the tree and PHP's server.
#   bash scripts/data-migration-e2e.sh
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${DATA_MIGRATION_PORT:-8213}"
WORK="$(mktemp -d)"
PID=""
cleanup() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
PASS=0; FAIL=0
ok() { if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1"; FAIL=$((FAIL + 1)); fi; }
mode() { stat -c '%a' "$1" 2>/dev/null; }
T="$WORK/t"; mkdir -p "$T"
(cd "$REPO" && tar --exclude=.git -cf - .) | tar -xf - -C "$T"
rm -rf "$T/data/panel"
(cd "$T" && printf 'admin\nmigrate-pass-12345\nmigrate-pass-12345\n' | php panel/setpass.php >/dev/null 2>&1)
(cd "$T" && exec env -u GV_PANEL_DATA PHP_CLI_SERVER_WORKERS=6 php -S "127.0.0.1:$PORT" -t . >"$WORK/php.log" 2>&1) &
PID=$!
URL="http://127.0.0.1:$PORT/panel/index.php"
for _ in $(seq 1 40); do curl -s -o /dev/null "$URL" && break; sleep 0.1; done
JAR="$WORK/jar"
tok() { curl -s -c "$1" -b "$1" "$URL?r=login" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed 's/.*value="//; s/"$//'; }
LOGIN_RESP="$WORK/login.resp"
curl -s -D "$LOGIN_RESP" -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$(tok "$JAR")" --data-urlencode "username=admin" --data-urlencode "password=migrate-pass-12345" "$URL?r=login"
page="$(curl -s -c "$JAR" -b "$JAR" "$URL?r=dashboard")"
ok "signed in" "$(grep -q 'data-chip="kill"' <<<"$page" && echo 1 || echo 0)"
if ! grep -q 'data-chip="kill"' <<<"$page"; then echo "--- login response:"; head -c 1500 "$LOGIN_RESP"; echo "--- dashboard:"; head -c 1500 <<<"$page"; echo "--- jar:"; cat "$JAR"; fi

# Put the files back where the PREVIOUS release kept them, as an install that has just been updated looks.
mv "$T/data/panel/users.json" "$T/panel/users.json"; [ -f "$T/data/panel/audit.jsonl" ] && mv "$T/data/panel/audit.jsonl" "$T/panel/audit.jsonl"
rm -rf "$T/data/panel"
chmod 600 "$T/panel/users.json"
# The first requests after the update arrive TOGETHER (several workers, so they really overlap): eight page loads of the signed-in administrator
# and three new sign-ins, all while the files are still only in panel/. Every one of them must succeed, none may lose the session.
BPIDS=""
for n in 1 2 3 4 5 6 7 8; do cp "$JAR" "$WORK/bj$n"; (curl -s -c "$WORK/bj$n" -b "$WORK/bj$n" "$URL?r=dashboard" >"$WORK/bp$n") & BPIDS="$BPIDS $!"; done
for n in 1 2 3; do (cj="$WORK/bl$n"; curl -s -c "$cj" -b "$cj" "$URL?r=login" >"$WORK/bf$n"; t="$(grep -o 'name="csrf" value="[^"]*"' "$WORK/bf$n" | head -1 | sed 's/.*value="//; s/"$//')"
  curl -s -o /dev/null -w '%{http_code}' -c "$cj" -b "$cj" --data-urlencode "csrf=$t" --data-urlencode "username=admin" --data-urlencode "password=migrate-pass-12345" "$URL?r=login" >"$WORK/bc$n") & BPIDS="$BPIDS $!"; done
wait $BPIDS
bursts=0; for n in 1 2 3 4 5 6 7 8; do grep -q 'data-chip="kill"' "$WORK/bp$n" && bursts=$((bursts + 1)); done
logins=0; for n in 1 2 3; do [ "$(cat "$WORK/bc$n" 2>/dev/null)" = 303 ] && logins=$((logins + 1)); done
ok "eight overlapping first page loads and three overlapping first sign-ins all succeed during the migration ($bursts/8 pages, $logins/3 sign-ins)" "$([ "$bursts" = 8 ] && [ "$logins" = 3 ] && echo 1 || echo 0)"
ok "...and the migrated store is one valid, complete copy (no half-written or older copy replaced a newer one)" "$(php -r '$j=json_decode(file_get_contents($argv[1]),true); $o=json_decode(file_get_contents($argv[2]),true); echo (is_array($j) && count($j["users"])===count($o["users"]) && $j["users"][0]["username"]==="admin" && $j["users"][0]["password_hash"]===$o["users"][0]["password_hash"] && $j["users"][0]["session_version"]===$o["users"][0]["session_version"]) ? 1 : 0;' "$T/data/panel/users.json" "$T/panel/users.json" 2>/dev/null)"
ls "$T/data/panel" | grep -q '\.mig' && ok "...no temporary copy is left behind" 0 || ok "...no temporary copy is left behind" 1
page="$(curl -s -c "$JAR" -b "$JAR" "$URL?r=dashboard")"
ok "the FIRST request after the move: the signed-in administrator is still signed in (the dashboard, not the login page)" "$(grep -q 'data-chip="kill"' <<<"$page" && echo 1 || echo 0)"
ok "...the store was migrated to data/panel/users.json (same user, password hash, role and session version)" "$(php -r '$a=json_decode(file_get_contents($argv[1]),true)["users"][0]; $b=json_decode(file_get_contents($argv[2]),true)["users"][0]; echo ($a["username"]===$b["username"] && $a["password_hash"]===$b["password_hash"] && $a["session_version"]===$b["session_version"] && $a["role"]===$b["role"]) ? 1 : 0;' "$T/panel/users.json" "$T/data/panel/users.json" 2>/dev/null)"
ok "...data/panel is 0700, users.json 0600, the audit trail 0600 (private to the web user)" "$([ "$(mode "$T/data/panel")" = 700 ] && [ "$(mode "$T/data/panel/users.json")" = 600 ] && [ "$(mode "$T/data/panel/audit.jsonl")" = 600 ] && echo 1 || echo 0)"
ok "...the old copy is left in panel/ for a rollback" "$([ -f "$T/panel/users.json" ] && echo 1 || echo 0)"
ok "...a deny .htaccess is in data/panel and the marker names the migrating version" "$([ -f "$T/data/panel/.htaccess" ] && [ "$(cat "$T/data/panel/.migrated")" = "$(cat "$T/VERSION")" ] && echo 1 || echo 0)"
JAR2="$WORK/jar2"
code="$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR2" -b "$JAR2" --data-urlencode "csrf=$(tok "$JAR2")" --data-urlencode "username=admin" --data-urlencode "password=migrate-pass-12345" "$URL?r=login")"
ok "a NEW sign-in works after the migration (303)" "$([ "$code" = 303 ] && echo 1 || echo 0)"
ok "a change made now (the session of the first jar writes the audit trail) lands in the NEW files only" "$(curl -s -o /dev/null -c "$JAR" -b "$JAR" "$URL?r=audit"; [ -s "$T/data/panel/audit.jsonl" ] && echo 1 || echo 0)"

# A login page that was open too long: the Strict cookie is gone (expired), the form still carries the old token.
JAR3="$WORK/jar3"
form="$(curl -s -c "$JAR3" -b "$JAR3" "$URL?r=login")"
old="$(grep -o 'name="csrf" value="[^"]*"' <<<"$form" | head -1 | sed 's/.*value="//; s/"$//')"
: > "$JAR3"                                                         # the browser dropped the cookie
resp="$(curl -s -D - -c "$JAR3" -b "$JAR3" --data-urlencode "csrf=$old" --data-urlencode "username=admin" --data-urlencode "password=migrate-pass-12345" "$URL?r=login")"
ok "a stale login page: the answer says the page was open too long, in the login card" "$(grep -q 'open too long' <<<"$resp" && grep -q 'gp-login-msg' <<<"$resp" && echo 1 || echo 0)"
ok "...the form that comes back is fresh (a NEW token and a new cookie) and keeps the user name, not the password" "$(new="$(grep -o 'name="csrf" value="[^"]*"' <<<"$resp" | head -1 | sed 's/.*value="//; s/"$//')"; [ -n "$new" ] && [ "$new" != "$old" ] && grep -qi '^set-cookie: gp_login_csrf=' <<<"$resp" && grep -q 'value="admin"' <<<"$resp" && ! grep -q 'migrate-pass' <<<"$resp" && echo 1 || echo 0)"
ok "...no session was started and nothing counts as a failed attempt" "$(grep -qi '^set-cookie: gp_sess' <<<"$resp" && echo 0 || echo 1)"
newtok="$(grep -o 'name="csrf" value="[^"]*"' <<<"$resp" | head -1 | sed 's/.*value="//; s/"$//')"
code2="$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR3" -b "$JAR3" --data-urlencode "csrf=$newtok" --data-urlencode "username=admin" --data-urlencode "password=migrate-pass-12345" "$URL?r=login")"
ok "...and signing in with that fresh form works (303)" "$([ "$code2" = 303 ] && echo 1 || echo 0)"
echo
echo "PASS $PASS  FAIL $FAIL"
[ "$FAIL" -eq 0 ]
