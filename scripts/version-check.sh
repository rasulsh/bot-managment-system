#!/usr/bin/env bash
# CI: a pull request that changes code must also change VERSION (and add that version to CHANGELOG.md).
#
#   bash scripts/version-check.sh <base-ref> [head-ref]
#
# "Code" is everything an install runs or ships: guard/, panel/, analyzer/, scripts/, prepend.php,
# .htaccess files, docs/ and the README. Changes that touch only .github/, tests of the CI itself
# or nothing else pass. Exit 0 = fine (or nothing to check), 1 = VERSION was not bumped, 2 = bad usage.
set -uo pipefail
BASE="${1:-}"
HEAD="${2:-HEAD}"
if [ -z "$BASE" ]; then echo "Usage: bash scripts/version-check.sh <base-ref> [head-ref]"; exit 2; fi
changed="$(git diff --name-only "$BASE"..."$HEAD" 2>/dev/null)" || { echo "version-check: cannot diff $BASE...$HEAD"; exit 2; }
code="$(grep -E '^(guard/|panel/|analyzer/|scripts/|docs/|prepend\.php$|README\.md$|ROLLOUT\.md$|\.htaccess$|updates/)' <<<"$changed" | grep -v '^scripts/version-check\.sh$' || true)"
if [ -z "$code" ]; then
	echo "version-check: no code files changed; VERSION not required."
	exit 0
fi
if ! grep -qx 'VERSION' <<<"$changed"; then
	echo "FAIL: this pull request changes code but not VERSION."
	echo "Bump VERSION (date style, e.g. $(date +%Y.%m.%d)) and add an entry for it at the top of CHANGELOG.md."
	echo "Changed code files:"; sed 's/^/  /' <<<"$code" | head -10
	exit 1
fi
new="$(git show "$HEAD":VERSION 2>/dev/null | tr -d '[:space:]')"
old="$(git show "$BASE":VERSION 2>/dev/null | tr -d '[:space:]')"
if [ -z "$new" ] || [ "$new" = "$old" ]; then echo "FAIL: VERSION is unchanged ($old)."; exit 1; fi
if ! git show "$HEAD":CHANGELOG.md 2>/dev/null | grep -Eq "^## +$(sed 's/\./\\./g' <<<"$new")[[:space:]]*$"; then
	echo "FAIL: CHANGELOG.md has no '## $new' entry."
	exit 1
fi
echo "version-check: VERSION $old -> $new and CHANGELOG.md has the entry."
exit 0
