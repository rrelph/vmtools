#!/usr/bin/env bash
# Run ShellCheck on every shell script this repo tracks.
#
#   bash .github/scripts/shellcheck.sh             warning severity (the default)
#   SEVERITY=info bash .github/scripts/shellcheck.sh
#
# Scripts are found by their #! line, not their name, so nothing is missed
# for lacking a .sh suffix (cvm-guard, the git hooks). Run by CI on every
# push; run it locally too once it is installed (apt install shellcheck, or
# brew install shellcheck).
#
# NO COMMENT LINE MAY BEGIN WITH THE WORD "shellcheck": ShellCheck reads any
# such comment as a directive to itself ("# shellcheck disable=...") and
# fails on one it cannot parse. This file's own first version did exactly
# that, twice, and was the only thing the first run found.
#
# Raised one level at a time, only once the level below is clean: error
# first (nearly always real bugs), then warning (2026-09-26). ShellCheck's
# levels are error, warning, info, style; each surfaces more, and each is
# worth working through deliberately rather than switching on blind.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 2
SEVERITY="${SEVERITY:-warning}"

if ! command -v shellcheck >/dev/null 2>&1; then
    echo "shellcheck.sh: shellcheck is not installed (apt install shellcheck / brew install shellcheck)" >&2
    exit 2
fi

files=()
while IFS= read -r -d '' f; do
    [ -f "$f" ] || continue
    first="$(head -n 1 "$f" 2>/dev/null)"
    case "$first" in
        '#!'*) printf '%s' "$first" | grep -qE '(^#!|[/ ])(ba|da|k)?sh([[:space:]]|$)' && files+=("$f") ;;
    esac
done < <(git ls-files -z)

echo "shellcheck $(shellcheck --version | sed -n 's/^version: //p'), severity $SEVERITY, ${#files[@]} scripts"
[ "${#files[@]}" -gt 0 ] || { echo "shellcheck.sh: no shell scripts found — refusing to report a clean result" >&2; exit 1; }

out="$(shellcheck --severity="$SEVERITY" --format=gcc "${files[@]}" 2>&1)"; rc=$?
if [ -n "$out" ]; then
    printf '%s\n' "$out"
    # On GitHub, also as annotations, so each finding shows on its line.
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
        printf '%s\n' "$out" | awk -F: '/^[^:]+:[0-9]+:[0-9]+: / {
            file = $1; line = $2; col = $3
            msg = $0; sub(/^[^:]+:[0-9]+:[0-9]+: [a-z]+: /, "", msg)
            printf "::error file=%s,line=%s,col=%s::%s\n", file, line, col, msg }'
    fi
fi
[ "$rc" -eq 0 ] && echo "clean at severity $SEVERITY"
exit "$rc"
