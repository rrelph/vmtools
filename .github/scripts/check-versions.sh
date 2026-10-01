#!/usr/bin/env bash
# One version for the whole attest workspace, and a release tag that names it.
#
#   bash .github/scripts/check-versions.sh [REF]
#
# Fails when a workspace member sets its own version instead of taking
# `version.workspace = true`, or when REF (default: $GITHUB_REF, as CI sets it)
# is a tag other than vmtools-<the workspace version>. A branch, or no REF at
# all, checks the members only.
#
# Why one version: every program a release builds then reports the release
# it came from, which is also its source and its Cargo.lock. Tags before
# vmtools-0.6.0 (vmt-unlock-X.Y.Z) predate the rule and are never pushed again.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../attest"

REF="${1:-${GITHUB_REF:-}}"
fail=0

# The [workspace.package] version: the first `version = "…"` after that header.
version="$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version = "\([^"]*\)"$/\1/p}' Cargo.toml | head -n 1)"
[ -n "$version" ] || { echo "check-versions: no [workspace.package] version in attest/Cargo.toml" >&2; exit 1; }

members="$(sed -n 's/^members = \[\(.*\)\]$/\1/p' Cargo.toml | tr -d '" ' | tr ',' ' ')"
[ -n "$members" ] || { echo "check-versions: no members line in attest/Cargo.toml" >&2; exit 1; }

for m in $members; do
    manifest="$m/Cargo.toml"
    if ! grep -qx 'version.workspace = true' "$manifest"; then
        echo "check-versions: $manifest does not take the workspace version (version.workspace = true)" >&2
        fail=1
    fi
    if grep -q '^version = ' "$manifest"; then
        echo "check-versions: $manifest sets its own version: $(grep '^version = ' "$manifest")" >&2
        fail=1
    fi
done

case "$REF" in
    refs/tags/*)
        tag="${REF#refs/tags/}"
        if [ "$tag" != "vmtools-$version" ]; then
            echo "check-versions: tag $tag does not match the workspace version; expected vmtools-$version" >&2
            fail=1
        fi
        ;;
esac

[ "$fail" -eq 0 ] || exit 1
echo "check-versions: every member is at the workspace version, $version${tag:+; tag $tag matches}"
