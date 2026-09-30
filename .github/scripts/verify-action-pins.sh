#!/usr/bin/env bash
# verify-action-pins — every action a workflow uses is pinned to a full commit
# SHA, and that SHA is the commit its named release tag points at.
#
#   bash .github/scripts/verify-action-pins.sh
#
# Each `uses:` line must read    uses: owner/repo@<40-hex SHA> # vX.Y.Z
# and the tag vX.Y.Z upstream must resolve to exactly that commit. Run by CI
# on every push and pull request, so a Dependabot PR is verified before you
# merge it, and a hand-edited SHA that does not match its comment fails.
#
# What this does NOT tell you: whether the release itself is trustworthy.
# Dependabot's cooldown (a week's delay before proposing a release) is the
# guard for that — time for a compromised release to be caught upstream.
#
# LS_REMOTE may name a stand-in for `git ls-remote --tags <url>`, for testing
# without network.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
LS_REMOTE="${LS_REMOTE:-git ls-remote --tags}"
fail=0; n=0

while IFS= read -r hit; do
    file="${hit%%:*}"; rest="${hit#*:}"; lineno="${rest%%:*}"; text="${rest#*:}"
    ref="$(printf '%s' "$text" | sed -nE 's/.*uses:[[:space:]]*([^[:space:]#]+).*/\1/p')"
    case "$ref" in ./*|docker://*|"") continue ;; esac     # local and container refs
    action="${ref%@*}"; sha="${ref#*@}"
    tag="$(printf '%s' "$text" | sed -nE 's/.*#[[:space:]]*(v?[0-9][^[:space:]]*).*/\1/p')"
    where="$file:$lineno"; n=$((n + 1))

    if ! [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
        echo "FAIL $where: $action@$sha is not pinned to a full commit SHA"; fail=1; continue
    fi
    if [ -z "$tag" ]; then
        echo "FAIL $where: no '# vX.Y.Z' comment naming the release this SHA is"; fail=1; continue
    fi
    repo="$(printf '%s' "$action" | cut -d/ -f1-2)"
    refs="$($LS_REMOTE "https://github.com/$repo" 2>/dev/null)"
    if [ -z "$refs" ]; then
        echo "FAIL $where: could not list tags of github.com/$repo"; fail=1; continue
    fi
    # An annotated tag lists twice: refs/tags/X (the tag object) and
    # refs/tags/X^{} (the commit it points at). A lightweight tag lists once,
    # already the commit. Prefer the peeled line.
    commit="$(printf '%s\n' "$refs" | awk -v t="refs/tags/$tag^{}" '$2 == t {print $1}')"
    [ -n "$commit" ] || commit="$(printf '%s\n' "$refs" | awk -v t="refs/tags/$tag" '$2 == t {print $1}')"
    if [ -z "$commit" ]; then
        echo "FAIL $where: $repo has no tag $tag"; fail=1
    elif [ "$commit" != "$sha" ]; then
        echo "FAIL $where: $repo $tag is commit $commit, but the workflow pins $sha"; fail=1
    else
        echo "ok   $where: $action@${sha:0:12} is $tag"
    fi
done < <(grep -rnE '^[[:space:]]*-?[[:space:]]*uses:' .github/workflows/)

[ "$n" -gt 0 ] || echo "note: no actions used"
exit "$fail"
