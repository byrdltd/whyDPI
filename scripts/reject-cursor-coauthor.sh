#!/usr/bin/env bash
# Reject commit messages that credit Cursor / cursoragent as co-author.
# Used by .githooks/commit-msg and pre-commit (commit-msg stage).
set -euo pipefail

bad=0
for msgfile in "$@"; do
    if grep -qiE 'Co-authored-by:[[:space:]]*Cursor|Co-authored-by:.*cursoragent\.com' "$msgfile"; then
        echo "reject-cursor-coauthor: Cursor Co-authored-by trailer is not allowed." >&2
        echo "  See .cursor/rules/git-authorship.mdc and CONTRIBUTING.md" >&2
        bad=1
    fi
done
exit "$bad"
