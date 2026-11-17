#!/usr/bin/env bash
# Pin for 10 (mises a jour depuis l'interface), contract section 2.8 and B-8:
# nothing this project tracks under panel/ or scripts/ names the upstream
# project's GitHub repository, and the update and install paths contact no
# release host on their own.
#
# Why: servers installed before the fork, and every copy of these scripts that
# still pointed at the upstream repository, would fetch code from a project
# whose releases this one does not sign. One stray default (a GITHUB_REPO=, a
# clone URL, a "check for updates" constant) is enough for an update to come
# from outside the signed chain. The panel binary now reaches GitHub itself,
# with an operator-supplied token, and verifies minisign + SHA-256 before
# anything runs; the scripts only receive verified files.
#
# Run from anywhere inside the repository, with git available (it reads the
# TRACKED files only, so an untracked scratch file cannot make it pass or fail).
#
# EXPECTED TO FAIL until both work streams A (backend) and B (agent + scripts)
# are merged: A owns telemetry_collector.rs, routes/sites.rs and the backend's
# services/panel_update.rs, which this pin also covers.
set -uo pipefail

ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null)" || {
    echo "no-upstream-repo-pin: not inside a git work tree"; exit 2; }
cd "$ROOT" || exit 2

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

# Assembled, so that this file does not match itself (and it lives in tests/,
# outside the searched pathspec, anyway).
FORBIDDEN="ovex""ro"

echo "── 1. no tracked file under panel/ or scripts/ names the upstream owner ──"
HITS=$(git grep -n -i -e "$FORBIDDEN" -- panel scripts 2>/dev/null || true)
if [ -z "$HITS" ]; then
    ok "git grep -i finds no mention of the upstream owner in panel/ or scripts/"
else
    bad "the upstream owner is still named in $(printf '%s\n' "$HITS" | wc -l) line(s):"
    printf '%s\n' "$HITS" | cut -c1-160 | sed 's/^/      /'
fi

echo "── 2. the update and install paths contact no release host themselves ──"
# A CLOSED list on purpose: other features legitimately call GitHub (OAuth,
# git status, Joomla, nixpacks, typst) and are out of scope. deploy-demo.sh
# keeps its URLs, without a default repository.
CLOSED_LIST=(
    scripts/update.sh
    scripts/agent-self-update.sh
    scripts/install-agent.sh
    scripts/install.sh
    scripts/setup.sh
    panel/backend/src/services/telemetry_collector.rs
    panel/backend/src/services/panel_update.rs
    panel/agent/src/routes/panel_update.rs
    panel/agent/src/services/phone_home.rs
    panel/agent/src/services/release_verify.rs
)
for f in "${CLOSED_LIST[@]}"; do
    if ! git ls-files --error-unmatch -- "$f" >/dev/null 2>&1; then
        bad "$f is not tracked - the closed list no longer matches the tree"
        continue
    fi
    H=$(git grep -n -e "api.github.com" -e "releases/download" -e "raw.githubusercontent" -- "$f" 2>/dev/null || true)
    if [ -z "$H" ]; then
        ok "$f names no release host"
    else
        bad "$f still names a release host:"
        printf '%s\n' "$H" | cut -c1-160 | sed 's/^/      /'
    fi
done

echo "── 3. negative control: the search is not blind ──"
# The same pathspec machinery must find a word that is known to be there, or a
# broken git grep (wrong cwd, no repository) would read as a clean tree.
if git grep -q -e "CyberHunter" -- scripts/setup.sh 2>/dev/null; then
    ok "git grep finds a known word in scripts/setup.sh (the search works)"
else
    bad "git grep cannot find 'CyberHunter' in scripts/setup.sh - section 1 is measuring nothing"
fi

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
