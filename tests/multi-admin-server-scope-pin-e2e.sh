#!/usr/bin/env bash
# multi-admin-server-scope-pin-e2e.sh
#
# A SECOND ADMINISTRATOR MAY TARGET THE LOCAL SERVER THROUGH `X-Server-Id`.
#
#   `GET /api/servers` lists every server to an administrator, so the frontend
#   (`ServerContext.tsx`) selects the local row and `api.ts` sends its id as
#   `X-Server-Id`. `ServerScope` then accepted only `servers.user_id = caller`,
#   while the local row belongs to the FIRST administrator: a second one read
#   "Server not found or access denied" on every page (v3.0.0-rc.4).
#
#   §A  ServerScope's lookup is the named predicate, not an inline owner check.
#   §B  The predicate keeps the owner arm, adds an admin arm bounded to
#       `is_local`, and reads the role from `users`, not from the token.
#   §C  Context arms, so a reader that reads nothing cannot pass.
#
# §A and §B were run against main (92e5b3a) and required to be red.
#
# This is a SOURCE pin. The behaviour with two real administrators is exercised
# by tests/multi-admin-server-scope-vm-e2e.sh on a live install.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=============================================="
echo "  multi-admin ServerScope - source pins"
echo "=============================================="
echo

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

code() {
  perl -0777 -pe '
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
    s{^\s*///.*$}{}gm;
  ' "$1"
}
flat() { tr '\n' ' ' <<< "$1" | tr -s ' '; }
has()  { grep -qF -- "$2" <<< "$1"; }

AUTH=panel/backend/src/auth.rs

# The ServerScope impl, from its `impl` line to the next top-level closing brace.
IMPL=$(flat "$(code "$AUTH" | awk '/^impl FromRequestParts<AppState> for ServerScope/{s=1} s{print} s&&/^}/{exit}')")

# The constant's string, joined across the Rust line continuations.
PRED=$(perl -0777 -ne 'if (/pub const SERVER_SCOPE_PREDICATE: &str = (.*?);\n/s) { $p=$1; $p =~ s/\\\n\s*//g; $p =~ s/"//g; $p =~ s/\s+/ /g; print $p }' "$AUTH")

# ── §A ────────────────────────────────────────────────────────────────────────
if [ -z "$IMPL" ]; then
  bad "A0 could not extract the ServerScope impl"
else
  ok "A0 ServerScope impl extracted"
  if has "$IMPL" 'WHERE id = $1 AND user_id = $2'; then
    bad "A1 ServerScope still checks owner-only - a second admin is refused the local server"
  else
    ok "A1 ServerScope no longer carries the owner-only lookup"
  fi
  if has "$IMPL" 'sqlx::query_as(SERVER_SCOPE_PREDICATE)'; then
    ok "A2 ServerScope looks the server up through SERVER_SCOPE_PREDICATE"
  else
    bad "A2 ServerScope does not use SERVER_SCOPE_PREDICATE"
  fi
  if has "$IMPL" 'Server not found or access denied'; then
    ok "A3 the refusal for everything else is unchanged"
  else
    bad "A3 the refusal sentence changed or vanished"
  fi
  if has "$IMPL" 'claims.role'; then
    bad "A4 ServerScope decides on the token's role"
  else
    ok "A4 ServerScope does not decide on the token's role"
  fi
fi

# ── §B ────────────────────────────────────────────────────────────────────────
if [ -z "$PRED" ]; then
  bad "B0 SERVER_SCOPE_PREDICATE not found"
else
  ok "B0 SERVER_SCOPE_PREDICATE found"
  if has "$PRED" 'sv.id = $1 AND (sv.user_id = $2 OR'; then
    ok "B1 owner arm kept - non-admins keep the owner rule"
  else
    bad "B1 owner arm missing"
  fi
  if has "$PRED" '(sv.is_local AND EXISTS ('; then
    ok "B2 admin arm is bounded to the local row"
  else
    bad "B2 admin arm is not bounded to is_local"
  fi
  if has "$PRED" "FROM users u WHERE u.id = \$2 AND u.role = 'admin'"; then
    ok "B3 admin arm reads users.role from the database"
  else
    bad "B3 admin arm does not read the role from users"
  fi
  if grep -qE 'OR sv\.is_local( OR|\))' <<< "$PRED"; then
    bad "B4 is_local stands alone - every account would reach the local server"
  else
    ok "B4 is_local never grants on its own"
  fi
fi

# ── §C context ───────────────────────────────────────────────────────────────
if [ "$(grep -c 'ServerScope' "$AUTH")" -ge 3 ]; then
  ok "C1 auth.rs still defines ServerScope (control)"
else
  bad "C1 auth.rs barely mentions ServerScope - the reader is broken"
fi
if has "$(flat "$(code panel/backend/src/routes/servers.rs)")" 'WHERE ($2 OR user_id = $1)'; then
  ok "C2 GET /api/servers still lists every server to an admin (the premise of this pin)"
else
  bad "C2 servers::list changed shape - re-read whether this pin still matters"
fi

echo
echo "----------------------------------------------"
printf '  PASS %d  FAIL %d\n' "$PASS" "$FAIL"
echo "----------------------------------------------"
echo
[ "$FAIL" -eq 0 ] || exit 1
exit 0
