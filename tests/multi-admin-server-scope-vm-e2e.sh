#!/usr/bin/env bash
# multi-admin-server-scope-vm-e2e.sh - two administrators on one live install.
#
# End-to-end, against the lab VM, from the Windows host (Git Bash). The source
# shape is pinned by tests/multi-admin-server-scope-pin-e2e.sh; this one proves
# the behaviour with real accounts:
#
#   §1 premise: admin 2 sees the local server in GET /api/servers, and the local
#      row is NOT admin 2's (it belongs to the first administrator)
#   §2 admin 2 with X-Server-Id = local gets 200 on ServerScope routes
#      (v3.0.0-rc.4: 403 "Server not found or access denied" on every one)
#   §3 admin 1 is unchanged, with and without the header
#   §4 a REMOTE row registered by admin 1 stays admin 1's: admin 2 gets 403.
#      The row is inserted by psql for the test and deleted afterwards.
#   §5 the role is read from the database: admin 2 demoted to `user` by psql,
#      same token, gets 403; restored to `admin` afterwards
#   §6 a non-admin with X-Server-Id = local still gets 403 (optional)
#
# PREREQUISITES (created in the VM with the owner's agreement, never by this
# script): two admin accounts, admin 1 being the first one (owner of the local
# row); optionally a non-admin account.
#
# SECRETS are read from files and never printed. Directory $MA_SECRETS
# (default lab/secrets/multi-admin), one value per file:
#   panel_url        https://<vm-ip>:8443
#   ssh_target       lab@<vm-ip>   (key: ~/.ssh/dockpanel_lab, passwordless sudo)
#   admin1_email admin1_password [admin1_totp_secret]
#   admin2_email admin2_password [admin2_totp_secret]
#   [nonadmin_email nonadmin_password]
#
# Usage: bash tests/multi-admin-server-scope-vm-e2e.sh

set -uo pipefail
cd "$(dirname "$0")/.."

SECRETS="${MA_SECRETS:-lab/secrets/multi-admin}"
[ -d "$SECRETS" ] || { echo "missing secrets directory $SECRETS"; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 2; }

MA_SECRETS_DIR="$SECRETS" exec python3 - <<'PYEOF'
import base64, hashlib, hmac, json, os, re, ssl, struct, subprocess, sys, time, uuid
import urllib.request, urllib.error

SECRETS = os.environ["MA_SECRETS_DIR"]
PASS = FAIL = SKIP = 0

def secret(name, required=True):
    p = os.path.join(SECRETS, name)
    if not os.path.exists(p):
        if required:
            raise SystemExit(f"missing secret file {name}")
        return None
    with open(p, encoding="utf-8") as f:
        return f.read().strip()

PANEL = secret("panel_url").rstrip("/")
SSH = secret("ssh_target")
SSH_KEY = os.path.expanduser("~/.ssh/dockpanel_lab")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE   # lab VM: self-signed certificate

def ok(m):
    global PASS; PASS += 1; print(f"  \033[32m✓\033[0m {m}")
def bad(m):
    global FAIL; FAIL += 1; print(f"  \033[31m✗\033[0m {m}")
def skip(m):
    global SKIP; SKIP += 1; print(f"  \033[33m⊘\033[0m {m} (skipped)")
def check(cond, m):
    ok(m) if cond else bad(m)

def totp(b32):
    key = base64.b32decode(b32.upper() + "=" * (-len(b32) % 8))
    h = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)

def http(method, path, cookie=None, server_id=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(PANEL + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Origin", PANEL)
    req.add_header("X-Requested-With", "XMLHttpRequest")
    if cookie:
        req.add_header("Cookie", f"token={cookie}")
    if server_id:
        req.add_header("X-Server-Id", server_id)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
            raw, status, headers = r.read(), r.status, r.headers
    except urllib.error.HTTPError as e:
        raw, status, headers = e.read(), e.code, e.headers
    try:
        js = json.loads(raw or b"null")
    except ValueError:
        js = None
    return status, js, headers

def login(prefix):
    email, pw = secret(f"{prefix}_email", False), secret(f"{prefix}_password", False)
    if not email or not pw:
        return None, None
    st, js, hd = http("POST", "/api/auth/login", body={"email": email, "password": pw})
    if st == 200 and js and js.get("requires_2fa"):
        t = secret(f"{prefix}_totp_secret", False)
        if not t:
            return None, email
        st, js, hd = http("POST", "/api/auth/2fa/verify",
                          body={"temp_token": js["temp_token"], "code": totp(t)})
    for c in hd.get_all("Set-Cookie") or []:
        m = re.match(r"token=([^;]+)", c)
        if m and m.group(1):
            return m.group(1), email
    return None, email

def psql(sql):
    # Values are fixed UUIDs/emails from this script's own secrets, quoted below.
    cmd = "sudo docker exec dockpanel-postgres psql -U dockpanel -d dockpanel -qtAc " + \
          "'" + sql.replace("'", "'\\''") + "'"
    r = subprocess.run(["ssh", "-i", SSH_KEY, "-o", "BatchMode=yes", SSH, cmd],
                       capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout.strip()

def q(s):
    return "'" + s.replace("'", "''") + "'"

DENIED = "Server not found or access denied"
ROUTES = ["/api/dashboard/intelligence", "/api/databases", "/api/apps"]

print("\n==============================================")
print("  multi-admin ServerScope - live VM")
print("==============================================\n")

a1, e1 = login("admin1")
a2, e2 = login("admin2")
if not a1 or not a2:
    bad("login of both administrators")
    print(f"\n  PASS {PASS}  FAIL {FAIL}  SKIP {SKIP}\n"); sys.exit(1)
ok("both administrators logged in")

# ── §1 premise ───────────────────────────────────────────────────────────────
st, servers, _ = http("GET", "/api/servers", cookie=a2)
local = next((s for s in (servers or []) if isinstance(s, dict) and s.get("is_local")), None)
check(st == 200 and local is not None, "§1 admin 2 sees the local server in GET /api/servers")
if not local:
    print(f"\n  PASS {PASS}  FAIL {FAIL}  SKIP {SKIP}\n"); sys.exit(1)
LOCAL = local["id"]
rc, owner = psql(f"SELECT u.email FROM servers s JOIN users u ON u.id = s.user_id WHERE s.id = {q(LOCAL)}")
check(rc == 0 and owner == e1, "§1 the local row belongs to admin 1")
check(rc == 0 and owner != e2, "§1 the local row is NOT admin 2's (the case that failed)")

# ── §2 admin 2 on the local server ───────────────────────────────────────────
for r in ROUTES:
    st, js, _ = http("GET", r, cookie=a2, server_id=LOCAL)
    check(st == 200, f"§2 admin 2 GET {r} with X-Server-Id=local -> {st} (want 200)")

# ── §3 admin 1 unchanged ─────────────────────────────────────────────────────
for r in ROUTES:
    st1, _, _ = http("GET", r, cookie=a1, server_id=LOCAL)
    st0, _, _ = http("GET", r, cookie=a1)
    check(st1 == 200 and st0 == 200, f"§3 admin 1 GET {r} with/without header -> {st1}/{st0}")

# ── §4 a remote row of admin 1 stays admin 1's ──────────────────────────────
REMOTE = str(uuid.uuid4())
rc, _ = psql(f"INSERT INTO servers (id, user_id, name, agent_token, status, is_local) "
             f"SELECT {q(REMOTE)}, id, 'ma-e2e-remote', {q('ma-e2e-' + REMOTE)}, 'offline', false "
             f"FROM users WHERE email = {q(e1)}")
if rc != 0:
    bad("§4 could not insert the test remote row")
else:
    try:
        st, js, _ = http("GET", ROUTES[0], cookie=a2, server_id=REMOTE)
        check(st == 403 and (js or {}).get("error") == DENIED,
              f"§4 admin 2 on admin 1's remote server -> {st} (want 403 '{DENIED}')")
        st, js, _ = http("GET", ROUTES[0], cookie=a1, server_id=REMOTE)
        check(st != 403, f"§4 admin 1 on its own remote server passes the scope -> {st} (offline agent, not 403)")
    finally:
        rc, _ = psql(f"DELETE FROM servers WHERE id = {q(REMOTE)}")
        check(rc == 0, "§4 test remote row deleted")

# ── §5 the role comes from the database ─────────────────────────────────────
rc, _ = psql(f"UPDATE users SET role = 'user' WHERE email = {q(e2)} AND role = 'admin'")
if rc != 0:
    bad("§5 could not demote admin 2")
else:
    try:
        st, js, _ = http("GET", ROUTES[1], cookie=a2, server_id=LOCAL)
        check(st == 403 and (js or {}).get("error") == DENIED,
              f"§5 demoted admin 2, same token, X-Server-Id=local -> {st} (want 403)")
    finally:
        rc, role = psql(f"UPDATE users SET role = 'admin' WHERE email = {q(e2)} RETURNING role")
        check(rc == 0 and role == "admin", "§5 admin 2 restored to admin")

# ── §6 a non-admin keeps the owner rule ─────────────────────────────────────
n, _ = login("nonadmin")
if not n:
    skip("§6 no non-admin account configured")
else:
    st, js, _ = http("GET", ROUTES[1], cookie=n, server_id=LOCAL)
    check(st == 403 and (js or {}).get("error") == DENIED,
          f"§6 non-admin with X-Server-Id=local -> {st} (want 403)")

print("\n----------------------------------------------")
print(f"  PASS {PASS}  FAIL {FAIL}  SKIP {SKIP}")
print("----------------------------------------------\n")
sys.exit(1 if FAIL else 0)
PYEOF
