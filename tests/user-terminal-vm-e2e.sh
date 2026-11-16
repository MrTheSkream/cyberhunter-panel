#!/usr/bin/env bash
# user-terminal-vm-e2e.sh - feature 09 (user terminal), contract A-8.
#
# End-to-end, against the lab VM, from the Windows host (Git Bash). Covers §8
# and §9 of conception/09-terminal-utilisateur.md:
#
#   §1 refusals: dp_ key, non-admin, admin without TOTP in this session, admin
#      without a mapping, mapping to root / uid < 1000, replayed ticket, wrong
#      Origin
#   §2 in the shell: id -u, /home/<user> and ~/.claude visible, `sudo -n true`
#      fails cleanly, `sudo` with the Linux password succeeds
#   §3 persistence: a counter in tmux survives a WebSocket cut and
#      `systemctl restart dockpanel-agent`
#   §4 paste: 200 lines in bracketed paste arrive intact (sha256)
#   §5 non-regression: @server is root, keeps `cd ..`, keeps the 30 min limit;
#      a site shell is www-data, rbash, blocklist, NO_NEW_PRIVS (sudo refused)
#   §6 lockdown: new tickets refused, open connection cut, tmux survives
#   §7 panic: connection AND tmux session killed (runs last: it locks down)
#
# PREREQUISITES (created in the VM with the owner's agreement, never by this
# script):
#   - an admin panel account WITH TOTP, linked to a test Linux user whose
#     "Start command" is EMPTY (the tests type into the shell, not into claude);
#   - a second admin WITHOUT TOTP and without a mapping (optional: §1 skips);
#   - a non-admin account; a dp_ API key of the admin; optionally a site id.
#
# SECRETS are read from files and never printed. Directory $UT_SECRETS
# (default lab/secrets/user-terminal), one value per file:
#   panel_url          https://<vm-ip>:8443
#   ssh_target         lab@<vm-ip>          (key: ~/.ssh/dockpanel_lab, passwordless sudo)
#   admin_email  admin_password  admin_totp_secret (base32)
#   linux_user   linux_password
#   nonadmin_email  nonadmin_password
#   dp_key
#   admin2_email  admin2_password            (optional)
#   site_id                                  (optional)
#
# Needs python3 with the `websockets` package on the host.
# Usage: bash tests/user-terminal-vm-e2e.sh

set -uo pipefail
cd "$(dirname "$0")/.."

SECRETS="${UT_SECRETS:-lab/secrets/user-terminal}"
[ -d "$SECRETS" ] || { echo "missing secrets directory $SECRETS"; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 2; }
python3 -c 'import websockets' 2>/dev/null || { echo "pip install websockets"; exit 2; }

PY=$(mktemp "${TMPDIR:-/tmp}/ut-e2e.XXXXXX.py")
trap 'rm -f "$PY"' EXIT

cat > "$PY" <<'PYEOF'
import asyncio, base64, hashlib, hmac, json, os, re, ssl, struct, subprocess, sys, time
import urllib.request, urllib.error, urllib.parse
import websockets

SECRETS = os.environ["UT_SECRETS_DIR"]
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
U = urllib.parse.urlparse(PANEL)
WS_BASE = ("wss" if U.scheme == "https" else "ws") + "://" + U.netloc
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
    msg = struct.pack(">Q", int(time.time()) // 30)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)

def http(method, path, cookie=None, bearer=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(PANEL + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Origin", PANEL)
    if cookie:
        req.add_header("Cookie", f"token={cookie}")
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
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

def login(email, password, totp_secret=None):
    st, js, hd = http("POST", "/api/auth/login", body={"email": email, "password": password})
    if st == 200 and js and js.get("requires_2fa"):
        if not totp_secret:
            return None
        st, js, hd = http("POST", "/api/auth/2fa/verify",
                          body={"temp_token": js["temp_token"], "code": totp(totp_secret)})
    for c in hd.get_all("Set-Cookie") or []:
        m = re.match(r"token=([^;]+)", c)
        if m and m.group(1):
            return m.group(1)
    return None

def ssh(cmd, timeout=60):
    r = subprocess.run(["ssh", "-i", SSH_KEY, "-o", "BatchMode=yes", SSH, cmd],
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip()

def user_ticket(cookie):
    return http("GET", "/api/terminal/user/token", cookie=cookie)

LAST_DIAL = [0.0]

async def dial(token, origin=PANEL, cols=120, rows=40):
    # The agent allows one terminal connection per clock second (429 otherwise).
    wait = LAST_DIAL[0] + 1.1 - time.monotonic()
    if wait > 0:
        await asyncio.sleep(wait)
    LAST_DIAL[0] = time.monotonic()
    url = f"{WS_BASE}/agent/terminal/ws?token={urllib.parse.quote(token)}&cols={cols}&rows={rows}"
    hdrs = {"Origin": origin} if origin else {}
    try:
        return await websockets.connect(url, ssl=CTX if url.startswith("wss") else None,
                                        additional_headers=hdrs, max_size=None, open_timeout=20)
    except TypeError:   # websockets < 14
        return await websockets.connect(url, ssl=CTX if url.startswith("wss") else None,
                                        extra_headers=hdrs, max_size=None, open_timeout=20)

def handshake_status(exc):
    for attr in ("response", ):
        r = getattr(exc, attr, None)
        if r is not None and hasattr(r, "status_code"):
            return r.status_code
    return getattr(exc, "status_code", None)

async def expect_refused(token, origin=PANEL):
    try:
        ws = await dial(token, origin)
    except Exception as e:
        return handshake_status(e) or -1
    await ws.close()
    return 101

class Term:
    def __init__(self, ws):
        self.ws, self.buf = ws, ""
    async def send(self, data):
        await self.ws.send(json.dumps({"type": "input", "data": data}))
    async def wait(self, pattern, timeout=20):
        rx = re.compile(pattern)
        end = time.monotonic() + timeout
        while True:
            m = rx.search(self.buf)
            if m:
                self.buf = self.buf[m.end():]
                return m
            left = end - time.monotonic()
            if left <= 0:
                return None
            try:
                self.buf += await asyncio.wait_for(self.ws.recv(), left)
            except (asyncio.TimeoutError, websockets.ConnectionClosed):
                return None
    async def run(self, cmd, tag, timeout=20):
        # The marker is computed by the shell, so the echoed command never matches.
        await self.send(f"{cmd}; echo UT$((40+2)){tag}:$?:END\r")
        m = await self.wait(rf"UT42{tag}:(\d+):END", timeout)
        return None if m is None else int(m.group(1))
    async def closed_within(self, seconds):
        end = time.monotonic() + seconds
        try:
            while time.monotonic() < end:
                await asyncio.wait_for(self.ws.recv(), end - time.monotonic())
        except websockets.ConnectionClosed:
            return True
        except asyncio.TimeoutError:
            return False
        return False

async def open_user_term(cookie):
    st, js, _ = user_ticket(cookie)
    if st != 200:
        return None, st
    return Term(await dial(js["token"])), 200

LOGIN = secret("linux_user")

def tmux_active():
    _, out = ssh(f"sudo systemctl --user -M {LOGIN}@ is-active dockpanel-tmux.service")
    return out == "active"

# ── scenarios ────────────────────────────────────────────────────────────

async def s_refusals(admin):
    print("§1 refusals")
    st, _, _ = http("GET", "/api/terminal/user/token", bearer=secret("dp_key"))
    check(st == 403, f"a dp_ key gets no ticket ({st})")
    na = login(secret("nonadmin_email"), secret("nonadmin_password"))
    if na:
        st, _, _ = user_ticket(na)
        check(st == 403, f"a non-admin gets no ticket ({st})")
    else:
        bad("non-admin login failed")
    e2, p2 = secret("admin2_email", False), secret("admin2_password", False)
    if e2 and p2:
        c2 = login(e2, p2)
        st, js, _ = user_ticket(c2) if c2 else (0, None, None)
        check(st == 403 and "mfa_required" in json.dumps(js), f"an admin session without TOTP is refused with mfa_required ({st})")
    else:
        skip("admin without TOTP / without mapping")
    # Mapping to root and to a system uid is refused (A-2 reasons relayed by B-4).
    st, js, _ = http("GET", "/api/terminal/user/accounts", cookie=admin)
    me = None
    if st == 200 and isinstance(js, list):
        me = next((a for a in js if a.get("linux_user") == LOGIN), None)
    elif st == 200 and isinstance(js, dict):
        me = next((a for a in js.get("accounts", []) if a.get("linux_user") == LOGIN), None)
    if me:
        for target in ("root", "daemon"):
            st, js, _ = http("PUT", f"/api/terminal/user/accounts/{me['user_id']}", cookie=admin, body={
                "linux_user": target, "autostart_command": None, "record": False,
                "proof": {"password": secret("admin_password")}})
            check(st in (400, 403) and js and js.get("reasons"), f"a mapping to {target} is refused with reasons ({st})")
        # Restore the real mapping, in case a refusal was not one.
        http("PUT", f"/api/terminal/user/accounts/{me['user_id']}", cookie=admin, body={
            "linux_user": LOGIN, "autostart_command": None, "record": False,
            "proof": {"password": secret("admin_password")}})
    else:
        skip("mapping refusals (could not find the admin's mapping)")
    # Replay and Origin.
    st, js, _ = user_ticket(admin)
    if st != 200:
        bad(f"the linked admin gets a ticket ({st})")
        return
    ok("the linked admin with TOTP gets a ticket")
    ws = await dial(js["token"])
    await ws.close()
    code = await expect_refused(js["token"])
    check(code == 401, f"a replayed ticket is refused ({code})")
    st, js, _ = user_ticket(admin)
    code = await expect_refused(js["token"], origin="https://evil.example.net")
    check(code == 403, f"a foreign Origin is refused ({code})")
    st, js, _ = user_ticket(admin)
    code = await expect_refused(js["token"], origin=None)
    check(code == 403, f"a missing Origin is refused ({code})")

async def s_shell(admin):
    print("§2 in the shell")
    t, st = await open_user_term(admin)
    if not t:
        bad(f"cannot open the user terminal ({st})"); return
    _, want_uid = ssh(f"id -u {LOGIN}")
    await t.send(f"echo UT$((1+1))ID$(id -u)X\r")
    m = await t.wait(r"UT2ID(\d+)X")
    check(m and m.group(1) == want_uid, f"id -u is the Linux user's uid ({m.group(1) if m else 'no answer'})")
    check(await t.run(f"ls /home/{LOGIN} >/dev/null", "LS") == 0, f"/home/{LOGIN} is visible")
    check(await t.run("test -d ~/.claude", "CL") == 0, "~/.claude is visible")
    rc = await t.run("sudo -k; sudo -n true 2>/dev/null", "SN")
    check(rc is not None and rc != 0, f"sudo -n true fails with a non-zero code ({rc})")
    check(await t.run("true", "ALIVE") == 0, "the terminal survives the refused sudo")
    await t.send("sudo -k; sudo -p 'UTPW:' true; echo UT$((40+2))SP:$?:END\r")
    if await t.wait(r"UTPW:"):
        await t.send(secret("linux_password") + "\r")
        m = await t.wait(r"UT42SP:(\d+):END", 30)
        check(m and m.group(1) == "0", "sudo with the Linux password succeeds")
    else:
        bad("sudo did not prompt for the password")
    await t.run("sudo -k", "K")
    await t.ws.close()

async def s_persistence(admin):
    print("§3 persistence")
    t, st = await open_user_term(admin)
    if not t:
        bad(f"cannot open the user terminal ({st})"); return
    await t.run("(while :; do date +%s > ~/.ut-counter; sleep 1; done) & echo $! > ~/.ut-counter.pid", "BG")
    await asyncio.sleep(3)
    await t.ws.close()                         # cut the WebSocket
    _, a = ssh(f"sudo cat /home/{LOGIN}/.ut-counter")
    await asyncio.sleep(4)
    _, b = ssh(f"sudo cat /home/{LOGIN}/.ut-counter")
    check(a.isdigit() and b.isdigit() and int(b) > int(a), "the counter keeps running after the WebSocket is cut")
    ssh("sudo systemctl restart dockpanel-agent", timeout=120)
    await asyncio.sleep(8)
    _, c = ssh(f"sudo cat /home/{LOGIN}/.ut-counter")
    check(c.isdigit() and b.isdigit() and int(c) > int(b), "the counter keeps running across an agent restart")
    t, st = await open_user_term(admin)
    if not t:
        bad(f"cannot reattach after the restart ({st})"); return
    check(await t.run("kill -0 $(cat ~/.ut-counter.pid)", "PID") == 0, "reattached to the same session: the job is still there")
    await t.run("kill $(cat ~/.ut-counter.pid); rm -f ~/.ut-counter ~/.ut-counter.pid", "CLEAN")
    await t.ws.close()

async def s_paste(admin):
    print("§4 paste")
    t, st = await open_user_term(admin)
    if not t:
        bad(f"cannot open the user terminal ({st})"); return
    lines = [f"line {i:03d} {'x' * (i % 70)} é😀" for i in range(1, 201)]
    want = hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()
    await t.run("rm -f ~/.ut-paste", "RM")
    await t.send("cat > ~/.ut-paste\r")
    await asyncio.sleep(1)
    payload = "\x1b[200~" + "\r".join(lines) + "\r" + "\x1b[201~"
    # 16 KiB frames like the page, cut on character boundaries.
    chunk = ""
    for ch in payload:
        if len((chunk + ch).encode()) > 16 * 1024:
            await t.send(chunk)
            chunk = ""
        chunk += ch
    if chunk:
        await t.send(chunk)
    await asyncio.sleep(2)
    await t.send("\x04")
    await t.send(f"echo UT$((1+1))H$(sha256sum < ~/.ut-paste | cut -c1-64)X\r")
    m = await t.wait(r"UT2H([0-9a-f]{64})X", 30)
    check(m and m.group(1) == want, "200 pasted lines arrive intact (sha256 matches)")
    await t.run("rm -f ~/.ut-paste", "RM2")
    await t.ws.close()

async def s_regression(admin):
    print("§5 non-regression of @server and site shells")
    st, js, _ = http("GET", "/api/terminal/token", cookie=admin)
    if st == 200:
        t = Term(await dial(js["token"]))
        await t.send("echo UT$((1+1))ID$(id -u)X\r")
        m = await t.wait(r"UT2ID(\d+)X")
        check(m and m.group(1) == "0", "@server is root")
        check(await t.run("cd .. && cd /root", "CD") == 0, "@server keeps cd ..")
        await t.ws.close()
    else:
        bad(f"@server ticket ({st})")
    rc, n = ssh("sudo grep -c 'Session timed out (30 minutes)' /usr/local/bin/dockpanel-agent")
    check(n.isdigit() and int(n) >= 1, "the 30 min limit of the other shells is still in the agent")
    site = secret("site_id", False)
    if not site:
        skip("site shell (no site_id)"); return
    st, js, _ = http("GET", f"/api/terminal/token?site_id={site}", cookie=admin)
    if st != 200:
        bad(f"site ticket ({st})"); return
    t = Term(await dial(js["token"]))
    await t.send("echo UT$((1+1))U$(id -un)X\r")
    m = await t.wait(r"UT2U([a-z_-]+)X")
    check(m and m.group(1) == "www-data", "a site shell is www-data")
    await t.send("echo UT$((1+1))R$(shopt -q restricted_shell && echo yes)X\r")
    m = await t.wait(r"UT2R(\w*)X")
    check(m and m.group(1) == "yes", "a site shell is rbash")
    await t.send("sudo id\r")
    check(await t.wait(r"Blocked:", 10) is not None, "the site blocklist still refuses sudo")
    await t.send("grep NoNewPrivs /proc/self/status | tr -d ' \\t' | sed 's/^/UT/'\r")
    m = await t.wait(r"UTNoNewPrivs:(\d)")
    check(m and m.group(1) == "1", "a site shell still has NO_NEW_PRIVS")
    await t.ws.close()

async def s_lockdown(admin):
    print("§6 lockdown")
    t, st = await open_user_term(admin)
    if not t:
        bad(f"cannot open the user terminal ({st})"); return
    await t.run("true", "W")
    st, _, _ = http("POST", "/api/security/lockdown/activate", cookie=admin, body={"reason": "user-terminal e2e"})
    check(st == 200, f"lockdown activated ({st})")
    check(await t.closed_within(20), "the open connection is cut")
    st, _, _ = user_ticket(admin)
    check(st == 503, f"no new ticket during lockdown ({st})")
    check(tmux_active(), "the tmux session survives the lockdown")
    st, _, _ = http("POST", "/api/security/lockdown/deactivate", cookie=admin, body={})
    check(st == 200, f"lockdown deactivated ({st})")

async def s_panic(admin):
    print("§7 panic")
    t, st = await open_user_term(admin)
    if not t:
        bad(f"cannot open the user terminal ({st})"); return
    await t.run("true", "W")
    st, js, _ = http("POST", "/api/security/panic", cookie=admin, body={})
    check(st == 200, f"panic accepted ({st})")
    check(await t.closed_within(20), "panic cuts the connection")
    await asyncio.sleep(3)
    check(not tmux_active(), "panic stops the tmux session")
    check("user_terminals_killed" in json.dumps(js or {}), "the panic report carries user_terminals_killed")
    http("POST", "/api/security/lockdown/deactivate", cookie=admin, body={})

async def main():
    admin = login(secret("admin_email"), secret("admin_password"), secret("admin_totp_secret"))
    if not admin:
        bad("admin login with TOTP failed"); return
    for s in (s_refusals, s_shell, s_persistence, s_paste, s_regression, s_lockdown):
        try:
            await asyncio.wait_for(s(admin), 300)
        except Exception as e:
            bad(f"{s.__name__} raised {type(e).__name__}")
        admin = login(secret("admin_email"), secret("admin_password"), secret("admin_totp_secret")) or admin
    try:
        await asyncio.wait_for(s_panic(admin), 120)
    except Exception as e:
        bad(f"s_panic raised {type(e).__name__}")

asyncio.run(main())
print(f"\nPASS {PASS} / FAIL {FAIL} / SKIP {SKIP}")
sys.exit(1 if FAIL else 0)
PYEOF

UT_SECRETS_DIR="$SECRETS" python3 "$PY"
