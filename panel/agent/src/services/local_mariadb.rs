//! Shared local MariaDB server (`kind='local'`, 05-import-hestia W2-A).
//!
//! One MariaDB instance per host, listening on `127.0.0.1:3306` and on the
//! socket [`SOCKET`], so `localhost` in an imported `wp-config.php` works the
//! way it did under HestiaCP. The agent is root and administers the server as
//! `root@localhost` through the socket (`unix_socket` authentication).
//!
//! Rules every function here keeps:
//! - SQL always travels on the client's STDIN, never on its argv (`ps` shows argv,
//!   and account statements carry passwords or `mysql_native_password` hashes).
//! - Identifiers are validated ([`is_valid_local_name`], [`is_valid_local_user`])
//!   BEFORE they are interpolated, and always sit between backticks / quotes.
//! - A statement batch that carries a secret never forwards the server's error
//!   text: MariaDB echoes the statement ("near '...'"), hash included.
//! - Tenant SQL runs as a temporary account limited to its one database
//!   (`ch_tmp_<hex>`), with `--binary-mode` (no client commands such as `system`
//!   or `source` on piped input) and `--sandbox` when the client knows it.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::OnceCell;

use crate::safe_cmd::{safe_command, safe_command_unsandboxed};

pub const SOCKET: &str = "/run/mysqld/mysqld.sock";
pub const BIND: &str = "127.0.0.1:3306";
pub const CNF_PATH: &str = "/etc/mysql/mariadb.conf.d/99-cyberhunter.cnf";
/// `/etc/mysql` is outside the agent's `ReadWritePaths`: the cnf is rendered here
/// (writable) and copied into place with an unsandboxed `install`.
const STAGE_DIR: &str = "/var/lib/dockpanel/localdb";
pub const TMP_PREFIX: &str = "ch_tmp_";
/// Value of `SCHEMA_COMMENT` on a database created by a Hestia import job: the
/// proof, checked at the destructive point, that a re-import may drop it.
pub fn import_marker(migration_id: &str) -> String {
    format!("ch-import:{migration_id}")
}

const ADMIN_TIMEOUT: Duration = Duration::from_secs(120);
const QUERY_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_OUTPUT_BYTES: usize = 5 * 1024 * 1024;
const MAX_ROWS: usize = 1000;
const SYSTEM_SCHEMAS: &str = "'mysql','sys','information_schema','performance_schema'";

// ───────────────────────────── validation ─────────────────────────────

fn local_ident_ok(n: &str, max: usize) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= max
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
        // `..` is refused although the D1 regex admits it: the dump directory and
        // backup file validators refuse it, so such a database could never be
        // backed up or restored.
        && !n.contains("..")
}

/// Names the system owns, for databases AND accounts. Case-insensitive.
fn is_reserved(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    matches!(
        l.as_str(),
        "mysql" | "sys" | "information_schema" | "performance_schema" | "root" | "mariadb.sys"
            | "debian-sys-maint" | "mysql.sys" | "mysql.session" | "mysql.infoschema"
    ) || l.starts_with(TMP_PREFIX)
}

/// Local database name: `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`, no `..`, not reserved.
pub fn is_valid_local_name(n: &str) -> bool {
    local_ident_ok(n, 64) && !is_reserved(n)
}

/// Local account name: same charset, up to 80 characters, not reserved.
pub fn is_valid_local_user(n: &str) -> bool {
    local_ident_ok(n, 80) && !is_reserved(n)
}

/// `mysql_native_password` hash as HestiaCP stores it: `*` + 40 hex.
pub fn is_valid_mysql_hash(h: &str) -> bool {
    h.len() == 41 && h.starts_with('*') && h[1..].bytes().all(|c| c.is_ascii_hexdigit())
}

/// `sql_mode` value accepted in the cnf (`^[A-Z0-9_,]*$`); empty = non strict.
pub fn is_valid_sql_mode(s: &str) -> bool {
    s.len() <= 1024 && s.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_' || c == b',')
}

fn is_valid_charset(c: &str) -> bool {
    !c.is_empty() && c.len() <= 32 && c.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn password_ok(p: &str) -> bool {
    !p.is_empty() && p.len() <= 128 && !p.contains(['\0', '\n', '\r'])
}

/// Database name as a GRANT pattern: `_` and `%` are wildcards there, so
/// `adm-jim_x` would otherwise also cover `adm-jimXx`.
pub fn grant_db_pattern(name: &str) -> String {
    let mut s = String::with_capacity(name.len() + 4);
    for c in name.chars() {
        if c == '_' || c == '%' {
            s.push('\\');
        }
        s.push(c);
    }
    s
}

/// Body of a single-quoted SQL string literal (MariaDB rules: `\` escapes).
fn sql_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "''")
}

/// `` `name` `` for a VALIDATED identifier (no backtick can be in it).
fn ident(n: &str) -> String {
    format!("`{n}`")
}

fn account(user: &str, host: &str) -> String {
    format!("'{}'@'{}'", sql_str(user), host)
}

const HOSTS: [&str; 2] = ["localhost", "127.0.0.1"];

// ───────────────────────────── cnf ─────────────────────────────

/// The panel-managed server options (D1). `sql_mode: None` = MariaDB defaults.
pub fn render_cnf(sql_mode: Option<&str>) -> String {
    let mut s = String::from(
        "# Managed by CyberHunter - Panel (shared local MariaDB). Rewritten by the panel:\n\
         # change sql_mode from the Databases page, not here.\n\
         [mysqld]\n\
         bind-address=127.0.0.1\n\
         port=3306\n\
         character-set-server=utf8mb4\n\
         max_allowed_packet=256M\n\
         local_infile=0\n",
    );
    if let Some(m) = sql_mode {
        s.push_str(&format!("sql_mode=\"{m}\"\n"));
    }
    s
}

/// `sql_mode` written in our cnf, `None` when absent (defaults).
pub fn parse_cnf_sql_mode(content: &str) -> Option<String> {
    content.lines().find_map(|l| {
        let v = l.trim().strip_prefix("sql_mode")?.trim_start().strip_prefix('=')?.trim();
        Some(v.trim_matches(|c| c == '"' || c == '\'').to_string())
    })
}

async fn current_cnf() -> Option<String> {
    tokio::fs::read_to_string(CNF_PATH).await.ok()
}

async fn write_cnf(content: &str) -> Result<(), String> {
    tokio::fs::create_dir_all(STAGE_DIR)
        .await
        .map_err(|e| format!("Cannot prepare {STAGE_DIR}: {e}"))?;
    let staged = format!("{STAGE_DIR}/99-cyberhunter.cnf");
    tokio::fs::write(&staged, content)
        .await
        .map_err(|e| format!("Cannot stage the MariaDB config: {e}"))?;
    let out = safe_command_unsandboxed("install", &[])
        .args(["-D", "-m", "0644", "-o", "root", "-g", "root", &staged, CNF_PATH])
        .output_with_timeout(Duration::from_secs(60))
        .await?;
    if !out.status.success() {
        return Err(format!(
            "Cannot write {CNF_PATH}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

async fn remove_cnf() {
    let _ = safe_command_unsandboxed("rm", &[])
        .args(["-f", CNF_PATH])
        .output_with_timeout(Duration::from_secs(30))
        .await;
}

// ───────────────────────────── client ─────────────────────────────

static CLIENT: OnceCell<&'static str> = OnceCell::const_new();
static SANDBOX: OnceCell<bool> = OnceCell::const_new();

async fn client_bin() -> &'static str {
    CLIENT
        .get_or_init(|| async {
            for b in ["/usr/bin/mariadb", "/usr/local/bin/mariadb"] {
                if Path::new(b).exists() {
                    return "mariadb";
                }
            }
            "mysql"
        })
        .await
}

/// `--sandbox` (no `system`, `source`, `tee`...) exists from MariaDB 10.5.25 / 11.x.
async fn sandbox_flag() -> bool {
    *SANDBOX
        .get_or_init(|| async {
            match safe_command(client_bin().await).arg("--help").output().await {
                Ok(o) => String::from_utf8_lossy(&o.stdout).contains("--sandbox"),
                Err(_) => false,
            }
        })
        .await
}

/// Base command: no option files, socket only.
async fn client(user: &str) -> tokio::process::Command {
    let mut c = safe_command(client_bin().await);
    c.args(["--no-defaults", "--protocol=socket", "-S", SOCKET, "-u", user, "--binary-mode"]);
    if sandbox_flag().await {
        c.arg("--sandbox");
    }
    c
}

/// Run a batch as root through the socket. `secret`: the batch carries a password
/// or a hash, so the server's error text (which echoes the statement) is replaced
/// by a generic sentence.
async fn root_exec(sql: &str, database: Option<&str>, secret: bool) -> Result<String, String> {
    let mut cmd = client("root").await;
    cmd.args(["--batch", "--skip-column-names", "--default-character-set=utf8mb4"]);
    if let Some(db) = database {
        cmd.arg(db);
    }
    let (ok, out, err) = run_with_stdin(cmd, sql.as_bytes(), ADMIN_TIMEOUT, MAX_OUTPUT_BYTES).await?;
    if ok {
        return Ok(String::from_utf8_lossy(&out).into_owned());
    }
    if secret {
        Err("MariaDB refused an account statement (details withheld: the statement carries a credential)".into())
    } else {
        Err(trim_err(&err))
    }
}

fn trim_err(err: &[u8]) -> String {
    let s = String::from_utf8_lossy(err);
    let s = s.trim();
    if s.is_empty() {
        "MariaDB client failed without an error message".into()
    } else {
        s.chars().take(500).collect()
    }
}

/// Root query returning tab-separated rows (no header).
async fn root_rows(sql: &str) -> Result<Vec<Vec<String>>, String> {
    let out = root_exec(sql, None, false).await?;
    Ok(out
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect())
}

async fn root_scalar(sql: &str) -> Result<String, String> {
    Ok(root_rows(sql)
        .await?
        .into_iter()
        .next()
        .and_then(|r| r.into_iter().next())
        .unwrap_or_default())
}

/// Spawn `cmd`, write `input` on stdin, collect stdout (capped) and stderr.
async fn run_with_stdin(
    mut cmd: tokio::process::Command,
    input: &[u8],
    timeout: Duration,
    cap: usize,
) -> Result<(bool, Vec<u8>, Vec<u8>), String> {
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let input = input.to_vec();
    let run = async move {
        let mut child = cmd.spawn().map_err(|e| format!("Cannot run the MariaDB client: {e}"))?;
        let mut stdin = child.stdin.take().ok_or("no stdin")?;
        let mut stdout = child.stdout.take().ok_or("no stdout")?;
        let mut stderr = child.stderr.take().ok_or("no stderr")?;
        let w = async move {
            let _ = stdin.write_all(&input).await;
            let _ = stdin.shutdown().await;
        };
        let r = async {
            let mut buf = Vec::new();
            let mut chunk = vec![0u8; 64 * 1024];
            let mut overflow = false;
            loop {
                match stdout.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if buf.len() + n > cap {
                            overflow = true;
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                }
            }
            (buf, overflow)
        };
        let e = async {
            let mut buf = Vec::new();
            let _ = (&mut stderr).take(64 * 1024).read_to_end(&mut buf).await;
            buf
        };
        let (_, (out, overflow), err) = tokio::join!(w, r, e);
        if overflow {
            let _ = child.start_kill();
            return Err(format!("Query output too large (max {} MB)", cap / (1024 * 1024)));
        }
        let status = child.wait().await.map_err(|e| format!("MariaDB client wait error: {e}"))?;
        Ok((status.success(), out, err))
    };
    match tokio::time::timeout(timeout, run).await {
        Ok(r) => r,
        Err(_) => Err(format!("MariaDB client timed out ({}s)", timeout.as_secs())),
    }
}

// ───────────────────────────── status / install / config ─────────────────────────────

pub async fn is_installed() -> bool {
    ["/usr/sbin/mariadbd", "/usr/sbin/mysqld", "/usr/bin/mariadbd"]
        .iter()
        .any(|p| Path::new(p).exists())
}

/// Server facts in one round trip; `Err` when it does not answer.
async fn probe() -> Result<(String, String, bool, u64), String> {
    let rows = root_rows(&format!(
        "SELECT VERSION(), @@GLOBAL.sql_mode, \
         (SELECT COUNT(*) FROM information_schema.COLLATIONS WHERE COLLATION_NAME='utf8mb4_uca1400_ai_ci'), \
         (SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ({SYSTEM_SCHEMAS}))"
    ))
    .await?;
    let r = rows.into_iter().next().ok_or("empty answer")?;
    let get = |i: usize| r.get(i).cloned().unwrap_or_default();
    Ok((get(0), get(1), get(2).trim() != "0", get(3).trim().parse().unwrap_or(0)))
}

pub async fn is_running() -> bool {
    Path::new(SOCKET).exists() && root_exec("SELECT 1", None, false).await.is_ok()
}

pub async fn status() -> serde_json::Value {
    let installed = is_installed().await;
    let probed = if Path::new(SOCKET).exists() { probe().await.ok() } else { None };
    let configured = current_cnf().await.and_then(|c| parse_cnf_sql_mode(&c));
    serde_json::json!({
        "installed": installed || probed.is_some(),
        "running": probed.is_some(),
        "version": probed.as_ref().map(|p| p.0.clone()),
        "socket": SOCKET,
        "bind": BIND,
        "supports_uca1400": probed.as_ref().map(|p| p.2).unwrap_or(false),
        "databases": probed.as_ref().map(|p| p.3).unwrap_or(0),
        "sql_mode": configured,
        "sql_mode_effective": probed.as_ref().map(|p| p.1.clone()),
    })
}

async fn systemctl(args: &[&str]) -> Result<(), String> {
    let out = tokio::time::timeout(ADMIN_TIMEOUT, safe_command("systemctl").args(args).output())
        .await
        .map_err(|_| format!("systemctl {} timed out", args.join(" ")))?
        .map_err(|e| format!("systemctl could not run: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Restart and wait (30 s) for the server to answer again.
async fn restart_and_wait() -> Result<(), String> {
    systemctl(&["restart", "mariadb"]).await?;
    for _ in 0..30 {
        if is_running().await {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err("MariaDB did not come back within 30 seconds after the restart".into())
}

/// mariadb.org 11.4 LTS apt source for this release, `Err` when not offered.
async fn add_mariadb_org_repo() -> Result<(), String> {
    let id = crate::services::pkg::os_release_value("ID").await.unwrap_or_default();
    let id = id.trim_matches('"').to_string();
    let codename = crate::services::pkg::os_release_value("VERSION_CODENAME")
        .await
        .unwrap_or_default()
        .trim_matches('"')
        .to_string();
    if !matches!(id.as_str(), "ubuntu" | "debian") || codename.is_empty()
        || !codename.bytes().all(|c| c.is_ascii_lowercase())
    {
        return Err(format!("mariadb.org has no repository for {id} {codename}"));
    }
    // The Release probe comes first: a suite mariadb.org does not publish must fall
    // back to the distribution package, not leave a broken apt source behind.
    let script = format!(
        "set -e; curl -fsSI https://deb.mariadb.org/11.4/{id}/dists/{codename}/Release >/dev/null; \
         mkdir -p /etc/apt/keyrings; \
         curl -fsSL -o /etc/apt/keyrings/mariadb-keyring.pgp https://mariadb.org/mariadb_release_signing_key.pgp; \
         printf 'X-Repolib-Name: MariaDB\\nTypes: deb\\nURIs: https://deb.mariadb.org/11.4/{id}\\nSuites: {codename}\\nComponents: main\\nSigned-By: /etc/apt/keyrings/mariadb-keyring.pgp\\n' \
           > /etc/apt/sources.list.d/mariadb.sources"
    );
    let out = safe_command_unsandboxed("bash", &[])
        .args(["-c", &script])
        .output_with_timeout(Duration::from_secs(120))
        .await?;
    if !out.status.success() {
        remove_mariadb_org_repo().await;
        return Err(String::from_utf8_lossy(&out.stderr).chars().take(300).collect());
    }
    crate::services::pkg::refresh_index().await;
    Ok(())
}

async fn remove_mariadb_org_repo() {
    let _ = safe_command_unsandboxed("rm", &[])
        .args(["-f", "/etc/apt/sources.list.d/mariadb.sources", "/etc/apt/keyrings/mariadb-keyring.pgp"])
        .output_with_timeout(Duration::from_secs(30))
        .await;
}

/// Idempotent install (D1): mariadb.org 11.4 LTS, distribution package as fallback.
pub async fn install() -> Result<(String, String), String> {
    if crate::services::pkg::manager().await != crate::services::pkg::PkgMgr::Dpkg {
        return Err("The shared local MariaDB server is only supported on Debian and Ubuntu".into());
    }
    if let Some(why) = crate::services::pkg::privileged_ops_reason("Installing MariaDB").await {
        return Err(why);
    }
    let mut notes = Vec::new();
    // Keep a sql_mode an operator already chose.
    let keep_mode = current_cnf().await.and_then(|c| parse_cnf_sql_mode(&c));
    let wanted = render_cnf(keep_mode.as_deref());
    let cnf_changed = current_cnf().await.as_deref() != Some(wanted.as_str());
    if cnf_changed {
        write_cnf(&wanted).await?;
    }

    if !is_installed().await {
        match add_mariadb_org_repo().await {
            Ok(()) => notes.push("MariaDB 11.4 LTS from mariadb.org".to_string()),
            Err(e) => {
                tracing::warn!("mariadb.org repository unavailable, using the distribution package: {e}");
                notes.push("distribution MariaDB package (mariadb.org repository unavailable)".to_string());
            }
        }
        if let Err(e) = crate::services::pkg::install(&["mariadb-server", "mariadb-client"]).await {
            return Err(crate::services::pkg::explain_package_failure(&e).await);
        }
    }
    systemctl(&["enable", "mariadb"]).await.ok();
    if cnf_changed || !is_running().await {
        restart_and_wait().await?;
    }
    let (version, _, uca, _) = probe().await?;
    if !uca {
        notes.push("utf8mb4_uca1400_ai_ci unknown here: imported dumps are rewritten to utf8mb4_unicode_ci".into());
    }
    Ok((version, notes.join("; ")))
}

/// `POST /localdb/config`: validate on the live server first, roll back on a
/// failed restart (a bad option file would take every tenant down).
pub async fn set_sql_mode(sql_mode: Option<&str>) -> Result<(), String> {
    if let Some(m) = sql_mode {
        if !is_valid_sql_mode(m) {
            return Err("sql_mode must match ^[A-Z0-9_,]*$".into());
        }
    }
    if !is_running().await {
        return Err("The local MariaDB server is not running".into());
    }
    if let Some(m) = sql_mode {
        root_exec(&format!("SET SESSION sql_mode='{m}'"), None, false)
            .await
            .map_err(|e| format!("MariaDB rejects this sql_mode: {e}"))?;
    }
    let previous = current_cnf().await;
    write_cnf(&render_cnf(sql_mode)).await?;
    if let Err(e) = restart_and_wait().await {
        match &previous {
            Some(p) => {
                let _ = write_cnf(p).await;
            }
            None => remove_cnf().await,
        }
        let _ = restart_and_wait().await;
        return Err(format!("{e}; the previous configuration was restored"));
    }
    Ok(())
}

// ───────────────────────────── databases and accounts ─────────────────────────────

struct SchemaInfo {
    comment: String,
    tables: u64,
}

async fn schema_info(name: &str) -> Result<Option<SchemaInfo>, String> {
    let n = sql_str(name);
    let rows = root_rows(&format!(
        "SELECT SCHEMA_COMMENT, (SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{n}') \
         FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='{n}'"
    ))
    .await?;
    Ok(rows.into_iter().next().map(|r| SchemaInfo {
        comment: r.first().cloned().unwrap_or_default(),
        tables: r.get(1).and_then(|t| t.trim().parse().ok()).unwrap_or(0),
    }))
}

pub async fn table_count(name: &str) -> Result<u64, String> {
    Ok(schema_info(name).await?.map(|s| s.tables).unwrap_or(0))
}

/// Hosts (`localhost`, `127.0.0.1`) at which `user` exists.
async fn user_hosts(user: &str) -> Result<Vec<String>, String> {
    let rows = root_rows(&format!(
        "SELECT Host FROM mysql.user WHERE User='{}' AND Host IN ('localhost','127.0.0.1')",
        sql_str(user)
    ))
    .await?;
    Ok(rows.into_iter().filter_map(|r| r.into_iter().next()).collect())
}

pub enum Credential<'a> {
    Password(&'a str),
    NativeHash(&'a str),
}

fn identified(c: &Credential) -> String {
    match c {
        Credential::Password(p) => format!("IDENTIFIED BY '{}'", sql_str(p)),
        // Stored uppercase by MariaDB; a lowercase hash would never authenticate.
        Credential::NativeHash(h) => format!("IDENTIFIED VIA mysql_native_password USING '{}'", h.to_ascii_uppercase()),
    }
}

/// SQL creating the account at both hosts and granting it the database.
pub fn create_account_sql(name: &str, user: &str, cred: &Credential, hosts: &[&str]) -> String {
    let mut s = String::new();
    for h in hosts {
        s.push_str(&format!("CREATE USER {} {};\n", account(user, h), identified(cred)));
    }
    s.push_str(&grant_sql(name, user));
    s
}

pub fn grant_sql(name: &str, user: &str) -> String {
    HOSTS
        .iter()
        .map(|h| format!("GRANT ALL PRIVILEGES ON {}.* TO {};\n", ident(&grant_db_pattern(name)), account(user, h)))
        .collect()
}

#[derive(Debug, PartialEq)]
pub enum CreateError {
    Invalid(String),
    Conflict(String),
    Failed(String),
}

/// `POST /localdb/databases`: never adopts an existing database or account.
pub async fn create_database(
    name: &str,
    user: &str,
    charset: Option<&str>,
    cred: Credential<'_>,
) -> Result<(), CreateError> {
    use CreateError::*;
    if !is_valid_local_name(name) {
        return Err(Invalid("Invalid database name".into()));
    }
    if !is_valid_local_user(user) {
        return Err(Invalid("Invalid database user".into()));
    }
    let charset = charset.unwrap_or("utf8mb4");
    if !is_valid_charset(charset) {
        return Err(Invalid("Invalid charset".into()));
    }
    match &cred {
        Credential::Password(p) if !password_ok(p) => return Err(Invalid("Invalid password".into())),
        Credential::NativeHash(h) if !is_valid_mysql_hash(h) => {
            return Err(Invalid("password_hash must be a mysql_native_password hash".into()))
        }
        _ => {}
    }
    if schema_info(name).await.map_err(Failed)?.is_some() {
        return Err(Conflict(format!("Database {name} already exists on the local server")));
    }
    if !user_hosts(user).await.map_err(Failed)?.is_empty() {
        return Err(Conflict(format!("Database user {user} already exists on the local server")));
    }
    root_exec(&format!("CREATE DATABASE {} CHARACTER SET {charset};", ident(name)), None, false)
        .await
        .map_err(Failed)?;
    if let Err(e) = root_exec(&create_account_sql(name, user, &cred, &HOSTS), None, true).await {
        // Both were verified absent above, so they are ours to remove.
        let _ = root_exec(&drop_users_sql(user), None, false).await;
        let _ = root_exec(&format!("DROP DATABASE IF EXISTS {};", ident(name)), None, false).await;
        return Err(Failed(e));
    }
    Ok(())
}

fn drop_users_sql(user: &str) -> String {
    format!(
        "DROP USER IF EXISTS {}, {};",
        account(user, "localhost"),
        account(user, "127.0.0.1")
    )
}

/// `POST /localdb/databases/{name}/drop`. Returns `(dropped_db, dropped_user)`.
pub async fn drop_database(name: &str, user: &str, drop_user_if_unused: bool) -> Result<(bool, bool), String> {
    if !is_valid_local_name(name) || !is_valid_local_user(user) {
        return Err("Invalid database or user name".into());
    }
    let existed = schema_info(name).await?.is_some();
    root_exec(&format!("DROP DATABASE IF EXISTS {};", ident(name)), None, false).await?;
    let u = sql_str(user);
    let pattern = sql_str(&grant_db_pattern(name));
    let granted: Vec<String> = root_rows(&format!(
        "SELECT Host FROM mysql.db WHERE User='{u}' AND Db='{pattern}' AND Host IN ('localhost','127.0.0.1')"
    ))
    .await?
    .into_iter()
    .filter_map(|r| r.into_iter().next())
    .collect();
    for h in &granted {
        root_exec(
            &format!("REVOKE ALL PRIVILEGES ON {}.* FROM {};", ident(&grant_db_pattern(name)), account(user, h)),
            None,
            false,
        )
        .await?;
    }
    let mut dropped_user = false;
    if drop_user_if_unused {
        let others = root_scalar(&format!("SELECT COUNT(*) FROM mysql.db WHERE User='{u}'")).await?;
        if others.trim() == "0" {
            root_exec(&drop_users_sql(user), None, false).await?;
            dropped_user = true;
        }
    }
    Ok((existed, dropped_user))
}

/// `POST /localdb/databases/{name}/password`: only an account granted on `name`.
pub async fn set_password(name: &str, user: &str, new_password: &str) -> Result<(), String> {
    if !is_valid_local_name(name) || !is_valid_local_user(user) {
        return Err("Invalid database or user name".into());
    }
    if !password_ok(new_password) {
        return Err("Invalid password".into());
    }
    let hosts: Vec<String> = root_rows(&format!(
        "SELECT Host FROM mysql.db WHERE User='{}' AND Db='{}' AND Host IN ('localhost','127.0.0.1')",
        sql_str(user),
        sql_str(&grant_db_pattern(name))
    ))
    .await?
    .into_iter()
    .filter_map(|r| r.into_iter().next())
    .collect();
    if hosts.is_empty() {
        return Err(format!("No account {user} is granted on {name}"));
    }
    let existing = user_hosts(user).await?;
    let mut sql = String::new();
    for h in HOSTS {
        if existing.iter().any(|e| e == h) {
            sql.push_str(&format!("ALTER USER {} {};\n", account(user, h), identified(&Credential::Password(new_password))));
        } else {
            // Keep `localhost` and `127.0.0.1` in step, as the import created them.
            sql.push_str(&format!("CREATE USER {} {};\n", account(user, h), identified(&Credential::Password(new_password))));
            sql.push_str(&format!(
                "GRANT ALL PRIVILEGES ON {}.* TO {};\n",
                ident(&grant_db_pattern(name)),
                account(user, h)
            ));
        }
    }
    root_exec(&sql, None, true).await.map(|_| ())
}

// ───────────────────────────── temporary accounts ─────────────────────────────

static LIVE_TMP: Mutex<Option<HashSet<String>>> = Mutex::new(None);
static SWEPT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn live_insert(u: &str) {
    LIVE_TMP.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashSet::new).insert(u.to_string());
}
fn live_remove(u: &str) {
    if let Some(s) = LIVE_TMP.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        s.remove(u);
    }
}
fn live_contains(u: &str) -> bool {
    LIVE_TMP.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_some_and(|s| s.contains(u))
}

pub fn is_tmp_account_name(u: &str) -> bool {
    u.strip_prefix(TMP_PREFIX)
        .is_some_and(|r| !r.is_empty() && r.len() <= 32 && r.bytes().all(|c| c.is_ascii_hexdigit()))
}

/// Drop every `ch_tmp_%` account this process is not using (left by a crash).
pub async fn sweep_tmp_accounts() -> Result<usize, String> {
    let rows = root_rows("SELECT User, Host FROM mysql.user WHERE User LIKE 'ch\\_tmp\\_%'").await?;
    let mut n = 0;
    for r in rows {
        let (Some(u), Some(h)) = (r.first(), r.get(1)) else { continue };
        if !is_tmp_account_name(u) || live_contains(u) || !h.bytes().all(|c| c.is_ascii_alphanumeric() || b".:-%_".contains(&c)) {
            continue;
        }
        if root_exec(&format!("DROP USER IF EXISTS {};", account(u, h)), None, false).await.is_ok() {
            n += 1;
        }
    }
    SWEPT.store(true, std::sync::atomic::Ordering::Relaxed);
    if n > 0 {
        tracing::info!("local MariaDB: removed {n} leftover temporary account(s)");
    }
    Ok(n)
}

/// Startup sweep, retried while MariaDB is not up yet (it may start after us).
pub async fn startup_sweep() {
    for _ in 0..20 {
        if SWEPT.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        if Path::new(SOCKET).exists() && sweep_tmp_accounts().await.is_ok() {
            return;
        }
        if !is_installed().await {
            return;
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Same shape as `POST /databases/query`.
#[derive(serde::Serialize)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub row_count: usize,
    pub execution_time_ms: u64,
    pub truncated: bool,
}

fn parse_tsv(output: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let mut lines = output.lines();
    let columns: Vec<String> = match lines.next() {
        Some(h) if !h.is_empty() => h.split('\t').map(str::to_string).collect(),
        _ => return (vec![], vec![]),
    };
    let rows = lines.filter(|l| !l.is_empty()).map(|l| l.split('\t').map(str::to_string).collect()).collect();
    (columns, rows)
}

/// `POST /localdb/query`: run tenant SQL as a temporary account limited to
/// `database`. Runs in its own task so a dropped request cannot skip the cleanup.
pub async fn query(database: String, sql: String) -> Result<QueryResult, String> {
    tokio::spawn(async move { query_inner(&database, &sql).await })
        .await
        .map_err(|e| format!("query task failed: {e}"))?
}

async fn query_inner(database: &str, sql: &str) -> Result<QueryResult, String> {
    if !is_valid_local_name(database) {
        return Err("Invalid database name".into());
    }
    if schema_info(database).await?.is_none() {
        return Err(format!("Database {database} does not exist on the local server"));
    }
    if !SWEPT.load(std::sync::atomic::Ordering::Relaxed) {
        let _ = sweep_tmp_accounts().await;
    }
    let user = format!("{TMP_PREFIX}{}", random_hex(8));
    let password = random_hex(24);
    live_insert(&user);
    let created = root_exec(
        &format!(
            "CREATE USER {acct} IDENTIFIED BY '{password}';\nGRANT ALL PRIVILEGES ON {db}.* TO {acct};\n",
            acct = account(&user, "localhost"),
            db = ident(&grant_db_pattern(database)),
        ),
        None,
        true,
    )
    .await;
    let result = match created {
        Ok(_) => run_tenant(&user, &password, database, sql).await,
        Err(e) => Err(e),
    };
    let _ = root_exec(&format!("KILL USER {};", account(&user, "localhost")), None, false).await;
    if let Err(e) = root_exec(&format!("DROP USER IF EXISTS {};", account(&user, "localhost")), None, false).await {
        tracing::warn!("local MariaDB: could not drop temporary account {user}: {e}");
    }
    live_remove(&user);
    result
}

async fn run_tenant(user: &str, password: &str, database: &str, sql: &str) -> Result<QueryResult, String> {
    let start = std::time::Instant::now();
    let mut cmd = client(user).await;
    cmd.env("MYSQL_PWD", password)
        .args(["--batch", "--column-names", "--default-character-set=utf8mb4", database]);
    let (ok, out, err) = run_with_stdin(cmd, sql.as_bytes(), QUERY_TIMEOUT, MAX_OUTPUT_BYTES).await?;
    if !ok {
        return Err(trim_err(&err));
    }
    let (columns, mut rows) = parse_tsv(&String::from_utf8_lossy(&out));
    let truncated = rows.len() > MAX_ROWS;
    rows.truncate(MAX_ROWS);
    Ok(QueryResult {
        columns,
        row_count: rows.len(),
        rows,
        execution_time_ms: start.elapsed().as_millis() as u64,
        truncated,
    })
}

// ───────────────────────────── dump stream filter ─────────────────────────────

/// Streaming byte filter between the dump reader and the client: detects
/// `CREATE TABLE`, and (when the server lacks it) rewrites the `uca1400`
/// collations of MariaDB 11.4 to `<charset>_unicode_ci`. Works on bytes (dumps
/// carry blobs and latin1), holds back only a possibly split token.
pub struct DumpFilter {
    rewrite: bool,
    pending: Vec<u8>,
    tail: Vec<u8>,
    pub replaced: u64,
    pub saw_create_table: bool,
}

const UCA_MID: &[u8] = b"_uca1400_";
const CREATE_TABLE: &[u8] = b"CREATE TABLE";
const MAX_SUFFIX: usize = 32;

impl DumpFilter {
    pub fn new(rewrite: bool) -> Self {
        Self { rewrite, pending: Vec::new(), tail: Vec::new(), replaced: 0, saw_create_table: false }
    }

    fn scan_create(&mut self, chunk: &[u8]) {
        if self.saw_create_table {
            return;
        }
        let mut hay = std::mem::take(&mut self.tail);
        hay.extend_from_slice(chunk);
        if hay.windows(CREATE_TABLE.len()).any(|w| w == CREATE_TABLE) {
            self.saw_create_table = true;
        }
        let keep = hay.len().min(CREATE_TABLE.len() - 1);
        self.tail = hay[hay.len() - keep..].to_vec();
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.scan_create(chunk);
        if !self.rewrite {
            return chunk.to_vec();
        }
        let mut buf = std::mem::take(&mut self.pending);
        buf.extend_from_slice(chunk);
        let (out, consumed) = self.process(&buf, false);
        self.pending = buf[consumed..].to_vec();
        out
    }

    pub fn finish(&mut self) -> Vec<u8> {
        let buf = std::mem::take(&mut self.pending);
        self.process(&buf, true).0
    }

    /// Returns (output, bytes of `buf` consumed).
    fn process(&mut self, buf: &[u8], eof: bool) -> (Vec<u8>, usize) {
        let mut out = Vec::with_capacity(buf.len());
        let mut last = 0;
        let mut i = 0;
        let head = 7 + UCA_MID.len(); // "utf8mb4" + "_uca1400_"
        while i < buf.len() {
            if buf[i] != b'u' {
                i += 1;
                continue;
            }
            let rest = &buf[i..];
            if rest.len() < head {
                // Could be the start of a token cut by the chunk boundary.
                let cand: &[&[u8]] = &[b"utf8mb4_uca1400_", b"utf8mb3_uca1400_"];
                if !eof && cand.iter().any(|c| c.starts_with(rest)) {
                    out.extend_from_slice(&buf[last..i]);
                    return (out, i);
                }
                i += 1;
                continue;
            }
            let is_tok = (&rest[..7] == b"utf8mb4" || &rest[..7] == b"utf8mb3") && &rest[7..head] == UCA_MID;
            if !is_tok {
                i += 1;
                continue;
            }
            let mut j = head;
            while j < rest.len() && j - head <= MAX_SUFFIX && (rest[j].is_ascii_lowercase() || rest[j].is_ascii_digit() || rest[j] == b'_') {
                j += 1;
            }
            if j == rest.len() && !eof {
                out.extend_from_slice(&buf[last..i]);
                return (out, i);
            }
            if j == head || j - head > MAX_SUFFIX {
                i += 1;
                continue;
            }
            out.extend_from_slice(&buf[last..i]);
            out.extend_from_slice(&rest[..7]);
            out.extend_from_slice(b"_unicode_ci");
            self.replaced += 1;
            i += j;
            last = i;
        }
        out.extend_from_slice(&buf[last..]);
        (out, buf.len())
    }
}

/// Copy `reader` into `writer` through `filter`, reporting bytes read.
pub async fn pump<R, W, F>(mut reader: R, mut writer: W, filter: &mut DumpFilter, mut on_progress: F) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(u64),
{
    let mut chunk = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        total += n as u64;
        let out = filter.feed(&chunk[..n]);
        writer.write_all(&out).await?;
        on_progress(total);
    }
    let out = filter.finish();
    writer.write_all(&out).await?;
    writer.shutdown().await?;
    Ok(total)
}

// ───────────────────────────── Hestia import job ─────────────────────────────

/// Archive members that may hold the dump of `db` (Hestia layout).
pub fn dump_members(db: &str) -> [String; 2] {
    [format!("db/{db}/{db}.mysql.sql.gz"), format!("db/{db}/{db}.mysql.sql.zst")]
}

pub struct ImportRequest {
    pub migration_id: String,
    pub db_name: String,
    pub replace: bool,
    pub file: Option<String>,
}

/// Body of the `/localdb/hestia/import` job. Errors starting with
/// `exists_not_ours:` / `already_imported:` carry a code for the backend.
pub async fn hestia_import(
    req: ImportRequest,
    job: crate::services::migration_jobs::JobHandle,
) -> Result<serde_json::Value, String> {
    let mid = req.migration_id.as_str();
    let name = req.db_name.as_str();
    job.progress("prepare", 0, 0, "reading database credentials");
    let cred = crate::services::hestia::db_credentials(mid, name)?;
    if !is_valid_local_user(&cred.user) {
        return Err(format!("db.conf of {name} names an unusable database user"));
    }
    if !is_valid_mysql_hash(&cred.mysql_hash) {
        return Err(format!(
            "db.conf of {name} does not hold a mysql_native_password hash; set a new password after import"
        ));
    }
    let mut warnings: Vec<String> = Vec::new();
    let charset = if is_valid_charset(&cred.charset.to_ascii_lowercase()) {
        cred.charset.to_ascii_lowercase()
    } else {
        warnings.push(format!("unknown charset in db.conf, {name} created as utf8mb4"));
        "utf8mb4".to_string()
    };
    let (_, _, uca, _) = probe().await.map_err(|e| format!("local MariaDB server not reachable: {e}"))?;

    // Destructive point: only a database carrying this migration's marker may go.
    let marker = import_marker(mid);
    if let Some(info) = schema_info(name).await? {
        if info.comment != marker {
            return Err(format!(
                "exists_not_ours: database {name} already exists on the local server and was not created by this import"
            ));
        }
        if info.tables > 0 && !req.replace {
            return Err(format!("already_imported: database {name} was already imported; force a re-import to overwrite it"));
        }
        job.progress("prepare", 0, 0, "dropping the partial database of a previous attempt");
        root_exec(&format!("DROP DATABASE {};", ident(name)), None, false).await?;
    }
    root_exec(
        &format!("CREATE DATABASE {} CHARACTER SET {charset} COMMENT '{}';", ident(name), sql_str(&marker)),
        None,
        false,
    )
    .await?;

    let outcome = import_into(&req, &cred, uca, &job, &mut warnings).await;
    match outcome {
        Ok((tables, created_users, rewritten)) => {
            for w in &warnings {
                job.warn(w.clone());
            }
            Ok(serde_json::json!({
                "tables": tables,
                "created_db": true,
                "created_user": !created_users.is_empty(),
                "collation_rewritten": rewritten,
                "warnings": warnings,
            }))
        }
        Err((e, created_users)) => {
            // Leave nothing half-imported behind: the database is ours (just created).
            let _ = root_exec(&format!("DROP DATABASE IF EXISTS {};", ident(name)), None, false).await;
            for h in created_users {
                let _ = root_exec(&format!("DROP USER IF EXISTS {};", account(&cred.user, h)), None, false).await;
            }
            Err(e)
        }
    }
}

type ImportOk = (u64, Vec<&'static str>, bool);

async fn import_into(
    req: &ImportRequest,
    cred: &crate::services::hestia::DbCred,
    uca: bool,
    job: &crate::services::migration_jobs::JobHandle,
    warnings: &mut Vec<String>,
) -> Result<ImportOk, (String, Vec<&'static str>)> {
    let name = req.db_name.as_str();
    let user = cred.user.as_str();
    let hash = cred.mysql_hash.to_ascii_uppercase();
    let mut created: Vec<&'static str> = Vec::new();

    // Accounts: an existing account is kept; a different hash is reported, never changed.
    let rows = root_rows_secret(&format!(
        "SELECT Host, IF(authentication_string='{hash}' OR Password='{hash}',1,0) FROM mysql.user \
         WHERE User='{}' AND Host IN ('localhost','127.0.0.1')",
        sql_str(user)
    ))
    .await
    .map_err(|e| (e, created.clone()))?;
    let mut sql = String::new();
    for h in HOSTS {
        match rows.iter().find(|r| r.first().map(String::as_str) == Some(h)) {
            Some(r) => {
                if r.get(1).map(String::as_str) != Some("1") {
                    warnings.push(format!(
                        "user {user}@{h} already exists with another password: kept unchanged"
                    ));
                }
            }
            None => {
                sql.push_str(&format!("CREATE USER {} {};\n", account(user, h), identified(&Credential::NativeHash(&hash))));
                created.push(h);
            }
        }
    }
    sql.push_str(&grant_sql(name, user));
    root_exec(&sql, None, true).await.map_err(|e| (e, created.clone()))?;

    // Dump member: the inventory's `file` when it is one of the two Hestia names.
    let candidates = dump_members(name);
    let ordered: Vec<String> = match &req.file {
        Some(f) if candidates.contains(f) => vec![f.clone()],
        // Without it: `.gz` then `.zst`. A missing member makes the reader exit
        // non-zero before any byte, which moves on to the next name.
        _ => candidates.to_vec(),
    };
    let mut last_err = String::from("no dump found for this database in the archive");
    for member in &ordered {
        match stream_member(&req.migration_id, member, name, !uca, job).await {
            Ok(Streamed { bytes: 0, .. }) if ordered.len() > 1 => {
                last_err = format!("{member}: empty or missing");
                continue;
            }
            Ok(s) => {
                let tables = table_count(name).await.map_err(|e| (e, created.clone()))?;
                if s.saw_create_table && tables == 0 {
                    return Err(("the dump defines tables but none exist after the import".into(), created));
                }
                return Ok((tables, created, s.replaced > 0));
            }
            Err(StreamError::ReaderFailed(e)) if ordered.len() > 1 => {
                last_err = e;
                continue;
            }
            Err(StreamError::ReaderFailed(e)) | Err(StreamError::Other(e)) => return Err((e, created)),
        }
    }
    Err((last_err, created))
}

async fn root_rows_secret(sql: &str) -> Result<Vec<Vec<String>>, String> {
    let out = root_exec(sql, None, true).await?;
    Ok(out.lines().filter(|l| !l.is_empty()).map(|l| l.split('\t').map(str::to_string).collect()).collect())
}

struct Streamed {
    bytes: u64,
    replaced: u64,
    saw_create_table: bool,
}

enum StreamError {
    /// The reader failed before anything reached the client (wrong member name).
    ReaderFailed(String),
    Other(String),
}

async fn stream_member(
    migration_id: &str,
    member: &str,
    db: &str,
    rewrite: bool,
    job: &crate::services::migration_jobs::JobHandle,
) -> Result<Streamed, StreamError> {
    let mut reader = crate::services::migration::spawn_member_reader(migration_id, member)
        .await
        .map_err(StreamError::ReaderFailed)?;
    let rstdout = reader.stdout.take().ok_or_else(|| StreamError::Other("dump reader has no stdout".into()))?;
    if let Some(mut e) = reader.stderr.take() {
        tokio::spawn(async move {
            let mut sink = Vec::new();
            let _ = (&mut e).take(64 * 1024).read_to_end(&mut sink).await;
        });
    }

    let mut cmd = client("root").await;
    cmd.args([
        "--batch",
        "--max-allowed-packet=1G",
        "--default-character-set=utf8mb4",
        "--init-command=SET foreign_key_checks=0, unique_checks=0",
        db,
    ])
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::piped())
    .kill_on_drop(true);
    let mut client_child = cmd.spawn().map_err(|e| StreamError::Other(format!("Cannot run the MariaDB client: {e}")))?;
    let stdin = client_child.stdin.take().ok_or_else(|| StreamError::Other("no client stdin".into()))?;
    let mut cerr = client_child.stderr.take().ok_or_else(|| StreamError::Other("no client stderr".into()))?;
    let err_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = (&mut cerr).take(64 * 1024).read_to_end(&mut buf).await;
        buf
    });

    let mut filter = DumpFilter::new(rewrite);
    let mut next_report = 0u64;
    let pumped = pump(rstdout, stdin, &mut filter, |n| {
        if n >= next_report {
            job.progress("import", n, 0, &format!("{} MiB of SQL read", n / (1024 * 1024)));
            next_report = n + 8 * 1024 * 1024;
        }
    })
    .await;
    if pumped.is_err() {
        // The client stopped reading: the reader would block on a full pipe forever.
        let _ = reader.start_kill();
    }
    let reader_status = reader.wait().await;
    let client_status = client_child.wait().await;
    let client_err = err_task.await.unwrap_or_default();

    let bytes = pumped.as_ref().copied().unwrap_or(0);
    let reader_ok = reader_status.map(|s| s.success()).unwrap_or(false);
    let client_ok = client_status.map(|s| s.success()).unwrap_or(false);
    if !client_ok {
        return Err(StreamError::Other(format!("SQL import failed: {}", trim_err(&client_err))));
    }
    if !reader_ok {
        let msg = format!("{member}: the dump could not be read to the end (truncated or corrupt archive)");
        return Err(if bytes == 0 { StreamError::ReaderFailed(msg) } else { StreamError::Other(msg) });
    }
    if let Err(e) = pumped {
        return Err(StreamError::Other(format!("SQL import stream error: {e}")));
    }
    job.progress("import", bytes, bytes, "SQL import finished");
    Ok(Streamed { bytes, replaced: filter.replaced, saw_create_table: filter.saw_create_table })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_names_follow_d1() {
        for ok in ["adm-jim_x", "adm-jim_shop.be", "Adm-Jim_WP", "a", "1db", &"x".repeat(64)] {
            assert!(is_valid_local_name(ok), "{ok}");
        }
        for bad in ["", "_x", ".x", "-x", "a..b", "a`b", "a/b", "a\\b", "a b", "a\0b", "a'b", &"x".repeat(65),
                    "mysql", "MySQL", "information_schema", "sys", "performance_schema", "ch_tmp_ab12"] {
            assert!(!is_valid_local_name(bad), "{bad:?}");
        }
        assert!(is_valid_local_user(&"u".repeat(80)));
        assert!(!is_valid_local_user(&"u".repeat(81)));
        assert!(!is_valid_local_user("root"));
        assert!(!is_valid_local_user("mariadb.sys"));
    }

    #[test]
    fn hash_shape() {
        let h = format!("*{}", "A1".repeat(20));
        assert!(is_valid_mysql_hash(&h));
        assert!(is_valid_mysql_hash(&h.to_ascii_lowercase()));
        assert!(!is_valid_mysql_hash(&h[1..]));
        assert!(!is_valid_mysql_hash(&format!("{h}0")));
        assert!(!is_valid_mysql_hash(&format!("*{}", "G1".repeat(20))));
        assert!(!is_valid_mysql_hash("$2y$10$abc"));
        assert!(!is_valid_mysql_hash(&format!("*{}'", "A".repeat(39))));
    }

    #[test]
    fn grant_pattern_escapes_wildcards() {
        assert_eq!(grant_db_pattern("adm-jim_x"), "adm-jim\\_x");
        assert_eq!(grant_db_pattern("a_b.c-d"), "a\\_b.c-d");
        assert_eq!(grant_db_pattern("plain"), "plain");
        let g = grant_sql("adm-jim_x", "adm-jim_x");
        assert!(g.contains("GRANT ALL PRIVILEGES ON `adm-jim\\_x`.* TO 'adm-jim_x'@'localhost';"), "{g}");
        assert!(g.contains("'adm-jim_x'@'127.0.0.1'"), "{g}");
    }

    #[test]
    fn account_sql_uses_native_hash_at_both_hosts() {
        let h = format!("*{}", "ab".repeat(20));
        let sql = create_account_sql("Shop.Be", "shop_u", &Credential::NativeHash(&h), &HOSTS);
        let up = h.to_ascii_uppercase();
        assert!(sql.contains(&format!("CREATE USER 'shop_u'@'localhost' IDENTIFIED VIA mysql_native_password USING '{up}';")));
        assert!(sql.contains(&format!("CREATE USER 'shop_u'@'127.0.0.1' IDENTIFIED VIA mysql_native_password USING '{up}';")));
        assert!(sql.contains("ON `Shop.Be`.*"));
        let pw = create_account_sql("d", "u", &Credential::Password("it's\\x"), &HOSTS[..1]);
        assert!(pw.contains("IDENTIFIED BY 'it''s\\\\x'"), "{pw}");
    }

    #[test]
    fn sql_mode_and_cnf() {
        assert!(is_valid_sql_mode(""));
        assert!(is_valid_sql_mode("NO_ENGINE_SUBSTITUTION,ERROR_FOR_DIVISION_BY_ZERO"));
        assert!(!is_valid_sql_mode("strict_trans_tables"));
        assert!(!is_valid_sql_mode("A'B"));
        assert!(!is_valid_sql_mode("A\nB"));
        let d = render_cnf(None);
        for k in ["bind-address=127.0.0.1", "port=3306", "character-set-server=utf8mb4", "max_allowed_packet=256M", "local_infile=0"] {
            assert!(d.contains(k), "{k}");
        }
        assert_eq!(parse_cnf_sql_mode(&d), None);
        assert_eq!(parse_cnf_sql_mode(&render_cnf(Some(""))), Some(String::new()));
        assert_eq!(
            parse_cnf_sql_mode(&render_cnf(Some("NO_ENGINE_SUBSTITUTION"))),
            Some("NO_ENGINE_SUBSTITUTION".into())
        );
    }

    #[test]
    fn tmp_account_names() {
        assert!(is_tmp_account_name("ch_tmp_0a1b2c3d4e5f6a7b"));
        assert!(!is_tmp_account_name("ch_tmp_"));
        assert!(!is_tmp_account_name("ch_tmp_x'"));
        assert!(!is_tmp_account_name("adm-jim_x"));
    }

    fn run_filter(rewrite: bool, input: &[u8], split: usize) -> (Vec<u8>, DumpFilter) {
        let mut f = DumpFilter::new(rewrite);
        let mut out = Vec::new();
        for c in input.chunks(split.max(1)) {
            out.extend(f.feed(c));
        }
        out.extend(f.finish());
        (out, f)
    }

    #[test]
    fn collation_filter_rewrites_across_chunk_boundaries() {
        let src = b"CREATE TABLE `t` (a text) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;\n\
                    INSERT INTO t VALUES ('\xff\x00 utf8mb3_uca1400_as_cs x');\nutf8mb4_uca1400_ai_ci";
        let want: &[u8] = b"CREATE TABLE `t` (a text) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;\n\
                    INSERT INTO t VALUES ('\xff\x00 utf8mb3_unicode_ci x');\nutf8mb4_unicode_ci";
        for split in 1..=40 {
            let (out, f) = run_filter(true, src, split);
            assert_eq!(out, want, "split {split}");
            assert_eq!(f.replaced, 3);
            assert!(f.saw_create_table, "split {split}");
        }
    }

    #[test]
    fn collation_filter_passes_through_when_disabled_or_absent() {
        let src = b"COLLATE=utf8mb4_uca1400_ai_ci; utf8mb4_general_ci; utf8 uca1400";
        let (out, f) = run_filter(false, src, 3);
        assert_eq!(out, src.to_vec());
        assert_eq!(f.replaced, 0);
        assert!(!f.saw_create_table);
        let plain = b"INSERT INTO x VALUES ('utf8mb4_unicode_ci','utf8mb4_uca1400_')";
        let (out, _) = run_filter(true, plain, 5);
        assert_eq!(out, plain.to_vec(), "a token with no suffix is left alone");
    }

    #[tokio::test]
    async fn pump_counts_bytes_and_filters() {
        let input: &[u8] = b"CREATE TABLE a (x int) COLLATE utf8mb4_uca1400_ai_ci;";
        let mut out: Vec<u8> = Vec::new();
        let mut f = DumpFilter::new(true);
        let mut seen = 0;
        let n = pump(input, &mut out, &mut f, |b| seen = b).await.unwrap();
        assert_eq!(n, input.len() as u64);
        assert_eq!(seen, n);
        assert_eq!(out, b"CREATE TABLE a (x int) COLLATE utf8mb4_unicode_ci;".to_vec());
    }

    #[test]
    fn dump_members_are_the_two_hestia_names() {
        let m = dump_members("adm-jim_x.y");
        assert_eq!(m[0], "db/adm-jim_x.y/adm-jim_x.y.mysql.sql.gz");
        assert_eq!(m[1], "db/adm-jim_x.y/adm-jim_x.y.mysql.sql.zst");
        assert_eq!(import_marker("u-1"), "ch-import:u-1");
    }
}
