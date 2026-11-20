//! `mail.<d>` certificates presented by SNI (Postfix + Dovecot), and port 465.
//! Design: conception/14-certificats-mail-sni.md (D2, D6, D7, D8).
//!
//! The panel certificate stays the default one (no SNI, unknown name); this
//! module only adds per-name overrides. No key is ever logged.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use crate::routes::mail as mail_routes;
use crate::safe_cmd::safe_command;
use crate::services::ssl;

/// `mail.<d>/{fullchain,privkey}.pem`, outside `/etc/dockpanel/ssl` (D2).
pub const MAIL_TLS_DIR: &str = "/etc/dockpanel/mail-tls";
pub const POSTFIX_SNI_MAP: &str = "/etc/postfix/tls_server_sni";
pub const DOVECOT_SNI_CONF: &str = "/etc/dovecot/conf.d/99-dockpanel-sni.conf";
const SNI_PARAM: &str = "tls_server_sni_maps";
const MAIL_MARKER: &str = "DockPanel mail configuration";
/// Comment carrying the chain digests: a renewal changes the rendered file,
/// which is what triggers the `postmap -F` that re-embeds the new files.
const STATE_PREFIX: &str = "# dockpanel-sni ";

/// Serialises every SNI rebuild and certificate install (startup heal, sync,
/// issue and import may overlap).
static SNI_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub fn host_of(domain: &str) -> String {
    format!("mail.{domain}")
}

pub fn cert_dir(base: &Path, domain: &str) -> PathBuf {
    base.join(host_of(domain))
}

/// Why a certificate is not presentable. `code()` is the import contract's `reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertProblem {
    Missing,
    Unreadable,
    Expired,
    WrongName,
}

impl CertProblem {
    pub fn code(self) -> &'static str {
        match self {
            CertProblem::Missing => "missing",
            CertProblem::Unreadable => "unreadable",
            CertProblem::Expired => "expired",
            CertProblem::WrongName => "wrong_name",
        }
    }
}

/// Judge a chain + key pair for `host`. Order matters: parse, then expiry,
/// then name (`cert_covers_domain` mixes parse and name errors). Ok = expiry.
pub fn evaluate(
    chain: Option<&str>,
    key: Option<&str>,
    host: &str,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, CertProblem> {
    let (Some(chain), Some(key)) = (chain, key) else {
        return Err(CertProblem::Missing);
    };
    if chain.trim().is_empty() || key.trim().is_empty() {
        return Err(CertProblem::Missing);
    }
    let meta = ssl::cert_metadata(chain).map_err(|_| CertProblem::Unreadable)?;
    if meta.not_after <= now {
        return Err(CertProblem::Expired);
    }
    if ssl::cert_covers_domain(chain, host).is_err() {
        return Err(CertProblem::WrongName);
    }
    // A mismatched pair would break the handshake for that name only.
    ssl::key_matches_cert(chain, key).map_err(|_| CertProblem::Unreadable)?;
    Ok(meta.not_after)
}

/// Domains of `virtual_domains` (active ones only), validated and lowercased:
/// they become paths and config keys.
pub fn parse_virtual_domains(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_ascii_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| mail_routes::valid_mail_domain(l))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// One presented name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniEntry {
    pub host: String,
    pub key_path: String,
    pub chain_path: String,
    /// SHA-256 of the chain file (the key is bound to it by `evaluate`).
    pub chain_sha256: String,
}

fn state_line(entries: &[SniEntry]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    for e in entries {
        h.update(e.host.as_bytes());
        h.update(b"\0");
        h.update(e.chain_sha256.as_bytes());
        h.update(b"\n");
    }
    format!("{STATE_PREFIX}{}\n", hex::encode(h.finalize()))
}

/// Postfix `tls_server_sni_maps` source: `host key chain`, key first
/// (postconf(5)). `None` = no entry, the table is removed.
pub fn render_postfix_sni(entries: &[SniEntry]) -> Option<String> {
    if entries.is_empty() {
        return None;
    }
    let mut out = String::from("# Managed by CyberHunter - Panel (mail.<domain> SNI). Do not edit.\n");
    out.push_str(&state_line(entries));
    for e in entries {
        out.push_str(&format!("{} {} {}\n", e.host, e.key_path, e.chain_path));
    }
    Some(out)
}

/// Dovecot drop-in, one `local_name` block per name. `None` = file removed.
pub fn render_dovecot_sni(entries: &[SniEntry], v24: bool) -> Option<String> {
    if entries.is_empty() {
        return None;
    }
    let mut out = String::from("# Managed by CyberHunter - Panel (mail.<domain> SNI). Do not edit.\n");
    out.push_str(&state_line(entries));
    for e in entries {
        out.push_str(&format!("local_name {} {{\n", e.host));
        if v24 {
            out.push_str(&format!("  ssl_server_cert_file = {}\n", e.chain_path));
            out.push_str(&format!("  ssl_server_key_file = {}\n", e.key_path));
        } else {
            out.push_str(&format!("  ssl_cert = <{}\n", e.chain_path));
            out.push_str(&format!("  ssl_key = <{}\n", e.key_path));
        }
        out.push_str("}\n");
    }
    Some(out)
}

/// Presentable entries for `domains`, read under `base` (injected for tests).
pub fn select_presentable(base: &Path, domains: &[String], now: DateTime<Utc>) -> Vec<SniEntry> {
    use sha2::Digest;
    let mut out = Vec::new();
    for d in domains {
        let host = host_of(d);
        let dir = cert_dir(base, d);
        let chain_path = dir.join("fullchain.pem");
        let key_path = dir.join("privkey.pem");
        let chain = read_small(&chain_path);
        let key = read_small(&key_path);
        match evaluate(chain.as_deref(), key.as_deref(), &host, now) {
            Ok(_) => out.push(SniEntry {
                host,
                key_path: key_path.to_string_lossy().into_owned(),
                chain_path: chain_path.to_string_lossy().into_owned(),
                chain_sha256: hex::encode(sha2::Sha256::digest(chain.unwrap_or_default().as_bytes())),
            }),
            Err(CertProblem::Missing) => {}
            Err(p) => tracing::info!("{host}: certificate on disk not presented ({})", p.code()),
        }
    }
    out
}

fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 256 * 1024 {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Outcome of [`rebuild_sni`], serialised as `host_tls` in the sync response.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SniOutcome {
    pub presented: Vec<String>,
    pub error: Option<String>,
}

fn mail_installed(main_cf: &str) -> bool {
    main_cf.contains(MAIL_MARKER)
}

/// Rebuild the SNI configuration from `virtual_domains` crossed with the
/// valid certificates on disk (D6). Validated before reload, restored on failure.
pub async fn rebuild_sni() -> SniOutcome {
    let _serial = SNI_LOCK.lock().await;
    rebuild_sni_locked().await
}

struct SniSnapshot {
    source: Option<String>,
    db: Option<Vec<u8>>,
    param: Option<String>,
    dovecot: Option<String>,
}

async fn rebuild_sni_locked() -> SniOutcome {
    let main_cf = tokio::fs::read_to_string(mail_routes::POSTFIX_MAIN_CF).await.unwrap_or_default();
    if !mail_installed(&main_cf) {
        return SniOutcome::default();
    }
    let domains = parse_virtual_domains(
        &tokio::fs::read_to_string(mail_routes::POSTFIX_VIRTUAL_DOMAINS).await.unwrap_or_default(),
    );
    let entries = {
        let domains = domains.clone();
        tokio::task::spawn_blocking(move || select_presentable(Path::new(MAIL_TLS_DIR), &domains, Utc::now()))
            .await
            .unwrap_or_default()
    };
    let presented: Vec<String> = entries.iter().map(|e| e.host.clone()).collect();
    let dovecot_dir = Path::new(DOVECOT_SNI_CONF).parent().is_some_and(|p| p.is_dir());

    let want_source = render_postfix_sni(&entries);
    let want_param = want_source.as_ref().map(|_| format!("hash:{POSTFIX_SNI_MAP}"));
    let want_dovecot = if dovecot_dir {
        render_dovecot_sni(&entries, mail_routes::dovecot_needs_v24_syntax().await)
    } else {
        None
    };

    let db_path = format!("{POSTFIX_SNI_MAP}.db");
    let snap = SniSnapshot {
        source: tokio::fs::read_to_string(POSTFIX_SNI_MAP).await.ok(),
        db: tokio::fs::read(&db_path).await.ok(),
        param: crate::services::mail_transports::main_cf_value(&main_cf, SNI_PARAM),
        dovecot: tokio::fs::read_to_string(DOVECOT_SNI_CONF).await.ok(),
    };
    // An admin's own value is left alone when there is nothing to present,
    // and replaced (with a warning) when there is.
    let ours = format!("hash:{POSTFIX_SNI_MAP}");
    let foreign = snap.param.as_ref().filter(|v| **v != ours).cloned();
    let want_param = match (&want_param, &foreign) {
        (None, Some(v)) => Some(v.clone()),
        (Some(_), Some(v)) => {
            tracing::warn!("mail SNI: replacing {SNI_PARAM}={v} set outside the panel");
            want_param
        }
        _ => want_param,
    };
    let postfix_changed = snap.source != want_source
        || snap.param != want_param
        || (want_source.is_some() && snap.db.is_none())
        || (want_source.is_none() && snap.db.is_some());
    let dovecot_changed = snap.dovecot != want_dovecot;
    if !postfix_changed && !dovecot_changed {
        return SniOutcome { presented, error: None };
    }

    if postfix_changed {
        if let Err(e) = apply_postfix(want_source.as_deref(), want_param.as_deref()).await {
            restore(&snap).await;
            tracing::error!("mail SNI: Postfix change refused, previous configuration restored: {e}");
            return SniOutcome { presented: Vec::new(), error: Some(e) };
        }
    }
    if dovecot_changed {
        if let Err(e) = apply_dovecot(want_dovecot.as_deref()).await {
            restore(&snap).await;
            tracing::error!("mail SNI: Dovecot change refused, previous configuration restored: {e}");
            return SniOutcome { presented: Vec::new(), error: Some(e) };
        }
    }
    if postfix_changed {
        reload("postfix").await;
    }
    if dovecot_changed {
        reload("dovecot").await;
    }
    tracing::info!("mail SNI: {} name(s) presented", presented.len());
    SniOutcome { presented, error: None }
}

async fn reload(service: &str) {
    match safe_command("systemctl").args(["reload", service]).output().await {
        Ok(o) if o.status.success() => {}
        Ok(o) => tracing::warn!("Failed to reload {service}: {}", String::from_utf8_lossy(&o.stderr).trim()),
        Err(e) => tracing::warn!("Failed to execute systemctl reload {service}: {e}"),
    }
}

fn short(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().chars().take(300).collect()
}

/// Write a file 0600 from creation, atomically.
async fn write_private(path: &str, content: &[u8]) -> Result<(), String> {
    let tmp = format!("{path}.tmp");
    let _ = tokio::fs::remove_file(&tmp).await;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let (t, c) = (tmp.clone(), content.to_vec());
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&t)?;
            f.write_all(&c)
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("cannot write {path}: {e}"))?;
    }
    #[cfg(not(unix))]
    tokio::fs::write(&tmp, content).await.map_err(|e| format!("cannot write {path}: {e}"))?;
    tokio::fs::rename(&tmp, path).await.map_err(|e| format!("cannot write {path}: {e}"))
}

async fn chmod_600(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await;
    }
}

async fn postconf_set(param: Option<&str>) -> Result<(), String> {
    let out = match param {
        Some(v) => safe_command("postconf").args(["-e", &format!("{SNI_PARAM}={v}")]).output().await,
        None => safe_command("postconf").args(["-X", SNI_PARAM]).output().await,
    };
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!("postconf failed: {}", short(&o.stderr))),
        Err(e) => Err(format!("postconf could not run: {e}")),
    }
}

async fn apply_postfix(source: Option<&str>, param: Option<&str>) -> Result<(), String> {
    let db_path = format!("{POSTFIX_SNI_MAP}.db");
    match source {
        Some(src) => {
            write_private(POSTFIX_SNI_MAP, src.as_bytes()).await?;
            // umask 077: the .db embeds the private keys from its first byte.
            let pm = safe_command("sh")
                .args(["-c", &format!("umask 077 && exec postmap -F hash:{POSTFIX_SNI_MAP}")])
                .output()
                .await
                .map_err(|e| format!("postmap could not run: {e}"))?;
            chmod_600(&db_path).await;
            if !pm.status.success() {
                return Err(format!("postmap -F failed: {}", short(&pm.stderr)));
            }
            postconf_set(param).await?;
        }
        None => {
            // `param` set here = a foreign value, kept.
            if param.is_none() {
                postconf_set(None).await?;
            }
            let _ = tokio::fs::remove_file(POSTFIX_SNI_MAP).await;
            let _ = tokio::fs::remove_file(&db_path).await;
        }
    }
    mail_routes::postfix_check().await.map_err(|e| format!("postfix check failed: {e}"))
}

async fn apply_dovecot(content: Option<&str>) -> Result<(), String> {
    match content {
        Some(c) => mail_routes::write_file_atomic(DOVECOT_SNI_CONF, c)
            .await
            .map_err(|e| format!("cannot write {DOVECOT_SNI_CONF}: {e}"))?,
        None => {
            let _ = tokio::fs::remove_file(DOVECOT_SNI_CONF).await;
        }
    }
    match safe_command("doveconf").arg("-n").output().await {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!("doveconf -n failed: {}", short(&o.stderr))),
        Err(e) => Err(format!("doveconf could not run: {e}")),
    }
}

async fn restore(snap: &SniSnapshot) {
    let db_path = format!("{POSTFIX_SNI_MAP}.db");
    match &snap.source {
        Some(s) => {
            let _ = write_private(POSTFIX_SNI_MAP, s.as_bytes()).await;
        }
        None => {
            let _ = tokio::fs::remove_file(POSTFIX_SNI_MAP).await;
        }
    }
    match &snap.db {
        Some(b) => {
            let _ = write_private(&db_path, b).await;
        }
        None => {
            let _ = tokio::fs::remove_file(&db_path).await;
        }
    }
    let _ = postconf_set(snap.param.as_deref()).await;
    match &snap.dovecot {
        Some(c) => {
            let _ = mail_routes::write_file_atomic(DOVECOT_SNI_CONF, c).await;
        }
        None => {
            let _ = tokio::fs::remove_file(DOVECOT_SNI_CONF).await;
        }
    }
}

// ── Certificate install (issue + Hestia import) ─────────────────────────

/// Install a chain + key for `mail.<domain>` (key 0600, both by rename so a
/// rebuild never reads a half-written file). Caller validated the pair.
pub async fn install_pair(domain: &str, chain_pem: &str, key_pem: &str) -> Result<(), String> {
    let _serial = SNI_LOCK.lock().await;
    let dir = cert_dir(Path::new(MAIL_TLS_DIR), domain);
    create_private_dir(Path::new(MAIL_TLS_DIR)).await?;
    create_private_dir(&dir).await?;
    let chain_path = dir.join("fullchain.pem").to_string_lossy().into_owned();
    let key_path = dir.join("privkey.pem").to_string_lossy().into_owned();
    let chain = format!("{}\n", chain_pem.trim());
    let key = format!("{}\n", key_pem.trim());
    write_private(&key_path, key.as_bytes()).await?;
    let tmp = format!("{chain_path}.tmp");
    tokio::fs::write(&tmp, chain.as_bytes()).await.map_err(|e| format!("cannot write {chain_path}: {e}"))?;
    tokio::fs::rename(&tmp, &chain_path).await.map_err(|e| format!("cannot write {chain_path}: {e}"))?;
    Ok(())
}

async fn create_private_dir(dir: &Path) -> Result<(), String> {
    tokio::fs::create_dir_all(dir).await.map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await;
    }
    Ok(())
}

/// D10: a removed domain loses its files.
pub async fn remove_domain_files(domain: &str) {
    if !mail_routes::valid_mail_domain(domain) {
        return;
    }
    let _serial = SNI_LOCK.lock().await;
    let _ = tokio::fs::remove_dir_all(cert_dir(Path::new(MAIL_TLS_DIR), domain)).await;
}

/// Hestia `<d>.crt` + `<d>.ca` as one fullchain: the CA blocks not already
/// in the crt are appended (a crt with more than one block is already a chain).
pub fn hestia_fullchain(crt: &str, ca: Option<&str>) -> String {
    let crt_blocks = cert_blocks(crt);
    let mut out = crt.trim().to_string();
    // No leaf: left unreadable rather than letting the CA pose as one.
    if crt_blocks.len() != 1 {
        return format!("{out}\n");
    }
    for block in ca.map(cert_blocks).unwrap_or_default() {
        if !crt_blocks.contains(&block) {
            out.push('\n');
            out.push_str(&block);
        }
    }
    format!("{out}\n")
}

/// The `CERTIFICATE` PEM blocks of a text, whitespace-normalised per line.
fn cert_blocks(text: &str) -> Vec<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut cur: Option<Vec<&str>> = None;
    for line in text.lines().map(str::trim) {
        if line == BEGIN {
            cur = Some(vec![BEGIN]);
        } else if let Some(c) = cur.as_mut() {
            if !line.is_empty() {
                c.push(line);
            }
            if line == END {
                out.push(c.join("\n"));
                cur = None;
            }
        }
    }
    out
}

/// Result of reading a staged Hestia `mail.<d>` certificate.
pub struct HestiaHostCert {
    pub chain_pem: String,
    pub key_pem: String,
    pub expiry: DateTime<Utc>,
}

/// Read and judge `<root>/mail/<d>/conf/ssl/<d>.{crt,ca,key}` (pure on its
/// inputs but for the reads; `root` = the staging's archive root).
pub fn read_hestia_host_cert(root: &Path, domain: &str, now: DateTime<Utc>) -> Result<HestiaHostCert, CertProblem> {
    let ssl_dir = root.join("mail").join(domain).join("conf").join("ssl");
    let crt = read_small(&ssl_dir.join(format!("{domain}.crt")));
    let key = read_small(&ssl_dir.join(format!("{domain}.key")));
    let ca = read_small(&ssl_dir.join(format!("{domain}.ca")));
    let (Some(crt), Some(key)) = (crt, key) else {
        return Err(CertProblem::Missing);
    };
    let chain = hestia_fullchain(&crt, ca.as_deref());
    let expiry = evaluate(Some(&chain), Some(&key), &host_of(domain), now)?;
    Ok(HestiaHostCert { chain_pem: chain, key_pem: key, expiry })
}

// ── Port 465 (D7) ───────────────────────────────────────────────────────

/// First token of an ACTIVE master.cf service line: column 0 (indented
/// lines are continuations), not a comment, second token `inet`.
fn active_inet_service(line: &str) -> Option<&str> {
    if line.starts_with(char::is_whitespace) || line.starts_with('#') {
        return None;
    }
    let mut it = line.split_whitespace();
    let name = it.next()?;
    (it.next()? == "inet").then_some(name)
}

/// Is an active `inet` service named exactly one of `names` (also as `host:name`)?
pub fn has_active_service(master_cf: &str, names: &[&str]) -> bool {
    master_cf.lines().filter_map(active_inet_service).any(|svc| {
        let port = svc.rsplit_once(':').map(|(_, p)| p).unwrap_or(svc);
        names.contains(&port)
    })
}

/// Names that already listen on 587 / 465. `smtps` is the legacy name of
/// 465: counted, so 465 is never bound twice.
const SUBMISSION_NAMES: &[&str] = &["submission", "587"];
const SUBMISSIONS_NAMES: &[&str] = &["submissions", "smtps", "465"];

/// Does `/etc/services` resolve `submissions` (name or alias) to 465/tcp?
pub fn services_knows_submissions(etc_services: &str) -> bool {
    etc_services.lines().any(|l| {
        let l = l.split('#').next().unwrap_or("");
        let mut it = l.split_whitespace();
        let (Some(name), Some(port)) = (it.next(), it.next()) else { return false };
        port == "465/tcp" && (name == "submissions" || it.any(|a| a == "submissions"))
    })
}

fn submission_block() -> &'static str {
    "submission inet n - y - - smtpd\n  -o syslog_name=postfix/submission\n  -o smtpd_tls_security_level=encrypt\n  -o smtpd_sasl_auth_enable=yes\n  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject\n"
}

fn submissions_block(service: &str) -> String {
    format!(
        "{service} inet n - y - - smtpd\n  -o syslog_name=postfix/submissions\n  -o smtpd_tls_wrappermode=yes\n  -o smtpd_sasl_auth_enable=yes\n  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject\n"
    )
}

fn append_block(master_cf: &str, block: &str) -> String {
    let mut out = master_cf.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(block);
    out
}

/// master.cf with the 587 block, if no active entry exists. Idempotent.
pub fn ensure_submission(master_cf: &str) -> Option<String> {
    (!has_active_service(master_cf, SUBMISSION_NAMES)).then(|| append_block(master_cf, submission_block()))
}

/// master.cf with the 465 block (`submissions`, or `465` when /etc/services
/// does not know the name), if no active entry exists. Idempotent.
pub fn ensure_submissions(master_cf: &str, name_known: bool) -> Option<String> {
    if has_active_service(master_cf, SUBMISSIONS_NAMES) {
        return None;
    }
    let service = if name_known { "submissions" } else { "465" };
    Some(append_block(master_cf, &submissions_block(service)))
}

async fn submissions_name_known() -> bool {
    services_knows_submissions(&tokio::fs::read_to_string("/etc/services").await.unwrap_or_default())
}

/// master.cf with 587 then 465 ensured, for the installer. `None` = unchanged.
pub async fn master_cf_with_submission_ports(master_cf: &str) -> Option<String> {
    let after_587 = ensure_submission(master_cf);
    let base = after_587.as_deref().unwrap_or(master_cf);
    ensure_submissions(base, submissions_name_known().await).or(after_587)
}

/// Add the 465 block on an existing install: `postfix check`, restored on
/// failure, then reload. Returns whether master.cf changed.
async fn ensure_465_installed() -> Result<bool, String> {
    let master = tokio::fs::read_to_string(mail_routes::POSTFIX_MASTER_CF)
        .await
        .map_err(|e| format!("cannot read master.cf: {e}"))?;
    let Some(new_master) = ensure_submissions(&master, submissions_name_known().await) else {
        return Ok(false);
    };
    mail_routes::write_file_atomic(mail_routes::POSTFIX_MASTER_CF, &new_master)
        .await
        .map_err(|e| format!("cannot write master.cf: {e}"))?;
    if let Err(e) = mail_routes::postfix_check().await {
        let _ = mail_routes::write_file_atomic(mail_routes::POSTFIX_MASTER_CF, &master).await;
        return Err(format!("postfix check refused the 465 block (restored): {e}"));
    }
    reload("postfix").await;
    Ok(true)
}

/// Startup heal (installed mail only): 465 listener, then SNI rebuild.
pub async fn heal_mail_tls() {
    let main_cf = tokio::fs::read_to_string(mail_routes::POSTFIX_MAIN_CF).await.unwrap_or_default();
    if !mail_installed(&main_cf) {
        return;
    }
    match ensure_465_installed().await {
        Ok(true) => tracing::info!("Healed master.cf: submissions (465) listener added"),
        Ok(false) => {}
        Err(e) => tracing::warn!("Port 465 heal skipped: {e}"),
    }
    let out = rebuild_sni().await;
    if let Some(e) = out.error {
        tracing::warn!("mail SNI heal failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    fn pair(sans: &[&str], expired: bool) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        if expired {
            params.not_before = rcgen::date_time_ymd(2019, 1, 1);
            params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        }
        (params.self_signed(&key).unwrap().pem(), key.serialize_pem())
    }

    fn entry(host: &str) -> SniEntry {
        SniEntry {
            host: host.into(),
            key_path: format!("/etc/dockpanel/mail-tls/{host}/privkey.pem"),
            chain_path: format!("/etc/dockpanel/mail-tls/{host}/fullchain.pem"),
            chain_sha256: "ab".repeat(32),
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("mail-tls-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn postfix_table_puts_the_key_before_the_chain() {
        let out = render_postfix_sni(&[entry("mail.a.example.test"), entry("mail.b.example.test")]).unwrap();
        let rows: Vec<&str> = out.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(
            rows,
            vec![
                "mail.a.example.test /etc/dockpanel/mail-tls/mail.a.example.test/privkey.pem /etc/dockpanel/mail-tls/mail.a.example.test/fullchain.pem",
                "mail.b.example.test /etc/dockpanel/mail-tls/mail.b.example.test/privkey.pem /etc/dockpanel/mail-tls/mail.b.example.test/fullchain.pem",
            ]
        );
        assert!(render_postfix_sni(&[]).is_none());
    }

    #[test]
    fn a_renewed_chain_changes_the_rendered_files() {
        let a = entry("mail.a.example.test");
        let mut b = a.clone();
        b.chain_sha256 = "cd".repeat(32);
        assert_ne!(render_postfix_sni(&[a.clone()]), render_postfix_sni(&[b.clone()]));
        assert_ne!(render_dovecot_sni(&[a], false), render_dovecot_sni(&[b], false));
    }

    #[test]
    fn dovecot_23_reads_files_with_the_angle_bracket() {
        let out = render_dovecot_sni(&[entry("mail.a.example.test")], false).unwrap();
        assert!(out.contains("local_name mail.a.example.test {\n"));
        assert!(out.contains("  ssl_cert = </etc/dockpanel/mail-tls/mail.a.example.test/fullchain.pem\n"));
        assert!(out.contains("  ssl_key = </etc/dockpanel/mail-tls/mail.a.example.test/privkey.pem\n"));
        assert!(!out.contains("ssl_server_"));
        assert_eq!(out.matches('{').count(), out.matches('}').count());
        assert!(render_dovecot_sni(&[], false).is_none());
    }

    #[test]
    fn dovecot_24_uses_the_file_settings() {
        let out = render_dovecot_sni(&[entry("mail.a.example.test")], true).unwrap();
        assert!(out.contains("  ssl_server_cert_file = /etc/dockpanel/mail-tls/mail.a.example.test/fullchain.pem\n"));
        assert!(out.contains("  ssl_server_key_file = /etc/dockpanel/mail-tls/mail.a.example.test/privkey.pem\n"));
        assert!(!out.contains("ssl_cert ="));
        assert!(!out.contains("= <"));
    }

    #[test]
    fn virtual_domains_are_validated_and_lowercased() {
        let got = parse_virtual_domains("B.example.test\n\n# c\na.example.test\n../etc\nbad domain\na.example.test\n");
        assert_eq!(got, vec!["a.example.test", "b.example.test"]);
    }

    #[test]
    fn evaluation_reports_each_problem() {
        let now = Utc::now();
        let (good, good_key) = pair(&["mail.a.example.test", "webmail.a.example.test"], false);
        assert!(evaluate(Some(&good), Some(&good_key), "mail.a.example.test", now).is_ok());
        assert_eq!(evaluate(None, Some(&good_key), "mail.a.example.test", now), Err(CertProblem::Missing));
        assert_eq!(evaluate(Some(&good), None, "mail.a.example.test", now), Err(CertProblem::Missing));
        assert_eq!(evaluate(Some("garbage"), Some(&good_key), "mail.a.example.test", now), Err(CertProblem::Unreadable));
        let (old, old_key) = pair(&["mail.a.example.test"], true);
        assert_eq!(evaluate(Some(&old), Some(&old_key), "mail.a.example.test", now), Err(CertProblem::Expired));
        let (apex, apex_key) = pair(&["a.example.test"], false);
        assert_eq!(evaluate(Some(&apex), Some(&apex_key), "mail.a.example.test", now), Err(CertProblem::WrongName));
        let (_, other_key) = pair(&["mail.a.example.test"], false);
        assert_eq!(evaluate(Some(&good), Some(&other_key), "mail.a.example.test", now), Err(CertProblem::Unreadable));
    }

    #[test]
    fn selection_keeps_only_valid_pairs_on_disk() {
        let base = tmpdir("select");
        let write = |d: &str, (c, k): (String, String)| {
            let dir = cert_dir(&base, d);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("fullchain.pem"), c).unwrap();
            std::fs::write(dir.join("privkey.pem"), k).unwrap();
        };
        write("a.example.test", pair(&["mail.a.example.test"], false));
        write("b.example.test", pair(&["mail.b.example.test"], true));
        write("c.example.test", pair(&["c.example.test"], false));
        let d_dir = cert_dir(&base, "d.example.test");
        std::fs::create_dir_all(&d_dir).unwrap();
        std::fs::write(d_dir.join("fullchain.pem"), pair(&["mail.d.example.test"], false).0).unwrap();
        let domains: Vec<String> = ["a", "b", "c", "d", "e"].iter().map(|x| format!("{x}.example.test")).collect();
        let got = select_presentable(&base, &domains, Utc::now());
        assert_eq!(got.iter().map(|e| e.host.as_str()).collect::<Vec<_>>(), vec!["mail.a.example.test"]);
        assert!(got[0].key_path.ends_with("mail.a.example.test/privkey.pem"));
        assert_eq!(got[0].chain_sha256.len(), 64);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn hestia_chain_appends_the_ca_once() {
        let (leaf, _) = pair(&["mail.a.example.test"], false);
        let (ca, _) = pair(&["ca.example.test"], false);
        let full = hestia_fullchain(&leaf, Some(&ca));
        assert_eq!(cert_blocks(&full).len(), 2);
        assert!(full.trim_start().starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(cert_blocks(&full)[0], cert_blocks(&leaf)[0]);
        // crt already a chain: left as is.
        assert_eq!(cert_blocks(&hestia_fullchain(&full, Some(&ca))).len(), 2);
        // ca identical to the leaf: not duplicated.
        assert_eq!(cert_blocks(&hestia_fullchain(&leaf, Some(&leaf))).len(), 1);
        assert_eq!(cert_blocks(&hestia_fullchain(&leaf, None)).len(), 1);
    }

    #[test]
    fn hestia_certificate_is_read_from_the_staging() {
        let root = tmpdir("hestia");
        let dir = root.join("mail/a.example.test/conf/ssl");
        std::fs::create_dir_all(&dir).unwrap();
        let now = Utc::now();
        assert_eq!(read_hestia_host_cert(&root, "a.example.test", now).err(), Some(CertProblem::Missing));
        let (leaf, key) = pair(&["mail.a.example.test", "webmail.a.example.test"], false);
        let (ca, _) = pair(&["ca.example.test"], false);
        std::fs::write(dir.join("a.example.test.crt"), &leaf).unwrap();
        std::fs::write(dir.join("a.example.test.ca"), &ca).unwrap();
        std::fs::write(dir.join("a.example.test.key"), &key).unwrap();
        let got = read_hestia_host_cert(&root, "a.example.test", now).ok().unwrap();
        assert_eq!(cert_blocks(&got.chain_pem).len(), 2);
        assert!(got.expiry > now);
        let (old, old_key) = pair(&["mail.a.example.test"], true);
        std::fs::write(dir.join("a.example.test.crt"), &old).unwrap();
        std::fs::write(dir.join("a.example.test.key"), &old_key).unwrap();
        assert_eq!(read_hestia_host_cert(&root, "a.example.test", now).err(), Some(CertProblem::Expired));
        let (apex, apex_key) = pair(&["a.example.test"], false);
        std::fs::write(dir.join("a.example.test.crt"), &apex).unwrap();
        std::fs::write(dir.join("a.example.test.key"), &apex_key).unwrap();
        assert_eq!(read_hestia_host_cert(&root, "a.example.test", now).err(), Some(CertProblem::WrongName));
        std::fs::write(dir.join("a.example.test.crt"), "not a pem").unwrap();
        assert_eq!(read_hestia_host_cert(&root, "a.example.test", now).err(), Some(CertProblem::Unreadable));
        let _ = std::fs::remove_dir_all(&root);
    }

    const STOCK_MASTER: &str = "smtp      inet  n       -       y       -       -       smtpd\n#submission inet n       -       y       -       -       smtpd\n#  -o syslog_name=postfix/submission\n#submissions     inet  n       -       y       -       -       smtpd\n#smtps     inet  n       -       y       -       -       smtpd\npickup    unix  n       -       y       60      1       pickup\n";

    #[test]
    fn active_entries_are_matched_on_the_exact_first_token() {
        let sub_only = format!("{STOCK_MASTER}submission inet n - y - - smtpd\n  -o smtpd_tls_wrappermode=no\n");
        assert!(has_active_service(&sub_only, SUBMISSION_NAMES));
        assert!(!has_active_service(&sub_only, SUBMISSIONS_NAMES));
        let subs_only = format!("{STOCK_MASTER}submissions inet n - y - - smtpd\n");
        assert!(!has_active_service(&subs_only, SUBMISSION_NAMES), "submissions is not submission");
        assert!(has_active_service(&subs_only, SUBMISSIONS_NAMES));
        assert!(!has_active_service(STOCK_MASTER, SUBMISSION_NAMES), "comments do not count");
        assert!(!has_active_service(STOCK_MASTER, SUBMISSIONS_NAMES));
        assert!(has_active_service("465 inet n - y - - smtpd\n", SUBMISSIONS_NAMES));
        assert!(has_active_service("0.0.0.0:465 inet n - y - - smtpd\n", SUBMISSIONS_NAMES));
        assert!(has_active_service("smtps inet n - y - - smtpd\n", SUBMISSIONS_NAMES));
        assert!(!has_active_service("  submission inet n - y - - smtpd\n", SUBMISSION_NAMES), "continuation line");
        assert!(!has_active_service("submission unix n - y - - smtpd\n", SUBMISSION_NAMES));
    }

    #[test]
    fn port_blocks_are_added_once() {
        let with_587 = ensure_submission(STOCK_MASTER).unwrap();
        assert!(ensure_submission(&with_587).is_none());
        let with_465 = ensure_submissions(&with_587, true).unwrap();
        assert!(ensure_submissions(&with_465, true).is_none());
        assert!(ensure_submissions(&with_465, false).is_none());
        assert!(ensure_submission(&with_465).is_none(), "465 block does not hide a missing 587");
        assert!(with_465.contains(
            "\nsubmissions inet n - y - - smtpd\n  -o syslog_name=postfix/submissions\n  -o smtpd_tls_wrappermode=yes\n  -o smtpd_sasl_auth_enable=yes\n  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject\n"
        ));
        assert!(with_465.starts_with(STOCK_MASTER));
        let numeric = ensure_submissions(STOCK_MASTER, false).unwrap();
        assert!(numeric.contains("\n465 inet n - y - - smtpd\n"));
        // An existing 465 block alone does not stop 587 being added.
        let subs_first = ensure_submissions(STOCK_MASTER, true).unwrap();
        assert!(ensure_submission(&subs_first).is_some());
        // No trailing newline: the block still starts on its own line.
        assert!(ensure_submission("smtp inet n - y - - smtpd").unwrap().contains("smtpd\n\nsubmission inet"));
    }

    #[test]
    fn etc_services_lookup_accepts_name_or_alias() {
        assert!(services_knows_submissions("submissions\t465/tcp\t\tssmtp smtps urd\t# over TLS\n"));
        assert!(services_knows_submissions("urd 465/tcp ssmtp smtps submissions\n"));
        assert!(!services_knows_submissions("urd 465/tcp ssmtp smtps\n"));
        assert!(!services_knows_submissions("# submissions 465/tcp\n"));
        assert!(!services_knows_submissions("submissions 465/udp\n"));
        assert!(!services_knows_submissions(""));
    }
}
