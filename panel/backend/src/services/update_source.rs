//! Where panel updates come from, and whether they are allowed at all.
//!
//! Two things must both hold before this panel contacts GitHub or installs
//! anything (the "configured" predicate, checked in this order):
//!   1. a minisign public key was compiled into the binary
//!      (`CYBERHUNTER_UPDATE_PUBKEY` at build time, see `build.rs`);
//!   2. a valid source: `/etc/dockpanel/update.conf` when it exists, or the
//!      default public release repository when it does not. An `update.conf`
//!      that exists but is invalid gives `no_source`.
//!
//! The token is optional (conception 12, D2). Without one, GitHub is queried
//! anonymously, which is enough for a public release repository; a private one
//! needs a token. Either way, a release is installed only once its signature
//! against the compiled key has been checked.
//!
//! The token itself is never a field of a `Serialize` or `Debug` structure. It
//! is read from disk right before a GitHub request, by
//! `release_fetch::github_auth_header`, and only lives in a sensitive header.

use std::path::{Path, PathBuf};
use std::sync::{LazyLock, OnceLock};

use base64::Engine;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The configuration file, read and written by this backend only.
pub const UPDATE_CONF_PATH: &str = "/etc/dockpanel/update.conf";
/// Where `PUT /api/update/source` puts the token when no valid config names a file.
pub const DEFAULT_TOKEN_FILE: &str = "/etc/dockpanel/update-token";
/// Release repository used when the operator does not name one: the public
/// releases repository, readable without a token.
pub const DEFAULT_UPDATE_REPO: &str = "MrTheSkream/cyberhunter-releases";
/// Every path the config may name lives under this directory.
const CONF_DIR: &str = "/etc/dockpanel/";
/// The only accepted name of the token file, inside the config directory.
const TOKEN_FILE_NAME: &str = "update-token";
const CONF_HEADER: &str = "# Managed by CyberHunter - Panel (Telemetry, Updates)";

/// The base64 line of the minisign `.pub` file, fixed at compile time.
const COMPILED_PUBKEY: Option<&str> = option_env!("CYBERHUNTER_UPDATE_PUBKEY");

pub const REASON_NO_SIGNING_KEY: &str = "no_signing_key";
pub const REASON_NO_SOURCE: &str = "no_source";

static REPO_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$").unwrap()
});
static TOKEN_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^github_pat_[A-Za-z0-9_]{20,255}$").unwrap());

// ── update.conf ──────────────────────────────────────────────────────────

/// A valid `update.conf`. Holds a path to the token, never the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSource {
    pub repo: String,
    pub token_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfError {
    /// The file does not exist. The default source is then used.
    Missing,
    /// The file exists but is not acceptable; the text says why (never a value).
    Invalid(&'static str),
}

/// `owner/name`, GitHub's own character rules, and never `.` or `..` as name.
pub fn validate_repo(repo: &str) -> bool {
    if !REPO_RE.is_match(repo) {
        return false;
    }
    !matches!(repo.split_once('/').map(|(_, n)| n), Some(".") | Some(".."))
}

/// Fine-grained tokens only.
pub fn validate_token(token: &str) -> bool {
    TOKEN_RE.is_match(token)
}

/// Exactly `<dir>update-token` (`/etc/dockpanel/update-token` for the real
/// config). A fixed name rather than "any file under the directory": a config
/// that could name another file under `/etc/dockpanel` could point the token
/// reader (and `clear_token`, which deletes it) at a file it has no business
/// with.
fn validate_token_path(p: &str, dir: &str) -> bool {
    !p.contains('\0') && p.strip_prefix(dir) == Some(TOKEN_FILE_NAME)
}

/// Parse the text of `update.conf`. Pure: no file access.
///
/// `KEY=value`, no quotes, `#` lines and blank lines ignored, unknown keys
/// ignored, a trailing `\r` tolerated. Both known keys are required, each at
/// most once; anything else that is not a comment is refused.
pub fn read_conf(text: &str) -> Result<UpdateSource, ConfError> {
    read_conf_in(text, CONF_DIR)
}

/// [`read_conf`] with the directory the token file must live in. The real
/// config passes `/etc/dockpanel/`; tests pass a temporary directory.
fn read_conf_in(text: &str, dir: &str) -> Result<UpdateSource, ConfError> {
    let mut repo: Option<String> = None;
    let mut token_file: Option<String> = None;
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(ConfError::Invalid("a line is not KEY=value"));
        };
        let slot = match key.trim() {
            "UPDATE_REPO" => &mut repo,
            "UPDATE_TOKEN_FILE" => &mut token_file,
            _ => continue,
        };
        if slot.is_some() {
            return Err(ConfError::Invalid("a key is set twice"));
        }
        *slot = Some(value.trim().to_string());
    }
    let repo = repo.ok_or(ConfError::Invalid("UPDATE_REPO is missing"))?;
    if !validate_repo(&repo) {
        return Err(ConfError::Invalid("UPDATE_REPO is not owner/name"));
    }
    let token_file = token_file.ok_or(ConfError::Invalid("UPDATE_TOKEN_FILE is missing"))?;
    if !validate_token_path(&token_file, dir) {
        return Err(ConfError::Invalid(
            "UPDATE_TOKEN_FILE is not /etc/dockpanel/update-token",
        ));
    }
    Ok(UpdateSource {
        repo,
        token_file: PathBuf::from(token_file),
    })
}

fn render_conf(source: &UpdateSource) -> String {
    format!(
        "{CONF_HEADER}\nUPDATE_REPO={}\nUPDATE_TOKEN_FILE={}\n",
        source.repo,
        source.token_file.display()
    )
}

/// The directory the token file must live in: the config's own directory.
fn conf_dir_of(conf_path: &Path) -> String {
    if conf_path == Path::new(UPDATE_CONF_PATH) {
        return CONF_DIR.to_string();
    }
    let parent = conf_path.parent().unwrap_or_else(|| Path::new("/"));
    format!("{}/", parent.display().to_string().trim_end_matches('/'))
}

fn read_conf_file(path: &Path) -> Result<UpdateSource, ConfError> {
    match std::fs::read_to_string(path) {
        Ok(text) if path == Path::new(UPDATE_CONF_PATH) => read_conf(&text),
        Ok(text) => read_conf_in(&text, &conf_dir_of(path)),
        // Only an absent file means "use the default source": a config that
        // exists but cannot be read (permissions, not UTF-8, a directory) is
        // invalid, never silently replaced by the default.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ConfError::Missing),
        Err(_) => Err(ConfError::Invalid("update.conf cannot be read")),
    }
}

/// The source used when no `update.conf` exists: the default public
/// repository, and the default token file next to the config (read only if
/// the operator put a token there).
fn default_source_for(conf_path: &Path) -> UpdateSource {
    UpdateSource {
        repo: DEFAULT_UPDATE_REPO.to_string(),
        token_file: default_token_file_for(conf_path),
    }
}

/// The source in effect: the config when it is valid, the default one when it
/// is missing, and the error when it exists but is invalid. The only place
/// where a missing config turns into the default source.
fn resolve_source(conf_path: &Path) -> Result<UpdateSource, ConfError> {
    match read_conf_file(conf_path) {
        Err(ConfError::Missing) => Ok(default_source_for(conf_path)),
        other => other,
    }
}

// ── Token file ───────────────────────────────────────────────────────────

/// The token, wiped from memory on drop, and opaque to `Debug`.
pub struct SecretToken(Zeroizing<String>);

impl SecretToken {
    /// Wrap a token typed by the operator, trimmed.
    pub fn from_input(token: &str) -> SecretToken {
        SecretToken(Zeroizing::new(token.trim().to_string()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretToken(<redacted>)")
    }
}

/// The token in `path`, spaces around it removed; `None` when absent or empty.
///
/// A symbolic link (or anything but a regular file) is refused, and the file
/// opened must be the one that was checked (same device and inode), so the
/// token cannot be redirected to another file's contents.
pub fn read_token(path: &Path) -> Option<SecretToken> {
    use std::io::Read;
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        if meta.file_type().is_symlink() {
            tracing::warn!("The update token file is a symbolic link; it is ignored");
        }
        return None;
    }
    let mut f = std::fs::File::open(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = f.metadata().ok()?;
        if opened.dev() != meta.dev() || opened.ino() != meta.ino() || !opened.is_file() {
            return None;
        }
    }
    let mut raw = Zeroizing::new(String::new());
    f.read_to_string(&mut raw).ok()?;
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    Some(SecretToken(Zeroizing::new(t.to_string())))
}

// ── Signing key ──────────────────────────────────────────────────────────

/// Parse the base64 line of a minisign public key and compute the ID minisign
/// prints for it (`untrusted comment: minisign public key <ID>`).
pub fn parse_public_key(b64: &str) -> Option<(minisign_verify::PublicKey, String)> {
    let b64 = b64.trim();
    if b64.is_empty() {
        return None;
    }
    let key = minisign_verify::PublicKey::from_base64(b64).ok()?;
    let raw = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    if raw.len() != 42 {
        return None;
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&raw[2..10]);
    Some((key, format!("{:016X}", u64::from_le_bytes(id))))
}

static SIGNING_KEY: OnceLock<Option<(minisign_verify::PublicKey, String)>> = OnceLock::new();

fn compiled_key() -> &'static Option<(minisign_verify::PublicKey, String)> {
    SIGNING_KEY.get_or_init(|| COMPILED_PUBKEY.and_then(parse_public_key))
}

/// The compiled-in update key, or `None`: absent, empty or malformed.
pub fn signing_key() -> Option<&'static minisign_verify::PublicKey> {
    compiled_key().as_ref().map(|(k, _)| k)
}

/// The compiled-in key's ID, formatted like minisign does.
pub fn signing_key_id() -> Option<String> {
    compiled_key().as_ref().map(|(_, id)| id.clone())
}

/// Called once at start-up.
pub fn log_signing_key_at_startup() {
    match (COMPILED_PUBKEY.map(str::trim), signing_key_id()) {
        (_, Some(id)) => tracing::info!("Update signing key {id} compiled in"),
        (Some(v), None) if !v.is_empty() => {
            tracing::error!("CYBERHUNTER_UPDATE_PUBKEY is not a valid minisign public key")
        }
        _ => tracing::warn!("No update signing key compiled in; updates are disabled"),
    }
}

// ── The predicate ────────────────────────────────────────────────────────

/// What `GET /api/update/status` and every gate need to know. No token here.
#[derive(Debug, Clone, Serialize)]
pub struct SourceStatus {
    pub configured: bool,
    pub reason: Option<&'static str>,
    pub repo: Option<String>,
    pub token_set: bool,
    pub signing_key_id: Option<String>,
    /// The valid config, kept for the callers that go on to fetch. Not serialized.
    #[serde(skip)]
    pub source: Option<UpdateSource>,
}

/// The predicate, pure. Reasons in contract order: key, then source. The
/// token is reported (`token_set`) but never required.
///
/// `conf` is the source already resolved: [`load_from`] turns a missing
/// `update.conf` into the default source before calling this, so any `Err`
/// here means no usable source.
pub fn evaluate(
    signing_key_id: Option<String>,
    conf: Result<UpdateSource, ConfError>,
    token_set: bool,
) -> SourceStatus {
    let source = conf.ok();
    let token_set = source.is_some() && token_set;
    let reason = if signing_key_id.is_none() {
        Some(REASON_NO_SIGNING_KEY)
    } else if source.is_none() {
        Some(REASON_NO_SOURCE)
    } else {
        None
    };
    SourceStatus {
        configured: reason.is_none(),
        reason,
        repo: source.as_ref().map(|s| s.repo.clone()),
        token_set,
        signing_key_id,
        source,
    }
}

/// Read the config and token file from their real places.
pub fn load() -> SourceStatus {
    load_from(Path::new(UPDATE_CONF_PATH), signing_key_id())
}

pub fn load_from(conf_path: &Path, signing_key_id: Option<String>) -> SourceStatus {
    let conf = resolve_source(conf_path);
    let token_set = conf
        .as_ref()
        .map(|s| read_token(&s.token_file).is_some())
        .unwrap_or(false);
    evaluate(signing_key_id, conf, token_set)
}

// ── Writing ──────────────────────────────────────────────────────────────

/// Write `contents` next to `path` and rename it into place, mode 0600.
fn write_private_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("/"));
    std::fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("update");
    let tmp = dir.join(format!(".{name}.tmp-{}", Uuid::new_v4()));
    let result = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Save a token (already validated and tested) and the repository: token
/// first, then `update.conf`, both by temporary file and `rename`, 0600.
pub fn write_source(repo: &str, token: &str) -> std::io::Result<()> {
    write_source_at(Path::new(UPDATE_CONF_PATH), repo, token)
}

pub fn write_source_at(conf_path: &Path, repo: &str, token: &str) -> std::io::Result<()> {
    // Keep a token file the existing (valid) config already names; otherwise the
    // default one, next to the config.
    let token_file = read_conf_file(conf_path)
        .map(|s| s.token_file)
        .unwrap_or_else(|_| default_token_file_for(conf_path));
    let line = Zeroizing::new(format!("{}\n", token.trim()));
    write_private_atomic(&token_file, line.as_bytes())?;
    let source = UpdateSource {
        repo: repo.to_string(),
        token_file,
    };
    write_private_atomic(conf_path, render_conf(&source).as_bytes())
}

/// The default token file sits next to the real config; tests point the config
/// elsewhere and must not touch `/etc/dockpanel`.
fn default_token_file_for(conf_path: &Path) -> PathBuf {
    if conf_path == Path::new(UPDATE_CONF_PATH) {
        PathBuf::from(DEFAULT_TOKEN_FILE)
    } else {
        conf_path.with_file_name("update-token")
    }
}

/// Delete the token file, keep `update.conf`.
pub fn clear_token() -> std::io::Result<()> {
    clear_token_at(Path::new(UPDATE_CONF_PATH))
}

pub fn clear_token_at(conf_path: &Path) -> std::io::Result<()> {
    let token_file = read_conf_file(conf_path)
        .map(|s| s.token_file)
        .unwrap_or_else(|_| default_token_file_for(conf_path));
    match std::fs::remove_file(&token_file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// The repository `PUT /api/update/source` uses when the body names none: the
/// one in effect (a missing config means the default), or the default when
/// the config is invalid.
pub fn current_or_default_repo() -> String {
    current_or_default_repo_at(Path::new(UPDATE_CONF_PATH))
}

fn current_or_default_repo_at(conf_path: &Path) -> String {
    resolve_source(conf_path)
        .map(|s| s.repo)
        .unwrap_or_else(|_| DEFAULT_UPDATE_REPO.to_string())
}

// ── Activity journal ─────────────────────────────────────────────────────

/// Who an update journal entry is attributed to.
#[derive(Debug, Clone)]
pub enum Actor {
    User {
        id: Uuid,
        email: String,
        ip: Option<String>,
        key_id: Option<Uuid>,
    },
    /// A result observed without a request (after a restart, by the poller):
    /// the snapshot's operator, or `"system"`.
    System(String),
}

impl Actor {
    pub fn from_claims(claims: &crate::auth::Claims, headers: &axum::http::HeaderMap) -> Self {
        Actor::User {
            id: claims.sub,
            email: claims.email.clone(),
            ip: crate::routes::client_ip(headers),
            key_id: claims.key_id,
        }
    }

    pub fn system() -> Self {
        Actor::System("system".to_string())
    }

    pub fn email(&self) -> &str {
        match self {
            Actor::User { email, .. } => email,
            Actor::System(e) => e,
        }
    }
}

pub const TARGET_TYPE: &str = "panel_update";

/// One `panel_update` row in the activity log. `details` never holds a token or
/// a download URL: every caller builds it from versions, codes and contract
/// messages only.
pub async fn audit(
    pool: &PgPool,
    actor: &Actor,
    action: &str,
    target_name: Option<&str>,
    details: serde_json::Value,
) {
    let details = details.to_string();
    match actor {
        Actor::User {
            id,
            email,
            ip,
            key_id,
        } => {
            crate::services::activity::log_activity(
                pool,
                *id,
                email,
                action,
                Some(TARGET_TYPE),
                target_name,
                Some(&details),
                ip.as_deref(),
                *key_id,
            )
            .await
        }
        Actor::System(email) => {
            crate::services::activity::log_activity_system(
                pool,
                email,
                action,
                Some(TARGET_TYPE),
                target_name,
                Some(&details),
                None,
                None,
            )
            .await
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const TEST_PUB: &str = include_str!("testdata/release/test.pub");
    /// A token of the accepted shape, used to prove it never leaks.
    pub(crate) const KNOWN_TOKEN: &str = "github_pat_11AAAAAAA0leakcheckZZZZZZZZZZZZZZZZZZZZ_9";

    pub(crate) fn test_key_line() -> &'static str {
        TEST_PUB.lines().nth(1).unwrap()
    }

    pub(crate) fn temp_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("chp-update-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const VALID: &str = "# Managed by CyberHunter - Panel (Telemetry, Updates)\n\
                         UPDATE_REPO=MrTheSkream/cyberhunter-panel\n\
                         UPDATE_TOKEN_FILE=/etc/dockpanel/update-token\n";

    #[test]
    fn a_valid_conf_is_read() {
        let s = read_conf(VALID).unwrap();
        assert_eq!(s.repo, "MrTheSkream/cyberhunter-panel");
        assert_eq!(s.token_file, PathBuf::from("/etc/dockpanel/update-token"));
    }

    #[test]
    fn comments_blank_lines_and_unknown_keys_are_ignored() {
        let text = "\n# a comment\n   # indented comment\nFUTURE_KEY=whatever\n\n\
                    UPDATE_REPO=owner/name\nUPDATE_TOKEN_FILE=/etc/dockpanel/update-token\n";
        let s = read_conf(text).unwrap();
        assert_eq!(s.repo, "owner/name");
    }

    #[test]
    fn a_trailing_carriage_return_is_tolerated() {
        let text = VALID.replace('\n', "\r\n");
        assert_eq!(read_conf(&text).unwrap(), read_conf(VALID).unwrap());
    }

    #[test]
    fn an_invalid_repo_makes_the_conf_invalid() {
        for repo in [
            "owner",
            "owner/",
            "/name",
            "-owner/name",
            "owner/name/extra",
            "owner/..",
            "owner/.",
            "\"owner/name\"",
            "owner/na me",
        ] {
            let text = format!("UPDATE_REPO={repo}\nUPDATE_TOKEN_FILE=/etc/dockpanel/update-token\n");
            assert!(read_conf(&text).is_err(), "{repo} must be refused");
            assert!(!validate_repo(repo), "{repo} must be refused");
        }
        assert!(validate_repo("a/b.c_d-e"));
    }

    #[test]
    fn a_token_path_outside_etc_dockpanel_makes_the_conf_invalid() {
        for p in [
            "/etc/passwd",
            "update-token",
            "/etc/dockpanel/",
            "/etc/dockpanel/../shadow",
            "/etc/dockpanelx/token",
            "/var/lib/dockpanel/token",
            "/etc/dockpanel//token",
            "/etc/dockpanel/tok",
            "/etc/dockpanel/update.conf",
            "/etc/dockpanel/sub/update-token",
            "/etc/dockpanel/update-token/",
        ] {
            let text = format!("UPDATE_REPO=owner/name\nUPDATE_TOKEN_FILE={p}\n");
            assert!(
                matches!(read_conf(&text), Err(ConfError::Invalid(_))),
                "{p} must be refused"
            );
        }
    }

    #[test]
    fn missing_or_repeated_keys_and_stray_lines_are_refused() {
        assert!(read_conf("UPDATE_REPO=owner/name\n").is_err());
        assert!(read_conf("UPDATE_TOKEN_FILE=/etc/dockpanel/update-token\n").is_err());
        assert!(read_conf(&format!("{VALID}UPDATE_REPO=other/name\n")).is_err());
        assert!(read_conf(&format!("{VALID}not a key value line\n")).is_err());
    }

    #[test]
    fn token_formats() {
        assert!(validate_token(KNOWN_TOKEN));
        assert!(validate_token(&format!("github_pat_{}", "a".repeat(20))));
        assert!(validate_token(&format!("github_pat_{}", "Z_9".repeat(85))));
        for bad in [
            "",
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "github_pat_short",
            &format!("github_pat_{}", "a".repeat(256)),
            &format!("github_pat_{}-x", "a".repeat(30)),
            &format!(" github_pat_{}", "a".repeat(30)),
            &format!("github_pat_{}\n", "a".repeat(30)),
            &format!("Bearer github_pat_{}", "a".repeat(30)),
        ] {
            assert!(!validate_token(bad), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_predicate_reports_each_reason_in_order() {
        let key = Some("531546B906DAE39E".to_string());
        let conf = || read_conf(VALID);
        let s = evaluate(key.clone(), conf(), true);
        assert!(s.configured);
        assert_eq!(s.reason, None);

        assert_eq!(
            evaluate(key.clone(), Err(ConfError::Invalid("x")), true).reason,
            Some(REASON_NO_SOURCE)
        );
        assert_eq!(evaluate(None, conf(), true).reason, Some(REASON_NO_SIGNING_KEY));

        // Order: no key wins over no source.
        assert_eq!(evaluate(None, Err(ConfError::Invalid("x")), false).reason, Some(REASON_NO_SIGNING_KEY));
        for s in [
            evaluate(None, conf(), true),
            evaluate(None, conf(), false),
            evaluate(key, Err(ConfError::Invalid("x")), true),
        ] {
            assert!(!s.configured);
        }
    }

    #[test]
    fn the_predicate_does_not_require_a_token() {
        let key = Some("531546B906DAE39E".to_string());
        let s = evaluate(key, read_conf(VALID), false);
        assert!(s.configured, "{s:?}");
        assert_eq!(s.reason, None);
        assert!(!s.token_set);
        assert_eq!(s.repo.as_deref(), Some("MrTheSkream/cyberhunter-panel"));
    }

    #[test]
    fn a_missing_conf_means_the_default_public_repository() {
        let dir = temp_dir();
        let conf = dir.join("update.conf");
        let key = Some("531546B906DAE39E".to_string());

        let s = load_from(&conf, key.clone());
        assert!(s.configured, "{s:?}");
        assert_eq!(s.reason, None);
        assert_eq!(s.repo.as_deref(), Some(DEFAULT_UPDATE_REPO));
        assert_eq!(DEFAULT_UPDATE_REPO, "MrTheSkream/cyberhunter-releases");
        assert!(!s.token_set);
        let src = s.source.as_ref().unwrap();
        assert_eq!(src.token_file, dir.join("update-token"), "default token file next to the config");
        assert_eq!(current_or_default_repo_at(&conf), DEFAULT_UPDATE_REPO);
        assert!(!conf.exists(), "loading writes nothing");

        // A token put in the default file is seen (and will be sent).
        std::fs::write(dir.join("update-token"), format!("{KNOWN_TOKEN}\n")).unwrap();
        let s = load_from(&conf, key);
        assert!(s.configured && s.token_set, "{s:?}");

        // Without a compiled key, still not configured.
        assert_eq!(load_from(&conf, None).reason, Some(REASON_NO_SIGNING_KEY));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_invalid_conf_is_still_no_source() {
        let dir = temp_dir();
        let conf = dir.join("update.conf");
        std::fs::write(&conf, "UPDATE_REPO=not a repo\n").unwrap();
        let s = load_from(&conf, Some("531546B906DAE39E".to_string()));
        assert!(!s.configured);
        assert_eq!(s.reason, Some(REASON_NO_SOURCE));
        assert_eq!(s.repo, None);
        assert!(s.source.is_none());
        assert_eq!(current_or_default_repo_at(&conf), DEFAULT_UPDATE_REPO);

        // A config that exists but cannot be read is not "missing".
        std::fs::write(&conf, [0xffu8, 0xfe, 0x00, 0x80]).unwrap();
        assert_eq!(load_from(&conf, Some("ID".into())).reason, Some(REASON_NO_SOURCE));
        std::fs::remove_file(&conf).unwrap();
        std::fs::create_dir(&conf).unwrap();
        assert_eq!(load_from(&conf, Some("ID".into())).reason, Some(REASON_NO_SOURCE));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_key_id_matches_the_one_minisign_printed() {
        let printed = TEST_PUB
            .lines()
            .next()
            .unwrap()
            .rsplit(' ')
            .next()
            .unwrap()
            .to_string();
        let (_, id) = parse_public_key(test_key_line()).expect("fixture key must parse");
        assert_eq!(id, printed);
        assert_eq!(id, "531546B906DAE39E");
    }

    #[test]
    fn a_malformed_or_empty_key_is_no_key() {
        assert!(parse_public_key("").is_none());
        assert!(parse_public_key("   ").is_none());
        assert!(parse_public_key("not base64 at all").is_none());
        assert!(parse_public_key("RWQ=").is_none());
    }

    #[test]
    fn write_then_load_then_clear_round_trip() {
        let dir = temp_dir();
        let conf = dir.join("update.conf");
        let key = Some("531546B906DAE39E".to_string());
        let s = load_from(&conf, key.clone());
        assert!(s.configured, "no config: the default source, no token needed");
        assert_eq!(s.repo.as_deref(), Some(DEFAULT_UPDATE_REPO));

        write_source_at(&conf, "owner/name", KNOWN_TOKEN).unwrap();
        let s = load_from(&conf, key.clone());
        assert!(s.configured, "{s:?}");
        assert_eq!(s.repo.as_deref(), Some("owner/name"));
        assert!(s.token_set);
        assert_eq!(
            std::fs::read_to_string(dir.join("update-token")).unwrap(),
            format!("{KNOWN_TOKEN}\n")
        );
        let conf_text = std::fs::read_to_string(&conf).unwrap();
        assert!(conf_text.starts_with(CONF_HEADER));
        assert!(!conf_text.contains(KNOWN_TOKEN), "the config must not hold the token");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in [&conf, &dir.join("update-token")] {
                let mode = std::fs::metadata(f).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{}", f.display());
            }
        }

        assert_eq!(current_or_default_repo_at(&conf), "owner/name");

        clear_token_at(&conf).unwrap();
        let s = load_from(&conf, key);
        assert!(s.configured, "no token: still configured, anonymous requests");
        assert_eq!(s.reason, None);
        assert!(!s.token_set);
        assert_eq!(s.repo.as_deref(), Some("owner/name"), "the config is kept");
        clear_token_at(&conf).unwrap(); // idempotent
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_token_file_is_trimmed_and_empty_means_none() {
        let dir = temp_dir();
        let p = dir.join("tok");
        std::fs::write(&p, format!("  {KNOWN_TOKEN}  \n")).unwrap();
        assert_eq!(read_token(&p).unwrap().expose(), KNOWN_TOKEN);
        std::fs::write(&p, " \n").unwrap();
        assert!(read_token(&p).is_none());
        assert!(read_token(&dir.join("absent")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_secret_token_does_not_debug_print() {
        let dir = temp_dir();
        let p = dir.join("tok");
        std::fs::write(&p, KNOWN_TOKEN).unwrap();
        let t = read_token(&p).unwrap();
        assert!(!format!("{t:?}").contains(KNOWN_TOKEN));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_rendered_conf_reads_back() {
        let s = UpdateSource {
            repo: "owner/name".into(),
            token_file: PathBuf::from(DEFAULT_TOKEN_FILE),
        };
        let text = render_conf(&s);
        assert!(text.starts_with(CONF_HEADER));
        assert_eq!(read_conf(&text).unwrap(), s);
    }

    /// The migration that drops an advertisement possibly inherited from the
    /// upstream repository (A-9). `sqlx::migrate!` embeds it at compile time;
    /// this pins what it deletes and that it does not name that repository.
    #[test]
    fn the_migration_clears_the_inherited_advertisement() {
        let sql = include_str!("../../migrations/20261124000000_update_source.sql");
        for key in ["update_available_version", "update_release_notes", "update_release_url"] {
            assert!(sql.contains(&format!("'{key}'")), "{key}");
        }
        assert!(sql.contains("DELETE FROM settings"));
        let upstream = concat!("ovex", "ro");
        assert!(!sql.to_lowercase().contains(upstream));
    }

    #[test]
    fn source_status_serialization_never_holds_the_token() {
        let dir = temp_dir();
        let conf = dir.join("update.conf");
        write_source_at(&conf, "owner/name", KNOWN_TOKEN).unwrap();
        let s = load_from(&conf, Some("ID".into()));
        assert!(s.configured);
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains(KNOWN_TOKEN));
        assert!(!format!("{s:?}").contains(KNOWN_TOKEN));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_token_file_is_ignored() {
        let dir = temp_dir();
        let real = dir.join("elsewhere");
        std::fs::write(&real, "github_pat_ABCDEFGHIJKLMNOPQRSTUV
").unwrap();
        let link = dir.join("update-token");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_token(&link).is_none(), "a symbolic link must not be followed");
        std::fs::remove_file(&link).unwrap();
        std::fs::copy(&real, &link).unwrap();
        assert_eq!(read_token(&link).unwrap().expose(), "github_pat_ABCDEFGHIJKLMNOPQRSTUV");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
