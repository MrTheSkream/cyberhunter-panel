//! Signed releases, agent side (feature 10).
//!
//! The agent never talks to the release host. It asks ITS PANEL for three
//! files of a release (`checksums.txt.minisig`, `checksums.txt`, then its own
//! binary), and installs nothing unless:
//!
//! 1. the minisign signature of `checksums.txt` verifies with the public key
//!    compiled into this binary (`CYBERHUNTER_UPDATE_PUBKEY` at build time);
//! 2. the signature's trusted comment is exactly `cyberhunter-release <tag>`,
//!    which binds the signed manifest to the version being installed;
//! 3. the binary's SHA-256 equals its manifest entry, and it is an ELF file.
//!
//! The panel is therefore only a relay: a compromised or mistaken panel can
//! refuse to serve, but cannot make this agent run bytes the release key did
//! not sign. `agent-self-update.sh` then only re-checks the SHA-256 it is
//! handed, on a file this module already verified.
//!
//! Same rules as the backend's reader (contract §2.2/§2.3), written separately
//! on purpose: the two crates share no code.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use minisign_verify::{PublicKey, Signature};
use sha2::{Digest, Sha256};

/// `checksums.txt` is at most this many bytes (contract §2.2).
pub const MAX_CHECKSUMS_BYTES: usize = 64 * 1024;
/// And at most this many lines.
pub const MAX_CHECKSUMS_LINES: usize = 32;
/// `checksums.txt.minisig` is at most this many bytes.
pub const MAX_MINISIG_BYTES: usize = 4 * 1024;
/// One release file is at most 200 MiB.
pub const MAX_ASSET_BYTES: usize = 209_715_200;
/// Where the verified agent binary is staged for `agent-self-update.sh`.
pub const STAGING_DIR: &str = "/var/lib/dockpanel/agent-release";
/// The prefix of the trusted comment; the tag follows after one space.
pub const TRUSTED_COMMENT_PREFIX: &str = "cyberhunter-release ";

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// The base64 line of the minisign `.pub` this binary was built with, if any.
/// A COMPILE-TIME variable: no key lives in the repository, a development
/// build has none (updates off, fail closed), and nobody who can write a file
/// on the box can swap it - only a new signed binary can.
pub fn compiled_key_b64() -> Option<&'static str> {
    option_env!("CYBERHUNTER_UPDATE_PUBKEY")
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Parse a minisign public key from the `.pub` file's second line.
pub fn parse_public_key(b64: &str) -> Option<PublicKey> {
    PublicKey::from_base64(b64.trim()).ok()
}

/// The key ID minisign prints (`untrusted comment: minisign public key <ID>`):
/// bytes 2..10 of the decoded key, read as a little-endian u64, upper hex.
pub fn key_id(b64: &str) -> Option<String> {
    use base64::Engine;
    let bin = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    if bin.len() != 42 {
        return None;
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&bin[2..10]);
    Some(format!("{:016X}", u64::from_le_bytes(id)))
}

/// The compiled-in key, parsed once. Absent or empty: `None`. Malformed:
/// `None` too, and an error in the log, because that is a broken build rather
/// than a configuration choice.
pub fn signing_key() -> Option<&'static PublicKey> {
    static KEY: OnceLock<Option<PublicKey>> = OnceLock::new();
    KEY.get_or_init(|| {
        let b64 = compiled_key_b64()?;
        let key = parse_public_key(b64);
        if key.is_none() {
            tracing::error!("CYBERHUNTER_UPDATE_PUBKEY is not a valid minisign public key");
        }
        key
    })
    .as_ref()
}

/// ID of the compiled-in key, for logs.
pub fn signing_key_id() -> Option<String> {
    signing_key()?;
    key_id(compiled_key_b64()?)
}

/// Why a release was refused. `Display` is the exact text the panel shows
/// (contract B-2 and §2.6); the precise cause goes to the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    /// The panel answered 409 `updates_not_configured`.
    NotConfigured,
    /// Missing, unreadable, other key, bad signature, legacy algorithm, or a
    /// trusted comment that does not name this tag.
    Signature(String),
    /// `checksums.txt` malformed, or no entry for the file we need.
    Incomplete(String),
    /// SHA-256 differs, not an ELF file, or too large.
    Checksum(String),
    /// Network error, timeout, or a status other than 200. The detail is the
    /// status code or a short cause, never a URL with credentials.
    Download(String),
    /// Local I/O while staging.
    Io(String),
}

impl std::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(f, "Updates are not configured"),
            Self::Signature(_) => write!(f, "Signature check failed, nothing was installed"),
            Self::Incomplete(_) => write!(
                f,
                "The release is missing required files, nothing was installed"
            ),
            Self::Checksum(_) => write!(f, "Checksum check failed, nothing was installed"),
            Self::Download(d) => write!(f, "Download failed ({d})"),
            Self::Io(d) => write!(f, "Could not stage the verified agent binary ({d})"),
        }
    }
}

impl ReleaseError {
    /// The precise cause, for `tracing` only.
    pub fn detail(&self) -> &str {
        match self {
            Self::NotConfigured => "panel answered updates_not_configured",
            Self::Signature(d)
            | Self::Incomplete(d)
            | Self::Checksum(d)
            | Self::Download(d)
            | Self::Io(d) => d,
        }
    }
}

/// `name -> lowercase sha256 hex`, from a well-formed `checksums.txt`.
pub type Manifest = BTreeMap<String, String>;

/// Parse `checksums.txt` (contract §2.2). Every deviation is a refusal; no
/// line is ever skipped.
pub fn parse_checksums(bytes: &[u8]) -> Result<Manifest, String> {
    if bytes.len() > MAX_CHECKSUMS_BYTES {
        return Err(format!("checksums.txt is {} bytes (max {MAX_CHECKSUMS_BYTES})", bytes.len()));
    }
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err("checksums.txt starts with a BOM".into());
    }
    if bytes.contains(&b'\r') {
        return Err("checksums.txt contains a carriage return".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "checksums.txt is not UTF-8".to_string())?;
    // A single trailing newline is tolerated; any other empty line is not.
    let body = text.strip_suffix('\n').unwrap_or(text);
    if body.is_empty() {
        return Err("checksums.txt is empty".into());
    }
    let lines: Vec<&str> = body.split('\n').collect();
    if lines.len() > MAX_CHECKSUMS_LINES {
        return Err(format!("checksums.txt has {} lines (max {MAX_CHECKSUMS_LINES})", lines.len()));
    }
    let mut out = Manifest::new();
    for (i, line) in lines.iter().enumerate() {
        let n = i + 1;
        let (hash, name) = line
            .split_once("  ")
            .ok_or_else(|| format!("line {n}: expected '<sha256>  <name>'"))?;
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(format!("line {n}: hash is not 64 lowercase hex digits"));
        }
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(format!("line {n}: file name is not allowed"));
        }
        if out.insert(name.to_string(), hash.to_string()).is_some() {
            return Err(format!("line {n}: duplicate entry for {name}"));
        }
    }
    Ok(out)
}

/// `v`-prefixed tag, whatever the caller passed (`3.0.0` or `v3.0.0`).
pub fn normalize_tag(tag: &str) -> String {
    format!("v{}", tag.trim().trim_start_matches('v'))
}

/// Verify the signature of `checksums` for `tag`, then parse it.
///
/// `allow_legacy = false`: only pre-hashed signatures (algorithm `ED`). The
/// global signature, which `verify` checks, covers the trusted comment, so
/// comparing the comment after a successful `verify` is sound.
pub fn verify_manifest(
    key: &PublicKey,
    checksums: &[u8],
    minisig: &[u8],
    tag: &str,
) -> Result<Manifest, ReleaseError> {
    if minisig.is_empty() {
        return Err(ReleaseError::Signature("checksums.txt.minisig is empty".into()));
    }
    if minisig.len() > MAX_MINISIG_BYTES {
        return Err(ReleaseError::Signature("checksums.txt.minisig is too large".into()));
    }
    let sig_text = std::str::from_utf8(minisig)
        .map_err(|_| ReleaseError::Signature("checksums.txt.minisig is not UTF-8".into()))?;
    let sig = Signature::decode(sig_text)
        .map_err(|e| ReleaseError::Signature(format!("unreadable signature: {e}")))?;
    key.verify(checksums, &sig, false)
        .map_err(|e| ReleaseError::Signature(format!("signature rejected: {e}")))?;
    let expected = format!("{TRUSTED_COMMENT_PREFIX}{}", normalize_tag(tag));
    if sig.trusted_comment() != expected {
        return Err(ReleaseError::Signature(format!(
            "trusted comment is '{}', expected '{expected}'",
            sig.trusted_comment()
        )));
    }
    parse_checksums(checksums).map_err(ReleaseError::Incomplete)
}

/// Lowercase SHA-256 hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Check a downloaded agent binary against its manifest entry. Returns its
/// SHA-256 on success, which is what `agent-self-update.sh` re-checks.
pub fn check_agent_binary(
    manifest: &Manifest,
    name: &str,
    bytes: &[u8],
) -> Result<String, ReleaseError> {
    let expected = manifest
        .get(name)
        .ok_or_else(|| ReleaseError::Incomplete(format!("checksums.txt has no entry for {name}")))?;
    if bytes.len() > MAX_ASSET_BYTES {
        return Err(ReleaseError::Checksum(format!("{name} is larger than {MAX_ASSET_BYTES} bytes")));
    }
    let actual = sha256_hex(bytes);
    if &actual != expected {
        return Err(ReleaseError::Checksum(format!(
            "sha256 of {name} is {actual}, manifest says {expected}"
        )));
    }
    if bytes.len() < 4 || bytes[..4] != ELF_MAGIC {
        return Err(ReleaseError::Checksum(format!("{name} is not an ELF executable")));
    }
    Ok(actual)
}

/// Release asset label for a Rust `std::env::consts::ARCH`.
pub fn arch_label(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("amd64"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

/// The agent asset name for this machine.
pub fn agent_asset_name() -> Option<String> {
    arch_label(std::env::consts::ARCH).map(|a| format!("cyberhunter-agent-linux-{a}"))
}

/// `{central}/api/agent/release/{tag}/{name}`.
/// Whether this agent may send its server token to `central`: `https://`, or
/// plain `http://` only to the loopback (`127.0.0.1`, `::1`, `localhost`).
/// Anything else would put the Bearer credential, and the release it fetches,
/// in the clear on the network.
pub fn panel_url_is_secure(central: &str) -> bool {
    let Ok(u) = url::Url::parse(central.trim()) else {
        return false;
    };
    match u.scheme() {
        "https" => u.host().is_some(),
        "http" => match u.host() {
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(ip)) => ip == std::net::Ipv4Addr::LOCALHOST,
            Some(url::Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
            None => false,
        },
        _ => false,
    }
}

pub fn release_url(central: &str, tag: &str, name: &str) -> String {
    format!(
        "{}/api/agent/release/{}/{name}",
        central.trim_end_matches('/'),
        normalize_tag(tag)
    )
}

/// Where the verified binary for `tag` is staged.
pub fn staged_path(tag: &str) -> PathBuf {
    Path::new(STAGING_DIR).join(format!("cyberhunter-agent-{}", normalize_tag(tag)))
}

/// Map a non-200 answer from the panel. A 409 carrying
/// `updates_not_configured` is the panel saying updates are switched off.
pub fn classify_status(status: u16, body: &[u8]) -> ReleaseError {
    if status == 409 {
        let code = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("code").and_then(|c| c.as_str()).map(str::to_string));
        if code.as_deref() == Some("updates_not_configured") {
            return ReleaseError::NotConfigured;
        }
    }
    ReleaseError::Download(status.to_string())
}

/// A client that never follows a redirect: the panel serves these files
/// itself, so a redirect is not something this agent should chase.
pub fn http_client() -> Result<reqwest::Client, ReleaseError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| ReleaseError::Download(format!("client: {e}")))
}

/// GET one release file from the panel, bounded in size and time.
pub async fn fetch(
    client: &reqwest::Client,
    url: &str,
    server_token: &str,
    max_bytes: usize,
    timeout: Duration,
) -> Result<Vec<u8>, ReleaseError> {
    let mut resp = client
        .get(url)
        .header("Authorization", format!("Bearer {server_token}"))
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| ReleaseError::Download(short_reqwest_error(e)))?;
    let status = resp.status().as_u16();
    if status != 200 {
        // Read at most a little of an error body, only to find the code.
        let mut body = Vec::new();
        while let Ok(Some(chunk)) = resp.chunk().await {
            body.extend_from_slice(&chunk);
            if body.len() > 4096 {
                break;
            }
        }
        return Err(classify_status(status, &body));
    }
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(ReleaseError::Download(format!("file too large ({len} bytes)")));
        }
    }
    let mut out = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if out.len() + chunk.len() > max_bytes {
                    return Err(ReleaseError::Download("file too large".into()));
                }
                out.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => return Err(ReleaseError::Download(short_reqwest_error(e))),
        }
    }
    Ok(out)
}

/// A reqwest error without its URL (the URL carries nothing secret here, but
/// the status line shown to an operator should stay short).
fn short_reqwest_error(e: reqwest::Error) -> String {
    if e.is_timeout() {
        "timeout".into()
    } else if e.is_connect() {
        "connection failed".into()
    } else {
        e.without_url().to_string()
    }
}

/// A binary that passed verification, staged for the shell updater.
#[derive(Debug, Clone)]
pub struct StagedAgent {
    pub path: PathBuf,
    pub sha256: String,
}

/// Fetch, verify and stage the agent binary of `tag` from the panel.
/// Nothing is written to disk unless every check passed.
pub async fn download_and_stage(
    central: &str,
    server_token: &str,
    tag: &str,
    key: &PublicKey,
) -> Result<StagedAgent, ReleaseError> {
    if !panel_url_is_secure(central) {
        return Err(ReleaseError::Download("the panel URL is not https".into()));
    }
    let asset = agent_asset_name().ok_or_else(|| {
        ReleaseError::Download(format!("unsupported architecture {}", std::env::consts::ARCH))
    })?;
    let client = http_client()?;
    let minisig = fetch(
        &client,
        &release_url(central, tag, "checksums.txt.minisig"),
        server_token,
        MAX_MINISIG_BYTES,
        Duration::from_secs(30),
    )
    .await?;
    let checksums = fetch(
        &client,
        &release_url(central, tag, "checksums.txt"),
        server_token,
        MAX_CHECKSUMS_BYTES,
        Duration::from_secs(30),
    )
    .await?;
    let manifest = verify_manifest(key, &checksums, &minisig, tag)?;
    if !manifest.contains_key(&asset) {
        return Err(ReleaseError::Incomplete(format!("checksums.txt has no entry for {asset}")));
    }
    // 600 s: the panel may first have to fetch the file from the release host.
    let bin = fetch(
        &client,
        &release_url(central, tag, &asset),
        server_token,
        MAX_ASSET_BYTES,
        Duration::from_secs(600),
    )
    .await?;
    let sha256 = check_agent_binary(&manifest, &asset, &bin)?;
    let path = stage(&bin, tag).map_err(|e| ReleaseError::Io(e.to_string()))?;
    Ok(StagedAgent { path, sha256 })
}

/// Write the verified bytes to `STAGING_DIR` (root, 0700): temporary name,
/// then rename, so a half-written file never carries the final name.
fn stage(bytes: &[u8], tag: &str) -> std::io::Result<PathBuf> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    std::fs::create_dir_all(STAGING_DIR)?;
    #[cfg(unix)]
    std::fs::set_permissions(STAGING_DIR, std::fs::Permissions::from_mode(0o700))?;
    let final_path = staged_path(tag);
    let tmp = Path::new(STAGING_DIR).join(format!(".partial-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o700);
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, &final_path)?;
    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUB: &str = include_str!("testdata/release/test.pub");
    const CHECKSUMS: &[u8] = include_bytes!("testdata/release/checksums.txt");
    const SIG: &[u8] = include_bytes!("testdata/release/checksums.txt.minisig");
    const SIG_OTHER_KEY: &[u8] = include_bytes!("testdata/release/checksums.txt.other-key.minisig");
    const SIG_WRONG_TAG: &[u8] = include_bytes!("testdata/release/checksums.txt.wrong-tag.minisig");
    const SIG_LEGACY: &[u8] = include_bytes!("testdata/release/checksums.txt.legacy.minisig");
    const FAKE_AGENT: &[u8] = include_bytes!("testdata/release/cyberhunter-agent-linux-amd64");
    const TAG: &str = "v9.9.9";

    fn pub_b64() -> &'static str {
        PUB.lines().nth(1).unwrap().trim()
    }
    fn key() -> PublicKey {
        parse_public_key(pub_b64()).unwrap()
    }
    const H: &str = "a960c613f821aa1ae6bbe7f00d1c25adcfe461be108408a23add1f194b2a0303";

    // ── checksums.txt ────────────────────────────────────────────────────
    #[test]
    fn a_valid_manifest_parses() {
        let m = parse_checksums(CHECKSUMS).unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(m["cyberhunter-agent-linux-amd64"], H);
    }

    #[test]
    fn a_manifest_without_the_final_newline_is_accepted() {
        let m = parse_checksums(CHECKSUMS.strip_suffix(b"\n").unwrap()).unwrap();
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn malformed_manifests_are_refused() {
        let line = format!("{H}  cyberhunter-agent-linux-amd64");
        let cases: Vec<(String, &str)> = vec![
            (format!("{line}\n{line}\n"), "duplicate"),
            (format!("{H} cyberhunter-agent-linux-amd64\n"), "one space"),
            (format!("{}  x\n", H.to_uppercase()), "uppercase"),
            (format!("{H}  dir/file\n"), "slash"),
            (format!("{line}\r\n"), "carriage return"),
            (format!("{line}\n\n"), "extra empty line"),
            (format!("\n{line}\n"), "leading empty line"),
            (format!("{}  x\n", &H[..63]), "short hash"),
            (String::new(), "empty"),
            (format!("\u{feff}{line}\n"), "bom"),
            ((0..33).map(|i| format!("{H}  f{i}\n")).collect(), "33 lines"),
            (format!("{H}  {}\n", "a".repeat(129)), "long name"),
            (format!("{H}  .\n"), "dot"),
            (format!("{H}  ..\n"), "dot dot"),
        ];
        for (text, why) in cases {
            assert!(parse_checksums(text.as_bytes()).is_err(), "{why} must be refused");
        }
        // 32 lines is the limit, not over it.
        let ok: String = (0..32).map(|i| format!("{H}  f{i}\n")).collect();
        assert!(parse_checksums(ok.as_bytes()).is_ok());
        // Over 64 KiB is refused before anything else.
        let big = vec![b'a'; MAX_CHECKSUMS_BYTES + 1];
        assert!(parse_checksums(&big).unwrap_err().contains("bytes"));
    }

    // ── signature ────────────────────────────────────────────────────────
    #[test]
    fn a_valid_signature_for_the_right_tag_verifies() {
        let m = verify_manifest(&key(), CHECKSUMS, SIG, TAG).unwrap();
        assert!(m.contains_key("cyberhunter-agent-linux-amd64"));
        // The tag is normalised: `9.9.9` names the same release.
        assert!(verify_manifest(&key(), CHECKSUMS, SIG, "9.9.9").is_ok());
    }

    #[test]
    fn a_manifest_changed_by_one_byte_is_refused() {
        let mut bad = CHECKSUMS.to_vec();
        bad[0] = if bad[0] == b'a' { b'b' } else { b'a' };
        let e = verify_manifest(&key(), &bad, SIG, TAG).unwrap_err();
        assert!(matches!(e, ReleaseError::Signature(_)), "{e:?}");
    }

    #[test]
    fn a_missing_or_garbled_signature_is_refused() {
        for sig in [&b""[..], &b"not a signature"[..], &SIG[..SIG.len() / 2]] {
            let e = verify_manifest(&key(), CHECKSUMS, sig, TAG).unwrap_err();
            assert!(matches!(e, ReleaseError::Signature(_)), "{e:?}");
        }
    }

    #[test]
    fn a_signature_by_another_key_is_refused() {
        let e = verify_manifest(&key(), CHECKSUMS, SIG_OTHER_KEY, TAG).unwrap_err();
        assert!(matches!(e, ReleaseError::Signature(_)), "{e:?}");
    }

    /// The trusted comment binds the signature to a version: a whole, intact
    /// older release republished under a new tag must be refused.
    #[test]
    fn a_signature_for_another_tag_is_refused() {
        let e = verify_manifest(&key(), CHECKSUMS, SIG_WRONG_TAG, TAG).unwrap_err();
        assert!(matches!(e, ReleaseError::Signature(_)), "{e:?}");
        let e = verify_manifest(&key(), CHECKSUMS, SIG, "v9.9.10").unwrap_err();
        assert!(matches!(e, ReleaseError::Signature(_)), "{e:?}");
    }

    #[test]
    fn a_legacy_non_prehashed_signature_is_refused() {
        // The fixture really is a legacy one (`Ed`), or this test proves nothing.
        use base64::Engine;
        let line = std::str::from_utf8(SIG_LEGACY).unwrap().lines().nth(1).unwrap();
        let bin = base64::engine::general_purpose::STANDARD.decode(line).unwrap();
        assert_eq!(&bin[..2], b"Ed");
        let e = verify_manifest(&key(), CHECKSUMS, SIG_LEGACY, TAG).unwrap_err();
        assert!(matches!(e, ReleaseError::Signature(_)), "{e:?}");
    }

    #[test]
    fn a_validly_signed_but_malformed_manifest_is_incomplete_not_accepted() {
        // Covered by the signature for a well-formed file only, so the parse
        // step is checked on its own: a signed file is still parsed strictly.
        assert!(parse_checksums(b"garbage\n").is_err());
    }

    #[test]
    fn the_key_id_matches_what_minisign_printed() {
        let printed = PUB
            .lines()
            .next()
            .unwrap()
            .trim()
            .rsplit(' ')
            .next()
            .unwrap()
            .to_string();
        assert_eq!(key_id(pub_b64()).unwrap(), printed);
        assert!(key_id("not base64!").is_none());
        assert!(parse_public_key("RWQ").is_none());
    }

    /// The tests above must not depend on how this binary was built: with
    /// and without `-e CYBERHUNTER_UPDATE_PUBKEY` they take the key as a
    /// parameter. What the build changes is only `signing_key()`.
    #[test]
    fn the_compiled_key_is_optional_and_consistent() {
        match compiled_key_b64() {
            None => assert!(signing_key().is_none() && signing_key_id().is_none()),
            Some(b64) => {
                assert_eq!(signing_key().is_some(), parse_public_key(b64).is_some());
            }
        }
    }

    // ── binary ───────────────────────────────────────────────────────────
    #[test]
    fn the_binary_must_match_its_manifest_entry_and_be_elf() {
        let m = parse_checksums(CHECKSUMS).unwrap();
        let name = "cyberhunter-agent-linux-amd64";
        assert_eq!(check_agent_binary(&m, name, FAKE_AGENT).unwrap(), H);

        let mut tampered = FAKE_AGENT.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            check_agent_binary(&m, name, &tampered),
            Err(ReleaseError::Checksum(_))
        ));

        // Right hash, wrong kind of file.
        let not_elf = b"#!/bin/sh\necho pwned\n";
        let mut m2 = Manifest::new();
        m2.insert(name.into(), sha256_hex(not_elf));
        assert!(matches!(
            check_agent_binary(&m2, name, not_elf),
            Err(ReleaseError::Checksum(_))
        ));

        // No entry at all.
        assert!(matches!(
            check_agent_binary(&m, "cyberhunter-agent-linux-arm64", FAKE_AGENT),
            Err(ReleaseError::Incomplete(_))
        ));
    }

    #[test]
    fn an_oversized_binary_is_refused_before_hashing() {
        let big = vec![0u8; MAX_ASSET_BYTES + 1];
        let mut m = Manifest::new();
        m.insert("a".into(), sha256_hex(&big));
        assert!(matches!(check_agent_binary(&m, "a", &big), Err(ReleaseError::Checksum(_))));
    }

    // ── URLs, names, statuses ────────────────────────────────────────────
    #[test]
    fn the_release_url_names_the_panel_tag_and_file() {
        assert_eq!(
            release_url("https://panel.example/", "3.0.0-rc.2", "checksums.txt"),
            "https://panel.example/api/agent/release/v3.0.0-rc.2/checksums.txt"
        );
        let asset = agent_asset_name().expect("tests run on amd64 or arm64");
        let want = match std::env::consts::ARCH {
            "x86_64" => "cyberhunter-agent-linux-amd64",
            _ => "cyberhunter-agent-linux-arm64",
        };
        assert_eq!(asset, want);
        assert_eq!(arch_label("x86_64"), Some("amd64"));
        assert_eq!(arch_label("aarch64"), Some("arm64"));
        assert_eq!(arch_label("riscv64"), None);
        assert_eq!(
            staged_path("3.0.0"),
            Path::new("/var/lib/dockpanel/agent-release/cyberhunter-agent-v3.0.0")
        );
    }

    #[test]
    fn panel_statuses_map_to_the_contract_messages() {
        let nc = br#"{"error":"Updates are not configured","code":"updates_not_configured"}"#;
        assert_eq!(classify_status(409, nc), ReleaseError::NotConfigured);
        assert_eq!(classify_status(409, nc).to_string(), "Updates are not configured");
        assert_eq!(classify_status(409, b"{}").to_string(), "Download failed (409)");
        assert_eq!(classify_status(403, b"").to_string(), "Download failed (403)");
        assert_eq!(classify_status(302, b"").to_string(), "Download failed (302)");
        assert_eq!(
            ReleaseError::Signature("x".into()).to_string(),
            "Signature check failed, nothing was installed"
        );
        assert_eq!(
            ReleaseError::Checksum("x".into()).to_string(),
            "Checksum check failed, nothing was installed"
        );
    }

    /// The release host is never contacted from here, and the panel's
    /// answers are never followed elsewhere.
    #[test]
    fn this_module_only_talks_to_the_panel() {
        let src = include_str!("release_verify.rs");
        assert!(src.contains("redirect::Policy::none()"));
        assert!(src.contains("/api/agent/release/"));
        for host in [concat!("github", ".com"), concat!("githubuser", "content")] {
            assert!(!src.contains(host), "no release host in the agent: {host}");
        }
    }

    #[test]
    fn the_token_only_goes_to_https_or_the_loopback() {
        for ok in [
            "https://panel.example.com",
            "https://panel.example.com:8443/",
            "http://127.0.0.1:3080",
            "http://localhost:3080",
            "http://[::1]:3080",
        ] {
            assert!(panel_url_is_secure(ok), "{ok}");
        }
        for bad in [
            "http://panel.example.com",
            "http://10.0.0.5:3080",
            "http://127.0.0.2",
            "http://localhost.example.com",
            "ftp://panel.example.com",
            "panel.example.com",
            "",
        ] {
            assert!(!panel_url_is_secure(bad), "{bad}");
        }
        let src = include_str!("release_verify.rs");
        let f = &src[src.find("pub async fn download_and_stage").unwrap()..];
        assert!(f.find("panel_url_is_secure(central)").unwrap() < f.find("fetch(").unwrap());
    }
}
