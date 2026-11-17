//! Fetching and verifying CyberHunter releases from GitHub.
//!
//! Nothing a release contains is used before three checks pass, all here:
//!   1. the minisign signature of `checksums.txt`, against the key compiled
//!      into this binary (`update_source::signing_key`), pre-hashed only;
//!   2. the signature's trusted comment, which must be exactly
//!      `cyberhunter-release <tag>` so a signed set cannot be republished
//!      under another tag;
//!   3. the SHA-256 and the size of every file, against that manifest.
//!
//! Verified files land in `/var/lib/dockpanel/releases/<tag>/`. A file present
//! there has passed its check: it is written under a temporary name and only
//! renamed once its digest matched.
//!
//! The GitHub token is optional. When its file holds one, it is read right
//! before the first request of a call ([`github_auth_header`]) and only travels
//! in a header marked sensitive, on that first request. When the file is absent
//! or empty, the request is anonymous: no `Authorization` header at all.
//! Redirects are followed by hand, to a closed list of hosts, and never carry
//! it. A redirect target (a signed URL) is never logged:
//! only its host.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use axum::http::StatusCode;
use reqwest::header::{
    HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_LENGTH, LOCATION, USER_AGENT,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::io::AsyncWriteExt;
use url::Url;
use uuid::Uuid;

use crate::error::{err_coded, ApiError};
use crate::services::panel_update::validate_target_version;
use crate::services::update_source::{self, SecretToken};

// ── Constants ────────────────────────────────────────────────────────────

/// Verified release cache. Not /tmp: `dockpanel-api` runs with `PrivateTmp`,
/// and the transient unit `update.sh` re-execs into would not see it.
pub const RELEASE_CACHE_DIR: &str = "/var/lib/dockpanel/releases";

pub const GITHUB_API_HOST: &str = "api.github.com";
const GITHUB_API_BASE: &str = "https://api.github.com";
const GITHUB_API_VERSION: &str = "2022-11-28";
const ACCEPT_JSON: &str = "application/vnd.github+json";
const ACCEPT_OCTET: &str = "application/octet-stream";

/// Every host a request may reach, the first one included.
pub const ALLOWED_DOWNLOAD_HOSTS: [&str; 3] = [
    "api.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];
const MAX_REDIRECTS: u8 = 3;

pub const MAX_LIST_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_CHECKSUMS_BYTES: u64 = 64 * 1024;
pub const MAX_MINISIG_BYTES: u64 = 4 * 1024;
pub const MAX_ASSET_BYTES: u64 = 209_715_200;
const MAX_MANIFEST_LINES: usize = 32;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const LIST_TIMEOUT: Duration = Duration::from_secs(15);
const SMALL_FILE_TIMEOUT: Duration = Duration::from_secs(30);
const ASSET_TIMEOUT: Duration = Duration::from_secs(300);
/// Budget for a whole panel preparation (`POST /api/update/apply`).
pub const PREPARE_TIMEOUT: Duration = Duration::from_secs(900);
/// Budget for the agent binaries of a fleet run, prepared synchronously.
pub const FLEET_PREPARE_TIMEOUT: Duration = Duration::from_secs(240);

pub const CHECKSUMS_NAME: &str = "checksums.txt";
pub const MINISIG_NAME: &str = "checksums.txt.minisig";
pub const FRONTEND_ARCHIVE: &str = "cyberhunter-frontend.tar.gz";
pub const SOURCE_ARCHIVE: &str = "cyberhunter-source.tar.gz";
pub const SOURCE_DIR: &str = "cyberhunter-source";
pub const AGENT_AMD64: &str = "cyberhunter-agent-linux-amd64";
pub const AGENT_ARM64: &str = "cyberhunter-agent-linux-arm64";

/// What `GET /api/agent/release/{tag}/{name}` may serve.
pub const AGENT_RELEASE_FILES: [&str; 4] = [CHECKSUMS_NAME, MINISIG_NAME, AGENT_AMD64, AGENT_ARM64];

static NAME_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9._-]{1,128}$").unwrap());

// ── Errors ───────────────────────────────────────────────────────────────

/// A failed fetch or check. `Display` is the contract message only (safe for an
/// API response); the detail - host, status, file name, never a URL or a
/// token - is for the log and the activity journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    NotConfigured,
    TokenInvalid,
    RepoUnreadable,
    /// 404 from api.github.com on a request sent without a token.
    RepoNotFoundAnonymous,
    RateLimited,
    ReleaseNotFound,
    ReleaseIncomplete(String),
    SignatureFailed(String),
    ChecksumFailed(String),
    DownloadFailed(String),
    FileUnknown,
}

impl FetchError {
    pub fn code(&self) -> &'static str {
        match self {
            FetchError::NotConfigured => "updates_not_configured",
            FetchError::TokenInvalid => "token_invalid",
            FetchError::RepoUnreadable => "repo_unreadable",
            FetchError::RepoNotFoundAnonymous => "repo_not_found",
            FetchError::RateLimited => "github_rate_limited",
            FetchError::ReleaseNotFound => "release_not_found",
            FetchError::ReleaseIncomplete(_) => "release_incomplete",
            FetchError::SignatureFailed(_) => "signature_failed",
            FetchError::ChecksumFailed(_) => "checksum_failed",
            FetchError::DownloadFailed(_) => "download_failed",
            FetchError::FileUnknown => "release_file_unknown",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            FetchError::NotConfigured => "Updates are not configured",
            FetchError::TokenInvalid => "The update token is missing or expired",
            FetchError::RepoUnreadable => "The update token cannot read this repository",
            FetchError::RepoNotFoundAnonymous => {
                "Repository not found or private. Add a token if the release repository is private."
            }
            FetchError::RateLimited => "GitHub rate limit reached, try again later",
            FetchError::ReleaseNotFound => "Release not found",
            FetchError::ReleaseIncomplete(_) => {
                "The release is missing required files, nothing was installed"
            }
            FetchError::SignatureFailed(_) => "Signature check failed, nothing was installed",
            FetchError::ChecksumFailed(_) => "Checksum check failed, nothing was installed",
            FetchError::DownloadFailed(_) => "Download failed",
            FetchError::FileUnknown => "Release file not available",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            FetchError::NotConfigured
            | FetchError::TokenInvalid
            | FetchError::RepoUnreadable
            | FetchError::RepoNotFoundAnonymous => StatusCode::CONFLICT,
            FetchError::RateLimited => StatusCode::SERVICE_UNAVAILABLE,
            FetchError::ReleaseNotFound | FetchError::FileUnknown => StatusCode::NOT_FOUND,
            FetchError::ReleaseIncomplete(_)
            | FetchError::SignatureFailed(_)
            | FetchError::ChecksumFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            FetchError::DownloadFailed(_) => StatusCode::BAD_GATEWAY,
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            FetchError::ReleaseIncomplete(d)
            | FetchError::SignatureFailed(d)
            | FetchError::ChecksumFailed(d)
            | FetchError::DownloadFailed(d) => Some(d),
            _ => None,
        }
    }

    /// `verify` for a release that was fetched but refused, `download` for one
    /// that could not be fetched (`update.apply_failed` stage).
    pub fn stage(&self) -> &'static str {
        match self {
            FetchError::ReleaseIncomplete(_)
            | FetchError::SignatureFailed(_)
            | FetchError::ChecksumFailed(_) => "verify",
            _ => "download",
        }
    }

    /// The text logged for this failure: code, message and detail.
    pub fn log_line(&self, context: &str) -> String {
        match self.detail() {
            Some(d) => format!("{context}: {} ({}): {d}", self.message(), self.code()),
            None => format!("{context}: {} ({})", self.message(), self.code()),
        }
    }

    pub fn log(&self, context: &str) {
        tracing::warn!("{}", self.log_line(context));
    }

    pub fn api_error(&self) -> ApiError {
        err_coded(self.status(), self.message(), self.code())
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for FetchError {}

/// A transport error, reduced to the host and reqwest's kind. `without_url`
/// matters: after a redirect the URL is a signed one.
fn send_error(host: &str, e: reqwest::Error) -> FetchError {
    let timeout = e.is_timeout();
    let e = e.without_url();
    if timeout {
        FetchError::DownloadFailed(format!("{host}: timed out"))
    } else {
        FetchError::DownloadFailed(format!("{host}: {e}"))
    }
}

// ── GitHub data ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AssetInfo {
    pub id: u64,
    pub name: String,
    #[serde(default)]
    pub size: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseInfo {
    pub tag_name: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub html_url: Option<String>,
    #[serde(default)]
    pub assets: Vec<AssetInfo>,
}

impl ReleaseInfo {
    pub fn asset(&self, name: &str) -> Option<&AssetInfo> {
        self.assets.iter().find(|a| a.name == name)
    }

    /// Release notes as stored: at most 4000 characters, verbatim.
    pub fn notes(&self) -> String {
        self.body.as_deref().unwrap_or("").chars().take(4000).collect()
    }

    /// The release page, only when it is a GitHub page.
    pub fn page_url(&self) -> Option<&str> {
        self.html_url
            .as_deref()
            .filter(|u| u.starts_with("https://github.com/"))
    }
}

/// `vX.Y.Z` or `vX.Y.Z-rc.N`, with exactly one `v`.
pub fn is_release_tag(tag: &str) -> bool {
    match tag.strip_prefix('v') {
        Some(rest) => !rest.starts_with('v') && validate_target_version(rest),
        None => false,
    }
}

/// The tag spelling of a version (`3.0.0` and `v3.0.0` give `v3.0.0`).
pub fn release_tag(version: &str) -> String {
    format!("v{}", version.trim().trim_start_matches('v'))
}

/// Marked as a pre-release on GitHub, or carrying an `-rc.N` suffix.
pub fn is_prerelease(r: &ReleaseInfo) -> bool {
    r.prerelease || r.tag_name.contains("-rc.")
}

/// The release to advertise on `channel`: drafts and tags of the wrong shape
/// dropped, pre-releases dropped unless `candidate`, then the maximum by
/// `release_key` (never GitHub's order).
pub fn select_release<'a>(releases: &'a [ReleaseInfo], channel: &str) -> Option<&'a ReleaseInfo> {
    let with_pre = channel == "candidate";
    releases
        .iter()
        .filter(|r| !r.draft && is_release_tag(&r.tag_name))
        .filter(|r| with_pre || !is_prerelease(r))
        .max_by_key(|r| crate::services::telemetry_collector::release_key(&r.tag_name))
}

// ── checksums.txt ────────────────────────────────────────────────────────

/// A parsed `checksums.txt`: file name to lowercase SHA-256 hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    entries: BTreeMap<String, String>,
}

impl Manifest {
    pub fn sha256(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(String::as_str)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    #[cfg(test)]
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }
}

fn incomplete(why: &str) -> FetchError {
    FetchError::ReleaseIncomplete(format!("checksums.txt: {why}"))
}

/// The reader of §2.2: strict, nothing skipped. A malformed manifest is a
/// release that is missing what it needs (`release_incomplete`).
pub fn parse_checksums(bytes: &[u8]) -> Result<Manifest, FetchError> {
    if bytes.len() as u64 > MAX_CHECKSUMS_BYTES {
        return Err(incomplete("larger than 64 KiB"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| incomplete("not UTF-8"))?;
    if text.contains('\r') {
        return Err(incomplete("carriage return"));
    }
    let body = text.strip_suffix('\n').unwrap_or(text);
    if body.is_empty() {
        return Err(incomplete("empty"));
    }
    let lines: Vec<&str> = body.split('\n').collect();
    if lines.len() > MAX_MANIFEST_LINES {
        return Err(incomplete("more than 32 lines"));
    }
    let mut entries = BTreeMap::new();
    for (i, line) in lines.iter().enumerate() {
        let n = i + 1;
        let bad = || incomplete(&format!("line {n} is not `<sha256>  <name>`"));
        if line.len() < 67 || !line.is_char_boundary(64) {
            return Err(bad());
        }
        let (hex, rest) = line.split_at(64);
        if !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(bad());
        }
        let Some(name) = rest.strip_prefix("  ") else {
            return Err(bad());
        };
        if !NAME_RE.is_match(name) || name == "." || name == ".." {
            return Err(bad());
        }
        if entries.insert(name.to_string(), hex.to_string()).is_some() {
            return Err(incomplete(&format!("{name} is listed twice")));
        }
    }
    Ok(Manifest { entries })
}

// ── Signature ────────────────────────────────────────────────────────────

/// The trusted comment a release for `tag` must carry.
pub fn trusted_comment_for(tag: &str) -> String {
    format!("cyberhunter-release {tag}")
}

/// Check the minisign signature of `checksums` against `key` (pre-hashed
/// signatures only), bind it to `tag`, then parse the manifest.
pub fn verify_signed_manifest(
    key: &minisign_verify::PublicKey,
    checksums: &[u8],
    minisig: &[u8],
    tag: &str,
) -> Result<Manifest, FetchError> {
    let failed = |why: &str| FetchError::SignatureFailed(why.to_string());
    if minisig.is_empty() {
        return Err(failed("no signature file"));
    }
    if minisig.len() as u64 > MAX_MINISIG_BYTES {
        return Err(failed("signature file larger than 4 KiB"));
    }
    let text = std::str::from_utf8(minisig).map_err(|_| failed("unreadable signature file"))?;
    let sig = minisign_verify::Signature::decode(text).map_err(|e| match e {
        minisign_verify::Error::UnsupportedAlgorithm => failed("unsupported signature algorithm"),
        _ => failed("unreadable signature file"),
    })?;
    key.verify(checksums, &sig, false).map_err(|e| match e {
        minisign_verify::Error::UnexpectedKeyId => failed("signed by another key"),
        minisign_verify::Error::UnexpectedAlgorithm => {
            failed("legacy signature (not pre-hashed) refused")
        }
        _ => failed("invalid signature"),
    })?;
    if sig.trusted_comment() != trusted_comment_for(tag) {
        return Err(failed("trusted comment does not name this tag"));
    }
    parse_checksums(checksums)
}

// ── Redirects and headers ────────────────────────────────────────────────

fn host_allowed(url: &Url, allowed: &[&str]) -> Result<(), FetchError> {
    let host = url.host_str().unwrap_or("");
    if url.scheme() != "https" {
        return Err(FetchError::DownloadFailed(format!(
            "refused a non-https target on {host}"
        )));
    }
    if url.port().is_some_and(|p| p != 443) {
        return Err(FetchError::DownloadFailed(format!(
            "refused a non-standard port on {host}"
        )));
    }
    if !allowed.contains(&host) {
        return Err(FetchError::DownloadFailed(format!(
            "refused redirect to host {host}"
        )));
    }
    Ok(())
}

/// Where redirect number `hop` (1 for the first) leads. A relative `Location`
/// is resolved against the current URL, then the target is checked: https,
/// port 443, host on the list, at most three hops.
pub fn next_hop(
    current: &Url,
    location: &str,
    hop: u8,
    allowed: &[&str],
) -> Result<Url, FetchError> {
    if hop > MAX_REDIRECTS {
        return Err(FetchError::DownloadFailed(format!(
            "more than {MAX_REDIRECTS} redirects"
        )));
    }
    let next = current.join(location).map_err(|_| {
        FetchError::DownloadFailed(format!(
            "unreadable redirect from {}",
            current.host_str().unwrap_or("")
        ))
    })?;
    host_allowed(&next, allowed)?;
    Ok(next)
}

fn user_agent() -> HeaderValue {
    HeaderValue::from_str(&format!("CyberHunter-Panel/{}", env!("CARGO_PKG_VERSION")))
        .unwrap_or_else(|_| HeaderValue::from_static("CyberHunter-Panel"))
}

/// Headers of request number `hop` (0 is the first). Only the first request
/// carries `Authorization` and the API version, whatever `auth` holds; later
/// ones carry the User-Agent alone. The caller adds `Accept`, which depends on
/// the call rather than on the hop.
pub fn request_headers(hop: u8, auth: Option<HeaderValue>) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(USER_AGENT, user_agent());
    if hop == 0 {
        h.insert("x-github-api-version", HeaderValue::from_static(GITHUB_API_VERSION));
        if let Some(mut a) = auth {
            a.set_sensitive(true);
            h.insert(AUTHORIZATION, a);
        }
    }
    h
}

/// `Bearer <token>`, marked sensitive.
pub fn bearer_header(token: &SecretToken) -> Result<HeaderValue, FetchError> {
    let line = zeroize::Zeroizing::new(format!("Bearer {}", token.expose()));
    let mut v = HeaderValue::from_str(&line).map_err(|_| FetchError::TokenInvalid)?;
    v.set_sensitive(true);
    Ok(v)
}

/// Read the token from its file, right before a request. `None` when the file
/// is absent or empty: the request then goes out anonymously. A file that holds
/// a token is always used.
pub fn github_auth_header(token_file: &Path) -> Result<Option<HeaderValue>, FetchError> {
    match update_source::read_token(token_file) {
        Some(token) => bearer_header(&token).map(Some),
        None => Ok(None),
    }
}

// ── Size limits ──────────────────────────────────────────────────────────

/// Byte budget of one body: a hard limit, plus the exact size GitHub announced
/// for an asset. Pure, so both refusals are testable without a network.
#[derive(Debug)]
pub struct SizeGuard {
    limit: u64,
    expected: Option<u64>,
    seen: u64,
}

impl SizeGuard {
    pub fn new(
        limit: u64,
        expected: Option<u64>,
        content_length: Option<u64>,
    ) -> Result<Self, FetchError> {
        if let Some(e) = expected
            && e > limit
        {
            return Err(FetchError::DownloadFailed(format!(
                "announced size {e} is over the {limit} byte limit"
            )));
        }
        if let Some(cl) = content_length {
            if cl > limit {
                return Err(FetchError::DownloadFailed(format!(
                    "Content-Length {cl} is over the {limit} byte limit"
                )));
            }
            if let Some(e) = expected
                && cl != e
            {
                return Err(FetchError::ChecksumFailed(format!(
                    "Content-Length {cl} differs from the announced size {e}"
                )));
            }
        }
        Ok(SizeGuard {
            limit,
            expected,
            seen: 0,
        })
    }

    /// Account for `n` more bytes; refuses as soon as a limit is crossed, so
    /// the stream is cut there.
    pub fn feed(&mut self, n: usize) -> Result<(), FetchError> {
        self.seen = self.seen.saturating_add(n as u64);
        if let Some(e) = self.expected
            && self.seen > e
        {
            return Err(FetchError::ChecksumFailed(format!(
                "body is longer than the announced size {e}"
            )));
        }
        if self.seen > self.limit {
            return Err(FetchError::DownloadFailed(format!(
                "body is over the {} byte limit",
                self.limit
            )));
        }
        Ok(())
    }

    pub fn finish(&self) -> Result<(), FetchError> {
        match self.expected {
            Some(e) if self.seen != e => Err(FetchError::ChecksumFailed(format!(
                "received {} bytes, announced {e}",
                self.seen
            ))),
            _ => Ok(()),
        }
    }
}

// ── The API seam ─────────────────────────────────────────────────────────

/// Everything that talks to GitHub. `check_for_updates_inner` and `prepare`
/// take it as a parameter, so a fake can prove that no request leaves without
/// a configuration.
pub trait ReleaseApi: Send + Sync {
    fn list_releases(
        &self,
        repo: &str,
        per_page: u8,
    ) -> impl Future<Output = Result<Vec<ReleaseInfo>, FetchError>> + Send;

    fn release_by_tag(
        &self,
        repo: &str,
        tag: &str,
    ) -> impl Future<Output = Result<ReleaseInfo, FetchError>> + Send;

    /// A small asset, in memory, at most `max` bytes and exactly its size.
    fn asset_bytes(
        &self,
        repo: &str,
        asset: &AssetInfo,
        max: u64,
    ) -> impl Future<Output = Result<Vec<u8>, FetchError>> + Send;

    /// A large asset, streamed to `dest`; returns its SHA-256 hex.
    fn asset_to_file(
        &self,
        repo: &str,
        asset: &AssetInfo,
        dest: &Path,
    ) -> impl Future<Output = Result<String, FetchError>> + Send;
}

#[derive(Clone)]
enum Auth {
    File(PathBuf),
    Header(HeaderValue),
}

/// The real client.
pub struct GithubApi {
    client: reqwest::Client,
    auth: Auth,
}

/// Set once the host serving assets has been logged (to check it in a VM).
static FINAL_HOST_LOGGED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CallKind {
    List,
    Tag,
    Asset,
}

/// GitHub status to contract error. `rate_exhausted` is
/// `x-ratelimit-remaining: 0`. `anonymous_api` is true for an answer of
/// api.github.com itself to a request sent without a token: GitHub answers 404
/// for a private repository then, which deserves its own message.
fn map_status(
    status: u16,
    rate_exhausted: bool,
    kind: CallKind,
    host: &str,
    anonymous_api: bool,
) -> Result<(), FetchError> {
    match status {
        200..=299 => Ok(()),
        404 if anonymous_api => Err(FetchError::RepoNotFoundAnonymous),
        401 => Err(FetchError::TokenInvalid),
        429 => Err(FetchError::RateLimited),
        403 if rate_exhausted => Err(FetchError::RateLimited),
        403 | 404 if kind == CallKind::List => Err(FetchError::RepoUnreadable),
        404 if kind == CallKind::Tag => Err(FetchError::ReleaseNotFound),
        403 if kind == CallKind::Tag => Err(FetchError::RepoUnreadable),
        s => Err(FetchError::DownloadFailed(format!("{host} answered {s}"))),
    }
}

impl GithubApi {
    fn build_client() -> Result<reqwest::Client, FetchError> {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .https_only(true)
            .build()
            .map_err(|_| FetchError::DownloadFailed("could not build the HTTP client".into()))
    }

    /// Reads the token from `token_file` before each call; anonymous when the
    /// file is absent or empty.
    pub fn new(token_file: PathBuf) -> Result<Self, FetchError> {
        Ok(GithubApi {
            client: Self::build_client()?,
            auth: Auth::File(token_file),
        })
    }

    /// For testing a token before it is saved (`PUT /api/update/source`).
    pub fn with_token(token: &str) -> Result<Self, FetchError> {
        let token = SecretToken::from_input(token);
        Ok(GithubApi {
            client: Self::build_client()?,
            auth: Auth::Header(bearer_header(&token)?),
        })
    }

    fn auth_header(&self) -> Result<Option<HeaderValue>, FetchError> {
        match &self.auth {
            Auth::File(p) => github_auth_header(p),
            Auth::Header(h) => Ok(Some(h.clone())),
        }
    }

    /// GET `start` (on api.github.com), following redirects by hand.
    async fn get(
        &self,
        start: Url,
        accept: &'static str,
        kind: CallKind,
    ) -> Result<(reqwest::Response, String), FetchError> {
        host_allowed(&start, &[GITHUB_API_HOST])?;
        let mut current = start;
        let mut hop: u8 = 0;
        let mut anonymous = false;
        loop {
            let auth = if hop == 0 { self.auth_header()? } else { None };
            if hop == 0 {
                anonymous = auth.is_none();
            }
            let mut headers = request_headers(hop, auth);
            headers.insert(ACCEPT, HeaderValue::from_static(accept));
            let host = current.host_str().unwrap_or("").to_string();
            let resp = self
                .client
                .get(current.clone())
                .headers(headers)
                .send()
                .await
                .map_err(|e| send_error(&host, e))?;
            let status = resp.status().as_u16();
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                let location = resp
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        FetchError::DownloadFailed(format!("{host} redirected without a Location"))
                    })?
                    .to_string();
                hop += 1;
                current = next_hop(&current, &location, hop, &ALLOWED_DOWNLOAD_HOSTS)?;
                continue;
            }
            let exhausted = resp
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.trim() == "0");
            let anonymous_api = anonymous && hop == 0 && host == GITHUB_API_HOST;
            map_status(status, exhausted, kind, &host, anonymous_api)?;
            return Ok((resp, host));
        }
    }

    async fn json_limited<T: serde::de::DeserializeOwned>(
        &self,
        url: Url,
        kind: CallKind,
    ) -> Result<T, FetchError> {
        let work = async {
            let (resp, host) = self.get(url, ACCEPT_JSON, kind).await?;
            let body = read_to_vec(resp, &host, MAX_LIST_BYTES, None).await?;
            serde_json::from_slice::<T>(&body)
                .map_err(|_| FetchError::DownloadFailed(format!("{host}: unreadable response")))
        };
        tokio::time::timeout(LIST_TIMEOUT, work)
            .await
            .map_err(|_| FetchError::DownloadFailed(format!("{GITHUB_API_HOST}: timed out")))?
    }

    fn asset_url(repo: &str, asset: &AssetInfo) -> Result<Url, FetchError> {
        Url::parse(&format!("{GITHUB_API_BASE}/repos/{repo}/releases/assets/{}", asset.id))
            .map_err(|_| FetchError::DownloadFailed("bad asset address".into()))
    }

    fn note_final_host(host: &str) {
        if !FINAL_HOST_LOGGED.swap(true, Ordering::Relaxed) {
            tracing::info!("Release files are served from host {host}");
        }
    }
}

fn content_length(resp: &reqwest::Response) -> Option<u64> {
    resp.headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
}

async fn read_to_vec(
    mut resp: reqwest::Response,
    host: &str,
    limit: u64,
    expected: Option<u64>,
) -> Result<Vec<u8>, FetchError> {
    let mut guard = SizeGuard::new(limit, expected, content_length(&resp))?;
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| send_error(host, e))? {
        guard.feed(chunk.len())?;
        out.extend_from_slice(&chunk);
    }
    guard.finish()?;
    Ok(out)
}

impl ReleaseApi for GithubApi {
    async fn list_releases(&self, repo: &str, per_page: u8) -> Result<Vec<ReleaseInfo>, FetchError> {
        let url = Url::parse(&format!(
            "{GITHUB_API_BASE}/repos/{repo}/releases?per_page={per_page}"
        ))
        .map_err(|_| FetchError::RepoUnreadable)?;
        self.json_limited(url, CallKind::List).await
    }

    async fn release_by_tag(&self, repo: &str, tag: &str) -> Result<ReleaseInfo, FetchError> {
        let url = Url::parse(&format!("{GITHUB_API_BASE}/repos/{repo}/releases/tags/{tag}"))
            .map_err(|_| FetchError::ReleaseNotFound)?;
        self.json_limited(url, CallKind::Tag).await
    }

    async fn asset_bytes(&self, repo: &str, asset: &AssetInfo, max: u64) -> Result<Vec<u8>, FetchError> {
        let url = Self::asset_url(repo, asset)?;
        let work = async {
            let (resp, host) = self.get(url, ACCEPT_OCTET, CallKind::Asset).await?;
            Self::note_final_host(&host);
            read_to_vec(resp, &host, max, Some(asset.size)).await
        };
        tokio::time::timeout(SMALL_FILE_TIMEOUT, work)
            .await
            .map_err(|_| FetchError::DownloadFailed(format!("{}: timed out", asset.name)))?
    }

    async fn asset_to_file(&self, repo: &str, asset: &AssetInfo, dest: &Path) -> Result<String, FetchError> {
        let url = Self::asset_url(repo, asset)?;
        let work = async {
            let (mut resp, host) = self.get(url, ACCEPT_OCTET, CallKind::Asset).await?;
            Self::note_final_host(&host);
            let mut guard = SizeGuard::new(MAX_ASSET_BYTES, Some(asset.size), content_length(&resp))?;
            let mut file = create_private_file(dest).await?;
            let mut hasher = Sha256::new();
            while let Some(chunk) = resp.chunk().await.map_err(|e| send_error(&host, e))? {
                guard.feed(chunk.len())?;
                hasher.update(&chunk);
                file.write_all(&chunk).await.map_err(io_failed)?;
            }
            guard.finish()?;
            file.flush().await.map_err(io_failed)?;
            file.sync_all().await.map_err(io_failed)?;
            Ok(hex::encode(hasher.finalize()))
        };
        tokio::time::timeout(ASSET_TIMEOUT, work)
            .await
            .map_err(|_| FetchError::DownloadFailed(format!("{}: timed out", asset.name)))?
    }
}

fn io_failed(e: std::io::Error) -> FetchError {
    FetchError::DownloadFailed(format!("cache write failed: {}", e.kind()))
}

async fn create_private_file(path: &Path) -> Result<tokio::fs::File, FetchError> {
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    opts.open(path).await.map_err(io_failed)
}

// ── Release cache ────────────────────────────────────────────────────────

/// A prepared release: its verified directory and manifest.
#[derive(Debug, Clone)]
pub struct Prepared {
    pub dir: PathBuf,
    pub manifest: Manifest,
}

static TAG_LOCKS: LazyLock<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

fn tag_lock(tag: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = TAG_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    locks
        .entry(tag.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

fn ensure_private_dir(dir: &Path) -> Result<(), FetchError> {
    std::fs::create_dir_all(dir).map_err(io_failed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(io_failed)?;
    }
    Ok(())
}

/// The architecture suffix of release assets for this machine.
pub fn arch_suffix() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("amd64"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

/// What a panel update needs, for `arch`.
pub fn panel_files_for(arch: &str) -> Vec<String> {
    let mut v: Vec<String> = ["agent", "api", "cli", "mcp"]
        .iter()
        .map(|c| format!("cyberhunter-{c}-linux-{arch}"))
        .collect();
    v.push(FRONTEND_ARCHIVE.to_string());
    v.push(SOURCE_ARCHIVE.to_string());
    v
}

pub fn panel_files() -> Result<Vec<String>, FetchError> {
    arch_suffix()
        .map(panel_files_for)
        .ok_or_else(|| FetchError::ReleaseIncomplete("no release files for this architecture".into()))
}

/// The key and repository to prepare with, or `NotConfigured`.
pub fn configured_source(
    status: &update_source::SourceStatus,
) -> Result<(update_source::UpdateSource, &'static minisign_verify::PublicKey), FetchError> {
    if !status.configured {
        return Err(FetchError::NotConfigured);
    }
    let source = status.source.clone().ok_or(FetchError::NotConfigured)?;
    let key = update_source::signing_key().ok_or(FetchError::NotConfigured)?;
    Ok((source, key))
}

/// Prepare `names` of release `tag` in the real cache, with the real client.
/// Requires "configured" even when everything is already cached.
pub async fn prepare_full(tag: &str, names: &[&str]) -> Result<Prepared, FetchError> {
    let (source, key) = configured_source(&update_source::load())?;
    let api = GithubApi::new(source.token_file.clone())?;
    prepare_with(
        &api,
        Some((source.repo.as_str(), key)),
        Path::new(RELEASE_CACHE_DIR),
        tag,
        names,
    )
    .await
}

/// [`prepare_full`], returning the release directory.
pub async fn prepare(tag: &str, names: &[&str]) -> Result<PathBuf, FetchError> {
    prepare_full(tag, names).await.map(|p| p.dir)
}

/// The agent binaries of `tag`: amd64, plus arm64 when the manifest lists it.
pub async fn prepare_agents(tag: &str) -> Result<Prepared, FetchError> {
    let p = prepare_full(tag, &[]).await?;
    let names = agent_files(&p.manifest);
    prepare_full(tag, &names).await
}

pub fn agent_files(manifest: &Manifest) -> Vec<&'static str> {
    let mut v = vec![AGENT_AMD64];
    if manifest.contains(AGENT_ARM64) {
        v.push(AGENT_ARM64);
    }
    v
}

/// Read and re-verify a cached manifest. `None` when it is not cached.
fn cached_manifest(
    dir: &Path,
    key: &minisign_verify::PublicKey,
    tag: &str,
) -> Option<Result<Manifest, FetchError>> {
    let sums = std::fs::read(dir.join(CHECKSUMS_NAME)).ok()?;
    let sig = std::fs::read(dir.join(MINISIG_NAME)).ok()?;
    Some(verify_signed_manifest(key, &sums, &sig, tag))
}

/// The core of [`prepare`], with every dependency injected. `cfg` is `None`
/// when updates are not configured: then nothing is called at all.
pub async fn prepare_with<A: ReleaseApi>(
    api: &A,
    cfg: Option<(&str, &minisign_verify::PublicKey)>,
    root: &Path,
    tag: &str,
    names: &[&str],
) -> Result<Prepared, FetchError> {
    let Some((repo, key)) = cfg else {
        return Err(FetchError::NotConfigured);
    };
    if !is_release_tag(tag) {
        return Err(FetchError::ReleaseNotFound);
    }
    for n in names {
        if !NAME_RE.is_match(n) || n.starts_with('.') {
            return Err(FetchError::FileUnknown);
        }
    }
    ensure_private_dir(root)?;
    let lock = tag_lock(tag);
    let _guard = lock.lock().await;
    let dir = root.join(tag);

    let mut release: Option<ReleaseInfo> = None;
    let manifest = match cached_manifest(&dir, key, tag) {
        Some(Ok(m)) => m,
        cached => {
            if cached.is_some() {
                // A cached manifest that no longer verifies (the key changed):
                // start over rather than trust anything in that directory.
                tracing::warn!("Cached release {tag} no longer verifies; fetching it again");
            }
            let (m, rel) = fetch_manifest(api, repo, key, root, &dir, tag).await?;
            release = Some(rel);
            m
        }
    };

    for name in names {
        if !manifest.contains(name) {
            return Err(FetchError::ReleaseIncomplete(format!("{name} is not in checksums.txt")));
        }
        let path = dir.join(name);
        // A cached file is trusted only after it is hashed AGAIN against the
        // signed manifest: the cache outlives the check that filled it, and a
        // file altered (or torn) on disk since must never be served to an agent
        // or installed. A mismatch is dropped and downloaded afresh.
        if std::fs::symlink_metadata(&path).is_ok() {
            if cached_file_matches(&path, manifest.sha256(name)).await {
                continue;
            }
            tracing::warn!("Cached {name} of {tag} no longer matches checksums.txt; fetching it again");
            std::fs::remove_file(&path).map_err(io_failed)?;
        }
        if release.is_none() {
            release = Some(fetch_release(api, repo, tag).await?);
        }
        let rel = release.as_ref().expect("release fetched above");
        let asset = rel
            .asset(name)
            .ok_or_else(|| FetchError::ReleaseIncomplete(format!("{name} is not attached")))?;
        if asset.size > MAX_ASSET_BYTES {
            return Err(FetchError::DownloadFailed(format!(
                "{name} is over the {MAX_ASSET_BYTES} byte limit"
            )));
        }
        let tmp = dir.join(format!(".{name}.part-{}", Uuid::new_v4()));
        let digest = match api.asset_to_file(repo, asset, &tmp).await {
            Ok(d) => d,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
        };
        if Some(digest.as_str()) != manifest.sha256(name) {
            let _ = std::fs::remove_file(&tmp);
            return Err(FetchError::ChecksumFailed(format!("{name}: SHA-256 differs")));
        }
        std::fs::rename(&tmp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            io_failed(e)
        })?;
    }

    // Extracted again on every preparation that asks for the source: the tree
    // update.sh runs from is then always the one in the archive verified just
    // above, never an older extraction that may have changed on disk.
    if names.contains(&SOURCE_ARCHIVE) {
        extract_source(&dir).await?;
    }

    Ok(Prepared { dir, manifest })
}

/// `true` when `path` is a regular file (not a link) whose SHA-256 is `want`.
/// Hashed off the async runtime: release binaries are tens of megabytes.
async fn cached_file_matches(path: &Path, want: Option<&str>) -> bool {
    let Some(want) = want.map(str::to_string) else {
        return false;
    };
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> std::io::Result<bool> {
        let meta = std::fs::symlink_metadata(&path)?;
        if !meta.file_type().is_file() {
            return Ok(false);
        }
        let mut f = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut f, &mut hasher)?;
        Ok(hex::encode(hasher.finalize()) == want)
    })
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or(false)
}

/// Check the listing of the source archive BEFORE it is extracted as root.
/// `names` is `tar -tzf` (one member per line), `verbose` is `tar -tvzf`
/// (same members, same order, type in the first column). Refused: an absolute
/// path, a `..` component, a member outside `cyberhunter-source/`, and any
/// member that is not a regular file or a directory (symbolic and hard links,
/// devices, FIFOs). Two listings of different lengths (a name with a newline)
/// are refused too. Pure.
pub fn check_source_listing(names: &str, verbose: &str) -> Result<(), String> {
    let lines = |s: &str| -> Vec<String> {
        s.split('\n').filter(|l| !l.is_empty()).map(str::to_string).collect()
    };
    let names = lines(names);
    let verbose = lines(verbose);
    if names.is_empty() {
        return Err("the archive is empty".into());
    }
    if names.len() != verbose.len() {
        return Err("the archive listing is ambiguous".into());
    }
    let prefix = format!("{SOURCE_DIR}/");
    for (name, line) in names.iter().zip(&verbose) {
        if name.starts_with('/') {
            return Err(format!("absolute path in the archive: {name}"));
        }
        if name.split('/').any(|c| c == "..") {
            return Err(format!("`..` in the archive: {name}"));
        }
        if !name.starts_with(&prefix) {
            return Err(format!("member outside {prefix}: {name}"));
        }
        match line.chars().next() {
            Some('-') | Some('d') => {}
            _ => return Err(format!("not a regular file or directory: {name}")),
        }
    }
    Ok(())
}

/// Run `tar` with `args` on the archive and return its stdout.
async fn tar_list(archive: &Path, verbose: bool) -> Result<String, FetchError> {
    let out = tokio::process::Command::new("tar")
        .arg(if verbose { "-tvzf" } else { "-tzf" })
        .arg(archive)
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| FetchError::ReleaseIncomplete(format!("tar could not run: {}", e.kind())))?;
    if !out.status.success() {
        return Err(FetchError::ReleaseIncomplete(format!(
            "{SOURCE_ARCHIVE} could not be listed ({})",
            out.status
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `scripts/update.sh` of the extracted source of a prepared release.
pub fn update_script_path(release_dir: &Path) -> PathBuf {
    release_dir.join(SOURCE_DIR).join("scripts").join("update.sh")
}

async fn fetch_release<A: ReleaseApi>(api: &A, repo: &str, tag: &str) -> Result<ReleaseInfo, FetchError> {
    let rel = api.release_by_tag(repo, tag).await?;
    if rel.draft || rel.tag_name != tag {
        return Err(FetchError::ReleaseNotFound);
    }
    Ok(rel)
}

/// Download, verify and cache `checksums.txt` and its signature, through a
/// `.partial-*` directory renamed into place only once both verified.
async fn fetch_manifest<A: ReleaseApi>(
    api: &A,
    repo: &str,
    key: &minisign_verify::PublicKey,
    root: &Path,
    dir: &Path,
    tag: &str,
) -> Result<(Manifest, ReleaseInfo), FetchError> {
    let rel = fetch_release(api, repo, tag).await?;
    let sums_asset = rel
        .asset(CHECKSUMS_NAME)
        .ok_or_else(|| FetchError::ReleaseIncomplete("checksums.txt is not attached".into()))?;
    let sig_asset = rel
        .asset(MINISIG_NAME)
        .ok_or_else(|| FetchError::SignatureFailed("no signature file".into()))?;
    if sums_asset.size > MAX_CHECKSUMS_BYTES {
        return Err(incomplete("larger than 64 KiB"));
    }
    if sig_asset.size > MAX_MINISIG_BYTES {
        return Err(FetchError::SignatureFailed("signature file larger than 4 KiB".into()));
    }
    let sums = api.asset_bytes(repo, sums_asset, MAX_CHECKSUMS_BYTES).await?;
    let sig = api.asset_bytes(repo, sig_asset, MAX_MINISIG_BYTES).await?;
    let manifest = verify_signed_manifest(key, &sums, &sig, tag)?;

    let partial = root.join(format!(".partial-{tag}-{}", Uuid::new_v4()));
    let write = || -> Result<(), FetchError> {
        ensure_private_dir(&partial)?;
        std::fs::write(partial.join(CHECKSUMS_NAME), &sums).map_err(io_failed)?;
        std::fs::write(partial.join(MINISIG_NAME), &sig).map_err(io_failed)?;
        if dir.exists() {
            std::fs::remove_dir_all(dir).map_err(io_failed)?;
        }
        std::fs::rename(&partial, dir).map_err(io_failed)
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_dir_all(&partial);
        return Err(e);
    }
    Ok((manifest, rel))
}

/// Unpack the verified source archive into `<tag>/cyberhunter-source/`,
/// through a temporary directory so a torn extraction never looks complete.
async fn extract_source(dir: &Path) -> Result<(), FetchError> {
    let tmp = dir.join(format!(".extract-{}", Uuid::new_v4()));
    ensure_private_dir(&tmp)?;
    let result = async {
        let archive = dir.join(SOURCE_ARCHIVE);
        let names = tar_list(&archive, false).await?;
        let verbose = tar_list(&archive, true).await?;
        check_source_listing(&names, &verbose).map_err(|why| {
            FetchError::ReleaseIncomplete(format!("{SOURCE_ARCHIVE} refused: {why}"))
        })?;
        let out = tokio::process::Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&tmp)
            .arg("--no-same-owner")
            .arg("--no-same-permissions")
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .map_err(|e| FetchError::ReleaseIncomplete(format!("tar could not run: {}", e.kind())))?;
        if !out.status.success() {
            return Err(FetchError::ReleaseIncomplete(format!(
                "{SOURCE_ARCHIVE} could not be extracted ({})",
                out.status
            )));
        }
        let extracted = tmp.join(SOURCE_DIR);
        if !update_script_path(&tmp).exists() {
            return Err(FetchError::ReleaseIncomplete(format!(
                "{SOURCE_ARCHIVE} has no {SOURCE_DIR}/scripts/update.sh"
            )));
        }
        let target = dir.join(SOURCE_DIR);
        if target.exists() {
            std::fs::remove_dir_all(&target).map_err(io_failed)?;
        }
        std::fs::rename(&extracted, &target).map_err(io_failed)
    }
    .await;
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

/// Remove cached releases that are not in `keep`. Hidden entries (partial
/// downloads, temporary extractions) are only removed at start-up, when no
/// preparation can be running; a tag whose lock is held is left alone.
pub fn retain_only(root: &Path, keep: &HashSet<String>, startup: bool) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            if startup {
                let _ = std::fs::remove_dir_all(entry.path());
            }
            continue;
        }
        if keep.contains(&name) {
            // A download cut by a timeout leaves its `.part-*` or `.extract-*`
            // inside the tag directory; at start-up nothing can own them.
            if startup && let Ok(inner) = std::fs::read_dir(entry.path()) {
                for f in inner.flatten() {
                    if f.file_name().to_string_lossy().starts_with('.') {
                        let p = f.path();
                        let _ = std::fs::remove_dir_all(&p).or_else(|_| std::fs::remove_file(&p));
                    }
                }
            }
            continue;
        }
        if tag_lock(&name).try_lock().is_err() {
            continue;
        }
        match std::fs::remove_dir_all(entry.path()) {
            Ok(()) => tracing::info!("Removed cached release {name}"),
            Err(e) => tracing::warn!("Could not remove cached release {name}: {}", e.kind()),
        }
    }
}

/// Keep the running tag, the advertised tag and unfinished fleet targets.
pub async fn cleanup_cache(pool: &PgPool, startup: bool) {
    let mut keep = HashSet::new();
    keep.insert(release_tag(env!("CARGO_PKG_VERSION")));
    if let Ok(Some(v)) = sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key = 'update_available_version'",
    )
    .fetch_optional(pool)
    .await
    {
        keep.insert(release_tag(&v));
    }
    match sqlx::query_scalar::<_, String>(
        "SELECT target_version FROM fleet_update_runs WHERE finished_at IS NULL",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => keep.extend(rows.iter().map(|t| release_tag(t))),
        // Without the list, deleting could pull a file from under a fleet run.
        Err(_) => return,
    }
    retain_only(Path::new(RELEASE_CACHE_DIR), &keep, startup);
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::services::update_source::tests::{temp_dir, test_key_line, KNOWN_TOKEN};
    use std::sync::atomic::AtomicUsize;

    const FIX_SUMS: &[u8] = include_bytes!("testdata/release/checksums.txt");
    const FIX_SIG: &[u8] = include_bytes!("testdata/release/checksums.txt.minisig");
    const FIX_SIG_OTHER_KEY: &[u8] = include_bytes!("testdata/release/checksums.txt.minisig-otherkey");
    const FIX_SIG_OTHER_TAG: &[u8] = include_bytes!("testdata/release/checksums.txt.minisig-othertag");
    const FIX_SIG_LEGACY: &[u8] = include_bytes!("testdata/release/checksums.txt.minisig-legacy");
    const FIX_FILES: [(&str, &[u8]); 6] = [
        ("cyberhunter-agent-linux-amd64", include_bytes!("testdata/release/cyberhunter-agent-linux-amd64")),
        ("cyberhunter-api-linux-amd64", include_bytes!("testdata/release/cyberhunter-api-linux-amd64")),
        ("cyberhunter-cli-linux-amd64", include_bytes!("testdata/release/cyberhunter-cli-linux-amd64")),
        ("cyberhunter-mcp-linux-amd64", include_bytes!("testdata/release/cyberhunter-mcp-linux-amd64")),
        ("cyberhunter-frontend.tar.gz", include_bytes!("testdata/release/cyberhunter-frontend.tar.gz")),
        ("cyberhunter-source.tar.gz", include_bytes!("testdata/release/cyberhunter-source.tar.gz")),
    ];
    pub(crate) const FIX_TAG: &str = "v9.9.9";

    pub(crate) fn test_key() -> minisign_verify::PublicKey {
        update_source::parse_public_key(test_key_line()).unwrap().0
    }

    fn line(name: &str) -> String {
        format!("{}  {name}", "a".repeat(64))
    }

    // ── checksums.txt ──

    #[test]
    fn a_valid_manifest_parses_with_or_without_the_final_newline() {
        let m = parse_checksums(FIX_SUMS).unwrap();
        assert_eq!(m.names().count(), 6);
        assert_eq!(
            m.sha256("cyberhunter-agent-linux-amd64"),
            Some("5e449f62211bd820ad0b4a59bd177ead6117b7b222b71779985644089ce0bd23")
        );
        let trimmed = &FIX_SUMS[..FIX_SUMS.len() - 1];
        assert_eq!(parse_checksums(trimmed).unwrap(), m);
    }

    #[test]
    fn malformed_manifests_are_refused() {
        let ok = format!("{}\n{}\n", line("a"), line("b"));
        assert!(parse_checksums(ok.as_bytes()).is_ok());
        let cases: Vec<(&str, String)> = vec![
            ("duplicate", format!("{}\n{}\n", line("a"), line("a"))),
            ("one space", format!("{} a\n", "a".repeat(64))),
            ("uppercase", format!("{}  a\n", "A".repeat(64))),
            ("slash", format!("{}\n", line("dir/a"))),
            ("carriage return", format!("{}\r\n", line("a"))),
            ("33 lines", (0..33).map(|i| line(&format!("f{i}")) + "\n").collect()),
            ("inner blank line", format!("{}\n\n{}\n", line("a"), line("b"))),
            ("two final newlines", format!("{}\n\n", line("a"))),
            ("empty", String::new()),
            ("short hex", format!("{}  a\n", "a".repeat(63))),
            ("bom", format!("\u{feff}{}\n", line("a"))),
            ("dot dot", format!("{}\n", line(".."))),
            ("tab", format!("{}\ta\n", "a".repeat(64))),
            ("trailing space", format!("{} \n", line("a"))),
        ];
        for (what, text) in cases {
            let e = parse_checksums(text.as_bytes()).expect_err(what);
            assert_eq!(e.code(), "release_incomplete", "{what}");
        }
        // 32 lines is the maximum, accepted.
        let max: String = (0..32).map(|i| line(&format!("f{i}")) + "\n").collect();
        assert!(parse_checksums(max.as_bytes()).is_ok());
        // Over 64 KiB, even before looking at lines.
        let big = vec![b'a'; 64 * 1024 + 1];
        assert_eq!(parse_checksums(&big).unwrap_err().code(), "release_incomplete");
    }

    // ── Signature ──

    #[test]
    fn the_fixture_signature_verifies() {
        let m = verify_signed_manifest(&test_key(), FIX_SUMS, FIX_SIG, FIX_TAG).unwrap();
        assert!(m.contains("cyberhunter-source.tar.gz"));
    }

    #[test]
    fn a_manifest_changed_by_one_byte_is_refused() {
        let mut sums = FIX_SUMS.to_vec();
        sums[0] = if sums[0] == b'0' { b'1' } else { b'0' };
        let e = verify_signed_manifest(&test_key(), &sums, FIX_SIG, FIX_TAG).unwrap_err();
        assert_eq!(e.code(), "signature_failed");
    }

    #[test]
    fn a_missing_signature_is_refused() {
        let e = verify_signed_manifest(&test_key(), FIX_SUMS, b"", FIX_TAG).unwrap_err();
        assert_eq!(e.code(), "signature_failed");
        let e = verify_signed_manifest(&test_key(), FIX_SUMS, b"garbage\n", FIX_TAG).unwrap_err();
        assert_eq!(e.code(), "signature_failed");
    }

    #[test]
    fn a_signature_from_another_key_is_refused() {
        let e = verify_signed_manifest(&test_key(), FIX_SUMS, FIX_SIG_OTHER_KEY, FIX_TAG).unwrap_err();
        assert_eq!(e, FetchError::SignatureFailed("signed by another key".into()));
        // ...and the other key's own signature does not pass under our key
        // through some other route either.
        let other = include_str!("testdata/release/other.pub").lines().nth(1).unwrap();
        let (other_key, _) = update_source::parse_public_key(other).unwrap();
        assert!(verify_signed_manifest(&other_key, FIX_SUMS, FIX_SIG_OTHER_KEY, FIX_TAG).is_ok());
        assert!(verify_signed_manifest(&other_key, FIX_SUMS, FIX_SIG, FIX_TAG).is_err());
    }

    #[test]
    fn a_trusted_comment_for_another_tag_is_refused() {
        let e = verify_signed_manifest(&test_key(), FIX_SUMS, FIX_SIG_OTHER_TAG, FIX_TAG).unwrap_err();
        assert_eq!(e.code(), "signature_failed");
        // The valid signature is bound to its own tag: v9.9.9 only.
        let e = verify_signed_manifest(&test_key(), FIX_SUMS, FIX_SIG, "v9.9.10").unwrap_err();
        assert_eq!(e.code(), "signature_failed");
    }

    #[test]
    fn a_legacy_signature_is_refused() {
        let e = verify_signed_manifest(&test_key(), FIX_SUMS, FIX_SIG_LEGACY, FIX_TAG).unwrap_err();
        assert_eq!(e, FetchError::SignatureFailed("legacy signature (not pre-hashed) refused".into()));
    }

    // ── Redirects and headers ──

    #[test]
    fn authorization_is_sent_on_the_first_request_only() {
        let auth = HeaderValue::from_static("Bearer x");
        let h0 = request_headers(0, Some(auth.clone()));
        assert!(h0.contains_key(AUTHORIZATION));
        assert!(h0.get(AUTHORIZATION).unwrap().is_sensitive());
        assert!(h0.contains_key(USER_AGENT));
        for hop in 1..=3 {
            let h = request_headers(hop, Some(auth.clone()));
            assert!(!h.contains_key(AUTHORIZATION), "hop {hop}");
            assert_eq!(h.len(), 1, "only the User-Agent before Accept is added");
            assert!(h.get(USER_AGENT).unwrap().to_str().unwrap().starts_with("CyberHunter-Panel/"));
        }
    }

    #[test]
    fn no_authorization_header_without_a_token() {
        let dir = temp_dir();
        let absent = dir.join("update-token");
        let empty = dir.join("empty");
        std::fs::write(&empty, " \n").unwrap();
        for p in [&absent, &empty] {
            let auth = github_auth_header(p).unwrap();
            assert!(auth.is_none(), "{}", p.display());
            for hop in 0..=2 {
                let h = request_headers(hop, auth.clone());
                assert!(!h.contains_key(AUTHORIZATION), "hop {hop}");
                assert!(h.contains_key(USER_AGENT));
            }
            assert!(request_headers(0, None).contains_key("x-github-api-version"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn redirect_targets_are_checked() {
        let cur = Url::parse("https://api.github.com/repos/o/n/releases/assets/1").unwrap();
        let ok = next_hop(&cur, "https://objects.githubusercontent.com/x?sig=1", 1, &ALLOWED_DOWNLOAD_HOSTS).unwrap();
        assert_eq!(ok.host_str(), Some("objects.githubusercontent.com"));
        assert!(next_hop(&cur, "https://release-assets.githubusercontent.com/a", 3, &ALLOWED_DOWNLOAD_HOSTS).is_ok());

        for (loc, why) in [
            ("https://evil.example.com/x", "host off the list"),
            ("http://objects.githubusercontent.com/x", "http"),
            ("https://objects.githubusercontent.com:8443/x", "port 8443"),
            ("https://api.github.com.evil.example/x", "suffix trick"),
        ] {
            let e = next_hop(&cur, loc, 1, &ALLOWED_DOWNLOAD_HOSTS).expect_err(why);
            assert_eq!(e.code(), "download_failed", "{why}");
            assert!(!e.detail().unwrap().contains("/x"), "no path in the detail: {why}");
        }
        assert!(next_hop(&cur, "https://objects.githubusercontent.com:443/x", 1, &ALLOWED_DOWNLOAD_HOSTS).is_ok());
        let e = next_hop(&cur, "https://objects.githubusercontent.com/x", 4, &ALLOWED_DOWNLOAD_HOSTS).unwrap_err();
        assert_eq!(e.code(), "download_failed");
    }

    #[test]
    fn a_relative_location_is_resolved_then_checked() {
        let cur = Url::parse("https://api.github.com/repos/o/n/releases/assets/1").unwrap();
        let next = next_hop(&cur, "/download/other", 1, &ALLOWED_DOWNLOAD_HOSTS).unwrap();
        assert_eq!(next.as_str(), "https://api.github.com/download/other");
        let evil = Url::parse("https://objects.githubusercontent.com/a/b").unwrap();
        assert!(next_hop(&evil, "../c", 1, &ALLOWED_DOWNLOAD_HOSTS).is_ok());
        assert!(next_hop(&cur, "//evil.example.com/x", 1, &ALLOWED_DOWNLOAD_HOSTS).is_err());
    }

    #[test]
    fn github_statuses_map_to_contract_codes() {
        let c = |s, ex, k| map_status(s, ex, k, "api.github.com", false).unwrap_err().code();
        assert!(map_status(200, false, CallKind::List, "h", false).is_ok());
        assert_eq!(c(401, false, CallKind::List), "token_invalid");
        assert_eq!(c(403, true, CallKind::List), "github_rate_limited");
        assert_eq!(c(429, false, CallKind::Tag), "github_rate_limited");
        assert_eq!(c(403, false, CallKind::List), "repo_unreadable");
        assert_eq!(c(404, false, CallKind::List), "repo_unreadable");
        assert_eq!(c(404, false, CallKind::Tag), "release_not_found");
        assert_eq!(c(500, false, CallKind::List), "download_failed");
        assert_eq!(c(404, false, CallKind::Asset), "download_failed");
    }

    #[test]
    fn an_anonymous_404_says_the_repository_may_be_private() {
        for kind in [CallKind::List, CallKind::Tag, CallKind::Asset] {
            let e = map_status(404, false, kind, "api.github.com", true).unwrap_err();
            assert_eq!(e, FetchError::RepoNotFoundAnonymous, "{kind:?}");
            assert_eq!(e.code(), "repo_not_found");
            assert_eq!(
                e.to_string(),
                "Repository not found or private. Add a token if the release repository is private."
            );
            assert_eq!(e.status().as_u16(), 409);
            assert_eq!(e.stage(), "download");
        }
        // Anonymous, other statuses keep their mapping.
        assert!(map_status(200, false, CallKind::List, "api.github.com", true).is_ok());
        assert_eq!(
            map_status(403, true, CallKind::List, "api.github.com", true).unwrap_err(),
            FetchError::RateLimited
        );
        // With a token, a 404 is unchanged.
        assert_eq!(
            map_status(404, false, CallKind::List, "api.github.com", false).unwrap_err(),
            FetchError::RepoUnreadable
        );
    }

    #[test]
    fn every_error_carries_its_exact_message_and_status() {
        let table = [
            (FetchError::NotConfigured, 409, "updates_not_configured", "Updates are not configured"),
            (FetchError::TokenInvalid, 409, "token_invalid", "The update token is missing or expired"),
            (FetchError::RepoUnreadable, 409, "repo_unreadable", "The update token cannot read this repository"),
            (
                FetchError::RepoNotFoundAnonymous,
                409,
                "repo_not_found",
                "Repository not found or private. Add a token if the release repository is private.",
            ),
            (FetchError::RateLimited, 503, "github_rate_limited", "GitHub rate limit reached, try again later"),
            (FetchError::ReleaseNotFound, 404, "release_not_found", "Release not found"),
            (FetchError::ReleaseIncomplete("x".into()), 422, "release_incomplete", "The release is missing required files, nothing was installed"),
            (FetchError::SignatureFailed("x".into()), 422, "signature_failed", "Signature check failed, nothing was installed"),
            (FetchError::ChecksumFailed("x".into()), 422, "checksum_failed", "Checksum check failed, nothing was installed"),
            (FetchError::DownloadFailed("x".into()), 502, "download_failed", "Download failed"),
            (FetchError::FileUnknown, 404, "release_file_unknown", "Release file not available"),
        ];
        for (e, status, code, msg) in table {
            assert_eq!(e.status().as_u16(), status);
            assert_eq!(e.code(), code);
            assert_eq!(e.to_string(), msg);
            let (s, body) = e.api_error();
            assert_eq!(s.as_u16(), status);
            assert_eq!(body.0["error"], msg);
            assert_eq!(body.0["code"], code);
            assert!(!msg.contains('\u{2014}'));
        }
    }

    // ── Sizes ──

    #[test]
    fn a_content_length_over_the_limit_is_refused() {
        let e = SizeGuard::new(MAX_ASSET_BYTES, None, Some(MAX_ASSET_BYTES + 1)).unwrap_err();
        assert_eq!(e.code(), "download_failed");
        assert!(SizeGuard::new(MAX_ASSET_BYTES, None, Some(MAX_ASSET_BYTES)).is_ok());
        let e = SizeGuard::new(MAX_ASSET_BYTES, Some(MAX_ASSET_BYTES + 1), None).unwrap_err();
        assert_eq!(e.code(), "download_failed");
        let e = SizeGuard::new(MAX_ASSET_BYTES, Some(10), Some(11)).unwrap_err();
        assert_eq!(e.code(), "checksum_failed");
    }

    #[test]
    fn a_stream_longer_than_announced_is_cut() {
        let mut g = SizeGuard::new(MAX_ASSET_BYTES, Some(10), None).unwrap();
        g.feed(6).unwrap();
        assert_eq!(g.feed(6).unwrap_err().code(), "checksum_failed");
        let mut g = SizeGuard::new(100, None, None).unwrap();
        g.feed(100).unwrap();
        assert_eq!(g.feed(1).unwrap_err().code(), "download_failed");
        let mut g = SizeGuard::new(100, Some(10), None).unwrap();
        g.feed(9).unwrap();
        assert_eq!(g.finish().unwrap_err().code(), "checksum_failed");
        g.feed(1).unwrap();
        assert!(g.finish().is_ok());
    }

    // ── Selection ──

    fn rel(tag: &str, draft: bool, pre: bool) -> ReleaseInfo {
        ReleaseInfo {
            tag_name: tag.into(),
            draft,
            prerelease: pre,
            body: Some(format!("notes {tag}")),
            html_url: Some(format!("https://github.com/o/n/releases/tag/{tag}")),
            assets: vec![],
        }
    }

    #[test]
    fn versions_order_as_the_contract_says() {
        use crate::services::telemetry_collector::is_newer_release;
        assert!(is_newer_release("3.0.0-rc.1", "2.242.1"));
        assert!(is_newer_release("3.0.0", "3.0.0-rc.2"));
        assert!(is_newer_release("3.0.0-rc.2", "3.0.0-rc.1"));
    }

    #[test]
    fn selection_drops_drafts_and_respects_the_channel() {
        let list = vec![
            rel("v3.0.0-rc.3", true, true), // draft: never
            rel("v3.0.0-rc.2", false, false), // rc tag not marked: still a pre-release
            rel("v2.9.0", false, false),
            rel("v3.0.1", false, true), // marked pre-release
            rel("v3.0.0-rc1", false, false), // refused tag shape
            rel("vv4.0.0", false, false), // refused tag shape
        ];
        assert_eq!(select_release(&list, "stable").unwrap().tag_name, "v2.9.0");
        assert_eq!(select_release(&list, "hold").unwrap().tag_name, "v2.9.0");
        assert_eq!(select_release(&list, "candidate").unwrap().tag_name, "v3.0.1");
        assert!(is_prerelease(&list[1]));
    }

    #[test]
    fn selection_takes_the_maximum_whatever_the_order() {
        let list = vec![
            rel("v3.0.0-rc.2", false, true),
            rel("v3.0.0", false, false),
            rel("v2.100.0", false, false),
            rel("v3.0.0-rc.10", false, true),
        ];
        assert_eq!(select_release(&list, "stable").unwrap().tag_name, "v3.0.0");
        let list = vec![rel("v3.0.0-rc.2", false, true), rel("v3.0.0-rc.10", false, true)];
        assert_eq!(select_release(&list, "candidate").unwrap().tag_name, "v3.0.0-rc.10");
        assert!(select_release(&list, "stable").is_none());
    }

    #[test]
    fn release_notes_and_page_are_bounded() {
        let mut r = rel("v1.0.0", false, false);
        r.body = Some("é".repeat(5000));
        assert_eq!(r.notes().chars().count(), 4000);
        r.html_url = Some("javascript:alert(1)".into());
        assert_eq!(r.page_url(), None);
    }

    #[test]
    fn release_tags_have_exactly_one_v() {
        assert!(is_release_tag("v3.0.0-rc.2"));
        assert!(!is_release_tag("3.0.0"));
        assert!(!is_release_tag("vv3.0.0"));
        assert!(!is_release_tag("v3.0.0/../x"));
        assert_eq!(release_tag("3.0.0"), "v3.0.0");
        assert_eq!(release_tag("v3.0.0"), "v3.0.0");
    }

    // ── prepare, with a fake GitHub ──

    #[derive(Default)]
    pub(crate) struct FakeApi {
        pub calls: AtomicUsize,
        pub releases: Vec<ReleaseInfo>,
        pub files: HashMap<String, Vec<u8>>,
    }

    impl FakeApi {
        pub(crate) fn fixture() -> Self {
            let mut files: HashMap<String, Vec<u8>> = FIX_FILES
                .iter()
                .map(|(n, b)| (n.to_string(), b.to_vec()))
                .collect();
            files.insert(CHECKSUMS_NAME.into(), FIX_SUMS.to_vec());
            files.insert(MINISIG_NAME.into(), FIX_SIG.to_vec());
            let mut r = rel(FIX_TAG, false, false);
            r.assets = files
                .iter()
                .enumerate()
                .map(|(i, (n, b))| AssetInfo {
                    id: i as u64,
                    name: n.clone(),
                    size: b.len() as u64,
                })
                .collect();
            FakeApi {
                calls: AtomicUsize::new(0),
                releases: vec![r],
                files,
            }
        }

        pub(crate) fn count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl ReleaseApi for FakeApi {
        async fn list_releases(&self, _repo: &str, _per_page: u8) -> Result<Vec<ReleaseInfo>, FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.releases.clone())
        }

        async fn release_by_tag(&self, _repo: &str, tag: &str) -> Result<ReleaseInfo, FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.releases
                .iter()
                .find(|r| r.tag_name == tag)
                .cloned()
                .ok_or(FetchError::ReleaseNotFound)
        }

        async fn asset_bytes(&self, _repo: &str, asset: &AssetInfo, max: u64) -> Result<Vec<u8>, FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let b = self.files.get(&asset.name).cloned().unwrap_or_default();
            let mut g = SizeGuard::new(max, Some(asset.size), None)?;
            g.feed(b.len())?;
            g.finish()?;
            Ok(b)
        }

        async fn asset_to_file(&self, _repo: &str, asset: &AssetInfo, dest: &Path) -> Result<String, FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let b = self.files.get(&asset.name).cloned().unwrap_or_default();
            let mut g = SizeGuard::new(MAX_ASSET_BYTES, Some(asset.size), None)?;
            g.feed(b.len())?;
            g.finish()?;
            std::fs::write(dest, &b).unwrap();
            Ok(hex::encode(Sha256::digest(&b)))
        }
    }

    fn panel_names() -> Vec<String> {
        panel_files_for("amd64")
    }

    #[tokio::test]
    async fn prepare_makes_no_request_without_a_configuration() {
        let api = FakeApi::fixture();
        let root = temp_dir();
        let names = panel_names();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let e = prepare_with(&api, None, &root, FIX_TAG, &refs).await.unwrap_err();
        assert_eq!(e, FetchError::NotConfigured);
        assert_eq!(api.count(), 0);
        assert!(!root.join(FIX_TAG).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn prepare_verifies_caches_and_extracts_a_release() {
        let api = FakeApi::fixture();
        let root = temp_dir();
        let key = test_key();
        let names = panel_names();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let p = prepare_with(&api, Some(("o/n", &key)), &root, FIX_TAG, &refs).await.unwrap();
        assert_eq!(p.dir, root.join(FIX_TAG));
        for n in &names {
            assert!(p.dir.join(n).exists(), "{n}");
        }
        assert!(update_script_path(&p.dir).exists(), "update.sh extracted");
        let leftovers: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(leftovers, vec![FIX_TAG.to_string()], "no partial directory left");
        let hidden = std::fs::read_dir(&p.dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
            .count();
        assert_eq!(hidden, 0, "no temporary file left");

        // Everything cached: a second preparation verifies from disk and makes
        // no request.
        let before = api.count();
        prepare_with(&api, Some(("o/n", &key)), &root, FIX_TAG, &refs).await.unwrap();
        assert_eq!(api.count(), before);

        // A cached file altered on disk is hashed again, dropped and fetched
        // afresh: what is served or installed always matches checksums.txt.
        let cached = p.dir.join(AGENT_AMD64);
        let good = std::fs::read(&cached).unwrap();
        std::fs::write(&cached, b"altered after the check\n").unwrap();
        // The extracted tree is replaced from the verified archive each time.
        std::fs::write(update_script_path(&p.dir), b"echo tampered\n").unwrap();
        prepare_with(&api, Some(("o/n", &key)), &root, FIX_TAG, &refs).await.unwrap();
        assert!(api.count() > before, "the altered file was downloaded again");
        assert_eq!(std::fs::read(&cached).unwrap(), good);
        assert_ne!(std::fs::read(update_script_path(&p.dir)).unwrap(), b"echo tampered\n".to_vec());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_source_listing_is_checked_before_extraction() {
        let ok_names = "cyberhunter-source/\ncyberhunter-source/scripts/\ncyberhunter-source/scripts/update.sh\n";
        let ok_verbose = "drwxr-xr-x root/root 0 2026-11-17 10:34 cyberhunter-source/\n\
                          drwxr-xr-x root/root 0 2026-11-17 10:34 cyberhunter-source/scripts/\n\
                          -rw-r--r-- root/root 43 2026-11-17 10:34 cyberhunter-source/scripts/update.sh\n";
        assert!(check_source_listing(ok_names, ok_verbose).is_ok());
        let one = |name: &str, kind: char| {
            check_source_listing(&format!("{name}\n"), &format!("{kind}rw-r--r-- root/root 1 d t {name}\n"))
        };
        assert!(one("cyberhunter-source/a", '-').is_ok());
        assert!(one("/etc/passwd", '-').is_err(), "absolute path");
        assert!(one("cyberhunter-source/../../etc/x", '-').is_err(), "dot-dot");
        assert!(one("other/a", '-').is_err(), "outside the prefix");
        for kind in ['l', 'h', 'c', 'b', 'p'] {
            assert!(one("cyberhunter-source/a", kind).is_err(), "type {kind}");
        }
        assert!(check_source_listing("", "").is_err(), "empty");
        assert!(check_source_listing(ok_names, "-rw-r--r-- x\n").is_err(), "listings differ");
    }

    #[tokio::test]
    async fn a_tampered_file_is_refused_and_not_kept() {
        let mut api = FakeApi::fixture();
        api.files.insert(AGENT_AMD64.into(), b"fake agent binary for testX\n".to_vec());
        let root = temp_dir();
        let key = test_key();
        let e = prepare_with(&api, Some(("o/n", &key)), &root, FIX_TAG, &[AGENT_AMD64])
            .await
            .unwrap_err();
        assert_eq!(e.code(), "checksum_failed");
        let dir = root.join(FIX_TAG);
        assert!(!dir.join(AGENT_AMD64).exists());
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().starts_with('.')).count(),
            0
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_release_without_signature_is_refused_and_nothing_is_cached() {
        let mut api = FakeApi::fixture();
        api.releases[0].assets.retain(|a| a.name != MINISIG_NAME);
        let root = temp_dir();
        let key = test_key();
        let e = prepare_with(&api, Some(("o/n", &key)), &root, FIX_TAG, &[]).await.unwrap_err();
        assert_eq!(e.code(), "signature_failed");
        assert!(!root.join(FIX_TAG).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn the_same_set_under_another_tag_is_refused() {
        let mut api = FakeApi::fixture();
        api.releases[0].tag_name = "v9.9.10".into();
        let root = temp_dir();
        let key = test_key();
        let e = prepare_with(&api, Some(("o/n", &key)), &root, "v9.9.10", &[]).await.unwrap_err();
        assert_eq!(e.code(), "signature_failed");
        assert!(!root.join("v9.9.10").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_missing_required_file_or_draft_is_refused() {
        let mut api = FakeApi::fixture();
        api.releases[0].assets.retain(|a| a.name != AGENT_AMD64);
        let root = temp_dir();
        let key = test_key();
        let e = prepare_with(&api, Some(("o/n", &key)), &root, FIX_TAG, &[AGENT_AMD64]).await.unwrap_err();
        assert_eq!(e.code(), "release_incomplete");
        let e = prepare_with(&api, Some(("o/n", &key)), &root, FIX_TAG, &[AGENT_ARM64]).await.unwrap_err();
        assert_eq!(e.code(), "release_incomplete", "not in the manifest");

        let mut api = FakeApi::fixture();
        api.releases[0].draft = true;
        let root2 = temp_dir();
        let e = prepare_with(&api, Some(("o/n", &key)), &root2, FIX_TAG, &[]).await.unwrap_err();
        assert_eq!(e.code(), "release_not_found");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&root2);
    }

    #[tokio::test]
    async fn retention_keeps_what_is_needed() {
        let root = temp_dir();
        for d in ["v1.0.0", "v2.0.0", "v3.0.0", ".partial-v4.0.0-x", "v2.0.0/.extract-y"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("v2.0.0/.a.part-z"), b"x").unwrap();
        std::fs::write(root.join("v2.0.0/checksums.txt"), b"x").unwrap();
        let keep: HashSet<String> = ["v2.0.0".to_string()].into();
        retain_only(&root, &keep, false);
        assert!(!root.join("v1.0.0").exists());
        assert!(root.join("v2.0.0").exists());
        assert!(root.join(".partial-v4.0.0-x").exists(), "hidden entries wait for start-up");
        assert!(root.join("v2.0.0/.a.part-z").exists());
        retain_only(&root, &keep, true);
        assert!(!root.join(".partial-v4.0.0-x").exists());
        assert!(!root.join("v2.0.0/.a.part-z").exists());
        assert!(!root.join("v2.0.0/.extract-y").exists());
        assert!(root.join("v2.0.0/checksums.txt").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── The token never leaks ──

    #[tokio::test]
    async fn a_failed_request_carrying_the_token_does_not_leak_it() {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let token = SecretToken::from_input(KNOWN_TOKEN);
        let headers = request_headers(0, Some(bearer_header(&token).unwrap()));
        let e = client
            .get("https://127.0.0.1:1/repos/o/n/releases?token-in-path=no")
            .headers(headers)
            .send()
            .await
            .unwrap_err();
        let fe = send_error("127.0.0.1", e);
        assert_eq!(fe.code(), "download_failed");
        for text in [fe.to_string(), format!("{fe:?}"), fe.log_line("update check")] {
            assert!(!text.contains(KNOWN_TOKEN), "{text}");
            assert!(!text.contains("github_pat_"), "{text}");
            assert!(!text.contains("token-in-path"), "no URL: {text}");
        }
        let h = bearer_header(&token).unwrap();
        assert!(!format!("{h:?}").contains(KNOWN_TOKEN), "sensitive header debug-prints redacted");
    }

    #[test]
    fn github_api_debug_free_and_auth_reads_from_file() {
        let dir = temp_dir();
        let p = dir.join("tok");
        assert_eq!(github_auth_header(&p).unwrap(), None, "no file: anonymous");
        std::fs::write(&p, format!("{KNOWN_TOKEN}\n")).unwrap();
        let h = github_auth_header(&p).unwrap().expect("a token file is always used");
        assert!(h.is_sensitive());
        assert_eq!(h.to_str().unwrap(), format!("Bearer {KNOWN_TOKEN}"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
