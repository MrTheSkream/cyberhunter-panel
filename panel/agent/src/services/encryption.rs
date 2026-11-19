//! Backup encryption: `openssl enc -aes-256-cbc -pbkdf2 -iter 100000`, then an
//! HMAC-SHA256 trailer (encrypt-then-MAC).
//!
//! # On-disk format (unchanged since the integrity fix)
//!
//! ```text
//! [ openssl output: "Salted__" | 8-byte salt | AES-256-CBC blocks ] [ 32-byte HMAC tag ] [ "DPHMAC01" ]
//! ```
//!
//! A file with no trailer is a legacy backup (made before the integrity fix):
//! it is still readable, unauthenticated, exactly as before.
//!
//! # Streaming
//!
//! Nothing here reads a whole file into memory. openssl reads its input and
//! writes its output itself; the HMAC is computed over the ciphertext in
//! 1 MiB chunks; decryption feeds openssl's stdin from the ciphertext part of
//! the file (everything before the trailer) through a pipe, so no stripped
//! copy is ever written. Memory use is a few MiB whatever the file size, and
//! transient disk use is one output file (written under a temporary name in
//! the destination directory, renamed on success, removed on failure).
//!
//! # Passphrase handling
//!
//! The passphrase never goes in argv nor in a child's environment:
//! - encryption: openssl reads the data from the source path (`-in`), so its
//!   stdin is free and carries the passphrase (`-pass stdin`), as before;
//! - decryption: stdin carries the ciphertext, so the passphrase goes through
//!   a dedicated pipe inherited by openssl only (`-pass fd:N`, N being the
//!   pipe's read end). openssl reads one line from either source the same way,
//!   so both derive the same AES key from the same passphrase.
//!
//! # Public API
//!
//! - [`encrypt_file`], [`decrypt_file`], [`verify_file`]: generic, any paths,
//!   the caller confines them;
//! - [`encrypt_backup`], [`decrypt_backup`]: the database-dump flavour,
//!   confined to `/var/backups/dockpanel/`, `x` <-> `x.enc`, plaintext removed
//!   after encryption.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::safe_cmd::safe_command;

type HmacSha256 = Hmac<Sha256>;

/// Validate that a filepath is within the allowed backup directory and contains no traversal.
fn validate_backup_path(filepath: &str) -> Result<(), String> {
    if !filepath.starts_with("/var/backups/dockpanel/") {
        return Err("Path must be within /var/backups/dockpanel/".to_string());
    }
    if filepath.contains("..") {
        return Err("Path must not contain '..'".to_string());
    }
    Ok(())
}

/// Appended after the ciphertext of every file this build encrypts: a
/// 32-byte HMAC-SHA256 tag over the ciphertext, followed by this 8-byte
/// marker. AES-256-CBC alone has no integrity check - PKCS7 padding bounds
/// only the final block, so a bit-flip anywhere earlier decrypts silently
/// into corrupted plaintext instead of failing. Encrypt-then-MAC catches
/// that: `decrypt_file` verifies the tag before it ever hands the
/// ciphertext to openssl.
///
/// A backup made before this fix has no trailer at all - its last 8 bytes
/// are AES output, not this marker, for all practical purposes (odds of a
/// collision are 1 in 2^64). `decrypt_file` treats that absence as "this
/// predates the integrity tag" and falls back to the old, unauthenticated
/// decrypt path so existing backups keep working.
const MAC_MAGIC: &[u8; 8] = b"DPHMAC01";
const MAC_TAG_LEN: usize = 32;
const MAC_TRAILER_LEN: usize = MAC_TAG_LEN + 8;

/// openssl's salted header: `Salted__` + 8 bytes of salt.
const OPENSSL_HEADER: &[u8; 8] = b"Salted__";
const OPENSSL_HEADER_LEN: u64 = 16;
const AES_BLOCK: u64 = 16;

/// Read/hash/copy granularity: memory use does not depend on the file size.
const CHUNK: usize = 1 << 20;

/// openssl reads at most one line of passphrase; anything this long is a
/// caller bug, and it must fit in the pipe buffer since it is written
/// before openssl is spawned.
const MAX_PASSPHRASE_LEN: usize = 1024;

/// Derive a MAC key from the backup passphrase, independent of the AES key
/// `openssl -pbkdf2` derives internally from that same passphrase (a value
/// this process never sees). Domain-separated by a fixed label so the tag
/// can't be turned into an oracle against the encryption key.
fn derive_mac_key(passphrase: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(passphrase.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(b"dockpanel-backup-hmac-v1");
    mac.finalize().into_bytes().to_vec()
}

fn new_mac(passphrase: &str) -> HmacSha256 {
    let key = derive_mac_key(passphrase);
    HmacSha256::new_from_slice(&key).expect("HMAC accepts a key of any length")
}

/// Feed exactly `len` bytes of `reader` into `mac`, 1 MiB at a time. A reader
/// that ends early is an error (the file shrank under us).
async fn feed_mac<R: AsyncRead + Unpin>(
    mac: &mut HmacSha256,
    mut reader: R,
    len: u64,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; CHUNK];
    let mut left = len;
    while left > 0 {
        let want = left.min(CHUNK as u64) as usize;
        let n = reader.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "file is shorter than expected",
            ));
        }
        mac.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(())
}

/// HMAC tag over the first `len` bytes of `reader`, streamed.
async fn compute_tag<R: AsyncRead + Unpin>(
    passphrase: &str,
    reader: R,
    len: u64,
) -> std::io::Result<[u8; MAC_TAG_LEN]> {
    let mut mac = new_mac(passphrase);
    feed_mac(&mut mac, reader, len).await?;
    let mut tag = [0u8; MAC_TAG_LEN];
    tag.copy_from_slice(&mac.finalize().into_bytes());
    Ok(tag)
}

/// Constant-time verification (via `hmac`'s own `verify_slice`) of `tag`
/// against the first `len` bytes of `reader`, streamed.
async fn verify_tag<R: AsyncRead + Unpin>(
    passphrase: &str,
    reader: R,
    len: u64,
    tag: &[u8],
) -> std::io::Result<bool> {
    let mut mac = new_mac(passphrase);
    feed_mac(&mut mac, reader, len).await?;
    Ok(mac.verify_slice(tag).is_ok())
}

/// Time budget for one encrypt/decrypt/verify of a file of `bytes` bytes:
/// 600 s, plus 300 s per started GiB, capped at 6 hours. Generous on
/// purpose (AES + HMAC run far faster than that on any disk); it exists to
/// bound a stuck openssl, not to race a slow one.
pub fn operation_timeout(bytes: u64) -> Duration {
    const BASE_SECS: u64 = 600;
    const PER_GIB_SECS: u64 = 300;
    const MAX_SECS: u64 = 6 * 3600;
    let gib = bytes.div_ceil(1 << 30);
    Duration::from_secs(BASE_SECS.saturating_add(gib.saturating_mul(PER_GIB_SECS)).min(MAX_SECS))
}

fn timeout_error(what: &str, bytes: u64) -> String {
    format!("{what} timed out after {} seconds", operation_timeout(bytes).as_secs())
}

/// Result of [`verify_file`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagStatus {
    /// The file carries an integrity tag and it matches the passphrase.
    Verified,
    /// The file has no integrity tag (encrypted before the integrity fix):
    /// nothing can be verified without decrypting it.
    Legacy,
}

/// Where the ciphertext ends and what trailer, if any, follows it.
struct Layout {
    /// Bytes handed to openssl (the whole file minus the trailer).
    ct_len: u64,
    tag: Option<[u8; MAC_TAG_LEN]>,
}

/// Inspect an encrypted file: openssl header, optional trailer, block
/// alignment. Reads 56 bytes at most. Rejects most truncations of either
/// format outright, since a cut almost never lands on a cipher block boundary.
async fn read_layout(f: &mut tokio::fs::File) -> Result<Layout, String> {
    let len = f
        .metadata()
        .await
        .map_err(|e| format!("Failed to read encrypted file: {e}"))?
        .len();
    let mut header = [0u8; 8];
    if len < OPENSSL_HEADER_LEN + AES_BLOCK {
        return Err("Encrypted backup is truncated or not an encrypted backup".to_string());
    }
    f.read_exact(&mut header)
        .await
        .map_err(|e| format!("Failed to read encrypted file: {e}"))?;
    if &header != OPENSSL_HEADER {
        return Err("Not an encrypted backup (missing OpenSSL salt header)".to_string());
    }

    let mut tag = None;
    if len >= OPENSSL_HEADER_LEN + AES_BLOCK + MAC_TRAILER_LEN as u64 {
        let mut trailer = [0u8; MAC_TRAILER_LEN];
        f.seek(std::io::SeekFrom::Start(len - MAC_TRAILER_LEN as u64))
            .await
            .map_err(|e| format!("Failed to read encrypted file: {e}"))?;
        f.read_exact(&mut trailer)
            .await
            .map_err(|e| format!("Failed to read encrypted file: {e}"))?;
        if &trailer[MAC_TAG_LEN..] == MAC_MAGIC.as_slice() {
            let mut t = [0u8; MAC_TAG_LEN];
            t.copy_from_slice(&trailer[..MAC_TAG_LEN]);
            tag = Some(t);
        }
    }
    let ct_len = if tag.is_some() { len - MAC_TRAILER_LEN as u64 } else { len };
    if ct_len % AES_BLOCK != 0 {
        return Err(
            "Encrypted backup is truncated or corrupted (not a whole number of cipher blocks)"
                .to_string(),
        );
    }
    f.seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(|e| format!("Failed to read encrypted file: {e}"))?;
    Ok(Layout { ct_len, tag })
}

/// An output file under a temporary name next to its destination: removed on
/// drop unless [`TempFile::persist`] renamed it into place. Created 0600 with
/// `create_new`, so it never clobbers anything and is never world-readable.
struct TempFile {
    path: PathBuf,
    armed: bool,
}

impl TempFile {
    fn create(dst: &Path) -> Result<(Self, std::fs::File), String> {
        let dir = match dst.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let name = dst
            .file_name()
            .ok_or_else(|| format!("Invalid destination path: {}", dst.display()))?
            .to_string_lossy();
        let path = dir.join(format!(".{name}.{:016x}.part", rand::random::<u64>()));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("Failed to create temporary file in {}: {e}", dir.display()))?;
        Ok((TempFile { path, armed: true }, file))
    }

    /// fsync, then rename into place. The temp file is kept for `Drop` to
    /// remove if either step fails.
    async fn persist(mut self, dst: &Path) -> Result<(), String> {
        let f = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .await
            .map_err(|e| format!("Failed to flush {}: {e}", dst.display()))?;
        f.sync_all()
            .await
            .map_err(|e| format!("Failed to flush {}: {e}", dst.display()))?;
        drop(f);
        tokio::fs::rename(&self.path, dst)
            .await
            .map_err(|e| format!("Failed to move output into place at {}: {e}", dst.display()))?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.armed {
            if let Err(e) = std::fs::remove_file(&self.path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::error!("Failed to remove temporary file {}: {e}", self.path.display());
                }
            }
        }
    }
}

/// A pipe holding the passphrase, for `openssl -pass fd:N`. Both ends are
/// created close-on-exec; the passphrase is written (no trailing newline,
/// like the former `-pass stdin`) and the write end closed before openssl is
/// spawned, so openssl sees EOF and no other child can inherit either end.
/// Returns the read end; [`inherit_fd`] makes it, and only it, survive exec.
fn passphrase_pipe(passphrase: &str) -> Result<OwnedFd, String> {
    use std::io::Write as _;
    if passphrase.len() > MAX_PASSPHRASE_LEN {
        return Err("Encryption key is too long".to_string());
    }
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid 2-element buffer for pipe2 to fill.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!(
            "Failed to create passphrase pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: pipe2 succeeded, both descriptors are fresh and owned here.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let mut write = unsafe { std::fs::File::from_raw_fd(fds[1]) };
    write
        .write_all(passphrase.as_bytes())
        .map_err(|e| format!("Failed to write passphrase pipe: {e}"))?;
    drop(write);
    Ok(read)
}

/// Clear close-on-exec on `fd` in the child only, between fork and exec.
/// The fd keeps its own number (no dup2 onto a fixed slot, which could
/// clobber a descriptor the spawn machinery itself uses).
fn inherit_fd(cmd: &mut tokio::process::Command, fd: &OwnedFd) {
    let raw = fd.as_raw_fd();
    // SAFETY: the closure only calls fcntl, which is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            let flags = libc::fcntl(raw, libc::F_GETFD);
            if flags < 0 || libc::fcntl(raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Copy exactly `len` bytes of `src` into openssl's stdin, 1 MiB at a time,
/// hashing them on the way when `recheck` holds the expected tag. Returns
/// whether the bytes actually streamed match that tag (always true when there
/// is no tag) - this closes the window between the up-front verification and
/// the decryption, should the file be swapped or modified in between.
async fn feed_ciphertext(
    mut src: tokio::fs::File,
    mut stdin: tokio::process::ChildStdin,
    len: u64,
    mut recheck: Option<(HmacSha256, [u8; MAC_TAG_LEN])>,
) -> std::io::Result<bool> {
    let mut buf = vec![0u8; CHUNK];
    let mut left = len;
    while left > 0 {
        let want = left.min(CHUNK as u64) as usize;
        let n = src.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "encrypted file shrank during decryption",
            ));
        }
        if let Some((mac, _)) = recheck.as_mut() {
            mac.update(&buf[..n]);
        }
        stdin.write_all(&buf[..n]).await?;
        left -= n as u64;
    }
    stdin.shutdown().await?;
    drop(stdin);
    Ok(match recheck {
        Some((mac, tag)) => mac.verify_slice(&tag).is_ok(),
        None => true,
    })
}

/// Encrypt `src` into `dst` (AES-256-CBC, PBKDF2 100000 iterations, via
/// openssl), then append the HMAC-SHA256 integrity trailer. Streams: memory
/// use does not depend on the file size.
///
/// `dst` is written under a temporary name in its own directory (mode 0600)
/// and renamed on success; on any failure nothing is left at `dst` or in its
/// directory. An existing `dst` is replaced. `src` is left untouched (see
/// [`encrypt_backup`] for the variant that removes the plaintext). Paths are
/// NOT confined here: the caller validates them. Returns the size of `dst`.
pub async fn encrypt_file(src: &Path, dst: &Path, passphrase: &str) -> Result<u64, String> {
    if passphrase.is_empty() {
        return Err("Encryption key must not be empty".to_string());
    }
    if passphrase.len() > MAX_PASSPHRASE_LEN {
        return Err("Encryption key is too long".to_string());
    }
    if src == dst {
        return Err("Source and destination must differ".to_string());
    }
    let src_meta = tokio::fs::metadata(src)
        .await
        .map_err(|_| format!("File not found: {}", src.display()))?;
    if !src_meta.is_file() {
        return Err(format!("Not a regular file: {}", src.display()));
    }
    let deadline = tokio::time::Instant::now() + operation_timeout(src_meta.len());

    let (tmp, out_file) = TempFile::create(dst)?;

    // openssl reads the data from `-in` itself; the key goes via stdin so it
    // never shows in the process listing.
    let mut child = safe_command("openssl")
        .args(["enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", "100000", "-in"])
        .arg(src)
        .args(["-pass", "stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("Failed to run openssl: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(passphrase.as_bytes())
            .await
            .map_err(|e| format!("Failed to write key to openssl stdin: {e}"))?;
        drop(stdin);
    }

    let output = tokio::time::timeout_at(deadline, child.wait_with_output())
        .await
        .map_err(|_| timeout_error("Encryption", src_meta.len()))?
        .map_err(|e| format!("Failed to run openssl: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Encryption failed: {}", stderr.trim()));
    }

    let mut reader = tokio::fs::File::open(&tmp.path)
        .await
        .map_err(|e| format!("Failed to read encrypted file: {e}"))?;
    let ct_len = reader
        .metadata()
        .await
        .map_err(|e| format!("Failed to read encrypted file: {e}"))?
        .len();
    if ct_len == 0 {
        return Err("Encryption produced empty output".to_string());
    }

    // Integrity tag over the ciphertext exactly as openssl wrote it, streamed
    // in 1 MiB chunks, so verification needs nothing but the passphrase.
    let tag = tokio::time::timeout_at(deadline, compute_tag(passphrase, &mut reader, ct_len))
        .await
        .map_err(|_| timeout_error("Encryption", src_meta.len()))?
        .map_err(|e| format!("Failed to read encrypted file: {e}"))?;
    drop(reader);

    let mut trailer = [0u8; MAC_TRAILER_LEN];
    trailer[..MAC_TAG_LEN].copy_from_slice(&tag);
    trailer[MAC_TAG_LEN..].copy_from_slice(MAC_MAGIC);
    let mut f = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&tmp.path)
        .await
        .map_err(|e| format!("Failed to open encrypted file to append integrity tag: {e}"))?;
    f.write_all(&trailer)
        .await
        .map_err(|e| format!("Failed to write integrity tag: {e}"))?;
    f.flush()
        .await
        .map_err(|e| format!("Failed to write integrity tag: {e}"))?;
    drop(f);

    tmp.persist(dst).await?;
    Ok(ct_len + MAC_TRAILER_LEN as u64)
}

/// Decrypt `src` (either format) into `dst`. Returns the size of `dst`.
///
/// A tagged file is verified first, streamed, and rejected with no output at
/// all if the tag does not match (wrong passphrase, bit flip, splice, tail
/// cut through the trailer). Only then is openssl fed the ciphertext part
/// through a pipe; the bytes are hashed again as they stream, and a mismatch
/// (file changed in between) fails the call. A legacy file (no trailer) is
/// decrypted unauthenticated, as before, with a warning in the log.
///
/// The plaintext is written to a 0600 temporary file in `dst`'s directory and
/// renamed to `dst` only on success: on any failure (integrity, wrong
/// passphrase, truncation, openssl error, timeout) neither `dst` nor a
/// temporary file is left behind. An existing `dst` is replaced on success.
/// Paths are NOT confined here: the caller validates them.
pub async fn decrypt_file(src: &Path, dst: &Path, passphrase: &str) -> Result<u64, String> {
    if passphrase.is_empty() {
        return Err("Encryption key must not be empty".to_string());
    }
    if src == dst {
        return Err("Source and destination must differ".to_string());
    }
    let mut f = tokio::fs::File::open(src)
        .await
        .map_err(|_| format!("File not found: {}", src.display()))?;
    let layout = read_layout(&mut f).await?;
    let total_len = layout.ct_len + if layout.tag.is_some() { MAC_TRAILER_LEN as u64 } else { 0 };
    let deadline = tokio::time::Instant::now() + operation_timeout(total_len);

    let has_tag = layout.tag.is_some();
    let recheck = if has_tag {
        let tag = layout.tag.expect("has_tag");
        // Verify-then-decrypt: a tampered or corrupted ciphertext never
        // reaches openssl.
        let ok = tokio::time::timeout_at(
            deadline,
            verify_tag(passphrase, &mut f, layout.ct_len, &tag),
        )
        .await
        .map_err(|_| timeout_error("Integrity check", total_len))?
        .map_err(|e| format!("Failed to read encrypted file: {e}"))?;
        if !ok {
            return Err(
                "Backup integrity check failed - the file may be corrupted or tampered with"
                    .to_string(),
            );
        }
        f.seek(std::io::SeekFrom::Start(0))
            .await
            .map_err(|e| format!("Failed to read encrypted file: {e}"))?;
        Some((new_mac(passphrase), tag))
    } else {
        tracing::warn!(
            "Decrypting {} without an integrity tag (backup predates the integrity \
             fix) - cannot verify it wasn't tampered with",
            src.display()
        );
        None
    };

    let (tmp, out_file) = TempFile::create(dst)?;

    // stdin carries the ciphertext, so the key goes through its own pipe
    // (`-pass fd:N`): never in argv, never in the environment.
    let pass_fd = passphrase_pipe(passphrase)?;
    let pass_arg = format!("fd:{}", pass_fd.as_raw_fd());
    let mut cmd = safe_command("openssl");
    cmd.args(["enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "100000", "-pass", &pass_arg])
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    inherit_fd(&mut cmd, &pass_fd);
    let mut child = cmd.spawn().map_err(|e| format!("Failed to run openssl: {e}"))?;
    drop(pass_fd);

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| "Failed to open openssl stdin".to_string())?;
    let feed = feed_ciphertext(f, stdin, layout.ct_len, recheck);
    let (fed, output) = tokio::time::timeout_at(deadline, async {
        tokio::join!(feed, child.wait_with_output())
    })
    .await
    .map_err(|_| timeout_error("Decryption", total_len))?;
    let output = output.map_err(|e| format!("Failed to run openssl: {e}"))?;

    // openssl's own verdict first: when it bails out early (wrong key on a
    // legacy file, bad padding), the feeder only saw a broken pipe.
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Decryption failed: {}", stderr.trim()));
    }
    match fed {
        Ok(true) => {}
        Ok(false) => {
            return Err(
                "Backup integrity check failed - the file changed during decryption".to_string(),
            )
        }
        Err(e) => return Err(format!("Failed to stream ciphertext to openssl: {e}")),
    }

    let out_len = tokio::fs::metadata(&tmp.path)
        .await
        .map_err(|e| format!("Failed to read decrypted file: {e}"))?
        .len();
    if out_len == 0 {
        return Err("Decryption produced empty output".to_string());
    }
    tmp.persist(dst).await?;
    Ok(out_len)
}

/// Check an encrypted file's integrity without decrypting it (streamed).
/// `Ok(Verified)`: tag present and valid for this passphrase.
/// `Ok(Legacy)`: no tag, nothing to check short of decrypting.
/// `Err`: not an encrypted backup, truncated, or tag mismatch.
pub async fn verify_file(src: &Path, passphrase: &str) -> Result<TagStatus, String> {
    let mut f = tokio::fs::File::open(src)
        .await
        .map_err(|_| format!("File not found: {}", src.display()))?;
    let layout = read_layout(&mut f).await?;
    let Some(tag) = layout.tag else {
        return Ok(TagStatus::Legacy);
    };
    let total_len = layout.ct_len + MAC_TRAILER_LEN as u64;
    let ok = tokio::time::timeout(
        operation_timeout(total_len),
        verify_tag(passphrase, &mut f, layout.ct_len, &tag),
    )
    .await
    .map_err(|_| timeout_error("Integrity check", total_len))?
    .map_err(|e| format!("Failed to read encrypted file: {e}"))?;
    if ok {
        Ok(TagStatus::Verified)
    } else {
        Err("Backup integrity check failed - the file may be corrupted or tampered with".to_string())
    }
}

/// Whether an error returned by this module is the FILE's fault (corrupt,
/// truncated, tampered with, not an encrypted backup, or the wrong passphrase)
/// rather than the host's (I/O, openssl missing, timeout). Callers answer the
/// first with 422 and the second with 500: the panel only relays a 4xx
/// sentence to the operator, and "the passphrase does not match" is the one
/// thing they need to read.
///
/// Keyed on the exact message prefixes this module produces; the tests below
/// run each failure for real and assert it is classified.
pub fn is_content_error(msg: &str) -> bool {
    const CONTENT: [&str; 6] = [
        "Backup integrity check failed",
        "Decryption failed",
        "Decryption produced empty output",
        "Encrypted backup is truncated",
        "Not an encrypted backup",
        "Encryption key must not be empty",
    ];
    CONTENT.iter().any(|p| msg.starts_with(p))
}

/// Database-dump flavour: encrypt `filepath` (confined to
/// `/var/backups/dockpanel/`) into `{filepath}.enc`, then remove the
/// plaintext. Returns the encrypted path.
pub async fn encrypt_backup(filepath: &str, key: &str) -> Result<String, String> {
    validate_backup_path(filepath)?;
    let enc_path = format!("{filepath}.enc");
    let size = encrypt_file(Path::new(filepath), Path::new(&enc_path), key).await?;

    // Remove the unencrypted original.
    if let Err(e) = std::fs::remove_file(filepath) {
        tracing::warn!("Encrypted {enc_path} but failed to remove the plaintext {filepath}: {e}");
    }
    tracing::info!("File encrypted: {enc_path} ({size} bytes)");
    Ok(enc_path)
}

/// Database-dump flavour: decrypt `enc_filepath` (confined to
/// `/var/backups/dockpanel/`) into the same path without `.enc` (or with
/// `.dec` appended when there is no `.enc`). Returns the decrypted path; the
/// caller removes it once done.
pub async fn decrypt_backup(enc_filepath: &str, key: &str) -> Result<String, String> {
    validate_backup_path(enc_filepath)?;
    let dec_path = match enc_filepath.strip_suffix(".enc") {
        Some(stem) => stem.to_string(),
        None => format!("{enc_filepath}.dec"),
    };
    let size = decrypt_file(Path::new(enc_filepath), Path::new(&dec_path), key).await?;
    tracing::info!("File decrypted: {dec_path} ({size} bytes)");
    Ok(dec_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only passphrase, the one the committed fixtures were made with.
    const FIXTURE_PASS: &str = "fixture-test-passphrase-not-a-secret";
    const FIXTURE_PLAIN: &[u8] = include_bytes!("../../tests/fixtures/encryption/plain.txt");
    /// Written by the pre-streaming `encrypt_file` (tag + DPHMAC01 trailer).
    const FIXTURE_CURRENT: &[u8] =
        include_bytes!("../../tests/fixtures/encryption/current.sql.enc");
    /// openssl output with no trailer: the format from before the integrity fix.
    const FIXTURE_LEGACY: &[u8] =
        include_bytes!("../../tests/fixtures/encryption/legacy.sql.enc");

    /// A unique scratch directory, removed on drop.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("dp-enc-test-{:016x}", rand::random::<u64>()));
            std::fs::create_dir_all(&p).unwrap();
            Scratch(p)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
        /// Everything in the directory, sorted.
        fn entries(&self) -> Vec<String> {
            let mut v: Vec<String> = std::fs::read_dir(&self.0)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn slice_tag(pass: &str, data: &[u8]) -> Vec<u8> {
        let mut mac = new_mac(pass);
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Streaming sha256 of a file, so the big test never holds it in memory twice.
    fn file_sha256(p: &Path) -> Vec<u8> {
        use sha2::Digest;
        use std::io::Read;
        let mut f = std::fs::File::open(p).unwrap();
        let mut h = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = f.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        h.finalize().to_vec()
    }

    #[tokio::test]
    async fn tag_round_trips() {
        let data = b"some ciphertext bytes";
        let tag = compute_tag("correct horse battery staple", &data[..], data.len() as u64)
            .await
            .unwrap();
        assert!(verify_tag("correct horse battery staple", &data[..], data.len() as u64, &tag)
            .await
            .unwrap());
        // Same construction as before streaming: HMAC over the whole slice.
        assert_eq!(tag.to_vec(), slice_tag("correct horse battery staple", data));
    }

    #[tokio::test]
    async fn tag_rejects_wrong_key() {
        let data = b"some ciphertext bytes";
        let tag = compute_tag("key-a", &data[..], data.len() as u64).await.unwrap();
        assert!(!verify_tag("key-b", &data[..], data.len() as u64, &tag).await.unwrap());
    }

    #[tokio::test]
    async fn tag_rejects_tampered_ciphertext() {
        let tag = compute_tag("key", &b"some ciphertext bytes"[..], 21).await.unwrap();
        assert!(!verify_tag("key", &b"some tampered!! bytes"[..], 21, &tag).await.unwrap());
    }

    #[tokio::test]
    async fn tag_rejects_truncated_ciphertext() {
        let tag = compute_tag("key", &b"some ciphertext bytes"[..], 21).await.unwrap();
        assert!(!verify_tag("key", &b"some ciphertext"[..], 15, &tag).await.unwrap());
        // And a reader shorter than announced is an error, not a short hash.
        assert!(verify_tag("key", &b"some ciphertext"[..], 21, &tag).await.is_err());
    }

    #[tokio::test]
    async fn tag_streams_across_chunks() {
        // > 2 chunks, not chunk-aligned: chunking must not change the tag.
        let data: Vec<u8> = (0..(2 * CHUNK + 12345)).map(|i| (i * 31 % 251) as u8).collect();
        let tag = compute_tag("k", &data[..], data.len() as u64).await.unwrap();
        assert_eq!(tag.to_vec(), slice_tag("k", &data));
    }

    #[test]
    fn mac_key_is_independent_per_passphrase() {
        assert_ne!(derive_mac_key("key-a"), derive_mac_key("key-b"));
    }

    #[test]
    fn timeout_grows_with_size_and_is_bounded() {
        assert_eq!(operation_timeout(0), Duration::from_secs(600));
        assert_eq!(operation_timeout(1), Duration::from_secs(900));
        assert_eq!(operation_timeout(1 << 30), Duration::from_secs(900));
        assert_eq!(operation_timeout((1 << 30) + 1), Duration::from_secs(1200));
        assert_eq!(operation_timeout(10 << 30), Duration::from_secs(3600));
        assert_eq!(operation_timeout(u64::MAX), Duration::from_secs(6 * 3600));
    }

    #[test]
    fn backup_wrappers_stay_confined() {
        assert!(validate_backup_path("/etc/passwd").is_err());
        assert!(validate_backup_path("/var/backups/dockpanel/../x").is_err());
        assert!(validate_backup_path("/var/backups/dockpanel/db/x.sql.gz").is_ok());
    }

    #[tokio::test]
    async fn fixture_current_format_decrypts_identically() {
        let s = Scratch::new();
        let src = s.path("current.sql.enc");
        std::fs::write(&src, FIXTURE_CURRENT).unwrap();
        assert_eq!(verify_file(&src, FIXTURE_PASS).await.unwrap(), TagStatus::Verified);
        let dst = s.path("current.sql");
        let n = decrypt_file(&src, &dst, FIXTURE_PASS).await.unwrap();
        assert_eq!(n as usize, FIXTURE_PLAIN.len());
        assert_eq!(std::fs::read(&dst).unwrap(), FIXTURE_PLAIN);
        assert_eq!(s.entries(), vec!["current.sql", "current.sql.enc"]);
    }

    #[tokio::test]
    async fn fixture_legacy_format_decrypts_identically() {
        let s = Scratch::new();
        let src = s.path("legacy.sql.enc");
        std::fs::write(&src, FIXTURE_LEGACY).unwrap();
        assert_eq!(verify_file(&src, FIXTURE_PASS).await.unwrap(), TagStatus::Legacy);
        let dst = s.path("legacy.sql");
        decrypt_file(&src, &dst, FIXTURE_PASS).await.unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), FIXTURE_PLAIN);
        assert_eq!(s.entries(), vec!["legacy.sql", "legacy.sql.enc"]);
    }

    /// The new writer produces exactly the old format: openssl ciphertext,
    /// then HMAC(ciphertext) and the marker. Stripping the trailer and running
    /// the former decrypt command (`-pass stdin`) gives back the plaintext.
    #[tokio::test]
    async fn new_output_is_the_old_format() {
        let s = Scratch::new();
        let src = s.path("plain.txt");
        std::fs::write(&src, FIXTURE_PLAIN).unwrap();
        let enc = s.path("plain.txt.enc");
        let size = encrypt_file(&src, &enc, FIXTURE_PASS).await.unwrap();
        let raw = std::fs::read(&enc).unwrap();
        assert_eq!(size as usize, raw.len());
        assert_eq!(&raw[..8], OPENSSL_HEADER);
        assert_eq!(&raw[raw.len() - 8..], MAC_MAGIC);
        let split = raw.len() - MAC_TRAILER_LEN;
        assert_eq!(raw[split..split + MAC_TAG_LEN].to_vec(), slice_tag(FIXTURE_PASS, &raw[..split]));
        // The plaintext stays: removing it is encrypt_backup's job.
        assert!(src.exists());

        let stripped = s.path("stripped");
        std::fs::write(&stripped, &raw[..split]).unwrap();
        let out = s.path("out");
        let mut child = std::process::Command::new("openssl")
            .args(["enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "100000", "-in"])
            .arg(&stripped)
            .arg("-out")
            .arg(&out)
            .args(["-pass", "stdin"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write as _;
            child.stdin.take().unwrap().write_all(FIXTURE_PASS.as_bytes()).unwrap();
        }
        assert!(child.wait().unwrap().success());
        assert_eq!(std::fs::read(&out).unwrap(), FIXTURE_PLAIN);
    }

    #[tokio::test]
    async fn round_trip_50_mib_and_bit_flip_rejected() {
        let s = Scratch::new();
        let src = s.path("big.bin");
        {
            use std::io::Write as _;
            let mut w = std::io::BufWriter::new(std::fs::File::create(&src).unwrap());
            let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
            let mut buf = vec![0u8; CHUNK];
            for _ in 0..50 {
                for b in buf.chunks_mut(8) {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    b.copy_from_slice(&x.to_le_bytes());
                }
                w.write_all(&buf).unwrap();
            }
            // Not block-aligned on purpose.
            w.write_all(b"tail").unwrap();
        }
        let enc = s.path("big.bin.enc");
        encrypt_file(&src, &enc, FIXTURE_PASS).await.unwrap();
        assert_eq!(verify_file(&enc, FIXTURE_PASS).await.unwrap(), TagStatus::Verified);

        let dst = s.path("big.out");
        let n = decrypt_file(&enc, &dst, FIXTURE_PASS).await.unwrap();
        assert_eq!(n, 50 * CHUNK as u64 + 4);
        assert_eq!(file_sha256(&dst), file_sha256(&src));
        std::fs::remove_file(&dst).unwrap();

        // Flip one bit in the middle of the ciphertext.
        {
            use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
            let mut f = std::fs::OpenOptions::new().read(true).write(true).open(&enc).unwrap();
            let pos = 25 * CHUNK as u64 + 7;
            let mut b = [0u8; 1];
            f.seek(SeekFrom::Start(pos)).unwrap();
            f.read_exact(&mut b).unwrap();
            b[0] ^= 0x01;
            f.seek(SeekFrom::Start(pos)).unwrap();
            f.write_all(&b).unwrap();
        }
        let err = decrypt_file(&enc, &dst, FIXTURE_PASS).await.unwrap_err();
        assert!(err.contains("integrity check failed"), "{err}");
        assert!(verify_file(&enc, FIXTURE_PASS).await.is_err());
        // No plaintext and no temporary file left behind.
        assert_eq!(s.entries(), vec!["big.bin", "big.bin.enc"]);
    }

    #[tokio::test]
    async fn wrong_passphrase_rejected_without_output() {
        let s = Scratch::new();
        for (name, bytes) in [("current.enc", FIXTURE_CURRENT), ("legacy.enc", FIXTURE_LEGACY)] {
            let src = s.path(name);
            std::fs::write(&src, bytes).unwrap();
            let err = decrypt_file(&src, &s.path("out"), "not-the-passphrase").await.unwrap_err();
            assert!(!err.is_empty());
            std::fs::remove_file(&src).unwrap();
            assert!(s.entries().is_empty(), "{name}: left {:?}", s.entries());
        }
        // The tagged file is rejected by the tag itself, before openssl.
        let src = s.path("current.enc");
        std::fs::write(&src, FIXTURE_CURRENT).unwrap();
        let err = decrypt_file(&src, &s.path("out"), "not-the-passphrase").await.unwrap_err();
        assert!(err.contains("integrity check failed"), "{err}");
    }

    #[tokio::test]
    async fn truncation_and_splice_rejected_without_output() {
        let s = Scratch::new();
        let len = FIXTURE_CURRENT.len();
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("cut-1", FIXTURE_CURRENT[..len - 1].to_vec()),
            ("cut-20", FIXTURE_CURRENT[..len - 20].to_vec()),
            ("cut-half", FIXTURE_CURRENT[..len / 2 + 3].to_vec()),
            ("cut-to-header", FIXTURE_CURRENT[..20].to_vec()),
            ("legacy-cut-1", FIXTURE_LEGACY[..FIXTURE_LEGACY.len() - 1].to_vec()),
        ];
        // Splice: drop one cipher block from the middle, keep the trailer.
        let mut spliced = FIXTURE_CURRENT[..160].to_vec();
        spliced.extend_from_slice(&FIXTURE_CURRENT[176..]);
        cases.push(("splice", spliced));
        for (name, bytes) in cases {
            let src = s.path(name);
            std::fs::write(&src, &bytes).unwrap();
            let r = decrypt_file(&src, &s.path("out"), FIXTURE_PASS).await;
            assert!(r.is_err(), "{name} was accepted");
            std::fs::remove_file(&src).unwrap();
            assert!(s.entries().is_empty(), "{name}: left {:?}", s.entries());
        }
    }

    /// The database-dump flavour the route calls: `x` -> `x.enc` with the
    /// plaintext removed, then `x.enc` -> `x`. Needs /var/backups/dockpanel
    /// writable (root, as in the build container); says so when it is not.
    #[tokio::test]
    async fn backup_wrappers_round_trip_in_place() {
        let dir = PathBuf::from(format!(
            "/var/backups/dockpanel/enc-test-{:016x}",
            rand::random::<u64>()
        ));
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("SKIPPED backup_wrappers_round_trip_in_place: cannot create {}: {e}", dir.display());
            return;
        }
        let s = Scratch(dir);
        let plain = s.path("db-20261119-120000.sql.gz");
        std::fs::write(&plain, FIXTURE_PLAIN).unwrap();
        let plain_str = plain.to_str().unwrap().to_string();
        let enc = encrypt_backup(&plain_str, FIXTURE_PASS).await.unwrap();
        assert_eq!(enc, format!("{plain_str}.enc"));
        assert_eq!(s.entries(), vec!["db-20261119-120000.sql.gz.enc"]);
        let dec = decrypt_backup(&enc, FIXTURE_PASS).await.unwrap();
        assert_eq!(dec, plain_str);
        assert_eq!(std::fs::read(&dec).unwrap(), FIXTURE_PLAIN);
    }

    #[tokio::test]
    async fn missing_source_and_same_path_rejected() {
        let s = Scratch::new();
        let missing = s.path("missing.enc");
        assert!(decrypt_file(&missing, &s.path("out"), FIXTURE_PASS).await.is_err());
        assert!(encrypt_file(&missing, &s.path("out"), FIXTURE_PASS).await.is_err());
        let p = s.path("same");
        std::fs::write(&p, b"x").unwrap();
        assert!(encrypt_file(&p, &p, FIXTURE_PASS).await.is_err());
        assert!(encrypt_file(&p, &s.path("o"), "").await.is_err());
        assert_eq!(s.entries(), vec!["same"]);
    }
    /// Every way the FILE can be wrong is classified as a content error (the
    /// routes answer 422), and a host-side failure is not.
    #[tokio::test]
    async fn content_errors_are_classified() {
        let s = Scratch::new();
        let mut cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("wrong-key-tagged", FIXTURE_CURRENT.to_vec(), "not-the-passphrase"),
            ("wrong-key-legacy", FIXTURE_LEGACY.to_vec(), "not-the-passphrase"),
            ("cut", FIXTURE_CURRENT[..FIXTURE_CURRENT.len() - 1].to_vec(), FIXTURE_PASS),
            ("header-only", FIXTURE_CURRENT[..20].to_vec(), FIXTURE_PASS),
            ("not-encrypted", FIXTURE_PLAIN.to_vec(), FIXTURE_PASS),
            ("empty-key", FIXTURE_CURRENT.to_vec(), ""),
        ];
        let mut flipped = FIXTURE_CURRENT.to_vec();
        flipped[40] ^= 0x01;
        cases.push(("flipped", flipped, FIXTURE_PASS));
        for (name, bytes, pass) in cases {
            let src = s.path(name);
            std::fs::write(&src, &bytes).unwrap();
            let err = decrypt_file(&src, &s.path("out"), pass).await.unwrap_err();
            assert!(is_content_error(&err), "{name}: {err}");
            if pass != "" && name != "wrong-key-legacy" {
                let v = verify_file(&src, pass).await;
                if let Err(e) = v {
                    assert!(is_content_error(&e), "{name} (verify): {e}");
                }
            }
        }
        let missing = decrypt_file(&s.path("missing"), &s.path("out"), FIXTURE_PASS).await.unwrap_err();
        assert!(!is_content_error(&missing), "{missing}");
        assert!(!is_content_error("Failed to run openssl: No such file or directory"));
        assert!(!is_content_error("Decryption timed out after 600 seconds"));
    }
}
