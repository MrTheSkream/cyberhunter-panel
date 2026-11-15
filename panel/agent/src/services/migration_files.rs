//! Tar reading and site file placement for the HestiaCP import (05-import-hestia, W1-A/W1-I).
//!
//! Three layers, from pure to effectful:
//! - tar headers (`parse_header`, `parse_pax`) and two readers built on them: a
//!   seekable INDEX of the outer `v-backup-user` archive (offsets, so a blob is
//!   later read straight from the archive without extracting it, D8), and a
//!   streaming reader of an inner `domain_data` tar used by the analysis pass;
//! - pure helpers for the decisions of D7/D9/D12 (path rewrite, db hints,
//!   upload PHP detection, disk);
//! - the file phases of `POST /migration/import-site` (place, fix), run as a job.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncReadExt};

// ---------------------------------------------------------------------------
// Tar headers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Hardlink,
    Other,
}

/// One raw 512-byte header, before long-name/pax overrides.
#[derive(Debug, Clone, PartialEq)]
pub struct RawHeader {
    pub name: String,
    pub size: u64,
    pub typeflag: u8,
    pub link: String,
    pub mode: u32,
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn parse_num(field: &[u8]) -> Result<u64, String> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        // GNU base-256 (sizes over 8 GiB).
        let mut v: u64 = (field[0] & 0x7f) as u64;
        for &b in &field[1..] {
            v = v.checked_mul(256).ok_or("tar size overflow")?.checked_add(b as u64).ok_or("tar size overflow")?;
        }
        return Ok(v);
    }
    let s: String = field
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as char)
        .collect();
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| "invalid number in tar header".to_string())
}

/// `Ok(None)` for an all-zero block (end of archive).
pub fn parse_header(block: &[u8]) -> Result<Option<RawHeader>, String> {
    if block.len() != 512 {
        return Err("short tar block".into());
    }
    if block.iter().all(|&b| b == 0) {
        return Ok(None);
    }
    let stored = parse_num(&block[148..156])?;
    let sum: u64 = block
        .iter()
        .enumerate()
        .map(|(i, &b)| if (148..156).contains(&i) { 32u64 } else { b as u64 })
        .sum();
    if stored != sum {
        return Err("not a tar archive (bad header checksum)".into());
    }
    let mut name = cstr(&block[0..100]);
    if &block[257..263] == b"ustar\0" {
        let prefix = cstr(&block[345..500]);
        if !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
    }
    Ok(Some(RawHeader {
        name,
        size: parse_num(&block[124..136])?,
        typeflag: block[156],
        link: cstr(&block[157..257]),
        mode: parse_num(&block[100..108]).unwrap_or(0) as u32,
    }))
}

/// Is this block the first header of a plain (uncompressed) tar?
pub fn looks_like_tar(block: &[u8]) -> bool {
    block.len() >= 512 && &block[257..262] == b"ustar" && matches!(parse_header(&block[..512]), Ok(Some(_)))
}

/// `path` and `linkpath` records of a pax extended header.
pub fn parse_pax(data: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let Some(sp) = rest.iter().position(|&c| c == b' ') else { break };
        let Ok(len) = std::str::from_utf8(&rest[..sp]).unwrap_or("x").parse::<usize>() else { break };
        if len == 0 || len > rest.len() || len <= sp + 1 {
            break;
        }
        let rec = &rest[sp + 1..len];
        let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
        if let Some(eq) = rec.iter().position(|&c| c == b'=') {
            out.push((
                String::from_utf8_lossy(&rec[..eq]).into_owned(),
                String::from_utf8_lossy(&rec[eq + 1..]).into_owned(),
            ));
        }
        rest = &rest[len..];
    }
    out
}

fn kind_of(typeflag: u8) -> EntryKind {
    match typeflag {
        b'0' | 0 | b'7' => EntryKind::File,
        b'5' => EntryKind::Dir,
        b'2' => EntryKind::Symlink,
        b'1' => EntryKind::Hardlink,
        _ => EntryKind::Other,
    }
}

/// Member name as the import names it: no leading `./` or `/`, no trailing `/`.
pub fn normalize_name(name: &str) -> String {
    let mut n = name;
    loop {
        if let Some(r) = n.strip_prefix("./") {
            n = r;
        } else if let Some(r) = n.strip_prefix('/') {
            n = r;
        } else {
            break;
        }
    }
    let n = n.trim_end_matches('/');
    if n == "." {
        String::new()
    } else {
        n.to_string()
    }
}

/// Does a member name contain a `..` component (or NUL)? Such members are
/// never indexed, extracted or read.
pub fn is_unsafe_name(name: &str) -> bool {
    name.contains('\0') || name.split('/').any(|c| c == "..")
}

fn pad(size: u64) -> u64 {
    (512 - size % 512) % 512
}

// ---------------------------------------------------------------------------
// Outer archive index (seekable)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IndexEntry {
    /// Normalized name (see [`normalize_name`]).
    pub name: String,
    /// Offset of the member's DATA in the archive.
    pub offset: u64,
    pub size: u64,
    pub kind: EntryKind,
}

/// Indexes a plain tar by walking its headers and seeking over the data: a
/// 10 GiB archive is listed by reading a few hundred KiB.
pub fn index_tar<R: Read + Seek>(r: &mut R) -> Result<(Vec<IndexEntry>, bool), String> {
    let mut out = Vec::new();
    let mut dot_prefix = false;
    let mut block = [0u8; 512];
    let mut long_name: Option<String> = None;
    let mut pax_path: Option<String> = None;
    let mut pax_size: Option<u64> = None;
    let mut pos: u64 = 0;
    loop {
        match read_full(r, &mut block) {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => return Err(e),
        }
        pos += 512;
        let Some(h) = parse_header(&block)? else { break };
        let data_off = pos;
        match h.typeflag {
            b'L' | b'K' | b'x' | b'g' => {
                if h.size > 1024 * 1024 {
                    return Err("oversized tar extended header".into());
                }
                let mut data = vec![0u8; h.size as usize];
                r.read_exact(&mut data).map_err(|e| format!("tar read failed: {e}"))?;
                let skip = pad(h.size);
                r.seek(SeekFrom::Current(skip as i64)).map_err(|e| format!("tar seek failed: {e}"))?;
                pos += h.size + skip;
                match h.typeflag {
                    b'L' => long_name = Some(cstr(&data)),
                    b'x' => {
                        for (k, v) in parse_pax(&data) {
                            match k.as_str() {
                                "path" => pax_path = Some(v),
                                "size" => pax_size = v.parse().ok(),
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
                continue;
            }
            _ => {}
        }
        let raw_name = pax_path.take().or(long_name.take()).unwrap_or(h.name.clone());
        let size = pax_size.take().unwrap_or(h.size);
        let kind = kind_of(h.typeflag);
        // Only regular files carry data in the archive.
        let data_len = if kind == EntryKind::File { size } else { 0 };
        let skip = data_len + pad(data_len);
        r.seek(SeekFrom::Current(skip as i64)).map_err(|e| format!("tar seek failed: {e}"))?;
        pos += skip;
        if raw_name.starts_with("./") {
            dot_prefix = true;
        }
        let name = normalize_name(&raw_name);
        if name.is_empty() || is_unsafe_name(&name) {
            continue;
        }
        out.push(IndexEntry { name, offset: data_off, size: data_len, kind });
    }
    Ok((out, dot_prefix))
}

/// `Ok(false)` on a clean EOF before the first byte.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool, String> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => {
                return if got == 0 { Ok(false) } else { Err("truncated tar archive".into()) };
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("tar read failed: {e}")),
        }
    }
    Ok(true)
}

/// Is this member one of the small metadata files the lazy mode copies into
/// the staging (D8)? Blobs (`*.tar.*`, `*.sql.*`, `*.tgz`) are read later,
/// straight from the archive.
pub fn is_metadata_member(e: &IndexEntry) -> bool {
    const MAX: u64 = 4 * 1024 * 1024;
    if e.kind != EntryKind::File || e.size > MAX {
        return false;
    }
    let base = e.name.rsplit('/').next().unwrap_or(&e.name);
    !(base.contains(".tar.") || base.contains(".sql.") || base.ends_with(".tgz") || base.ends_with(".tar"))
}

// ---------------------------------------------------------------------------
// Streaming reader (inner domain_data tar)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)] // size/link: part of the reader API, not needed by the scan
pub struct StreamEntry {
    pub name: String,
    pub size: u64,
    pub kind: EntryKind,
    pub link: String,
}

pub struct TarStream<R> {
    r: R,
    /// Data bytes (with padding) of the current entry not consumed yet.
    left: u64,
    data_left: u64,
    done: bool,
    /// Bytes read so far (uncompressed).
    pub read_bytes: u64,
}

impl<R: AsyncRead + Unpin> TarStream<R> {
    pub fn new(r: R) -> Self {
        Self { r, left: 0, data_left: 0, done: false, read_bytes: 0 }
    }

    async fn read_block(&mut self, block: &mut [u8; 512]) -> Result<bool, String> {
        let mut got = 0;
        while got < 512 {
            let n = self.r.read(&mut block[got..]).await.map_err(|e| format!("read failed: {e}"))?;
            if n == 0 {
                return if got == 0 { Ok(false) } else { Err("truncated tar stream".into()) };
            }
            got += n;
        }
        self.read_bytes += 512;
        Ok(true)
    }

    async fn skip(&mut self, mut n: u64) -> Result<(), String> {
        let mut buf = vec![0u8; 64 * 1024];
        while n > 0 {
            let want = n.min(buf.len() as u64) as usize;
            let got = self.r.read(&mut buf[..want]).await.map_err(|e| format!("read failed: {e}"))?;
            if got == 0 {
                return Err("truncated tar stream".into());
            }
            n -= got as u64;
            self.read_bytes += got as u64;
        }
        Ok(())
    }

    async fn read_exact_vec(&mut self, n: usize) -> Result<Vec<u8>, String> {
        let mut v = vec![0u8; n];
        self.r.read_exact(&mut v).await.map_err(|e| format!("truncated tar stream: {e}"))?;
        self.read_bytes += n as u64;
        Ok(v)
    }

    pub async fn next_entry(&mut self) -> Result<Option<StreamEntry>, String> {
        if self.done {
            return Ok(None);
        }
        if self.left > 0 {
            let n = self.left;
            self.left = 0;
            self.data_left = 0;
            self.skip(n).await?;
        }
        let mut long_name: Option<String> = None;
        let mut long_link: Option<String> = None;
        let mut pax_path: Option<String> = None;
        let mut pax_link: Option<String> = None;
        let mut pax_size: Option<u64> = None;
        let mut block = [0u8; 512];
        loop {
            if !self.read_block(&mut block).await? {
                self.done = true;
                return Ok(None);
            }
            let Some(h) = parse_header(&block)? else {
                self.done = true;
                return Ok(None);
            };
            match h.typeflag {
                b'L' | b'K' | b'x' | b'g' => {
                    if h.size > 1024 * 1024 {
                        return Err("oversized tar extended header".into());
                    }
                    let data = self.read_exact_vec(h.size as usize).await?;
                    self.skip(pad(h.size)).await?;
                    match h.typeflag {
                        b'L' => long_name = Some(cstr(&data)),
                        b'K' => long_link = Some(cstr(&data)),
                        b'x' => {
                            for (k, v) in parse_pax(&data) {
                                match k.as_str() {
                                    "path" => pax_path = Some(v),
                                    "linkpath" => pax_link = Some(v),
                                    "size" => pax_size = v.parse().ok(),
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
                _ => {
                    let kind = kind_of(h.typeflag);
                    let size = pax_size.unwrap_or(h.size);
                    let data = if kind == EntryKind::File { size } else { 0 };
                    self.data_left = data;
                    self.left = data + pad(data);
                    return Ok(Some(StreamEntry {
                        name: pax_path.or(long_name).unwrap_or(h.name),
                        size: data,
                        kind,
                        link: pax_link.or(long_link).unwrap_or(h.link),
                    }));
                }
            }
        }
    }

    /// Content of the current entry when it is at most `limit` bytes; `None`
    /// (and the data is skipped by the next `next_entry`) otherwise.
    pub async fn read_data(&mut self, limit: usize) -> Result<Option<Vec<u8>>, String> {
        if self.data_left > limit as u64 {
            return Ok(None);
        }
        let n = self.data_left as usize;
        let v = self.read_exact_vec(n).await?;
        let p = self.left - self.data_left;
        self.left = 0;
        self.data_left = 0;
        self.skip(p).await?;
        Ok(Some(v))
    }
}

// ---------------------------------------------------------------------------
// Pure decisions (D7, D9, D12)
// ---------------------------------------------------------------------------

/// D9 default list (relative to the web root), also used to count the PHP
/// files already sitting in upload folders.
pub const NO_EXEC_DEFAULT_DIRS: &[&str] =
    &["/wp-content/uploads", "/sites/default/files", "/storage/app/public", "/uploads", "/upload"];

/// Would the D9 nginx rule `^<dir>/.*\.(?:php[0-9]?|phtml|pht|phps|phar)(/|$)`
/// (case-insensitive) deny this web-root-relative path?
pub fn is_upload_php(rel: &str) -> bool {
    let p = format!("/{}", rel.trim_start_matches('/')).to_ascii_lowercase();
    let in_dir = NO_EXEC_DEFAULT_DIRS.iter().any(|d| p.starts_with(&format!("{d}/")));
    if !in_dir {
        return false;
    }
    p.split('/').any(|seg| {
        seg.rsplit_once('.').is_some_and(|(_, ext)| {
            matches!(ext, "phtml" | "pht" | "phps" | "phar" | "php")
                || (ext.len() == 4 && ext.starts_with("php") && ext.as_bytes()[3].is_ascii_digit())
        })
    })
}

/// Files whose content the analysis reads to find the database a site uses (D12),
/// relative to the web root or to `private/`.
pub const DB_HINT_FILES: &[&str] = &[
    "wp-config.php",
    ".env",
    "configuration.php",
    "app/etc/env.php",
    "config.php",
    "includes/config.php",
];

/// Text files worth scanning for absolute `/home/<user>/` paths (D7).
pub fn is_path_scan_candidate(base: &str) -> bool {
    let b = base.to_ascii_lowercase();
    if b == ".htaccess" || b == ".user.ini" || b.starts_with(".env") {
        return true;
    }
    matches!(
        b.rsplit_once('.').map(|(_, e)| e),
        Some("php" | "ini" | "inc" | "json" | "yml" | "yaml" | "conf" | "xml" | "env" | "phtml")
    )
}

/// Which of `dbs` does a config file name? A name counts when it appears
/// delimited (quotes, `=`, whitespace, `;`). When several match, those on a
/// line that looks like a database setting win.
pub fn find_db_names(content: &str, dbs: &[String]) -> Vec<String> {
    let delim = |c: Option<char>| match c {
        None => true,
        Some(c) => matches!(c, '\'' | '"' | '=' | ' ' | '\t' | ';' | '\n' | '\r' | ',' | ')' | '('),
    };
    let mut hits: Vec<(String, bool)> = Vec::new();
    for line in content.lines() {
        let lower = line.to_ascii_lowercase();
        let dbish = ["db_name", "db_database", "dbname", "$db ", "$db=", "database", "'db'", "\"db\""]
            .iter()
            .any(|k| lower.contains(k));
        for db in dbs {
            if db.is_empty() {
                continue;
            }
            for (i, _) in line.match_indices(db.as_str()) {
                let before = line[..i].chars().next_back();
                let after = line[i + db.len()..].chars().next();
                if delim(before) && delim(after) {
                    match hits.iter_mut().find(|(d, _)| d == db) {
                        Some(h) => h.1 |= dbish,
                        None => hits.push((db.clone(), dbish)),
                    }
                }
            }
        }
    }
    if hits.iter().any(|(_, s)| *s) {
        hits.retain(|(_, s)| *s);
    }
    hits.into_iter().map(|(d, _)| d).collect()
}

/// D7 rewrite: the exact string `/home/<user>/web/<d>/<src_dir>` becomes
/// `new_root`, and `/home/<user>/web/<d>/private` becomes `new_private`, each
/// only when the next character ends the path component. Returns the new text
/// and the number of replacements.
pub fn rewrite_hestia_paths(
    content: &str,
    user: &str,
    domain: &str,
    src_dir: &str,
    new_root: &str,
    new_private: &str,
) -> (String, usize) {
    let pairs = [
        (format!("/home/{user}/web/{domain}/{src_dir}"), new_root),
        (format!("/home/{user}/web/{domain}/private"), new_private),
    ];
    let mut out = String::with_capacity(content.len());
    let mut count = 0;
    let mut i = 0;
    let bytes = content.as_bytes();
    'outer: while i < content.len() {
        for (from, to) in &pairs {
            if content[i..].starts_with(from.as_str()) {
                let next = bytes.get(i + from.len()).copied();
                let ends = match next {
                    None => true,
                    Some(c) => !(c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.'),
                };
                if ends {
                    out.push_str(to);
                    i += from.len();
                    count += 1;
                    continue 'outer;
                }
            }
        }
        let ch = content[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8().max(1);
    }
    (out, count)
}

/// Occurrences of the source panel's home prefix (`/home/<user>/`).
pub fn count_home_paths(content: &[u8], user: &str) -> usize {
    let needle = format!("/home/{user}/");
    let n = needle.as_bytes();
    if n.is_empty() || content.len() < n.len() {
        return 0;
    }
    content.windows(n.len()).filter(|w| *w == n).count()
}

/// Disk check of the analysis (`disk` of the inventory).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct DiskReport {
    pub staging_free: u64,
    pub www_free: u64,
    pub www_needed_estimate: u64,
    pub ok: bool,
    pub reason: Option<String>,
}

pub const GIB: u64 = 1024 * 1024 * 1024;

/// Free space a site import needs at that moment (D8): 2.5 x blob + 1 GiB.
pub fn site_space_needed(blob: u64) -> u64 {
    blob.saturating_mul(5) / 2 + GIB
}

/// The estimate is the worst moment of the whole import: every other site
/// already placed (about 1.5 x its compressed size) while the largest one is
/// being unpacked (2.5 x + 1 GiB, the per-site rule).
pub fn compute_disk(staging_free: u64, www_free: u64, blobs: &[u64], staging_needed: u64) -> DiskReport {
    let total: u64 = blobs.iter().sum();
    let largest = blobs.iter().copied().max().unwrap_or(0);
    let www_needed_estimate = if blobs.is_empty() {
        0
    } else {
        (total - largest).saturating_mul(3) / 2 + site_space_needed(largest)
    };
    let mut reasons = Vec::new();
    if staging_free < staging_needed {
        reasons.push(format!(
            "staging needs {} MiB, {} MiB free under /var/lib/dockpanel",
            staging_needed / (1024 * 1024),
            staging_free / (1024 * 1024)
        ));
    }
    if www_free < www_needed_estimate {
        reasons.push(format!(
            "importing the sites needs about {:.1} GiB under /var/www, {:.1} GiB free",
            www_needed_estimate as f64 / GIB as f64,
            www_free as f64 / GIB as f64
        ));
    }
    DiskReport {
        staging_free,
        www_free,
        www_needed_estimate,
        ok: reasons.is_empty(),
        reason: if reasons.is_empty() { None } else { Some(reasons.join("; ")) },
    }
}

/// Free bytes of the filesystem holding `path` (nearest existing ancestor).
pub fn free_bytes(path: &Path) -> u64 {
    let mut p = path.to_path_buf();
    loop {
        if p.exists() {
            break;
        }
        if !p.pop() {
            return 0;
        }
    }
    match rustix::fs::statvfs(&p) {
        Ok(s) => s.f_bavail.saturating_mul(s.f_frsize),
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// Analysis pass over one domain_data (D7, D9, D12)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SiteScan {
    pub has_public_html: bool,
    pub has_public_html0: bool,
    pub has_private: bool,
    pub file_count: u64,
    /// Counted per candidate web root (`public_html`, `public_html0`).
    pub upload_php: [u64; 2],
    pub paths_to_fix: Vec<(String, usize)>,
    /// `(database, file)` hints.
    pub db_hits: Vec<(String, String)>,
}

impl SiteScan {
    pub fn doc_root_dir(&self) -> Option<&'static str> {
        if self.has_public_html {
            Some("public_html")
        } else if self.has_public_html0 {
            Some("public_html0")
        } else {
            None
        }
    }

    pub fn upload_php_files(&self) -> u64 {
        if self.has_public_html { self.upload_php[0] } else { self.upload_php[1] }
    }
}

/// One read of a decompressed `domain_data` tar: never writes a file.
pub async fn scan_domain_data<R: AsyncRead + Unpin>(
    reader: R,
    user: &str,
    dbs: &[String],
    mut on_progress: impl FnMut(u64),
) -> Result<SiteScan, String> {
    const CONTENT_LIMIT: usize = 1024 * 1024;
    let mut ts = TarStream::new(reader);
    let mut scan = SiteScan::default();
    let mut last = 0u64;
    while let Some(e) = ts.next_entry().await? {
        if ts.read_bytes - last > 8 * 1024 * 1024 {
            last = ts.read_bytes;
            on_progress(ts.read_bytes);
        }
        let name = normalize_name(&e.name);
        if name.is_empty() || is_unsafe_name(&name) {
            continue;
        }
        let (top, rest) = name.split_once('/').unwrap_or((name.as_str(), ""));
        let root_idx = match top {
            "public_html" => {
                scan.has_public_html = true;
                Some(0)
            }
            "public_html0" => {
                scan.has_public_html0 = true;
                Some(1)
            }
            "private" => {
                scan.has_private = true;
                None
            }
            _ => continue,
        };
        if e.kind != EntryKind::File || rest.is_empty() {
            continue;
        }
        scan.file_count += 1;
        if let Some(i) = root_idx {
            if is_upload_php(rest) {
                scan.upload_php[i] += 1;
            }
        }
        if rest.starts_with(".hestia-import/") {
            continue;
        }
        let depth = rest.split('/').count();
        let base = rest.rsplit('/').next().unwrap_or(rest);
        let label = if top == "private" { format!("private/{rest}") } else { rest.to_string() };
        let is_hint = DB_HINT_FILES
            .iter()
            .any(|h| rest == *h || (depth <= 3 && rest.ends_with(&format!("/{h}"))));
        let is_path = depth <= 3 && is_path_scan_candidate(base);
        if !(is_hint || is_path) {
            continue;
        }
        let Some(data) = ts.read_data(CONTENT_LIMIT).await? else { continue };
        if is_path {
            let n = count_home_paths(&data, user);
            if n > 0 {
                scan.paths_to_fix.push((label.clone(), n));
            }
        }
        if is_hint && !dbs.is_empty() {
            let text = String::from_utf8_lossy(&data);
            for db in find_db_names(&text, dbs) {
                if !scan.db_hits.iter().any(|(d, _)| *d == db) {
                    scan.db_hits.push((db, base.to_string()));
                }
            }
        }
    }
    on_progress(ts.read_bytes);
    Ok(scan)
}

// ---------------------------------------------------------------------------
// Placement and fix (import-site phases)
// ---------------------------------------------------------------------------

/// Empty, or holding only the panel's own placeholder `index.html`.
pub fn is_effectively_empty(dir: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else { return true };
    let entries: Vec<_> = rd.flatten().collect();
    match entries.as_slice() {
        [] => true,
        [only] => {
            only.file_name() == "index.html"
                && only.file_type().map(|t| t.is_file()).unwrap_or(false)
                && crate::services::nginx::is_placeholder_page(&only.path())
        }
        _ => false,
    }
}

/// Moves `src` to `dest` by rename when `dest` is absent or effectively empty
/// (same filesystem, no double occupation); otherwise `rsync -a` (`--delete`
/// when `force`) and removes `src`. Returns `"rename"` or `"rsync"`.
pub async fn place_dir(src: &Path, dest: &Path, force: bool, excludes: &[&str]) -> Result<&'static str, String> {
    if is_effectively_empty(dest) {
        if dest.exists() {
            std::fs::remove_dir_all(dest).map_err(|e| format!("could not clear {}: {e}", dest.display()))?;
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("could not create {}: {e}", parent.display()))?;
        }
        if std::fs::rename(src, dest).is_ok() {
            return Ok("rename");
        }
        std::fs::create_dir_all(dest).map_err(|e| format!("could not create {}: {e}", dest.display()))?;
    } else {
        // An operator's file named index.html is kept; only ours goes.
        let idx = dest.join("index.html");
        if crate::services::nginx::is_placeholder_page(&idx) {
            let _ = std::fs::remove_file(&idx);
        }
    }
    let mut cmd = crate::safe_cmd::safe_command("rsync");
    cmd.arg("-a");
    if force {
        cmd.arg("--delete");
    }
    for x in excludes {
        cmd.arg(format!("--exclude={x}"));
    }
    cmd.arg(format!("{}/", src.display())).arg(format!("{}/", dest.display()));
    cmd.kill_on_drop(true);
    let out = cmd.output().await.map_err(|e| format!("rsync could not start: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "rsync failed: {}",
            String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("").trim()
        ));
    }
    let _ = std::fs::remove_dir_all(src);
    Ok("rsync")
}

/// Lexical normalisation of `base/link` (no filesystem access).
pub fn resolve_lexically(base: &Path, link: &Path) -> PathBuf {
    let joined = if link.is_absolute() { link.to_path_buf() } else { base.join(link) };
    let mut out = PathBuf::new();
    for c in joined.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[derive(Debug, Default)]
pub struct FixResult {
    pub files_bytes: u64,
    pub symlinks_out: Vec<String>,
    pub paths_to_fix: Vec<(String, usize)>,
    pub upload_php_files: u64,
}

/// Fix walk over the placed tree (blocking: run in `spawn_blocking`). Never
/// follows a symlink. Clears setuid/setgid, lists symlinks leaving the site
/// tree, sums file sizes, counts PHP files in upload folders, lists files still
/// holding a `/home/<user>/` path (depth <= 3).
pub fn fix_walk(site_dir: &Path, doc_root: &Path, private: &Path, user: &str) -> FixResult {
    use std::os::unix::fs::PermissionsExt;
    let mut res = FixResult::default();
    let roots: [(&Path, Option<&str>); 2] = [(doc_root, None), (private, Some("private"))];
    for (root, label_prefix) in roots {
        if !root.is_dir() {
            continue;
        }
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for entry in rd.flatten() {
                let path = entry.path();
                let Ok(md) = std::fs::symlink_metadata(&path) else { continue };
                let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().to_string();
                if label_prefix.is_some() && rel.starts_with(".hestia-import") {
                    continue;
                }
                let ft = md.file_type();
                if ft.is_symlink() {
                    if let Ok(target) = std::fs::read_link(&path) {
                        let resolved = resolve_lexically(&dir, &target);
                        if !resolved.starts_with(site_dir) {
                            let label = match label_prefix {
                                Some(p) => format!("{p}/{rel}"),
                                None => rel.clone(),
                            };
                            if res.symlinks_out.len() < 200 {
                                res.symlinks_out.push(format!("{label} -> {}", target.display()));
                            }
                        }
                    }
                    continue;
                }
                let mode = md.permissions().mode();
                if mode & 0o6000 != 0 {
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode & !0o6000 & 0o7777));
                }
                if ft.is_dir() {
                    if entry.file_name() != ".git" {
                        stack.push(path);
                    }
                    continue;
                }
                if !ft.is_file() {
                    continue;
                }
                res.files_bytes += md.len();
                if label_prefix.is_none() && is_upload_php(&rel) {
                    res.upload_php_files += 1;
                }
                let depth = rel.split('/').count();
                let base = rel.rsplit('/').next().unwrap_or(&rel);
                if depth <= 3 && md.len() <= 1024 * 1024 && is_path_scan_candidate(base) {
                    if let Ok(data) = std::fs::read(&path) {
                        let n = count_home_paths(&data, user);
                        if n > 0 {
                            let label = match label_prefix {
                                Some(p) => format!("{p}/{rel}"),
                                None => rel.clone(),
                            };
                            res.paths_to_fix.push((label, n));
                        }
                    }
                }
            }
        }
    }
    res.paths_to_fix.sort();
    res
}

/// D7 rewrite of `.user.ini`, `php.ini`, `.htaccess` at the web root. Each
/// original is saved once under `private/.hestia-import/orig/` (a rerun never
/// overwrites the saved original with an already rewritten file). Regular
/// files only: a symlink is never read nor written through.
pub fn rewrite_root_files(
    doc_root: &Path,
    private: &Path,
    user: &str,
    domain: &str,
    src_dir: &str,
) -> Result<Vec<String>, String> {
    use std::os::unix::fs::PermissionsExt;
    let mut rewritten = Vec::new();
    let new_root = doc_root.to_string_lossy().to_string();
    let new_private = private.to_string_lossy().to_string();
    for name in [".user.ini", "php.ini", ".htaccess"] {
        let path = doc_root.join(name);
        let Ok(md) = std::fs::symlink_metadata(&path) else { continue };
        if !md.file_type().is_file() || md.len() > 1024 * 1024 {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let (new_text, n) = rewrite_hestia_paths(&text, user, domain, src_dir, &new_root, &new_private);
        if n == 0 {
            continue;
        }
        let orig_dir = private.join(".hestia-import").join("orig");
        std::fs::create_dir_all(&orig_dir).map_err(|e| format!("could not create {}: {e}", orig_dir.display()))?;
        let orig = orig_dir.join(name);
        if std::fs::symlink_metadata(&orig).is_err() {
            std::fs::write(&orig, &text).map_err(|e| format!("could not save the original {name}: {e}"))?;
        }
        let tmp = doc_root.join(format!(".{name}.import-tmp"));
        std::fs::write(&tmp, new_text).map_err(|e| format!("could not write {name}: {e}"))?;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(md.permissions().mode() & 0o777));
        std::fs::rename(&tmp, &path).map_err(|e| format!("could not replace {name}: {e}"))?;
        rewritten.push(name.to_string());
    }
    Ok(rewritten)
}

/// Startup sweep: `/var/www/*/.import-*` left by an agent killed mid-import
/// (its job is gone with the process; the backend reruns with a new job).
pub fn sweep_stale_import_dirs() {
    let Ok(rd) = std::fs::read_dir("/var/www") else { return };
    for site in rd.flatten() {
        if !site.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        remove_import_dirs(&site.path(), None);
    }
}

/// Removes `.import-*` work dirs of one site dir, or only `.import-<job>`.
pub fn remove_import_dirs(site_dir: &Path, job: Option<&str>) {
    let Ok(rd) = std::fs::read_dir(site_dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let matches = match job {
            Some(j) => name == format!(".import-{j}"),
            None => name.starts_with(".import-"),
        };
        if matches && e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            if let Err(err) = std::fs::remove_dir_all(e.path()) {
                tracing::warn!("could not remove {}: {err}", e.path().display());
            }
        }
    }
}

#[cfg(test)]
pub mod test_tar {
    //! Minimal tar writer for the tests (ustar, GNU long names).

    fn octal(field: &mut [u8], v: u64) {
        let s = format!("{:0width$o}", v, width = field.len() - 1);
        field[..s.len()].copy_from_slice(s.as_bytes());
    }

    fn header(name: &str, size: u64, typeflag: u8, link: &str) -> [u8; 512] {
        let mut h = [0u8; 512];
        let nb = name.as_bytes();
        h[..nb.len().min(100)].copy_from_slice(&nb[..nb.len().min(100)]);
        octal(&mut h[100..108], 0o644);
        octal(&mut h[108..116], 0);
        octal(&mut h[116..124], 0);
        octal(&mut h[124..136], size);
        octal(&mut h[136..148], 0);
        h[156] = typeflag;
        let lb = link.as_bytes();
        h[157..157 + lb.len()].copy_from_slice(lb);
        h[257..263].copy_from_slice(b"ustar ");
        h[263..265].copy_from_slice(b" \0");
        h[148..156].copy_from_slice(b"        ");
        let sum: u64 = h.iter().map(|&b| b as u64).sum();
        let s = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(s.as_bytes());
        h
    }

    fn push_data(out: &mut Vec<u8>, data: &[u8]) {
        out.extend_from_slice(data);
        let p = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, p));
    }

    pub enum E<'a> {
        F(&'a str, &'a [u8]),
        D(&'a str),
        L(&'a str, &'a str),
    }

    pub fn build(entries: &[E]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in entries {
            let (name, data, t, link): (&str, &[u8], u8, &str) = match e {
                E::F(n, d) => (n, d, b'0', ""),
                E::D(n) => (n, b"", b'5', ""),
                E::L(n, l) => (n, b"", b'2', l),
            };
            if name.len() > 100 {
                let mut ln = name.as_bytes().to_vec();
                ln.push(0);
                out.extend_from_slice(&header("././@LongLink", ln.len() as u64, b'L', ""));
                push_data(&mut out, &ln);
            }
            out.extend_from_slice(&header(name, data.len() as u64, t, link));
            push_data(&mut out, data);
        }
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::test_tar::{build, E};
    use super::*;

    #[test]
    fn index_finds_offsets_and_normalizes_names() {
        let long = format!("./web/{}/domain_data.tar.gz", "a".repeat(120));
        let tar = build(&[
            E::D("./"),
            E::D("./hestia/"),
            E::F("./hestia/user.conf", b"NAME='u'\n"),
            E::F(&long, b"BLOB"),
            E::F("./../evil", b"x"),
            E::L("./link", "/etc/passwd"),
        ]);
        let (idx, dot) = index_tar(&mut std::io::Cursor::new(&tar)).unwrap();
        assert!(dot);
        let names: Vec<_> = idx.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"hestia/user.conf"));
        assert!(!names.iter().any(|n| n.contains("..")), "traversal members are not indexed");
        let blob = idx.iter().find(|e| e.name.ends_with("domain_data.tar.gz")).unwrap();
        assert_eq!(blob.size, 4);
        assert_eq!(&tar[blob.offset as usize..blob.offset as usize + 4], b"BLOB");
        let uc = idx.iter().find(|e| e.name == "hestia/user.conf").unwrap();
        assert_eq!(&tar[uc.offset as usize..uc.offset as usize + uc.size as usize], b"NAME='u'\n");
        assert_eq!(idx.iter().find(|e| e.name == "link").unwrap().kind, EntryKind::Symlink);
    }

    #[test]
    fn bad_checksum_is_not_a_tar() {
        let mut tar = build(&[E::F("a", b"x")]);
        tar[0] = b'b';
        assert!(index_tar(&mut std::io::Cursor::new(&tar)).is_err());
        assert!(!looks_like_tar(&[0x1f, 0x8b, 0, 0]));
        let ok = build(&[E::F("a", b"x")]);
        assert!(looks_like_tar(&ok));
    }

    #[test]
    fn pax_records() {
        let data = b"30 path=web/x.example/a b.txt\n11 size=42\n";
        let p = parse_pax(data);
        assert_eq!(p[0], ("path".into(), "web/x.example/a b.txt".into()));
        assert_eq!(p[1], ("size".into(), "42".into()));
        assert!(parse_pax(b"garbage").is_empty());
    }

    #[test]
    fn base256_size() {
        let mut f = [0u8; 12];
        f[0] = 0x80;
        f[11] = 0x02;
        f[10] = 0x01;
        assert_eq!(parse_num(&f).unwrap(), 258);
    }

    #[test]
    fn metadata_selection() {
        let e = |name: &str, size: u64, kind| IndexEntry { name: name.into(), offset: 0, size, kind };
        assert!(is_metadata_member(&e("web/x/hestia/web.conf", 900, EntryKind::File)));
        assert!(!is_metadata_member(&e("web/x/domain_data.tar.gz", 900, EntryKind::File)));
        assert!(!is_metadata_member(&e("web/x/domain_data.tar.zst", 900, EntryKind::File)));
        assert!(!is_metadata_member(&e("db/x/x.mysql.sql.gz", 900, EntryKind::File)));
        assert!(!is_metadata_member(&e("hestia/big.log", 5 * 1024 * 1024, EntryKind::File)));
        assert!(!is_metadata_member(&e("link", 0, EntryKind::Symlink)));
    }

    #[test]
    fn upload_php_matches_the_nginx_rule() {
        assert!(is_upload_php("wp-content/uploads/x.php"));
        assert!(is_upload_php("wp-content/uploads/x.jpg/x.php"));
        assert!(is_upload_php("Uploads/x.PHP"));
        assert!(is_upload_php("uploads/a/b.phtml"));
        assert!(is_upload_php("upload/shell.php7"));
        assert!(!is_upload_php("wp-content/uploads/x.jpg"));
        assert!(!is_upload_php("wp-content/plugins/x.php"));
        assert!(!is_upload_php("uploadsx/x.php"));
    }

    #[test]
    fn db_names_found_in_config() {
        let dbs = vec!["u_shop".to_string(), "u_blog".to_string(), "u_shop2".to_string()];
        let wp = "define( 'DB_NAME', 'u_blog' );\ndefine( 'DB_USER', 'u_blog' );\n";
        assert_eq!(find_db_names(wp, &dbs), vec!["u_blog".to_string()]);
        let env = "APP=x\nDB_DATABASE=u_shop2\nCACHE=u_shop\n";
        assert_eq!(find_db_names(env, &dbs), vec!["u_shop2".to_string()]);
        assert!(find_db_names("nothing here u_shopX", &dbs).is_empty());
    }

    #[test]
    fn rewrite_exact_paths_only() {
        let ini = "auto_prepend_file = '/home/u/web/example.com/public_html/wordfence-waf.php'\n\
                   x=/home/u/web/example.com/public_html2/y\n\
                   p=/home/u/web/example.com/private\n\
                   o=/home/u/web/other.com/public_html/z\n";
        let (out, n) = rewrite_hestia_paths(ini, "u", "example.com", "public_html", "/var/www/example.com/public", "/var/www/example.com/private");
        assert_eq!(n, 2);
        assert!(out.contains("'/var/www/example.com/public/wordfence-waf.php'"));
        assert!(out.contains("/home/u/web/example.com/public_html2/y"));
        assert!(out.contains("p=/var/www/example.com/private\n"));
        assert!(out.contains("/home/u/web/other.com/public_html/z"));
        let (same, n0) = rewrite_hestia_paths("é /home/u/x", "u", "example.com", "public_html", "a", "b");
        assert_eq!((same.as_str(), n0), ("é /home/u/x", 0));
    }

    #[test]
    fn home_path_count() {
        assert_eq!(count_home_paths(b"/home/u/a /home/u/b /home/uu/c", "u"), 2);
        assert_eq!(count_home_paths(b"", "u"), 0);
    }

    #[test]
    fn disk_computation() {
        let d = compute_disk(10 * GIB, 100 * GIB, &[2 * GIB, 4 * GIB], 1024);
        // other sites at 1.5x (3 GiB) + largest at 2.5x + 1 GiB (11 GiB)
        assert_eq!(d.www_needed_estimate, 14 * GIB);
        assert!(d.ok);
        assert!(d.reason.is_none());
        let d = compute_disk(0, GIB, &[4 * GIB], 1024);
        assert!(!d.ok);
        let r = d.reason.unwrap();
        assert!(r.contains("staging") && r.contains("/var/www"));
        assert_eq!(compute_disk(1, 1, &[], 0).www_needed_estimate, 0);
        assert_eq!(site_space_needed(2 * GIB), 6 * GIB);
    }

    #[test]
    fn lexical_resolution() {
        let site = Path::new("/var/www/example.com");
        let dir = Path::new("/var/www/example.com/public/a");
        assert!(resolve_lexically(dir, Path::new("../../private/x")).starts_with(site));
        assert!(!resolve_lexically(dir, Path::new("../../../other/x")).starts_with(site));
        assert!(!resolve_lexically(dir, Path::new("/etc/passwd")).starts_with(site));
    }

    #[tokio::test]
    async fn scan_reads_one_pass() {
        let wp = b"<?php define('DB_NAME', 'u_ex');\nrequire '/home/u/web/example.com/private/x.php';\n";
        let tar = build(&[
            E::D("public_html/"),
            E::F("public_html/wp-config.php", wp),
            E::F("public_html/.user.ini", b"auto_prepend_file=/home/u/web/example.com/public_html/w.php\n"),
            E::F("public_html/wp-content/uploads/2024/evil.php", b"<?php"),
            E::F("public_html/a/b/c/d/deep.php", b"/home/u/"),
            E::F("private/app/.env", b"DB_DATABASE=u_other\n"),
            E::F("logs/x.log", b"/home/u/"),
        ]);
        let dbs = vec!["u_ex".to_string(), "u_other".to_string()];
        let scan = scan_domain_data(std::io::Cursor::new(tar), "u", &dbs, |_| {}).await.unwrap();
        assert!(scan.has_public_html && scan.has_private && !scan.has_public_html0);
        assert_eq!(scan.doc_root_dir(), Some("public_html"));
        assert_eq!(scan.upload_php_files(), 1);
        assert_eq!(scan.file_count, 5);
        let files: Vec<_> = scan.paths_to_fix.iter().map(|(f, _)| f.as_str()).collect();
        assert!(files.contains(&"wp-config.php"));
        assert!(files.contains(&".user.ini"));
        assert!(!files.iter().any(|f| f.contains("deep.php")), "depth > 3 is not scanned");
        assert!(!files.iter().any(|f| f.contains("x.log")), "logs/ is never read");
        assert!(scan.db_hits.contains(&("u_ex".into(), "wp-config.php".into())));
        assert!(scan.db_hits.contains(&("u_other".into(), ".env".into())));
    }

    #[tokio::test]
    async fn scan_handles_dot_prefix_and_public_html0() {
        let tar = build(&[E::D("./"), E::D("./public_html0/"), E::F("./public_html0/uploads/x.php", b"")]);
        let scan = scan_domain_data(std::io::Cursor::new(tar), "u", &[], |_| {}).await.unwrap();
        assert_eq!(scan.doc_root_dir(), Some("public_html0"));
        assert_eq!(scan.upload_php_files(), 1);
    }

    #[test]
    fn fix_walk_and_rewrite_on_disk() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("w1-fix-{}", uuid::Uuid::new_v4()));
        let site = base.join("example.com");
        let doc = site.join("public");
        let private = site.join("private");
        std::fs::create_dir_all(doc.join("wp-content/uploads")).unwrap();
        std::fs::create_dir_all(&private).unwrap();
        std::fs::write(doc.join(".user.ini"), "auto_prepend_file='/home/u/web/example.com/public_html/w.php'\n").unwrap();
        std::fs::write(doc.join("wp-config.php"), "require '/home/u/web/example.com/private/x';").unwrap();
        std::fs::write(doc.join("wp-content/uploads/e.php"), "<?php").unwrap();
        std::fs::write(doc.join("suid"), "x").unwrap();
        std::fs::set_permissions(doc.join("suid"), std::fs::Permissions::from_mode(0o4755)).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", doc.join("out")).unwrap();
        std::os::unix::fs::symlink("../private", doc.join("in")).unwrap();

        let rw = rewrite_root_files(&doc, &private, "u", "example.com", "public_html").unwrap();
        assert_eq!(rw, vec![".user.ini".to_string()]);
        let ini = std::fs::read_to_string(doc.join(".user.ini")).unwrap();
        assert!(ini.contains(&format!("{}/w.php", doc.display())));
        assert!(private.join(".hestia-import/orig/.user.ini").exists());
        // Rerun: nothing more to rewrite, original untouched.
        assert!(rewrite_root_files(&doc, &private, "u", "example.com", "public_html").unwrap().is_empty());
        assert!(std::fs::read_to_string(private.join(".hestia-import/orig/.user.ini")).unwrap().contains("/home/u/"));

        let r = fix_walk(&site, &doc, &private, "u");
        assert_eq!(r.upload_php_files, 1);
        assert_eq!(r.symlinks_out, vec!["out -> /etc/passwd".to_string()]);
        assert_eq!(r.paths_to_fix, vec![("wp-config.php".to_string(), 1)]);
        let mode = std::fs::metadata(doc.join("suid")).unwrap().permissions().mode();
        assert_eq!(mode & 0o6000, 0, "setuid cleared");
        assert!(r.files_bytes > 0);
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn effectively_empty_dirs() {
        let base = std::env::temp_dir().join(format!("w1-empty-{}", uuid::Uuid::new_v4()));
        assert!(is_effectively_empty(&base), "absent counts as empty");
        std::fs::create_dir_all(&base).unwrap();
        assert!(is_effectively_empty(&base));
        std::fs::write(base.join("index.html"), crate::services::nginx::placeholder_page("example.com")).unwrap();
        assert!(is_effectively_empty(&base));
        std::fs::write(base.join("index.html"), "<h1>mine</h1>").unwrap();
        assert!(!is_effectively_empty(&base));
        std::fs::remove_dir_all(&base).unwrap();
    }
}
