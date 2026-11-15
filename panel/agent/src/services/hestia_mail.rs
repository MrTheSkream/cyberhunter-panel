//! HestiaCP mail import helpers (05-import-hestia W4-A).
//!
//! Reads one mail domain of a staged `v-backup-user` archive:
//!
//! * `mail/<d>/hestia/<d>.conf`: one `ACCOUNT= ALIAS= FWD= FWD_ONLY= MD5= QUOTA=
//!   SUSPENDED=` line per mailbox (the authority on mailboxes, aliases and
//!   forwards);
//! * `mail/<d>/conf/passwd`: the Dovecot passwd-file Hestia served
//!   (`user:{BLF-CRYPT}$2y$...:uid:gid::home:0:userdb_quota_rule=...`), the hash
//!   actually verified at login, preferred over `MD5=`;
//! * `mail/<d>/conf/aliases`: the Exim alias file. Measured on the reference
//!   archive, its sources are MAILBOX addresses (they are the `FWD` of each
//!   account, not aliases); a line whose source is not a mailbox is an extra
//!   alias. One `virtual_alias_maps` key per source is kept (`postmap` keeps the
//!   first duplicate, which would silently defeat a forward + local copy);
//! * `mail/<d>/hestia/mail.conf` (`DKIM_SELECTOR`, `CATCHALL`) and
//!   `mail/<d>/conf/dkim.pem` (or `hestia/<d>.pem`).
//!
//! The parsing is pure and tested on synthetic fixtures. Hashes and the DKIM
//! private key are secrets: [`MailSecrets`] redacts them in `Debug`, and nothing
//! here logs them.

use std::collections::BTreeMap;
use std::path::Path;

/// One mailbox, as Hestia described it.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct HestiaAccount {
    pub email: String,
    /// Dovecot hash with its `{SCHEME}` prefix. SECRET.
    pub hash: String,
    /// Upper-case scheme (`BLF-CRYPT`, `SHA512-CRYPT`...), `UNKNOWN` if none.
    pub scheme: String,
    /// `None` = unlimited.
    pub quota_mb: Option<i64>,
    /// Forward targets, comma-separated as Hestia stores them.
    pub forward_to: Option<String>,
    pub forward_only: bool,
    pub suspended: bool,
}

impl std::fmt::Debug for HestiaAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HestiaAccount")
            .field("email", &self.email)
            .field("hash", &"<redacted>")
            .field("scheme", &self.scheme)
            .field("quota_mb", &self.quota_mb)
            .field("forward_to", &self.forward_to)
            .field("forward_only", &self.forward_only)
            .field("suspended", &self.suspended)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HestiaAlias {
    pub source: String,
    pub destination: String,
}

/// Body of `POST /mail/hestia/secrets`.
#[derive(Clone, serde::Serialize)]
pub struct MailSecrets {
    pub selector: String,
    /// SECRET.
    pub dkim_private_pem: Option<String>,
    pub catch_all: Option<String>,
    /// Hestia scanned this domain's mail with ClamAV (`ANTIVIRUS='yes'`).
    pub antivirus: bool,
    pub accounts: Vec<HestiaAccount>,
    pub aliases: Vec<HestiaAlias>,
}

impl std::fmt::Debug for MailSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailSecrets")
            .field("selector", &self.selector)
            .field("dkim_private_pem", &self.dkim_private_pem.as_ref().map(|_| "<redacted>"))
            .field("catch_all", &self.catch_all)
            .field("antivirus", &self.antivirus)
            .field("accounts", &self.accounts)
            .field("aliases", &self.aliases)
            .finish()
    }
}

/// `KEY='value'` pairs of one Hestia config line, by key: W1's
/// [`crate::services::hestia::parse_pairs`], first occurrence of a key wins
/// (as its own lookups do).
pub fn pairs(line: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in crate::services::hestia::parse_pairs(line) {
        out.entry(k).or_insert(v);
    }
    out
}

/// `local -> hash` of a Dovecot passwd-file (field 2).
pub fn parse_passwd(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let user = f.next()?.trim();
            let hash = f.next()?.trim();
            (!user.is_empty() && !hash.is_empty()).then(|| (user.to_ascii_lowercase(), hash.to_string()))
        })
        .collect()
}

/// `(source, destinations)` lines of an Exim alias file (`src:dst1,dst2`).
pub fn parse_aliases_file(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let (src, dst) = l.trim().split_once(':')?;
            let (src, dst) = (src.trim().to_ascii_lowercase(), dst.trim().to_ascii_lowercase());
            (!src.is_empty() && !dst.is_empty()).then_some((src, dst))
        })
        .collect()
}

/// Scheme of a Dovecot hash and the hash with an explicit `{SCHEME}` prefix.
/// A bare crypt(3) hash is labelled by its `$id$`; anything else is `UNKNOWN`
/// (left as is - the backend imports such a mailbox disabled).
pub fn hash_scheme(hash: &str) -> (String, String) {
    let h = hash.trim();
    if let Some(rest) = h.strip_prefix('{') {
        if let Some(end) = rest.find('}') {
            let scheme = rest[..end].to_ascii_uppercase();
            if !scheme.is_empty() && scheme.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.') {
                return (scheme, h.to_string());
            }
        }
        return ("UNKNOWN".into(), h.to_string());
    }
    let scheme = if h.starts_with("$2y$") || h.starts_with("$2a$") || h.starts_with("$2b$") {
        "BLF-CRYPT"
    } else if h.starts_with("$6$") {
        "SHA512-CRYPT"
    } else if h.starts_with("$5$") {
        "SHA256-CRYPT"
    } else if h.starts_with("$1$") {
        "MD5-CRYPT"
    } else {
        return ("UNKNOWN".into(), h.to_string());
    };
    (scheme.to_string(), format!("{{{scheme}}}{h}"))
}

fn yes(v: Option<&String>) -> bool {
    matches!(v.map(|s| s.trim().to_ascii_lowercase()).as_deref(), Some("yes") | Some("1") | Some("true"))
}

fn non_empty(v: Option<&String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// `QUOTA='unlimited'` (or empty / 0) gives `None`, a number gives its MB.
pub fn parse_quota(v: Option<&String>) -> Option<i64> {
    let s = v.map(|s| s.trim().to_ascii_lowercase()).unwrap_or_default();
    match s.parse::<i64>() {
        Ok(n) if n > 0 => Some(n),
        _ => None,
    }
}

/// Selector characters accepted by `dkim_generate` / `rebuild_dkim_tables`.
pub fn is_valid_selector(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// Mailbox local part accepted by the maildir import (`[A-Za-z0-9._+-]+`, no `..`).
pub fn is_valid_account(a: &str) -> bool {
    !a.is_empty()
        && a.len() <= 64
        && !a.contains("..")
        && !a.starts_with('.')
        && a.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'+' | b'-'))
}

/// Inputs of one domain, already read from the staging.
#[derive(Default)]
pub struct DomainFiles {
    pub domain_conf: String,
    pub passwd: String,
    pub aliases: String,
    pub fwd_only: String,
    pub mail_conf: String,
    pub dkim_pem: Option<String>,
}

/// Build the secrets answer of one domain from its files. Pure.
pub fn build_secrets(domain: &str, files: &DomainFiles) -> MailSecrets {
    let domain = domain.to_ascii_lowercase();
    let passwd = parse_passwd(&files.passwd);
    let alias_file = parse_aliases_file(&files.aliases);
    let fwd_only_list: Vec<String> = files
        .fwd_only
        .lines()
        .map(|l| l.trim().to_ascii_lowercase())
        .filter(|l| !l.is_empty())
        .collect();
    let mail_conf = files.mail_conf.lines().find(|l| l.contains("DOMAIN=")).map(pairs).unwrap_or_default();

    let mut accounts = Vec::new();
    let mut aliases: Vec<HestiaAlias> = Vec::new();
    for line in files.domain_conf.lines() {
        let p = pairs(line);
        let Some(local) = non_empty(p.get("ACCOUNT")).map(|s| s.to_ascii_lowercase()) else { continue };
        let email = format!("{local}@{domain}");
        let raw = passwd.get(&local).cloned().or_else(|| non_empty(p.get("MD5"))).unwrap_or_default();
        let (scheme, hash) = if raw.is_empty() { ("UNKNOWN".to_string(), String::new()) } else { hash_scheme(&raw) };
        let fwd_from_file = alias_file
            .iter()
            .find(|(s, _)| *s == email)
            .map(|(_, d)| d.split(',').map(str::trim).filter(|d| *d != email).collect::<Vec<_>>().join(","))
            .filter(|d| !d.is_empty());
        let forward_to = non_empty(p.get("FWD")).map(|s| s.to_ascii_lowercase()).or(fwd_from_file);
        let forward_only = yes(p.get("FWD_ONLY")) || fwd_only_list.iter().any(|l| *l == local || *l == email);
        for a in p.get("ALIAS").map(String::as_str).unwrap_or("").split(',') {
            let a = a.trim().to_ascii_lowercase();
            if a.is_empty() {
                continue;
            }
            let source = if a.contains('@') { a } else { format!("{a}@{domain}") };
            aliases.push(HestiaAlias { source, destination: email.clone() });
        }
        accounts.push(HestiaAccount {
            email,
            hash,
            scheme,
            quota_mb: parse_quota(p.get("QUOTA")),
            forward_to,
            forward_only,
            suspended: yes(p.get("SUSPENDED")),
        });
    }
    // Extra aliases of the Exim file: sources that are not mailboxes.
    for (src, dst) in &alias_file {
        let full = if src.contains('@') { src.clone() } else { format!("{src}@{domain}") };
        if accounts.iter().any(|a| a.email == full) {
            continue;
        }
        aliases.push(HestiaAlias { source: full, destination: dst.clone() });
    }
    // One key per source; never a mailbox address.
    let mut seen = std::collections::BTreeSet::new();
    aliases.retain(|a| !accounts.iter().any(|acc| acc.email == a.source) && seen.insert(a.source.clone()));

    let selector = non_empty(mail_conf.get("DKIM_SELECTOR"))
        .filter(|s| is_valid_selector(s))
        .unwrap_or_else(|| "mail".to_string());
    let catch_all = non_empty(mail_conf.get("CATCHALL")).map(|c| c.to_ascii_lowercase());
    let antivirus = yes(mail_conf.get("ANTIVIRUS"));
    let dkim_private_pem = files
        .dkim_pem
        .as_ref()
        .map(|p| p.trim().to_string())
        .filter(|p| p.starts_with("-----BEGIN") && p.contains("PRIVATE KEY-----"));
    MailSecrets { selector, dkim_private_pem, catch_all, antivirus, accounts, aliases }
}

const MAX_META_FILE: u64 = 4 * 1024 * 1024;

fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_META_FILE {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Read one mail domain from the migration staging. `Err` when the domain is
/// not in the backup.
pub fn read_domain(migration_id: &str, domain: &str) -> Result<MailSecrets, String> {
    let base = crate::services::migration::archive_root(migration_id)?.join("mail").join(domain);
    let domain_conf = read_small(&base.join("hestia").join(format!("{domain}.conf")))
        .ok_or_else(|| format!("mail domain {domain} is not in the backup"))?;
    let files = DomainFiles {
        domain_conf,
        passwd: read_small(&base.join("conf").join("passwd")).unwrap_or_default(),
        aliases: read_small(&base.join("conf").join("aliases")).unwrap_or_default(),
        fwd_only: read_small(&base.join("conf").join("fwd_only")).unwrap_or_default(),
        mail_conf: read_small(&base.join("hestia").join("mail.conf")).unwrap_or_default(),
        dkim_pem: read_small(&base.join("conf").join("dkim.pem"))
            .or_else(|| read_small(&base.join("hestia").join(format!("{domain}.pem")))),
    };
    Ok(build_secrets(domain, &files))
}

/// Archive members that may hold the maildirs of `domain`, in try order. In
/// `full` mode the blob is on disk in the staging and is the only candidate.
pub fn maildir_blob_candidates(migration_id: &str, domain: &str) -> Vec<String> {
    let names = [format!("mail/{domain}/accounts.tar.gz"), format!("mail/{domain}/accounts.tar.zst")];
    // W1's locator answers for both modes (index in lazy, extracted tree in full).
    let present: Vec<String> = names
        .iter()
        .filter(|n| crate::services::migration::member_size(migration_id, n).is_ok())
        .cloned()
        .collect();
    if present.is_empty() { names.to_vec() } else { present }
}

/// Bytes of the regular files of a tree (symlinks not followed).
pub fn tree_bytes(root: &Path) -> u64 {
    let mut n = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                stack.push(e.path());
            } else if md.is_file() {
                n += md.len();
            }
        }
    }
    n
}

/// Messages in a maildir tree: files directly under a `cur` or `new` directory.
pub fn count_messages(root: &Path) -> u64 {
    let mut n = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let in_box = matches!(dir.file_name().and_then(|f| f.to_str()), Some("cur") | Some("new"));
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() && in_box {
                n += 1;
            }
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic fixtures in the reference archive's shape; no real data.
    const CONF: &str = "\
ACCOUNT='info' ALIAS='contact,sales' AUTOREPLY='no' FWD='' FWD_ONLY='' MD5='{BLF-CRYPT}$2y$05$fakefakefakefakefakefu' QUOTA='unlimited' U_DISK='0' SUSPENDED='no' TIME='10:00:00' DATE='2026-01-01'
ACCOUNT='jim' ALIAS='' AUTOREPLY='no' FWD='jim.fwd@example.org' FWD_ONLY='' MD5='{BLF-CRYPT}$2y$05$md5fieldmd5fieldmd5fi' QUOTA='500' U_DISK='0' SUSPENDED='no' TIME='10:00:00' DATE='2026-01-01'
ACCOUNT='bob' ALIAS='' AUTOREPLY='no' FWD='' FWD_ONLY='yes' MD5='{SSHA512}ZmFrZQ==' QUOTA='0' U_DISK='0' SUSPENDED='yes' TIME='10:00:00' DATE='2026-01-01'
ACCOUNT='old' ALIAS='' AUTOREPLY='no' FWD='' FWD_ONLY='' MD5='$1$salt$fakefake' QUOTA='unlimited' U_DISK='0' SUSPENDED='no' TIME='10:00:00' DATE='2026-01-01'
";
    const PASSWD: &str = "\
info:{BLF-CRYPT}$2y$05$passwdpasswdpasswdpas:adm-x:mail::/home/adm-x:0:userdb_quota_rule=*:storage=0M
jim:{BLF-CRYPT}$2y$05$jimjimjimjimjimjimjimj:adm-x:mail::/home/adm-x:0:userdb_quota_rule=*:storage=500M
";
    const ALIASES: &str = "\
jim@d.be:jim.fwd@example.org
bob@d.be:other@example.org
postmaster@d.be:info@d.be
contact@d.be:someone@else.org
";
    const MAIL_CONF: &str = "DOMAIN='d.be' ANTIVIRUS='no' DKIM='yes' DKIM_SELECTOR='mail' CATCHALL='' ACCOUNTS='4' SUSPENDED='no'";

    fn files() -> DomainFiles {
        DomainFiles {
            domain_conf: CONF.into(),
            passwd: PASSWD.into(),
            aliases: ALIASES.into(),
            fwd_only: String::new(),
            mail_conf: MAIL_CONF.into(),
            dkim_pem: Some("-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n-----END RSA PRIVATE KEY-----\n".into()),
        }
    }

    fn acc<'a>(s: &'a MailSecrets, email: &str) -> &'a HestiaAccount {
        s.accounts.iter().find(|a| a.email == email).expect(email)
    }

    #[test]
    fn pairs_parse_quoted_values_in_order() {
        let p = pairs("ACCOUNT='info' ALIAS='a,b' FWD='' QUOTA='unlimited'");
        assert_eq!(p.get("ACCOUNT").map(String::as_str), Some("info"));
        assert_eq!(p.get("ALIAS").map(String::as_str), Some("a,b"));
        assert_eq!(p.get("FWD").map(String::as_str), Some(""));
        assert_eq!(p.get("QUOTA").map(String::as_str), Some("unlimited"));
    }

    #[test]
    fn account_fields_map_from_the_domain_conf() {
        let s = build_secrets("d.be", &files());
        assert_eq!(s.accounts.len(), 4);
        let info = acc(&s, "info@d.be");
        assert_eq!(info.quota_mb, None, "unlimited");
        assert_eq!(info.forward_to, None);
        assert!(!info.forward_only && !info.suspended);
        assert_eq!(info.scheme, "BLF-CRYPT");
        // conf/passwd wins over MD5= (it is what Dovecot verified).
        assert!(info.hash.contains("passwdpasswd"));

        let jim = acc(&s, "jim@d.be");
        assert_eq!(jim.quota_mb, Some(500));
        assert_eq!(jim.forward_to.as_deref(), Some("jim.fwd@example.org"));
        assert!(!jim.forward_only, "FWD without FWD_ONLY = forward + local copy");

        let bob = acc(&s, "bob@d.be");
        assert_eq!(bob.quota_mb, None, "0 = unlimited");
        assert!(bob.forward_only && bob.suspended);
        assert_eq!(bob.scheme, "SSHA512", "no passwd line: MD5= is used");
        // FWD empty but the Exim file forwards: taken from there.
        assert_eq!(bob.forward_to.as_deref(), Some("other@example.org"));

        let old = acc(&s, "old@d.be");
        assert_eq!(old.scheme, "MD5-CRYPT");
        assert!(old.hash.starts_with("{MD5-CRYPT}$1$"));
    }

    #[test]
    fn aliases_come_from_alias_fields_and_non_mailbox_exim_sources_once_each() {
        let s = build_secrets("d.be", &files());
        let srcs: Vec<&str> = s.aliases.iter().map(|a| a.source.as_str()).collect();
        assert_eq!(srcs, vec!["contact@d.be", "sales@d.be", "postmaster@d.be"]);
        // `contact` is both an ALIAS of info and an Exim line: the ALIAS field wins.
        assert_eq!(s.aliases[0].destination, "info@d.be");
        // A forward line (source = a mailbox) never becomes an alias.
        assert!(!srcs.contains(&"jim@d.be") && !srcs.contains(&"bob@d.be"));
    }

    #[test]
    fn domain_settings_and_dkim() {
        let s = build_secrets("d.be", &files());
        assert_eq!(s.selector, "mail");
        assert_eq!(s.catch_all, None);
        assert!(!s.antivirus, "ANTIVIRUS='no'");
        assert!(s.dkim_private_pem.is_some());
        assert_eq!(serde_json::to_value(&s).unwrap()["antivirus"], false);
        let mut f = files();
        f.mail_conf = "DOMAIN='d.be' ANTIVIRUS='yes' DKIM='yes' DKIM_SELECTOR='mail'".into();
        let s = build_secrets("d.be", &f);
        assert!(s.antivirus);
        assert_eq!(serde_json::to_value(&s).unwrap()["antivirus"], true);
        f.mail_conf = "DOMAIN='d.be' DKIM_SELECTOR='bad/sel' CATCHALL='info@d.be'".into();
        f.dkim_pem = Some("not a key".into());
        let s = build_secrets("d.be", &f);
        assert_eq!(s.selector, "mail", "an unusable selector falls back to Hestia's default");
        assert_eq!(s.catch_all.as_deref(), Some("info@d.be"));
        assert_eq!(s.dkim_private_pem, None);
    }

    #[test]
    fn fwd_only_file_marks_forward_only() {
        let mut f = files();
        f.fwd_only = "jim\n".into();
        assert!(acc(&build_secrets("d.be", &f), "jim@d.be").forward_only);
    }

    #[test]
    fn hash_schemes() {
        assert_eq!(hash_scheme("{BLF-CRYPT}$2y$05$x").0, "BLF-CRYPT");
        assert_eq!(hash_scheme("{blf-crypt}$2y$05$x").0, "BLF-CRYPT");
        assert_eq!(hash_scheme("$2y$05$x"), ("BLF-CRYPT".into(), "{BLF-CRYPT}$2y$05$x".into()));
        assert_eq!(hash_scheme("$6$s$x").0, "SHA512-CRYPT");
        assert_eq!(hash_scheme("plainjunk").0, "UNKNOWN");
        assert_eq!(hash_scheme("{}x").0, "UNKNOWN");
    }

    #[test]
    fn debug_never_prints_secrets() {
        let s = build_secrets("d.be", &files());
        let d = format!("{s:?}");
        assert!(!d.contains("$2y$") && !d.contains("PRIVATE KEY") && !d.contains("ZmFrZQ"));
    }

    #[test]
    fn account_and_selector_validation() {
        for ok in ["info", "jim.doe", "a+b", "x_y-z"] {
            assert!(is_valid_account(ok), "{ok}");
        }
        for bad in ["", "..", "a..b", ".hidden", "a/b", "a b", "a@b"] {
            assert!(!is_valid_account(bad), "{bad:?}");
        }
        assert!(is_valid_selector("mail") && is_valid_selector("dock_panel-1"));
        assert!(!is_valid_selector("a.b") && !is_valid_selector(""));
    }

    #[test]
    fn messages_are_counted_under_cur_and_new_only() {
        let root = std::env::temp_dir().join(format!("hm-{}", uuid::Uuid::new_v4().simple()));
        for d in ["cur", "new", "tmp", ".Spam/cur"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        for f in ["cur/1", "cur/2", "new/3", "tmp/4", ".Spam/cur/5", "dovecot-uidlist"] {
            std::fs::write(root.join(f), b"x").unwrap();
        }
        assert_eq!(count_messages(&root), 4);
        let _ = std::fs::remove_dir_all(&root);
    }
}
