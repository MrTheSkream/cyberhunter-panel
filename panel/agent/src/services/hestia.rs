//! HestiaCP backup helpers shared by the import workstreams (05-import-hestia, W1-H).
//!
//! Pure parsers of the small configuration files a `v-backup-user` archive
//! carries (`web.conf`, `db.conf`, `mail.conf`, `<d>.conf`, `*.conf_redirect`),
//! plus the two readers W2/W4 call to fetch a secret straight from the staging
//! (`db_credentials`, `ftp_hash`). Secrets (hashes, keys) leave this module only
//! through those two readers: the inventory types below carry a hash SCHEME,
//! never a hash, and nothing here logs a value.

use std::path::Path;

/// Credentials of one HestiaCP database, read from `db/<db>/hestia/db.conf`.
/// `mysql_hash` is a `mysql_native_password` hash: never logged, never returned.
pub struct DbCred {
    pub db: String,
    pub user: String,
    pub mysql_hash: String,
    /// Lowercased and validated (`^[a-z0-9_]{1,32}$`), safe to splice into
    /// `CREATE DATABASE ... CHARACTER SET`.
    pub charset: String,
}

impl std::fmt::Debug for DbCred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbCred")
            .field("db", &self.db)
            .field("user", &self.user)
            .field("mysql_hash", &"<redacted>")
            .field("charset", &self.charset)
            .finish()
    }
}

/// `KEY='value'` pairs of one HestiaCP config line, in order (ex-`hestia_pairs`).
pub fn parse_pairs(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = line.trim();
    while let Some(eq) = rest.find("='") {
        let key = rest[..eq].trim().to_string();
        let after = &rest[eq + 2..];
        let Some(end) = after.find('\'') else {
            break;
        };
        out.push((key, after[..end].to_string()));
        rest = after[end + 1..].trim_start();
    }
    out
}

/// Value of `key` in a parsed line, `""` when absent.
fn get<'a>(pairs: &'a [(String, String)], key: &str) -> &'a str {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

/// `PHP-X_Y` gives `Some("X.Y")`, `default` (or anything else) gives `None`.
pub fn php_version_from_backend(b: &str) -> Option<String> {
    let rest = b.trim().strip_prefix("PHP-")?;
    let (major, minor) = rest.split_once('_')?;
    let digits = |s: &str| !s.is_empty() && s.len() <= 2 && s.bytes().all(|c| c.is_ascii_digit());
    if digits(major) && digits(minor) {
        Some(format!("{major}.{minor}"))
    } else {
        None
    }
}

/// PHP version a Hestia vhost (`conf/nginx.conf` / `conf/apache2.conf`) talks to,
/// from its FPM socket `php8.3-fpm-<domain>.sock`. Used when `BACKEND='default'`
/// (D2): the template keeps `%backend_version%`, only the rendered vhost knows.
pub fn php_version_from_conf(conf: &str, domain: &str) -> Option<String> {
    let needle = format!("-fpm-{domain}.sock");
    for (idx, _) in conf.match_indices(&needle) {
        let head = &conf[..idx];
        let Some(p) = head.rfind("php") else { continue };
        let ver = &head[p + 3..];
        let mut parts = ver.split('.');
        let (Some(a), Some(b), None) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let digits = |s: &str| !s.is_empty() && s.len() <= 2 && s.bytes().all(|c| c.is_ascii_digit());
        if digits(a) && digits(b) {
            return Some(format!("{a}.{b}"));
        }
    }
    None
}

/// Canonical host from a Hestia `*.conf_redirect` file: `"www"` | `"apex"`.
///
/// The file is `if ($host != "www.d") { return 301 $scheme://www.d$request_uri; }`;
/// the redirect TARGET decides. Anything else (another host, no redirect) is `None`.
pub fn canonical_from_redirect(domain: &str, conf: &str) -> Option<&'static str> {
    let domain = domain.trim().to_ascii_lowercase();
    for line in conf.lines() {
        let l = line.trim();
        let Some(pos) = l.find("return 301") else { continue };
        let target = &l[pos + "return 301".len()..];
        let Some(scheme_end) = target.find("://") else { continue };
        let host: String = target[scheme_end + 3..]
            .chars()
            .take_while(|c| !matches!(c, '$' | '/' | ';' | ' ' | ':' | '"'))
            .collect::<String>()
            .to_ascii_lowercase();
        if host == format!("www.{domain}") {
            return Some("www");
        }
        if host == domain {
            return Some("apex");
        }
    }
    None
}

/// One path component of the archive (a domain, a database name): no
/// separator, no traversal, no NUL, bounded.
pub fn is_safe_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && !s.starts_with('.')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && !s.contains("..")
}

/// Reads `db/<db>/hestia/db.conf` (line `DB=<db>`) from the migration staging.
pub fn db_credentials(migration_id: &str, db: &str) -> Result<DbCred, String> {
    if !is_safe_component(db) {
        return Err("invalid database name".into());
    }
    let dir = crate::services::migration::archive_root(migration_id)?;
    let path = dir.join("db").join(db).join("hestia").join("db.conf");
    let text = std::fs::read_to_string(&path)
        .map_err(|_| format!("db.conf of {db} not found in the staging"))?;
    db_credentials_from(&text, db)
}

/// Pure half of [`db_credentials`].
pub fn db_credentials_from(text: &str, db: &str) -> Result<DbCred, String> {
    for line in text.lines() {
        let pairs = parse_pairs(line);
        if get(&pairs, "DB") != db {
            continue;
        }
        let user = get(&pairs, "DBUSER").to_string();
        if user.is_empty() {
            return Err(format!("db.conf of {db} has no DBUSER"));
        }
        let charset = normalize_charset(get(&pairs, "CHARSET"))
            .ok_or_else(|| format!("db.conf of {db} has an unusable CHARSET"))?;
        return Ok(DbCred {
            db: db.to_string(),
            user,
            mysql_hash: get(&pairs, "MD5").to_string(),
            charset,
        });
    }
    Err(format!("db.conf has no line for {db}"))
}

/// `UTF8MB4` gives `utf8mb4`; empty gives `utf8mb4`; anything outside
/// `^[a-z0-9_]{1,32}$` after lowercasing gives `None`.
pub fn normalize_charset(raw: &str) -> Option<String> {
    let c = raw.trim().to_ascii_lowercase();
    if c.is_empty() {
        return Some("utf8mb4".into());
    }
    if c.len() <= 32 && c.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
        Some(c)
    } else {
        None
    }
}

/// `(ftp_user, crypt(3) hash)` of a web domain; never logged.
///
/// Hestia keeps several FTP accounts as `:`-separated lists in `FTP_USER` and
/// `FTP_MD5`; the panel has one SFTP account per site, so the FIRST pair wins
/// (the inventory warns when there are more).
pub fn ftp_hash(migration_id: &str, domain: &str) -> Option<(String, String)> {
    if !is_safe_component(domain) {
        return None;
    }
    let dir = crate::services::migration::archive_root(migration_id).ok()?;
    let text = read_web_conf(&dir.join("web").join(domain))?;
    ftp_hash_from(&text, domain)
}

/// Pure half of [`ftp_hash`].
pub fn ftp_hash_from(text: &str, domain: &str) -> Option<(String, String)> {
    let line = domain_line(text, domain)?;
    let pairs = parse_pairs(line);
    let user = get(&pairs, "FTP_USER").split(':').next()?.trim().to_string();
    let hash = get(&pairs, "FTP_MD5").split(':').next()?.trim().to_string();
    if user.is_empty() || hash.is_empty() {
        return None;
    }
    Some((user, hash))
}

/// `web/<d>/hestia/web.conf` (or the older `web/<d>/web.conf`).
pub fn read_web_conf(domain_dir: &Path) -> Option<String> {
    ["hestia/web.conf", "web.conf"]
        .iter()
        .find_map(|f| std::fs::read_to_string(domain_dir.join(f)).ok())
}

/// The line of a multi-domain conf that belongs to `domain` (a line without a
/// `DOMAIN` key counts, as in a per-domain backup file).
fn domain_line<'a>(text: &'a str, domain: &str) -> Option<&'a str> {
    let mut fallback = None;
    for line in text.lines() {
        let pairs = parse_pairs(line);
        if pairs.is_empty() {
            continue;
        }
        match pairs.iter().find(|(k, _)| k == "DOMAIN") {
            Some((_, d)) if d == domain => return Some(line),
            Some(_) => {}
            None => {
                if fallback.is_none() {
                    fallback = Some(line);
                }
            }
        }
    }
    fallback
}

/// Scheme of a crypt(3) hash, for the inventory (the hash itself never leaves).
pub fn crypt_scheme(hash: &str) -> &'static str {
    let h = hash.trim();
    if h.is_empty() {
        return "none";
    }
    if h.starts_with("$y$") {
        "yescrypt"
    } else if h.starts_with("$gy$") {
        "gost-yescrypt"
    } else if h.starts_with("$7$") {
        "scrypt"
    } else if h.starts_with("$6$") {
        "sha512crypt"
    } else if h.starts_with("$5$") {
        "sha256crypt"
    } else if h.starts_with("$2a$") || h.starts_with("$2b$") || h.starts_with("$2x$") || h.starts_with("$2y$") {
        "bcrypt"
    } else if h.starts_with("$1$") {
        "md5crypt"
    } else {
        "unknown"
    }
}

/// Dovecot scheme of a mail password hash: `{BLF-CRYPT}$2y$...` gives
/// `BLF-CRYPT`; a bare crypt(3) hash is named the way Dovecot would.
pub fn mail_hash_scheme(hash: &str) -> String {
    let h = hash.trim();
    if let Some(rest) = h.strip_prefix('{') {
        if let Some(end) = rest.find('}') {
            let s = &rest[..end];
            if !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
                return s.to_ascii_uppercase();
            }
        }
        return "UNKNOWN".into();
    }
    match crypt_scheme(h) {
        "bcrypt" => "BLF-CRYPT",
        "sha512crypt" => "SHA512-CRYPT",
        "sha256crypt" => "SHA256-CRYPT",
        "md5crypt" => "MD5-CRYPT",
        "none" => "NONE",
        "yescrypt" => "CRYPT",
        _ => "UNKNOWN",
    }
    .into()
}

/// What the inventory needs from one `web.conf` line. No secret field.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WebConf {
    pub aliases: Vec<String>,
    pub backend: String,
    pub proxy: String,
    pub tpl: String,
    pub ssl: bool,
    pub ssl_force: bool,
    pub ssl_hsts: bool,
    pub ftp_users: Vec<String>,
    /// Scheme of each `FTP_MD5` hash, in `ftp_users` order.
    pub ftp_schemes: Vec<&'static str>,
    pub suspended: bool,
    pub custom_docroot: String,
}

/// Parses the `web.conf` line of `domain`. `None` when no line matches.
pub fn parse_web_conf(text: &str, domain: &str) -> Option<WebConf> {
    let line = domain_line(text, domain)?;
    let p = parse_pairs(line);
    let yes = |k: &str| get(&p, k).eq_ignore_ascii_case("yes");
    let dom = domain.to_ascii_lowercase();
    let mut aliases: Vec<String> = Vec::new();
    for a in get(&p, "ALIAS").split(',') {
        let a = a.trim().to_ascii_lowercase();
        if !a.is_empty() && a != dom && !aliases.contains(&a) {
            aliases.push(a);
        }
    }
    let ftp_users: Vec<String> = get(&p, "FTP_USER")
        .split(':')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let hashes: Vec<&str> = get(&p, "FTP_MD5").split(':').collect();
    let ftp_schemes = (0..ftp_users.len())
        .map(|i| crypt_scheme(hashes.get(i).copied().unwrap_or("")))
        .collect();
    Some(WebConf {
        aliases,
        backend: get(&p, "BACKEND").to_string(),
        proxy: get(&p, "PROXY").to_string(),
        tpl: get(&p, "TPL").to_string(),
        ssl: yes("SSL"),
        ssl_force: yes("SSL_FORCE"),
        ssl_hsts: yes("SSL_HSTS"),
        ftp_schemes,
        ftp_users,
        suspended: yes("SUSPENDED"),
        custom_docroot: get(&p, "CUSTOM_DOCROOT").to_string(),
    })
}

/// `mail/<d>/hestia/mail.conf`, without secrets.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MailDomainConf {
    pub dkim: bool,
    pub selector: String,
    pub catch_all: Option<String>,
    pub suspended: bool,
    /// `ANTIVIRUS='yes'`: Hestia scanned this domain's mail (feature 5, A-H).
    pub antivirus: bool,
}

pub fn parse_mail_conf(text: &str, domain: &str) -> Option<MailDomainConf> {
    let line = domain_line(text, domain)?;
    let p = parse_pairs(line);
    let selector = get(&p, "DKIM_SELECTOR").trim();
    let catch_all = get(&p, "CATCHALL").trim();
    Some(MailDomainConf {
        dkim: get(&p, "DKIM").eq_ignore_ascii_case("yes"),
        selector: if selector.is_empty() { "mail".into() } else { selector.to_string() },
        catch_all: if catch_all.is_empty() { None } else { Some(catch_all.to_string()) },
        suspended: get(&p, "SUSPENDED").eq_ignore_ascii_case("yes"),
        antivirus: get(&p, "ANTIVIRUS").eq_ignore_ascii_case("yes"),
    })
}

/// One mailbox line of `mail/<d>/hestia/<d>.conf`, without the hash.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MailAccountConf {
    pub account: String,
    pub aliases: Vec<String>,
    pub forward_to: Option<String>,
    pub forward_only: bool,
    pub quota_mb: Option<u64>,
    pub suspended: bool,
    pub hash_scheme: String,
}

pub fn parse_mail_accounts(text: &str) -> Vec<MailAccountConf> {
    let mut out = Vec::new();
    for line in text.lines() {
        let p = parse_pairs(line);
        let account = get(&p, "ACCOUNT").trim();
        if account.is_empty() {
            continue;
        }
        let list = |k: &str| -> Vec<String> {
            get(&p, k)
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };
        let fwd = list("FWD");
        let quota = get(&p, "QUOTA").trim();
        out.push(MailAccountConf {
            account: account.to_string(),
            aliases: list("ALIAS"),
            forward_to: if fwd.is_empty() { None } else { Some(fwd.join(",")) },
            forward_only: get(&p, "FWD_ONLY").eq_ignore_ascii_case("yes"),
            quota_mb: if quota.eq_ignore_ascii_case("unlimited") { None } else { quota.parse().ok() },
            suspended: get(&p, "SUSPENDED").eq_ignore_ascii_case("yes"),
            hash_scheme: mail_hash_scheme(get(&p, "MD5")),
        });
    }
    out
}

/// Scheme per user from a Dovecot `conf/passwd` (`user:{SCHEME}hash:...`).
pub fn passwd_schemes(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.splitn(3, ':');
            let user = it.next()?.trim();
            let hash = it.next()?;
            if user.is_empty() {
                return None;
            }
            Some((user.to_string(), mail_hash_scheme(hash)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pairs_in_order_and_empty_values() {
        let p = parse_pairs("DOMAIN='example.com' IP6='' ALIAS='www.example.com,shop.example.com' X='a b'");
        assert_eq!(p.len(), 4);
        assert_eq!(p[0], ("DOMAIN".into(), "example.com".into()));
        assert_eq!(p[1], ("IP6".into(), String::new()));
        assert_eq!(p[3], ("X".into(), "a b".into()));
        assert!(parse_pairs("").is_empty());
        assert!(parse_pairs("garbage").is_empty());
        // Unterminated value stops the parse instead of swallowing the rest.
        assert_eq!(parse_pairs("A='1' B='2").len(), 1);
    }

    #[test]
    fn php_version_from_backend_cases() {
        assert_eq!(php_version_from_backend("PHP-5_6").as_deref(), Some("5.6"));
        assert_eq!(php_version_from_backend("PHP-8_4").as_deref(), Some("8.4"));
        assert_eq!(php_version_from_backend("default"), None);
        assert_eq!(php_version_from_backend(""), None);
        assert_eq!(php_version_from_backend("PHP-8"), None);
        assert_eq!(php_version_from_backend("PHP-x_y"), None);
        assert_eq!(php_version_from_backend("PHP-8_4;rm"), None);
    }

    #[test]
    fn php_version_from_conf_reads_the_socket() {
        let apache = r#"<FilesMatch \.php$>
    SetHandler "proxy:unix:/run/php/php8.3-fpm-example.com.sock|fcgi://localhost"
</FilesMatch>"#;
        assert_eq!(php_version_from_conf(apache, "example.com").as_deref(), Some("8.3"));
        let nginx = "fastcgi_pass unix:/run/php/php5.6-fpm-example.org.sock;";
        assert_eq!(php_version_from_conf(nginx, "example.org").as_deref(), Some("5.6"));
        assert_eq!(php_version_from_conf(nginx, "example.com"), None);
        assert_eq!(php_version_from_conf("", "example.com"), None);
    }

    #[test]
    fn canonical_from_redirect_www_apex_absent() {
        let www = "if ($host != \"www.example.com\") {\n   return 301 $scheme://www.example.com$request_uri;\n}\n";
        assert_eq!(canonical_from_redirect("example.com", www), Some("www"));
        let apex = "if ($host != \"example.com\") {\n   return 301 $scheme://example.com$request_uri;\n}\n";
        assert_eq!(canonical_from_redirect("example.com", apex), Some("apex"));
        let https = "return 301 https://WWW.Example.com$request_uri;";
        assert_eq!(canonical_from_redirect("example.com", https), Some("www"));
        assert_eq!(canonical_from_redirect("example.com", ""), None);
        let other = "return 301 $scheme://other.example.net$request_uri;";
        assert_eq!(canonical_from_redirect("example.com", other), None);
    }

    #[test]
    fn db_credentials_reads_the_right_line_and_redacts() {
        let text = "DB='u_other' DBUSER='u_o' MD5='*AAAA' CHARSET='latin1'\n\
                    DB='u_shop.example' DBUSER='u_shop' MD5='*0123456789ABCDEF0123456789ABCDEF01234567' HOST='localhost' TYPE='mysql' CHARSET='UTF8MB4'\n";
        let c = db_credentials_from(text, "u_shop.example").unwrap();
        assert_eq!(c.user, "u_shop");
        assert_eq!(c.charset, "utf8mb4");
        assert_eq!(c.mysql_hash.len(), 41);
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("0123456789ABCDEF"), "Debug must mask the hash");
        assert!(db_credentials_from(text, "missing").is_err());
        let bad = "DB='x' DBUSER='y' MD5='' CHARSET='utf8; DROP'\n";
        assert!(db_credentials_from(bad, "x").is_err());
    }

    #[test]
    fn db_credentials_rejects_unsafe_names() {
        assert!(db_credentials("00000000-0000-0000-0000-000000000000", "../etc").is_err());
        assert!(db_credentials("00000000-0000-0000-0000-000000000000", "a/b").is_err());
        assert!(db_credentials("not-a-uuid", "db").is_err());
    }

    #[test]
    fn ftp_hash_first_pair() {
        let text = "DOMAIN='example.com' FTP_USER='u_one:u_two' FTP_MD5='$y$j9T$salt$hash1:$6$s$h2'\n";
        let (u, h) = ftp_hash_from(text, "example.com").unwrap();
        assert_eq!(u, "u_one");
        assert_eq!(h, "$y$j9T$salt$hash1");
        assert!(ftp_hash_from("DOMAIN='example.com' FTP_USER='' FTP_MD5=''", "example.com").is_none());
        assert!(ftp_hash_from(text, "other.com").is_none());
    }

    #[test]
    fn web_conf_fields() {
        let text = "DOMAIN='example.com' ALIAS='www.example.com,example.com,WWW.example.com' TPL='default' SSL='yes' \
                    SSL_FORCE='no' FTP_USER='u_ex' FTP_MD5='$y$j9T$a$b' BACKEND='PHP-5_6' PROXY='custom-x' SUSPENDED='no'\n";
        let w = parse_web_conf(text, "example.com").unwrap();
        assert_eq!(w.aliases, vec!["www.example.com".to_string()]);
        assert!(w.ssl && !w.ssl_force && !w.ssl_hsts);
        assert_eq!(w.ftp_users, vec!["u_ex".to_string()]);
        assert_eq!(w.ftp_schemes, vec!["yescrypt"]);
        assert_eq!(w.proxy, "custom-x");
        assert_eq!(w.backend, "PHP-5_6");
    }

    #[test]
    fn schemes() {
        assert_eq!(crypt_scheme("$y$j9T$x$y"), "yescrypt");
        assert_eq!(crypt_scheme("$2y$10$abc"), "bcrypt");
        assert_eq!(crypt_scheme(""), "none");
        assert_eq!(crypt_scheme("*ABC"), "unknown");
        assert_eq!(mail_hash_scheme("{BLF-CRYPT}$2y$05$abc"), "BLF-CRYPT");
        assert_eq!(mail_hash_scheme("{sha512-crypt}$6$x"), "SHA512-CRYPT");
        assert_eq!(mail_hash_scheme("$1$abc$def"), "MD5-CRYPT");
        assert_eq!(mail_hash_scheme("{weird"), "UNKNOWN");
    }

    #[test]
    fn mail_conf_and_accounts() {
        let mc = parse_mail_conf(
            "DOMAIN='example.org' DKIM='yes' DKIM_SELECTOR='' CATCHALL='' SUSPENDED='no'",
            "example.org",
        )
        .unwrap();
        assert!(mc.dkim);
        assert_eq!(mc.selector, "mail");
        assert_eq!(mc.catch_all, None);
        assert!(!mc.antivirus, "no ANTIVIRUS key = false");
        let av = parse_mail_conf("DOMAIN='example.org' ANTIVIRUS='yes' DKIM='no'", "example.org").unwrap();
        assert!(av.antivirus && !av.dkim);
        let acc = parse_mail_accounts(
            "ACCOUNT='info' ALIAS='contact,hello' FWD='a@example.net' FWD_ONLY='' MD5='{BLF-CRYPT}$2y$x' QUOTA='unlimited' SUSPENDED='no'\n\
             ACCOUNT='sales' ALIAS='' FWD='' FWD_ONLY='no' MD5='$6$x' QUOTA='512' SUSPENDED='yes'\n",
        );
        assert_eq!(acc.len(), 2);
        assert_eq!(acc[0].aliases.len(), 2);
        assert_eq!(acc[0].forward_to.as_deref(), Some("a@example.net"));
        assert!(!acc[0].forward_only);
        assert_eq!(acc[0].quota_mb, None);
        assert_eq!(acc[0].hash_scheme, "BLF-CRYPT");
        assert_eq!(acc[1].quota_mb, Some(512));
        assert!(acc[1].suspended);
        assert_eq!(acc[1].hash_scheme, "SHA512-CRYPT");
        let pw = passwd_schemes("info:{BLF-CRYPT}$2y$05$x:1000:1000::/home/u:0:userdb_quota_rule=*:storage=0\n");
        assert_eq!(pw, vec![("info".to_string(), "BLF-CRYPT".to_string())]);
    }
}
