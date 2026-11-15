//! HestiaCP backup helpers shared by the import workstreams (05-import-hestia).
//!
//! STEP 0 SKELETON (owner: W1). Signatures fixed by contract W1-H; W1 replaces
//! this whole file with the real implementation.
#![allow(dead_code)]

/// Credentials of one HestiaCP database, read from `db/<db>/hestia/db.conf`.
/// `mysql_hash` is a `mysql_native_password` hash: never logged, never returned.
pub struct DbCred {
    pub db: String,
    pub user: String,
    pub mysql_hash: String,
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
pub fn parse_pairs(_line: &str) -> Vec<(String, String)> {
    Vec::new()
}

/// `PHP-X_Y` gives `Some("X.Y")`, `default` (or anything else) gives `None`.
pub fn php_version_from_backend(_b: &str) -> Option<String> {
    None
}

/// Canonical host from a Hestia `*.conf_redirect` file: `"www"` | `"apex"`.
pub fn canonical_from_redirect(_domain: &str, _conf: &str) -> Option<&'static str> {
    None
}

/// Reads `db/<db>/hestia/db.conf` (line `DB=<db>`) from the migration staging.
pub fn db_credentials(_migration_id: &str, _db: &str) -> Result<DbCred, String> {
    Err("not implemented".into())
}

/// `(ftp_user, crypt(3) hash)` of a web domain; never logged.
pub fn ftp_hash(_migration_id: &str, _domain: &str) -> Option<(String, String)> {
    None
}
