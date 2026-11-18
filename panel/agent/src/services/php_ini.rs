//! Global `php.ini` editor helpers (per version, FPM only - never the CLI
//! file). Contract: `conception/02-php-contrats.md` §A2/§A3.
//!
//! Pure: [`read_ini_values`], [`set_ini_values`], [`ini_test_passed`].

use std::collections::BTreeMap;

/// The keys the form edits (A2). `set_ini_values` callers are limited to these.
pub const INI_KEYS: &[&str] = &[
    "memory_limit",
    "max_execution_time",
    "max_input_time",
    "upload_max_filesize",
    "post_max_size",
    "display_errors",
    "error_reporting",
    "date.timezone",
];

/// Raw-editor size cap.
pub const MAX_INI_BYTES: usize = 512 * 1024;

/// `128M`, `2G`, `512K`, `1048576` -> bytes. `None` when not a PHP size.
fn parse_size(v: &str) -> Option<u64> {
    let v = v.trim();
    let (num, mult) = match v.chars().last()? {
        'k' | 'K' => (&v[..v.len() - 1], 1u64 << 10),
        'm' | 'M' => (&v[..v.len() - 1], 1u64 << 20),
        'g' | 'G' => (&v[..v.len() - 1], 1u64 << 30),
        _ => (v, 1),
    };
    if num.is_empty() || num.len() > 12 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    num.parse::<u64>().ok()?.checked_mul(mult)
}

fn parse_int(v: &str) -> Option<i64> {
    let v = v.trim();
    let digits = v.strip_prefix('-').unwrap_or(v);
    if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse().ok()
}

/// Type and bounds of each of the 8 [`INI_KEYS`] (contract A3, hardened after
/// the 22.04 run of 18/11/2026, where `memory_limit = lots` was accepted and
/// written). The pool route bounds its own copies of these keys; the global
/// php.ini, which every site inherits, now does too. Pure: the timezone's
/// existence on disk is checked by the caller.
pub fn validate_ini_value(key: &str, value: &str) -> Result<(), String> {
    const MB: u64 = 1 << 20;
    const GB: u64 = 1 << 30;
    let v = value.trim();
    let size_in = |lo: u64, hi: u64, what: &str| -> Result<(), String> {
        match parse_size(v) {
            Some(b) if b >= lo && b <= hi => Ok(()),
            _ => Err(format!("{key} must be {what} (for example 256M)")),
        }
    };
    let int_in = |lo: i64, hi: i64| -> Result<(), String> {
        match parse_int(v) {
            Some(n) if n >= lo && n <= hi => Ok(()),
            _ => Err(format!("{key} must be a whole number between {lo} and {hi}")),
        }
    };
    match key {
        "memory_limit" if v == "-1" => Ok(()),
        "memory_limit" => size_in(16 * MB, 16 * GB, "-1 or a size between 16M and 16G"),
        "upload_max_filesize" => size_in(1 << 10, 16 * GB, "a size between 1K and 16G"),
        "post_max_size" if v == "0" => Ok(()),
        "post_max_size" => size_in(1 << 10, 16 * GB, "0 or a size between 1K and 16G"),
        "max_execution_time" => int_in(0, 86_400),
        "max_input_time" => int_in(-1, 86_400),
        "display_errors" => {
            let l = v.to_ascii_lowercase();
            if matches!(l.as_str(), "on" | "off" | "1" | "0" | "true" | "false" | "yes" | "no" | "stdout" | "stderr") {
                Ok(())
            } else {
                Err(format!("{key} must be On, Off, stdout or stderr"))
            }
        }
        "error_reporting" => {
            let shape_ok = !v.is_empty()
                && v.len() <= 256
                && v.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || " _&|~^()-".contains(c));
            let tokens_ok = v
                .split(|c: char| " &|~^()".contains(c))
                .filter(|t| !t.is_empty())
                .all(|t| (t.starts_with("E_") && t.len() > 2) || parse_int(t).is_some());
            if shape_ok && tokens_ok {
                Ok(())
            } else {
                Err(format!("{key} must be an expression of E_* constants (for example E_ALL & ~E_DEPRECATED)"))
            }
        }
        "date.timezone" => {
            let ok = !v.is_empty()
                && v.len() <= 64
                && v.split('/').count() <= 3
                && v.split('/').all(|p| {
                    !p.is_empty()
                        && p.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                        && p.chars().all(|c| c.is_ascii_alphanumeric() || "_+-".contains(c))
                });
            if ok {
                Ok(())
            } else {
                Err(format!("{key} must be a timezone name such as Europe/Paris or UTC"))
            }
        }
        _ => Err(format!("{key} cannot be set here. Allowed: {}", INI_KEYS.join(", "))),
    }
}

/// Raw-editor checks before anything is written: the file keeps its `[PHP]`
/// section, and every one of the 8 main keys it sets passes
/// [`validate_ini_value`]. Returns the timezone to check on disk, if any.
pub fn validate_ini_content(content: &str) -> Result<Option<String>, String> {
    if !content.lines().any(|l| section_header(l).is_some_and(|h| h == "PHP")) {
        return Err("php.ini content has no [PHP] section - send the whole file, not an extract".into());
    }
    let values = read_ini_values(content);
    for (k, v) in &values {
        if let Some(v) = v {
            validate_ini_value(k, v)?;
        }
    }
    Ok(values.get("date.timezone").cloned().flatten())
}

/// `Unable to load dynamic library ...` lines of a `php-fpm -t` output that
/// were not already in `before` (the test of the file being replaced). PHP
/// reports a missing extension as a startup warning and `-t` still succeeds,
/// so the raw editor could drop or misspell an extension unnoticed; a warning
/// the server already had does not block an unrelated edit.
pub fn new_startup_failures(before: &str, after: &str) -> Vec<String> {
    let pick = |s: &str| -> Vec<String> {
        s.lines()
            .filter(|l| l.to_ascii_lowercase().contains("unable to load dynamic library"))
            .map(|l| l.trim().to_string())
            .collect()
    };
    let old = pick(before);
    pick(after).into_iter().filter(|l| !old.contains(l)).collect()
}

/// The FPM php.ini of a version (Debian layout).
pub fn ini_path(version: &str) -> String {
    format!("/etc/php/{version}/fpm/php.ini")
}

/// `[PATH=…]` / `[HOST=…]` sections apply to some requests only; a value set
/// there is not the global one, so neither reading nor editing looks inside.
fn is_scoped_section(header: &str) -> bool {
    let h = header.to_ascii_uppercase();
    h.starts_with("PATH=") || h.starts_with("HOST=")
}

/// Section name if `line` is a `[section]` header.
fn section_header(line: &str) -> Option<&str> {
    let t = line.trim();
    t.strip_prefix('[')?.strip_suffix(']')
}

/// If `line` is an active `key = value` assignment of `key`, the raw value.
fn active_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let t = line.trim_start();
    let rest = t.strip_prefix(key)?;
    let rest = rest.trim_start().strip_prefix('=')?;
    Some(rest.trim())
}

/// `;key = …` (any spaces after the `;`, `=` required - so prose lines like
/// `; display_errors` in the quick-reference block never match).
fn is_commented_assignment(line: &str, key: &str) -> bool {
    let t = line.trim_start();
    match t.strip_prefix(';') {
        Some(rest) => active_value(rest, key).is_some(),
        None => false,
    }
}

/// Strip one pair of surrounding double quotes, and a trailing `; comment`
/// after an unquoted value.
fn clean_value(raw: &str) -> String {
    let raw = raw.trim();
    if let Some(inner) = raw.strip_prefix('"').and_then(|r| r.split('"').next()) {
        return inner.to_string();
    }
    raw.split(';').next().unwrap_or("").trim().to_string()
}

/// Effective value of each [`INI_KEYS`] entry: the LAST active assignment in
/// the file wins (as in PHP); `None` when absent or only commented out.
pub fn read_ini_values(content: &str) -> BTreeMap<String, Option<String>> {
    let mut out: BTreeMap<String, Option<String>> =
        INI_KEYS.iter().map(|k| (k.to_string(), None)).collect();
    let mut scoped = false;
    for line in content.lines() {
        if let Some(h) = section_header(line) {
            scoped = is_scoped_section(h);
            continue;
        }
        if scoped {
            continue;
        }
        for k in INI_KEYS {
            if let Some(v) = active_value(line, k) {
                out.insert(k.to_string(), Some(clean_value(v)));
            }
        }
    }
    out
}

/// Set `key = value` for each entry of `values`:
/// 1. the last active line of the key is replaced;
/// 2. else the first commented `;key = …` line is replaced, uncommented;
/// 3. else the line is appended at the end of the `[PHP]` section (before
///    the next section header), or at the end of the file without `[PHP]`.
///
/// Everything else in the file is kept byte for byte (line endings included).
pub fn set_ini_values(content: &str, values: &BTreeMap<String, String>) -> String {
    // split_inclusive keeps each line's own terminator (\n or \r\n).
    let mut lines: Vec<String> = content.split_inclusive('\n').map(String::from).collect();

    for (key, value) in values {
        let new_body = format!("{key} = {value}");
        let mut last_active = None;
        let mut first_commented = None;
        let mut scoped = false;
        for (i, line) in lines.iter().enumerate() {
            if let Some(h) = section_header(line) {
                scoped = is_scoped_section(h);
                continue;
            }
            if scoped {
                continue;
            }
            if active_value(line, key).is_some() {
                last_active = Some(i);
            } else if first_commented.is_none() && is_commented_assignment(line, key) {
                first_commented = Some(i);
            }
        }
        if let Some(i) = last_active.or(first_commented) {
            let eol = line_ending(&lines[i]);
            lines[i] = format!("{new_body}{eol}");
            continue;
        }

        // Append inside [PHP]: after its last non-blank line.
        let php_start = lines
            .iter()
            .position(|l| section_header(l).is_some_and(|h| h.eq_ignore_ascii_case("PHP")));
        let insert_at = match php_start {
            Some(start) => {
                let next = lines
                    .iter()
                    .enumerate()
                    .skip(start + 1)
                    .find(|(_, l)| section_header(l).is_some())
                    .map(|(i, _)| i)
                    .unwrap_or(lines.len());
                let mut at = next;
                while at > start + 1 && lines[at - 1].trim().is_empty() {
                    at -= 1;
                }
                at
            }
            None => lines.len(),
        };
        let eol = lines.first().map(|l| line_ending(l)).filter(|e| !e.is_empty()).unwrap_or("\n");
        // The line before the insertion point may be a last line without a
        // terminator; give it one so the new line does not glue onto it.
        if insert_at > 0 && line_ending(&lines[insert_at - 1]).is_empty() {
            lines[insert_at - 1].push_str(eol);
        }
        lines.insert(insert_at, format!("{new_body}{eol}"));
    }
    lines.concat()
}

fn line_ending(line: &str) -> &'static str {
    if line.ends_with("\r\n") {
        "\r\n"
    } else if line.ends_with('\n') {
        "\n"
    } else {
        ""
    }
}

/// Verdict on `php-fpm<ver> -t`. A php.ini syntax error does not make FPM
/// exit non-zero - it prints `PHP:  syntax error, unexpected … in
/// /etc/php/X.Y/fpm/php.ini on line N` and carries on - so the output is read
/// too, or a broken php.ini would pass and be restarted into.
pub fn ini_test_passed(exit_ok: bool, output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    exit_ok && !lower.contains("syntax error") && !lower.contains("parse error")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "[PHP]\n\
; display_errors\n\
;   Default Value: On\n\
engine = On\n\
memory_limit = 128M\n\
max_execution_time = 30\n\
memory_limit = 256M\n\
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT\n\
display_errors = Off\n\
upload_max_filesize = \"2M\" ; quoted\n\
\n\
[CLI Server]\n\
cli_server.color = On\n\
\n\
[Date]\n\
;date.timezone =\n\
\n\
[PATH=/var/www/x]\n\
max_input_time = 5\n";

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn read_takes_the_last_active_value_and_ignores_comments() {
        let v = read_ini_values(SAMPLE);
        assert_eq!(v["memory_limit"].as_deref(), Some("256M"));
        assert_eq!(v["max_execution_time"].as_deref(), Some("30"));
        assert_eq!(v["display_errors"].as_deref(), Some("Off"));
        assert_eq!(v["error_reporting"].as_deref(), Some("E_ALL & ~E_DEPRECATED & ~E_STRICT"));
        assert_eq!(v["upload_max_filesize"].as_deref(), Some("2M"));
        assert_eq!(v["date.timezone"], None, "commented out");
        assert_eq!(v["post_max_size"], None, "absent");
        assert_eq!(v["max_input_time"], None, "only in a [PATH=] section");
        assert_eq!(v.len(), INI_KEYS.len());
    }

    #[test]
    fn set_replaces_the_last_active_line() {
        let out = set_ini_values(SAMPLE, &map(&[("memory_limit", "512M")]));
        assert!(out.contains("memory_limit = 128M\n"), "earlier duplicate left alone");
        assert!(out.contains("max_execution_time = 30\nmemory_limit = 512M\n"));
        assert_eq!(read_ini_values(&out)["memory_limit"].as_deref(), Some("512M"));
        assert_eq!(out.len(), SAMPLE.len(), "only that line changed");
    }

    #[test]
    fn set_uncomments_the_commented_line_in_its_own_section() {
        let out = set_ini_values(SAMPLE, &map(&[("date.timezone", "Europe/Paris")]));
        assert!(out.contains("[Date]\ndate.timezone = Europe/Paris\n"));
        assert!(!out.contains(";date.timezone"));
        assert_eq!(read_ini_values(&out)["date.timezone"].as_deref(), Some("Europe/Paris"));
    }

    #[test]
    fn set_does_not_mistake_prose_for_a_commented_assignment() {
        let src = "[PHP]\n; display_errors\n;   Default Value: On\nengine = On\n\n[Date]\n";
        let out = set_ini_values(src, &map(&[("display_errors", "On")]));
        assert!(out.contains("; display_errors\n"), "prose kept");
        assert_eq!(out, "[PHP]\n; display_errors\n;   Default Value: On\nengine = On\ndisplay_errors = On\n\n[Date]\n");
    }

    #[test]
    fn set_appends_at_the_end_of_the_php_section() {
        let out = set_ini_values(SAMPLE, &map(&[("post_max_size", "64M")]));
        assert!(out.contains("upload_max_filesize = \"2M\" ; quoted\npost_max_size = 64M\n\n[CLI Server]\n"));
    }

    #[test]
    fn set_ignores_path_sections_and_appends_globally() {
        let out = set_ini_values(SAMPLE, &map(&[("max_input_time", "60")]));
        assert!(out.contains("[PATH=/var/www/x]\nmax_input_time = 5\n"), "scoped value untouched");
        assert!(out.contains("; quoted\nmax_input_time = 60\n\n[CLI Server]"));
    }

    #[test]
    fn set_without_php_section_appends_at_end_even_without_trailing_newline() {
        let out = set_ini_values("engine = On", &map(&[("memory_limit", "1G")]));
        assert_eq!(out, "engine = On\nmemory_limit = 1G\n");
    }

    #[test]
    fn set_keeps_crlf_line_endings() {
        let src = "[PHP]\r\nmemory_limit = 128M\r\n[Date]\r\n";
        let out = set_ini_values(src, &map(&[("memory_limit", "256M"), ("max_input_time", "60")]));
        assert_eq!(out, "[PHP]\r\nmemory_limit = 256M\r\nmax_input_time = 60\r\n[Date]\r\n");
    }

    #[test]
    fn key_prefix_does_not_match_a_longer_key() {
        let src = "[PHP]\nmemory_limit_extra = 1\n";
        assert_eq!(read_ini_values(src)["memory_limit"], None);
    }

    #[test]
    fn ini_test_verdict() {
        assert!(ini_test_passed(true, "NOTICE: configuration file /etc/php/8.3/fpm/php-fpm.conf test is successful"));
        assert!(!ini_test_passed(false, "ERROR: failed"));
        assert!(!ini_test_passed(
            true,
            "PHP:  syntax error, unexpected '=' in /etc/php/8.3/fpm/php.ini on line 12\nNOTICE: configuration file /etc/php/8.3/fpm/php-fpm.conf test is successful"
        ));
    }

    #[test]
    fn ini_values_are_typed_and_bounded() {
        for (k, v) in [
            ("memory_limit", "256M"), ("memory_limit", "-1"), ("memory_limit", "2G"),
            ("upload_max_filesize", "64M"), ("post_max_size", "0"), ("post_max_size", "72M"),
            ("max_execution_time", "0"), ("max_execution_time", "300"), ("max_input_time", "-1"),
            ("display_errors", "Off"), ("display_errors", "stderr"),
            ("error_reporting", "E_ALL & ~E_DEPRECATED & ~E_STRICT"), ("error_reporting", "E_ALL"),
            ("error_reporting", "32767"), ("date.timezone", "Europe/Paris"), ("date.timezone", "UTC"),
            ("date.timezone", "America/Argentina/Buenos_Aires"),
        ] {
            assert!(validate_ini_value(k, v).is_ok(), "{k} = {v}");
        }
        // s18/11 on 22.04: `memory_limit: "lots"` went through and was written.
        for (k, v) in [
            ("memory_limit", "lots"), ("memory_limit", "8M"), ("memory_limit", "64G"), ("memory_limit", ""),
            ("memory_limit", "12Q"), ("upload_max_filesize", "0"), ("post_max_size", "-1"),
            ("max_execution_time", "-5"), ("max_execution_time", "abc"), ("max_input_time", "999999"),
            ("display_errors", "maybe"), ("error_reporting", "E_ALL; system"), ("error_reporting", "foo"),
            ("date.timezone", "../../etc/passwd"), ("date.timezone", "/etc/passwd"), ("date.timezone", ""),
            ("engine", "On"),
        ] {
            assert!(validate_ini_value(k, v).is_err(), "{k} = {v} should be refused");
        }
    }

    #[test]
    fn raw_content_checks() {
        assert_eq!(validate_ini_content(SAMPLE), Ok(None));
        assert_eq!(
            validate_ini_content("[PHP]\ndate.timezone = Europe/Paris\n"),
            Ok(Some("Europe/Paris".into()))
        );
        // The 3-line replacement of the 22.04 run: no [PHP] section.
        assert!(validate_ini_content("extension=nope\nmemory_limit=128M\nengine=On\n").is_err());
        assert!(validate_ini_content("[PHP]\nmemory_limit = lots\n").is_err());
        // A value set only inside a [PATH=] section is not the global one.
        assert!(validate_ini_content("[PHP]\n[PATH=/var/www/x]\nmemory_limit = lots\n").is_ok());
    }

    #[test]
    fn only_new_extension_failures_count() {
        let warn = "PHP Warning:  PHP Startup: Unable to load dynamic library 'nope' (tried: /usr/lib/php/20210902/nope (cannot open)) in Unknown on line 0";
        let ok = "NOTICE: configuration file /etc/php/8.1/fpm/php-fpm.conf test is successful";
        assert!(new_startup_failures(ok, ok).is_empty());
        assert_eq!(new_startup_failures(ok, &format!("{warn}\n{ok}")).len(), 1);
        // Already broken before this edit: not this edit's fault.
        assert!(new_startup_failures(&format!("{warn}\n{ok}"), &format!("{warn}\n{ok}")).is_empty());
    }
}
