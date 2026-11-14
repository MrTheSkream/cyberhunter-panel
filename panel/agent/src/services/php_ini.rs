//! Global `php.ini` editor helpers (per version, FPM only — never the CLI
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

/// `;key = …` (any spaces after the `;`, `=` required — so prose lines like
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
/// exit non-zero — it prints `PHP:  syntax error, unexpected … in
/// /etc/php/X.Y/fpm/php.ini on line N` and carries on — so the output is read
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
}
