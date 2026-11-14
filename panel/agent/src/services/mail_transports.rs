//! Per-domain outgoing IP for Postfix - pure text generation.
//!
//! One `smtp` transport per send IP, named `dp-ip-a-b-c-d`, declared in a
//! managed block of `master.cf` with `smtp_bind_address` (and the PTR as
//! `smtp_helo_name`). `/etc/postfix/sender_transport` routes each sender
//! domain to its transport through `sender_dependent_default_transport_maps`.
//!
//! The rate limit is the subtle part: `<transport>_destination_rate_delay`
//! and `<transport>_extra_recipient_limit` are read by **qmgr from main.cf**
//! (a `-o` in master.cf would be ignored), and the per-transport defaults are
//! `$default_destination_rate_delay` / `$default_extra_recipient_limit`, NOT
//! the `smtp_` values the rate-limit route writes. So without a copy of those
//! values per transport, every domain moved to its own IP would escape the
//! limit. [`render_main_block`] writes that copy, in a managed block of
//! `main.cf`, and is called both by the mail sync and by the rate-limit route.
//!
//! Everything here is pure so the blocks can be tested for idempotency, clean
//! removal and stable names; the IO lives in `routes/mail.rs`.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

pub const SENDER_TRANSPORT_MAP: &str = "/etc/postfix/sender_transport";

pub const MASTER_BEGIN: &str = "# BEGIN DockPanel IP transports (generated, do not edit)";
pub const MASTER_END: &str = "# END DockPanel IP transports";
/// The main.cf markers must not contain `# DockPanel rate limit` (the
/// rate-limit route drops every line containing that) nor
/// `# DockPanel relay` (the relay routes do the same).
pub const MAIN_BEGIN: &str = "# BEGIN DockPanel IP transport limits (generated, do not edit)";
pub const MAIN_END: &str = "# END DockPanel IP transport limits";

/// Begin markers are matched on this prefix, so rewording the "(generated…)"
/// note never orphans an older block.
fn begin_prefix(begin: &str) -> &str {
    begin.split(" (").next().unwrap_or(begin)
}

/// `192.0.2.107` → `dp-ip-192-0-2-107`.
pub fn transport_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("dp-ip-{}-{}-{}-{}", o[0], o[1], o[2], o[3])
}

/// Send IPs → optional HELO name (the IP's PTR). Ordered by IP for stable output.
pub type Transports = BTreeMap<Ipv4Addr, Option<String>>;

/// The managed master.cf block, markers included; empty when there is no
/// transport (the block is then removed).
pub fn render_master_block(transports: &Transports) -> String {
    if transports.is_empty() {
        return String::new();
    }
    let mut out = format!("{MASTER_BEGIN}\n");
    for (ip, helo) in transports {
        out.push_str(&format!("{} unix - - n - - smtp\n", transport_name(*ip)));
        out.push_str(&format!("  -o smtp_bind_address={ip}\n"));
        if let Some(h) = helo {
            out.push_str(&format!("  -o smtp_helo_name={h}\n"));
        }
        // smtp_bind_address only covers IPv4: without this, mail to an
        // IPv6-reachable MX would leave from the host's IPv6 instead.
        out.push_str("  -o inet_protocols=ipv4\n");
    }
    out.push_str(MASTER_END);
    out.push('\n');
    out
}

/// Replace the block delimited by `begin`/`end` in `text` with `block`
/// (which carries its own markers, or is empty to remove the block).
///
/// Every existing occurrence is removed and the new block is appended at the
/// end of the file. Idempotent: applying the same block twice yields the same
/// text. A begin marker with no end removes through end of file - only our
/// own generated lines can follow it, and leaving half a block would make
/// Postfix read it as part of the previous service.
pub fn replace_block(text: &str, begin: &str, end: &str, block: &str) -> String {
    let prefix = begin_prefix(begin);
    // No block present and none wanted: the text is returned byte for byte,
    // so a box that never used the feature is never rewritten (and the
    // caller's "nothing changed" test stays true).
    if block.is_empty() && !text.lines().any(|l| l.trim_end().starts_with(prefix)) {
        return text.to_string();
    }
    let mut kept: Vec<&str> = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if !inside && line.trim_end().starts_with(prefix) {
            inside = true;
            continue;
        }
        if inside {
            if line.trim_end() == end {
                inside = false;
            }
            continue;
        }
        kept.push(line);
    }
    // Drop the blank lines a previous append left at the end, so repeated
    // rewrites do not grow the file.
    while kept.last().is_some_and(|l| l.trim().is_empty()) {
        kept.pop();
    }
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    if !block.is_empty() {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(block);
    }
    out
}

/// Names of the transports currently declared in the master.cf block - what
/// the rate-limit route regenerates main.cf from, since it has no domain list.
pub fn transports_in_block(master_cf: &str) -> Vec<String> {
    let prefix = begin_prefix(MASTER_BEGIN);
    let mut names = Vec::new();
    let mut inside = false;
    for line in master_cf.lines() {
        let t = line.trim_end();
        if !inside {
            inside = t.starts_with(prefix);
            continue;
        }
        if t == MASTER_END {
            break;
        }
        if line.starts_with(char::is_whitespace) || t.starts_with('#') || t.is_empty() {
            continue;
        }
        if let Some(name) = t.split_whitespace().next() {
            names.push(name.to_string());
        }
    }
    names
}

/// The transports (IP + HELO) the master.cf block currently declares, read
/// back from its `-o smtp_bind_address=` / `-o smtp_helo_name=` lines. Used to
/// declare old ∪ new transports while the map is being swapped.
pub fn parse_master_block(master_cf: &str) -> Transports {
    let prefix = begin_prefix(MASTER_BEGIN);
    let mut out = Transports::new();
    let mut inside = false;
    let mut current: Option<(Option<Ipv4Addr>, Option<String>)> = None;
    let flush = |cur: &mut Option<(Option<Ipv4Addr>, Option<String>)>, out: &mut Transports| {
        if let Some((Some(ip), helo)) = cur.take() {
            out.insert(ip, helo);
        }
    };
    for line in master_cf.lines() {
        let t = line.trim();
        if !inside {
            inside = line.trim_end().starts_with(prefix);
            continue;
        }
        if t == MASTER_END {
            break;
        }
        if line.starts_with(char::is_whitespace) {
            if let Some(cur) = current.as_mut() {
                if let Some(v) = t.strip_prefix("-o smtp_bind_address=") {
                    cur.0 = v.trim().parse().ok();
                } else if let Some(v) = t.strip_prefix("-o smtp_helo_name=") {
                    cur.1 = Some(v.trim().to_string());
                }
            }
        } else if !t.is_empty() && !t.starts_with('#') {
            flush(&mut current, &mut out);
            current = Some((None, None));
        }
    }
    flush(&mut current, &mut out);
    out
}

/// Comment line, inside the main.cf managed block, recording the
/// `smtp_helo_name` value the panel set - so that a later sync without
/// `primary_helo` removes *our* value and never an admin's own.
const HELO_RECORD: &str = "# managed smtp_helo_name = ";

/// The `smtp_helo_name` the panel last set, if recorded in the block.
pub fn recorded_helo(main_cf: &str) -> Option<String> {
    let prefix = begin_prefix(MAIN_BEGIN);
    let mut inside = false;
    for line in main_cf.lines() {
        let t = line.trim_end();
        if !inside {
            inside = t.starts_with(prefix);
            continue;
        }
        if t == MAIN_END {
            break;
        }
        if let Some(v) = t.strip_prefix(HELO_RECORD) {
            let v = v.trim();
            return (!v.is_empty()).then(|| v.to_string());
        }
    }
    None
}

/// Value of a top-level `key = value` in main.cf, outside our managed block.
/// The last occurrence wins, as it does for Postfix.
pub fn main_cf_value(main_cf: &str, key: &str) -> Option<String> {
    let mut value = None;
    for line in main_cf.lines() {
        if line.starts_with(char::is_whitespace) || line.trim_start().starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                value = Some(v.trim().to_string());
            }
        }
    }
    value.filter(|v| !v.is_empty())
}

/// The managed main.cf block: each transport's copy of the global
/// `smtp_destination_rate_delay` / `smtp_extra_recipient_limit`. Empty (block
/// removed) when there is no transport or no global value to copy - absent
/// globals mean the defaults, which are the same for every transport.
pub fn render_main_block(names: &[String], main_cf: &str, helo_record: Option<&str>) -> String {
    let delay = main_cf_value(main_cf, "smtp_destination_rate_delay");
    let limit = main_cf_value(main_cf, "smtp_extra_recipient_limit");
    let limits = !names.is_empty() && (delay.is_some() || limit.is_some());
    if !limits && helo_record.is_none() {
        return String::new();
    }
    let mut out = format!("{MAIN_BEGIN}\n");
    if let Some(h) = helo_record {
        out.push_str(&format!("{HELO_RECORD}{h}\n"));
    }
    for n in names.iter().filter(|_| limits) {
        if let Some(d) = &delay {
            out.push_str(&format!("{n}_destination_rate_delay = {d}\n"));
        }
        if let Some(l) = &limit {
            out.push_str(&format!("{n}_extra_recipient_limit = {l}\n"));
        }
    }
    out.push_str(MAIN_END);
    out.push('\n');
    out
}

/// `main.cf` with its managed block regenerated for the transports declared
/// in `master_cf`. The one generator both callers use.
/// The HELO record already in `main_cf` is preserved (the rate-limit route
/// must not forget it).
pub fn main_cf_with_limits(main_cf: &str, master_cf: &str) -> String {
    main_cf_with_block(main_cf, master_cf, recorded_helo(main_cf).as_deref())
}

/// Same, with an explicit HELO record (`None` drops it) - what the sync uses.
pub fn main_cf_with_block(main_cf: &str, master_cf: &str, helo_record: Option<&str>) -> String {
    let names = transports_in_block(master_cf);
    let block = render_main_block(&names, main_cf, helo_record);
    replace_block(main_cf, MAIN_BEGIN, MAIN_END, &block)
}

/// Content of [`SENDER_TRANSPORT_MAP`]: `@domain<TAB>dp-ip-…:` per domain,
/// sorted by domain. Empty map when nothing is routed.
pub fn render_sender_transport(routes: &BTreeMap<String, Ipv4Addr>) -> String {
    routes
        .iter()
        .map(|(domain, ip)| format!("@{domain}\t{}:\n", transport_name(*ip)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    const MASTER: &str = "smtp      inet  n       -       y       -       -       smtpd\nsubmission inet n - y - - smtpd\n  -o syslog_name=postfix/submission\n";
    const MAIN: &str = "myhostname = mail.lab\n\n# DockPanel rate limit: 100/hour\nsmtp_destination_rate_delay = 36s\nsmtp_extra_recipient_limit = 50\n";

    fn transports() -> Transports {
        let mut t = Transports::new();
        t.insert(ip("192.168.250.12"), None);
        t.insert(ip("192.0.2.107"), Some("mail2.example.fr".into()));
        t
    }

    #[test]
    fn names_are_stable() {
        assert_eq!(transport_name(ip("192.0.2.107")), "dp-ip-192-0-2-107");
        assert_eq!(transport_name(ip("192.168.250.12")), "dp-ip-192-168-250-12");
    }

    #[test]
    fn master_block_shape() {
        let b = render_master_block(&transports());
        assert!(b.starts_with(MASTER_BEGIN));
        assert!(b.ends_with(&format!("{MASTER_END}\n")));
        // Ordered by IP (51.x before 192.x), helo only where given.
        let first = b.find("dp-ip-192-0-2-107").unwrap();
        let second = b.find("dp-ip-192-168-250-12").unwrap();
        assert!(first < second);
        assert!(b.contains("dp-ip-192-0-2-107 unix - - n - - smtp\n  -o smtp_bind_address=192.0.2.107\n  -o smtp_helo_name=mail2.example.fr\n  -o inet_protocols=ipv4\n"));
        assert!(b.contains("dp-ip-192-168-250-12 unix - - n - - smtp\n  -o smtp_bind_address=192.168.250.12\n  -o inet_protocols=ipv4\n"));
        assert_eq!(render_master_block(&Transports::new()), "");
    }

    #[test]
    fn master_replacement_is_idempotent_and_removable() {
        let block = render_master_block(&transports());
        let once = replace_block(MASTER, MASTER_BEGIN, MASTER_END, &block);
        let twice = replace_block(&once, MASTER_BEGIN, MASTER_END, &block);
        assert_eq!(once, twice);
        assert!(once.starts_with(MASTER));
        assert_eq!(once.matches(MASTER_BEGIN).count(), 1);
        assert_eq!(transports_in_block(&once), vec!["dp-ip-192-0-2-107", "dp-ip-192-168-250-12"]);

        // A changed set replaces, never accumulates.
        let mut t = Transports::new();
        t.insert(ip("10.0.0.5"), None);
        let changed = replace_block(&once, MASTER_BEGIN, MASTER_END, &render_master_block(&t));
        assert_eq!(transports_in_block(&changed), vec!["dp-ip-10-0-0-5"]);
        assert!(!changed.contains("192.0.2.107"));

        // Empty set: the file is back to what it was.
        let removed = replace_block(&once, MASTER_BEGIN, MASTER_END, "");
        assert_eq!(removed, MASTER);
        assert!(transports_in_block(&removed).is_empty());
        // Removing from a file that never had a block changes nothing, byte
        // for byte - even odd endings (relay_remove writes no final newline).
        assert_eq!(replace_block(MASTER, MASTER_BEGIN, MASTER_END, ""), MASTER);
        assert_eq!(replace_block("a\nb", MASTER_BEGIN, MASTER_END, ""), "a\nb");
        assert_eq!(replace_block("a\n\n", MASTER_BEGIN, MASTER_END, ""), "a\n\n");
        assert_eq!(main_cf_with_limits("a\nb", MASTER), "a\nb");
    }

    #[test]
    fn block_in_the_middle_and_missing_trailing_newline() {
        let block = render_master_block(&transports());
        let middle = format!("a unix - - n - - x\n{block}b unix - - n - - y");
        let out = replace_block(&middle, MASTER_BEGIN, MASTER_END, &block);
        assert!(out.starts_with("a unix - - n - - x\nb unix - - n - - y\n\n"));
        assert!(out.ends_with(&format!("{MASTER_END}\n")));
        assert_eq!(out.matches(MASTER_BEGIN).count(), 1);
    }

    #[test]
    fn main_block_copies_global_limits() {
        let master = replace_block(MASTER, MASTER_BEGIN, MASTER_END, &render_master_block(&transports()));
        let main = main_cf_with_limits(MAIN, &master);
        assert!(main.starts_with(MAIN.trim_end()));
        assert!(main.contains("dp-ip-192-0-2-107_destination_rate_delay = 36s\ndp-ip-192-0-2-107_extra_recipient_limit = 50\n"));
        assert!(main.contains("dp-ip-192-168-250-12_destination_rate_delay = 36s\n"));
        // Idempotent.
        assert_eq!(main_cf_with_limits(&main, &master), main);
        // The rate-limit route's own filters do not touch our markers.
        assert!(!MAIN_BEGIN.contains("# DockPanel rate limit") && !MAIN_END.contains("# DockPanel rate limit"));
        assert!(!MAIN_BEGIN.contains("# DockPanel relay"));
        // Our own lines are never mistaken for the global value.
        assert_eq!(main_cf_value(&main, "smtp_destination_rate_delay").as_deref(), Some("36s"));
    }

    #[test]
    fn main_block_follows_a_rate_change_and_removal() {
        let master = replace_block(MASTER, MASTER_BEGIN, MASTER_END, &render_master_block(&transports()));
        let main = main_cf_with_limits(MAIN, &master);
        let changed_rate = main.replace("smtp_destination_rate_delay = 36s", "smtp_destination_rate_delay = 172s");
        let regenerated = main_cf_with_limits(&changed_rate, &master);
        assert!(regenerated.contains("dp-ip-192-0-2-107_destination_rate_delay = 172s"));
        assert!(!regenerated.contains("= 36s"));
        // No transports any more → block gone, file back to the original.
        assert_eq!(main_cf_with_limits(&main, MASTER), MAIN);
        // No global limit → no block.
        assert_eq!(main_cf_with_limits("myhostname = x\n", &master), "myhostname = x\n");
    }

    #[test]
    fn master_block_reads_back() {
        let master = replace_block(MASTER, MASTER_BEGIN, MASTER_END, &render_master_block(&transports()));
        assert_eq!(parse_master_block(&master), transports());
        assert!(parse_master_block(MASTER).is_empty());
    }

    #[test]
    fn helo_record_round_trip_and_survives_limit_refresh() {
        let master = replace_block(MASTER, MASTER_BEGIN, MASTER_END, &render_master_block(&transports()));
        let main = main_cf_with_block(MAIN, &master, Some("mail.example.fr"));
        assert_eq!(recorded_helo(&main).as_deref(), Some("mail.example.fr"));
        // The rate-limit refresh keeps the record.
        let changed = main.replace("= 36s", "= 72s");
        let refreshed = main_cf_with_limits(&changed, &master);
        assert_eq!(recorded_helo(&refreshed).as_deref(), Some("mail.example.fr"));
        assert!(refreshed.contains("dp-ip-192-0-2-107_destination_rate_delay = 72s"));
        // A record alone keeps a block even with no transports.
        let only = main_cf_with_block(MAIN, MASTER, Some("mail.example.fr"));
        assert_eq!(recorded_helo(&only).as_deref(), Some("mail.example.fr"));
        assert!(!only.contains("dp-ip-"));
        // Dropping it removes the block cleanly.
        assert_eq!(main_cf_with_block(&only, MASTER, None), MAIN);
        // The record is a comment: never read as the parameter itself.
        assert_eq!(main_cf_value(&only, "smtp_helo_name"), None);
        assert_eq!(recorded_helo(MAIN), None);
    }

    #[test]
    fn sender_transport_map() {
        let mut routes = BTreeMap::new();
        routes.insert("b.lab".to_string(), ip("192.168.250.12"));
        routes.insert("a.lab".to_string(), ip("192.168.250.11"));
        assert_eq!(
            render_sender_transport(&routes),
            "@a.lab\tdp-ip-192-168-250-11:\n@b.lab\tdp-ip-192-168-250-12:\n"
        );
        assert_eq!(render_sender_transport(&BTreeMap::new()), "");
    }
}
