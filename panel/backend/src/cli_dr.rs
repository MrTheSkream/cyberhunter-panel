//! `dockpanel-api dr list|restore`: disaster recovery from the command line of
//! a freshly installed machine (lot 2, step 2.5). Runs BEFORE any configuration
//! is read (no api.env, no database needed), like `--version`.
//!
//! ```text
//! dockpanel-api dr list    --destination-file <file> [--install-id <uuid>]
//! dockpanel-api dr restore --archive <name> --identity-file <file> --destination-file <file> [--yes]
//! ```
//!
//! Secrets are never read from the command line: the destination's credentials
//! come from the destination file (mode 0600) or are typed without echo, the
//! recovery key from the identity file (mode 0600). Any argument that looks like
//! a secret, or a flag meant to carry one, is refused. Everything goes through
//! the local agent (its socket, its token in /etc/dockpanel/agent.token).

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::services::agent::{AgentClient, AgentHandle};
use crate::services::dr_post_restore;
use crate::services::dr_restore::{self as rs, Reporter};
use crate::services::dr_snapshot as dr;
use crate::services::panel_snapshot::RESTORE_RESULT_PATH;

const AGENT_SOCKET: &str = "/var/run/dockpanel/agent.sock";
const AGENT_TOKEN_FILE: &str = "/etc/dockpanel/agent.token";

pub const USAGE: &str = "\
Usage:
  dockpanel-api dr list    --destination-file <file> [--install-id <uuid>]
  dockpanel-api dr restore --archive <name> --identity-file <file> --destination-file <file> [--yes]

  --destination-file  JSON file (mode 0600) describing the S3 or SFTP destination
                      the off-site snapshots were sent to. A secret it omits
                      (secret_key, password) is asked for without echo.
  --install-id        The Install ID of the lost server (Disaster recovery card).
                      May also be given as \"install_id\" in the destination file.
  --archive           cyberhunter-dr-<install id>-<stamp>.tar.gz.age, from `dr list`.
  --identity-file     The recovery key file (mode 0600), as saved at enrolment.
  --yes               Do not ask for confirmation.

Secrets are never accepted on the command line. See docs/guides/disaster-recovery.md.";

#[derive(Debug, Clone, PartialEq)]
pub enum DrCommand {
    List { destination_file: PathBuf, install_id: Option<Uuid> },
    Restore { archive: String, identity_file: PathBuf, destination_file: PathBuf, yes: bool },
}

/// Flags that would carry a secret: refused with an explanation.
const SECRET_FLAGS: &[&str] = &[
    "--identity", "--key", "--recovery-key", "--password", "--pass", "--secret", "--secret-key",
    "--access-key", "--passphrase", "--token",
];

/// Parse the arguments after `dr`.
pub fn parse_args(args: &[String]) -> Result<DrCommand, String> {
    for a in args {
        if a.contains("AGE-SECRET-KEY") {
            return Err("a recovery key was given on the command line: it is now in your shell history. \
                        Put it in a file (chmod 600) and pass --identity-file instead"
                .into());
        }
    }
    let (sub, rest) = args.split_first().ok_or("missing subcommand: list or restore")?;
    let mut opts: Vec<(String, Option<String>)> = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let a = &rest[i];
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if a.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        if SECRET_FLAGS.contains(&flag.as_str()) {
            return Err(format!(
                "{flag}: secrets are never accepted on the command line. Put them in the destination \
                 file or the identity file (mode 0600), or leave them out to be asked without echo"
            ));
        }
        if !flag.starts_with("--") {
            return Err(format!("unexpected argument '{a}'"));
        }
        if flag == "--yes" {
            opts.push((flag, None));
            i += 1;
            continue;
        }
        let value = match inline {
            Some(v) => v,
            None => {
                i += 1;
                rest.get(i).cloned().ok_or_else(|| format!("{flag} needs a value"))?
            }
        };
        if opts.iter().any(|(f, _)| *f == flag) {
            return Err(format!("{flag} is given twice"));
        }
        opts.push((flag, Some(value)));
        i += 1;
    }
    let get = |f: &str| opts.iter().find(|(k, _)| k == f).and_then(|(_, v)| v.clone());
    let allowed: &[&str] = match sub.as_str() {
        "list" => &["--destination-file", "--install-id"],
        "restore" => &["--archive", "--identity-file", "--destination-file", "--yes"],
        other => return Err(format!("unknown subcommand '{other}': list or restore")),
    };
    if let Some((f, _)) = opts.iter().find(|(f, _)| !allowed.contains(&f.as_str())) {
        return Err(format!("unknown option {f} for `dr {sub}`"));
    }
    let destination_file = PathBuf::from(get("--destination-file").ok_or("--destination-file is required")?);
    match sub.as_str() {
        "list" => {
            let install_id = match get("--install-id") {
                Some(s) => Some(Uuid::parse_str(s.trim()).map_err(|_| "--install-id must be a UUID")?),
                None => None,
            };
            Ok(DrCommand::List { destination_file, install_id })
        }
        _ => {
            let archive = get("--archive").ok_or("--archive is required")?;
            if rs::parse_archive_name(&archive).is_none() {
                return Err(format!("'{archive}' is not an off-site snapshot archive name (see `dr list`)"));
            }
            let identity_file = PathBuf::from(get("--identity-file").ok_or("--identity-file is required")?);
            Ok(DrCommand::Restore { archive, identity_file, destination_file, yes: opts.iter().any(|(f, _)| f == "--yes") })
        }
    }
}

/// Entry point from `main`. Returns the process exit code.
pub async fn run(args: &[String]) -> i32 {
    let cmd = match parse_args(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return 2;
        }
    };
    let r = match cmd {
        DrCommand::List { destination_file, install_id } => list(&destination_file, install_id).await,
        DrCommand::Restore { archive, identity_file, destination_file, yes } => {
            restore(&archive, &identity_file, &destination_file, yes).await
        }
    };
    match r {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn agent() -> Result<AgentHandle, String> {
    let token = std::fs::read_to_string(AGENT_TOKEN_FILE).map_err(|e| {
        format!("cannot read {AGENT_TOKEN_FILE} ({e}): run this as root on the machine the panel is installed on")
    })?;
    let token = Zeroizing::new(token.trim().to_string());
    if token.is_empty() {
        return Err(format!("{AGENT_TOKEN_FILE} is empty"));
    }
    Ok(AgentHandle::Local(AgentClient::new(AGENT_SOCKET.to_string(), token.to_string())))
}

/// Read the destination file, ask for the secret it omits.
fn destination(path: &Path) -> Result<rs::DestinationSpec, String> {
    rs::private_enough(path)?;
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?);
    let mut spec = rs::parse_destination_file(&text)?;
    if let Some(field) = spec.missing_secret {
        let label = if field == "secret_key" { "S3 secret key" } else { "SFTP password" };
        let secret = read_secret(&format!("{label}: "))?;
        if secret.is_empty() {
            return Err(format!("no {label} given"));
        }
        if let Some(o) = spec.payload.as_object_mut() {
            o.insert(field.to_string(), serde_json::Value::String(secret.to_string()));
        }
    }
    Ok(spec)
}

/// Read one line from the terminal without echo (stty), never from argv.
fn read_secret(prompt: &str) -> Result<Zeroizing<String>, String> {
    let echo_off = std::process::Command::new("stty")
        .arg("-echo")
        .stdin(std::process::Stdio::inherit())
        .status()
        .map_err(|e| format!("cannot run stty: {e}"))?;
    if !echo_off.success() {
        return Err("no terminal to type the secret on: put it in the destination file (mode 0600)".into());
    }
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = Zeroizing::new(String::new());
    let read = std::io::stdin().lock().read_line(&mut line);
    let restored = std::process::Command::new("stty").arg("echo").stdin(std::process::Stdio::inherit()).status();
    eprintln!();
    if !restored.is_ok_and(|s| s.success()) {
        eprintln!("warning: the terminal echo could not be turned back on: run `stty echo`");
    }
    read.map_err(|e| format!("reading the secret: {e}"))?;
    Ok(Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string()))
}

async fn list(destination_file: &Path, install_id: Option<Uuid>) -> Result<i32, String> {
    let spec = destination(destination_file)?;
    let install_id = install_id.or(spec.install_id).ok_or(
        "the Install ID of the lost server is needed: --install-id <uuid>, or \"install_id\" in the destination file \
         (it is on the Disaster recovery card, and in every archive name)",
    )?;
    let agent = agent()?;
    let payload = dr::dr_destination_payload(&spec.payload, install_id);
    let objects = rs::list_remote(&agent, &payload, install_id).await?;
    let archives: Vec<&rs::Listed> = objects.iter().filter(|o| o.name.ends_with(".tar.gz.age")).collect();
    if archives.is_empty() {
        println!("No off-site snapshot of install {install_id} at this destination.");
        return Ok(1);
    }
    let (version, arch) = (env!("CARGO_PKG_VERSION"), std::env::consts::ARCH);
    println!("Off-site snapshots of install {install_id} (this machine: version {version}, {arch}), newest first:\n");
    for a in archives {
        let verdict = match rs::fetch_manifest(&agent, &payload, &a.name).await {
            Ok(m) => match rs::validate_manifest(&m, &a.name, version, arch) {
                Ok(()) => format!("version {}, {}, {} bytes, created {}: can be restored here", m.from_version, m.arch, m.size_bytes, m.created_at),
                Err(e) => format!("version {}, {}: NOT restorable here: {e}", m.from_version, m.arch),
            },
            Err(e) => format!("{} bytes: manifest unreadable: {e}", a.size),
        };
        println!("  {}\n      {verdict}", a.name);
    }
    Ok(0)
}

struct TerminalReporter;

impl Reporter for TerminalReporter {
    fn phase(&self, _phase: &'static str, detail: &str) {
        eprintln!("  ... {detail}");
    }
}

fn read_json(path: &str) -> Option<serde_json::Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

async fn restore(archive: &str, identity_file: &Path, destination_file: &Path, yes: bool) -> Result<i32, String> {
    rs::private_enough(identity_file)?;
    let key = Zeroizing::new(
        std::fs::read_to_string(identity_file).map_err(|e| format!("cannot read {}: {e}", identity_file.display()))?,
    );
    dr::parse_identity(&key)?;
    let spec = destination(destination_file)?;
    let (install_id, _) = rs::parse_archive_name(archive).ok_or("not an off-site snapshot archive name")?;
    let agent = agent()?;
    let payload = dr::dr_destination_payload(&spec.payload, install_id);

    println!(
        "This restores the off-site snapshot\n  {archive}\nonto THIS machine:\n\
         \n  1. download its manifest and check it: same version ({}) and architecture ({}) as this machine,\
         \n     and your recovery key is the one it was encrypted to;\
         \n  2. download the encrypted archive and check its sha256 against the manifest;\
         \n  3. decrypt it (in memory, to a 0600 file in the restore inbox, removed afterwards);\
         \n  4. stop the panel, REPLACE its database and /etc/dockpanel with the snapshot's\
         \n     (this machine's DATABASE_URL is kept), restore the PowerDNS zones if the snapshot has them,\
         \n     start the panel again;\
         \n  5. rebuild every site's nginx configuration from the restored database, moving to this\
         \n     machine's primary IP the sites whose IP does not exist here.\
         \n\nWhatever this machine's panel holds now is replaced (a dump of it is kept in /var/lib/dockpanel).",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH
    );
    if !yes {
        print!("\nType RESTORE to continue: ");
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer).map_err(|e| e.to_string())?;
        if answer.trim() != "RESTORE" {
            println!("Cancelled: nothing was changed.");
            return Ok(1);
        }
    }

    let before = read_json(RESTORE_RESULT_PATH).and_then(|v| v.get("finished_at").cloned());
    eprintln!("\nPreparing the archive:");
    let prepared = rs::fetch_and_decrypt(&agent, &payload, archive, &key, &TerminalReporter).await?;
    drop(key);
    eprintln!("  ... archive verified and decrypted (snapshot {})", prepared.snapshot_id);
    rs::launch(&prepared, Some("dockpanel-api dr restore")).await?;
    eprintln!("\nRestore started (unit dockpanel-snapshot-restore-{}). Waiting for its verdict...", prepared.snapshot_id);

    // The verdict: written at the start ("started"), then once at the end.
    let mut verdict = None;
    for _ in 0..(45 * 60 / 3) {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if let Some(v) = read_json(RESTORE_RESULT_PATH) {
            let fresh = v.get("finished_at").cloned() != before
                && v.get("snapshot_id").and_then(|s| s.as_str()) == Some(prepared.snapshot_id.to_string().as_str());
            if fresh && v.get("stage").and_then(|s| s.as_str()) != Some("started") {
                verdict = Some(v);
                break;
            }
        }
    }
    let Some(v) = verdict else {
        eprintln!("No verdict after 45 minutes: see `journalctl -u dockpanel-snapshot-restore-{}`.", prepared.snapshot_id);
        return Ok(1);
    };
    let ok = v.get("ok").and_then(|o| o.as_bool()).unwrap_or(false);
    println!(
        "\nRestore verdict: {} (stage {})\n  {}",
        if ok { "OK" } else { "NEEDS ATTENTION" },
        v.get("stage").and_then(|s| s.as_str()).unwrap_or("?"),
        v.get("detail").and_then(|s| s.as_str()).unwrap_or("")
    );

    // The vhost rebuild runs at the api's first start after the restore.
    let mut report = None;
    let want = prepared.snapshot_id.to_string();
    for _ in 0..(10 * 60 / 3) {
        if let Some(r) = dr_post_restore::read_report().filter(|r| r.snapshot_id.as_deref() == Some(want.as_str())) {
            report = Some(r);
            break;
        }
        if !Path::new(dr_post_restore::MARKER).exists() && !ok {
            break;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    match &report {
        Some(r) => {
            println!(
                "\nSite configurations: {} rebuilt, {} moved to the primary IP, {} failed{}",
                r.rebuilt,
                r.remapped,
                r.failed,
                if r.ok { "" } else { " (see below)" }
            );
            for s in &r.sites {
                let moved = s.remapped_from.as_deref().map(|f| format!(" (moved from {f})")).unwrap_or_default();
                println!("  {:8} {}{moved}{}", s.status, s.domain, s.detail.as_deref().map(|d| format!(": {d}")).unwrap_or_default());
            }
            if let Some(t) = &r.nginx_test {
                println!("  nginx -t: {}", if t.ok { "ok".to_string() } else { format!("FAILED: {}", t.output) });
            }
            if let Some(l) = &r.reload {
                println!("  nginx reload: {}", if l.ok { "ok".to_string() } else { format!("FAILED: {}", l.detail) });
            }
            for k in &r.key_paths {
                println!("  SFTP destination '{}' now uses {} (was {})", k.destination, k.to, k.from);
            }
            for e in &r.errors {
                println!("  ! {e}");
            }
            if let Some(c) = r.panel_certificate.as_ref().filter(|c| !c.names_primary_ip) {
                println!("  ! panel certificate: {}", c.detail);
            }
            if let Some(d) = &r.dr_snapshots {
                println!(
                    "  Off-site copies at the destinations: {} added to the Disaster recovery card, {} marked removed",
                    d.added.len(),
                    d.removed.len()
                );
                for e in &d.errors {
                    println!("  ! off-site copies: {e}");
                }
            }
        }
        None if Path::new(dr_post_restore::MARKER).exists() => {
            println!("\nThe site configurations are still being rebuilt: see {} later.", dr_post_restore::REPORT);
        }
        None => println!("\nNo site configuration rebuild was run."),
    }
    println!(
        "\nNext steps (docs/guides/disaster-recovery.md):\
         \n  - sign in to the panel with your usual account and check Disaster recovery;\
         \n  - \"Restore sites and databases from remote backups\" on that card;\
         \n  - restore app data, mail and DNS from their own backups;\
         \n  - point the DNS at this machine, then issue the panel certificate again with certbot."
    );
    Ok(if ok && report.as_ref().is_some_and(|r| r.ok) { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    const A: &str = "cyberhunter-dr-0b3f7a52-5f1e-4f53-9a43-7f2b8f0c1d2e-20261119-033000.tar.gz.age";

    #[test]
    fn list_and_restore_parse() {
        assert_eq!(
            parse_args(&s(&["list", "--destination-file", "/root/d.json"])).unwrap(),
            DrCommand::List { destination_file: "/root/d.json".into(), install_id: None }
        );
        let l = parse_args(&s(&["list", "--destination-file=/root/d.json", "--install-id", "0b3f7a52-5f1e-4f53-9a43-7f2b8f0c1d2e"])).unwrap();
        assert!(matches!(l, DrCommand::List { install_id: Some(_), .. }));
        assert_eq!(
            parse_args(&s(&["restore", "--archive", A, "--identity-file", "/root/k.txt", "--destination-file", "/root/d.json", "--yes"])).unwrap(),
            DrCommand::Restore { archive: A.into(), identity_file: "/root/k.txt".into(), destination_file: "/root/d.json".into(), yes: true }
        );
    }

    #[test]
    fn bad_invocations_are_refused() {
        for bad in [
            vec![],
            vec!["purge"],
            vec!["list"],
            vec!["list", "--destination-file"],
            vec!["list", "--destination-file", "a", "--archive", A],
            vec!["list", "--destination-file", "a", "--install-id", "nope"],
            vec!["restore", "--archive", "x.tar.gz", "--identity-file", "k", "--destination-file", "d"],
            vec!["restore", "--archive", A, "--destination-file", "d"],
            vec!["restore", "--archive", A, "--archive", A, "--identity-file", "k", "--destination-file", "d"],
            vec!["restore", "positional"],
        ] {
            assert!(parse_args(&s(&bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn secrets_on_the_command_line_are_refused() {
        let e = parse_args(&s(&["restore", "--archive", A, "--identity-file", "AGE-SECRET-KEY-1QQQ", "--destination-file", "d"])).unwrap_err();
        assert!(e.contains("--identity-file instead") && !e.contains("QQQ"), "{e}");
        for flag in SECRET_FLAGS {
            let e = parse_args(&s(&["list", "--destination-file", "d", flag, "hunter2"])).unwrap_err();
            assert!(e.contains("never accepted on the command line") && !e.contains("hunter2"), "{flag}: {e}");
            let inline = format!("{flag}=hunter2");
            let e = parse_args(&s(&["list", "--destination-file", "d", &inline])).unwrap_err();
            assert!(e.contains("never accepted") && !e.contains("hunter2"), "{flag}: {e}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_must_not_be_readable_by_others() {
        use std::os::unix::fs::PermissionsExt;
        let p = std::env::temp_dir().join(format!("dr-cli-{}", Uuid::new_v4()));
        std::fs::write(&p, "{}").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(rs::private_enough(&p).unwrap_err().contains("chmod 600"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(rs::private_enough(&p).is_ok());
        std::fs::remove_file(&p).unwrap();
    }
}
