use std::path::Path;
use crate::safe_cmd::safe_command;

/// Returned when the binary a password-authenticated SFTP destination execs is
/// absent from the box the backup runs on.
///
/// It is a named constant because the caller has to recognise this specific
/// condition to answer with a 4xx. Reporting it as a 5xx makes the panel replace
/// the whole sentence with an incident reference, so the operator is told their
/// agent broke when the agent is working perfectly and the box is simply missing
/// a package - which is the state s289 measured and the message below was
/// written to end.
pub const SSHPASS_MISSING: &str =
    "sshpass is not installed on this server, and it is required for \
     password-authenticated SFTP destinations. The panel can install it for you from \
     Settings, or use an SSH key instead.";

/// RAII guard that deletes a temp file on drop, ensuring cleanup on all code paths.
///
/// The file holds a credential (the S3 key pair for curl's `-K`, or the SFTP
/// password for `sshpass -f`), so it is created `create_new` at mode 0600 in one
/// step. Writing first and `chmod`ing after left a window where the file existed
/// with the umask's mode, and `create_new` refuses a pre-planted file or symlink
/// at the random name. `/tmp` is the unit's `PrivateTmp`, which the curl/sftp
/// children inherit, so no other unit can see it at all.
struct TempFileGuard {
    path: String,
}

impl TempFileGuard {
    fn create(label: &str, content: &str) -> Result<Self, String> {
        Self::create_kind("s3", label, content)
    }

    fn create_kind(kind: &str, label: &str, content: &str) -> Result<Self, String> {
        use std::io::Write;
        let random_suffix: u64 = rand::random();
        let path = format!("/tmp/.dockpanel-{}-{}-{:016x}", kind, label, random_suffix);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&path)
            .map_err(|e| format!("Failed to write {kind} credential file: {e}"))?;
        // From here on the guard owns the path, so a failed write still removes it.
        let guard = Self { path };
        f.write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write {kind} credential file: {e}"))?;
        Ok(guard)
    }
}

/// Quote one value for a curl config file (`-K`).
///
/// curl parses a double-quoted config value with backslash escapes, so a secret
/// key containing `"` or `\` used to end the value early or lose a character, and
/// the request then failed with a signature mismatch that named neither cause.
/// A line break cannot be carried at all: it would end the `user =` line.
fn curl_config_quote(v: &str) -> Result<String, String> {
    if v.contains('\n') || v.contains('\r') {
        return Err("S3 credentials may not contain a line break".to_string());
    }
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for ch in v.chars() {
        if ch == '\\' || ch == '"' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    Ok(out)
}

/// The `-K` config file holding the S3 key pair, never argv.
fn s3_credentials_file(label: &str, access_key: &str, secret_key: &str) -> Result<TempFileGuard, String> {
    let user = curl_config_quote(&format!("{access_key}:{secret_key}"))?;
    TempFileGuard::create(label, &format!("user = {user}\n"))
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).ok();
    }
}

/// Run a curl invocation against the S3 endpoint and return `(status, body)`.
///
/// # Why every S3 call goes through here
///
/// These calls used `--fail`, which fails on 4xx/5xx and says nothing about **3xx**.
/// Without `-L`, curl does not follow a redirect either: it prints the redirect body,
/// transfers no payload, and **exits 0**. So an endpoint that answers 301 - an S3
/// bucket addressed in the wrong region, or an `http://` endpoint whose provider
/// redirects to `https://` - made `upload_s3` return `Ok`, the agent answer
/// `{"success":true}`, and the panel light the "remote" badge for an object that was
/// never written. Measured on a live box (s289): policy run reported
/// *"1 successes, 0 failures, 0 not uploaded off-site"* against an empty bucket.
///
/// Following redirects is NOT the fix: an AWS SigV4 signature is bound to the host
/// and path it was computed for, so a followed redirect authenticates as garbage -
/// and on 301/302 curl would downgrade the `PUT` to `GET`. The fix is to stop
/// treating "not an error status" as "the bytes arrived": require an explicit 2xx.
///
/// One runner for all four S3 operations on purpose. The same latent bug sat in
/// `test_s3`, `list_s3` and `delete_s3`, and fixing the copy under investigation
/// while leaving its siblings is a mistake this file has already shipped once.
async fn s3_curl(
    args: Vec<String>,
    timeout_secs: u64,
    label: &str,
) -> Result<(u16, String), String> {
    // `--fail` is deliberately absent: it suppresses the response body, and the body
    // is where S3 puts the reason. The status check below replaces it.
    let mut full: Vec<String> = vec![
        "--silent".into(),
        "--show-error".into(),
        "-w".into(),
        "\n%{http_code}".into(),
    ];
    full.extend(args);

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        // safe_command sets no kill_on_drop, so a timed-out (dropped) future
        // would otherwise leave `curl` running in the background against the
        // S3 endpoint - see git_build.rs/deploy.rs/backups.rs's identical fix
        // and database.rs:317, migration.rs:91, database_backup.rs:424,
        // security_scanner.rs:633 for the same fix elsewhere in this crate.
        safe_command("curl").args(&full).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| format!("{label} timed out"))?
    .map_err(|e| format!("Failed to run curl: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (body, code_str) = match stdout.rsplit_once('\n') {
        Some((b, c)) => (b.trim().to_string(), c.trim().to_string()),
        None => (String::new(), stdout.trim().to_string()),
    };

    // curl itself failed (DNS, refused connection, TLS) - there is no HTTP status.
    let code: u16 = code_str.parse().map_err(|_| {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = if stderr.trim().is_empty() { body.clone() } else { stderr.trim().to_string() };
        format!("{label} failed: {detail}")
    })?;

    // A transfer that broke AFTER the status line arrived - a reset mid-body, or
    // `--max-filesize` tripping on a download - still prints a 2xx through `-w`
    // and would have been reported as success over a truncated file. The status
    // says what the server answered; the exit code says whether the bytes made it.
    if s3_ok(code) && !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "{label} failed after HTTP {code}: curl exited with {}{}",
            output.status,
            if stderr.trim().is_empty() { String::new() } else { format!(": {}", stderr.trim()) }
        ));
    }

    Ok((code, body))
}

/// True only for 2xx. A 3xx is not success - see [`s3_curl`].
fn s3_ok(code: u16) -> bool {
    (200..300).contains(&code)
}

/// Blank the elements of an S3 error body that echo the request's credentials.
///
/// A `SignatureDoesNotMatch` answer carries `<AWSAccessKeyId>` plus the string
/// and canonical request the server expected, and this text becomes an API
/// error message and a log line. Only the element contents are replaced, so the
/// error code and message an operator needs stay readable.
fn redact_s3_body(body: &str) -> String {
    let mut out = body.to_string();
    for tag in [
        "AWSAccessKeyId",
        "StringToSign",
        "StringToSignBytes",
        "CanonicalRequest",
        "CanonicalRequestBytes",
        "SignatureProvided",
    ] {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let mut from = 0;
        while let Some(i) = out[from..].find(&open) {
            let start = from + i + open.len();
            match out[start..].find(&close) {
                Some(j) => {
                    out.replace_range(start..start + j, "[redacted]");
                    from = start + "[redacted]".len() + close.len();
                }
                None => {
                    out.truncate(start);
                    out.push_str("[redacted]");
                    break;
                }
            }
        }
    }
    out
}

/// Trim an S3 error body down to something a log line can carry.
fn s3_detail(code: u16, body: &str) -> String {
    let redacted = redact_s3_body(body);
    let b = redacted.trim();
    if b.is_empty() {
        format!("HTTP {code}")
    } else {
        format!("HTTP {code}: {}", b.chars().take(300).collect::<String>())
    }
}

/// Upload a backup file to S3-compatible storage using curl --aws-sigv4.
pub async fn upload_s3(
    filepath: &str,
    bucket: &str,
    region: &str,
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
    remote_path: &str,
) -> Result<String, String> {
    let path = Path::new(filepath);
    if !path.exists() {
        return Err(format!("Backup file not found: {filepath}"));
    }

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid filename")?;

    // Build the S3 URL: endpoint/bucket/prefix/filename
    let prefix = remote_path.trim_matches('/');
    let url = if prefix.is_empty() {
        format!("{endpoint}/{bucket}/{filename}")
    } else {
        format!("{endpoint}/{bucket}/{prefix}/{filename}")
    };

    tracing::info!("Uploading {filename} to {url}");

    // Write credentials to a temp file so they don't appear in process listing
    let config_guard = s3_credentials_file("upload", access_key, secret_key)?;

    let (code, body) = s3_curl(
        vec![
            "--aws-sigv4".into(),
            format!("aws:amz:{region}:s3"),
            "-K".into(),
            config_guard.path.clone(),
            "-X".into(),
            "PUT".into(),
            "-H".into(),
            "Content-Type: application/gzip".into(),
            "-T".into(),
            filepath.to_string(),
            url.clone(),
        ],
        600,
        "Upload",
    )
    .await?;

    drop(config_guard);

    if !s3_ok(code) {
        return Err(format!("S3 upload failed: {}", s3_detail(code, &body)));
    }

    tracing::info!("Upload complete: {filename} (HTTP {code})");
    Ok(url)
}

/// Build the options every SFTP operation shares.
///
/// # Why this is one function
///
/// `upload_sftp` and `test_sftp` each built this list by hand, with a comment
/// promising they were "kept in step deliberately". They were not: `ConnectTimeout`
/// was set on the test and missing from the upload, so the two operations the
/// operator is told are equivalent could hang differently. A hand-maintained
/// invariant between two copies is the thing that keeps failing here - so there is
/// now one copy and the promise is structural.
///
/// There is no longer a port-flag parameter: both operations speak the SFTP
/// subsystem now, so both take the same uppercase port flag. When this list served
/// `ssh` (lowercase flag) as well, that difference was the one argument each caller
/// had to supply.
///
/// The two settings encoded here each cost a release to find (s288):
///
/// * `UserKnownHostsFile=/etc/dockpanel/known_hosts` - `accept-new` means "trust on
///   first use, then pin", and pinning is a WRITE. ssh's default target is
///   `~/.ssh/known_hosts`, which under this unit's `ProtectHome=yes` cannot be
///   created: *"Could not create directory '/root/.ssh' (Read-only file system)"*.
///   `/etc/dockpanel` is in the unit's `ReadWritePaths` and is where `deploy.rs`
///   already points git's ssh, so one trust store serves both. Redirecting the file
///   keeps first-use pinning; `/dev/null` or `StrictHostKeyChecking=no` would have
///   "fixed" it by discarding host verification entirely.
///
/// * `BatchMode=yes` ONLY when authenticating by key. It means "never prompt", which
///   is right for a key and fatal for a password: it disables password and
///   keyboard-interactive auth outright, so `sshpass` has nothing left to answer.
///   Each setting is correct alone and together they made password SFTP impossible.
///
///   That trap has a second entrance, found s339: **`sftp -b` sets `BatchMode` by
///   itself**, so the password case has to say `BatchMode=no` out loud or every
///   password-authenticated destination dies at `Permission denied` - the identical
///   s288 failure, arriving through the flag instead of through this list.
fn sftp_opts(port: u16, password: Option<&str>, key_path: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        "UserKnownHostsFile=/etc/dockpanel/known_hosts".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-P".into(),
        port.to_string(),
    ];
    if key_path.is_some() || password.is_none() {
        args.push("-o".into());
        args.push("BatchMode=yes".into());
    } else {
        args.push("-o".into());
        args.push("BatchMode=no".into());
    }
    if let Some(key) = key_path {
        args.push("-i".into());
        args.push(key.into());
    }
    args
}

/// Quote one path as a single `sftp` batch argument.
///
/// A batch line is parsed by sftp's own tokeniser, **not by a shell**, and the
/// difference is not cosmetic: an unquoted space splits the path in two, and
/// `put local /backups/my dir/f.tgz` then writes to `/backups/my` under the
/// SOURCE filename and **exits 0**. Measured s339 - a success report for an
/// archive that landed somewhere else under another name, which is a worse
/// outcome than the failure this whole change is fixing.
///
/// Double quotes carry spaces, single quotes and glob characters literally; a
/// backslash or a double quote inside must itself be escaped.
fn sftp_quote(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 2);
    out.push('"');
    for ch in path.chars() {
        if ch == '\\' || ch == '"' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

/// Reject a path that cannot be expressed as one batch line.
///
/// In a batch script a newline **starts a new command**, so a `remote_path`
/// carrying one appends attacker-chosen sftp operations to the script the agent
/// built (verified s339 by planting a second `put`). `remote_path` reaches here
/// straight from the request body with no validation anywhere upstream, so this
/// is the only place that can refuse it.
fn reject_unquotable_path(path: &str) -> Result<(), String> {
    if path.contains('\n') || path.contains('\r') {
        return Err("Remote path may not contain a line break".to_string());
    }
    Ok(())
}

/// One `-mkdir` per ancestor, deepest last.
///
/// `sftp` has no `mkdir -p`: `mkdir /a/b/c` fails outright when `/a/b` is absent,
/// and the `put` after it then fails too. So each component is created in turn.
/// The `-` prefix means "continue past this command's failure", which is required
/// rather than tidy: a plain `mkdir` of an **existing** directory reports Failure
/// and **aborts the whole batch** (both measured s339), and every component of an
/// already-provisioned destination exists.
fn sftp_mkdir_script(dir: &str) -> String {
    let absolute = dir.starts_with('/');
    let mut out = String::new();
    let mut acc = String::new();
    for comp in dir.split('/').filter(|c| !c.is_empty()) {
        if acc.is_empty() {
            if absolute {
                acc.push('/');
            }
        } else {
            acc.push('/');
        }
        acc.push_str(comp);
        out.push_str("-mkdir ");
        out.push_str(&sftp_quote(&acc));
        out.push('\n');
    }
    out
}

/// Makes each Test Connection's local probe filename unique within the process,
/// so two destinations tested at once cannot delete each other's file.
static PROBE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Join both of a finished command's streams into one operator-facing detail.
///
/// Reading only `stderr` is what made issue #102 unreadable: `internal-sftp`
/// writes its refusal - *"This service allows sftp connections only."* - to
/// **stdout**, leaving stderr holding nothing but ssh's known-hosts banner. The
/// operator was shown `Warning: Permanently added '[host]:port' ...` as the entire
/// cause of a failed backup, and on any later connection, with the key already
/// pinned, stderr is empty and the message degraded to "no error output from ssh".
fn command_detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut parts: Vec<&str> = Vec::new();
    let e = stderr.trim();
    let o = stdout.trim();
    if !e.is_empty() {
        parts.push(e);
    }
    if !o.is_empty() {
        parts.push(o);
    }
    if parts.is_empty() {
        "no output from sftp".to_string()
    } else {
        parts.join(" | ")
    }
}

/// Run `ssh`/`scp`, routing through `sshpass` when a password is the credential.
///
/// `sshpass -f` reads the password from a 0600 file in the unit's private
/// `/tmp`, so it appears neither in a process listing (argv) nor in the child's
/// `/proc/<pid>/environ`. It used to be `sshpass -e` with `SSHPASS` in the
/// environment, which kept it out of argv but left it readable in environ for the
/// whole transfer - and the off-site snapshot recette greps exactly that. The
/// file is removed when this function returns, on every path.
/// A key beats a password when both are supplied.
async fn run_sftp(
    program: &str,
    args: Vec<String>,
    password: Option<&str>,
    key_path: Option<&str>,
    timeout_secs: u64,
    label: &str,
    batch_script: Option<&str>,
) -> Result<std::process::Output, String> {
    // Held until the child has exited: dropping it deletes the password file.
    let mut _pw_file: Option<TempFileGuard> = None;
    let (prog, final_args) = match password {
        Some(pw) if key_path.is_none() => {
            // sshpass -f takes the FIRST LINE of the file as the password, so a
            // line break would silently authenticate with a truncated secret.
            if pw.contains('\n') || pw.contains('\r') {
                return Err("SFTP password may not contain a line break".to_string());
            }
            let guard = TempFileGuard::create_kind("sftp", "pass", &format!("{pw}\n"))?;
            let mut a: Vec<String> = vec!["-f".into(), guard.path.clone(), program.into()];
            a.extend(args);
            _pw_file = Some(guard);
            ("sshpass".to_string(), a)
        }
        _ => (program.to_string(), args),
    };

    let mut cmd = safe_command(&prog);
    cmd.args(&final_args);
    // safe_command sets no kill_on_drop, so a timed-out (dropped) future would
    // otherwise leave sftp/sshpass running in the background against the remote
    // host - the sibling s3_curl() above already carries this fix (v2.204.0);
    // this call site was out of that commit's scope and has carried the gap
    // since. Same fix as database.rs:317, migration.rs:91, database_backup.rs:424,
    // security_scanner.rs:633 and 20+ other call sites in this crate.
    cmd.kill_on_drop(true);

    // `sftp -b -` reads its command script from stdin, which keeps the script out
    // of the filesystem entirely - no temp file to create under `ProtectSystem=
    // strict`, and no window where a world-readable batch names the destination.
    // Writing before reading is safe only because these scripts are a few hundred
    // bytes: a script large enough to fill the pipe buffer would deadlock against
    // an sftp that is blocked writing its own progress to a full stdout.
    let run = async {
        match batch_script {
            Some(script) => {
                cmd.stdin(std::process::Stdio::piped());
                cmd.stdout(std::process::Stdio::piped());
                cmd.stderr(std::process::Stdio::piped());
                let mut child = cmd.spawn()?;
                if let Some(mut sink) = child.stdin.take() {
                    use tokio::io::AsyncWriteExt;
                    sink.write_all(script.as_bytes()).await?;
                    sink.shutdown().await?;
                    // Dropped here on purpose: sftp runs its script to completion
                    // and only then exits, so it needs to see EOF on stdin.
                    drop(sink);
                }
                child.wait_with_output().await
            }
            None => cmd.output().await,
        }
    };

    tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), run)
        .await
        .map_err(|_| format!("{label} timed out"))?
        .map_err(|e| {
            // `sshpass` is a separate package and the agent shells out to it for
            // every password-authenticated destination. When it is absent the raw
            // error is "No such file or directory (os error 2)", which names neither
            // the binary nor the remedy - s289 measured exactly that, as an opaque
            // 502, on a fresh install where nothing had installed it.
            if prog == "sshpass" && e.kind() == std::io::ErrorKind::NotFound {
                SSHPASS_MISSING.to_string()
            } else {
                format!("Failed to run {prog}: {e}")
            }
        })
}

/// Upload a backup file via SCP.
pub async fn upload_sftp(
    filepath: &str,
    host: &str,
    port: u16,
    username: &str,
    password: Option<&str>,
    key_path: Option<&str>,
    remote_path: &str,
) -> Result<String, String> {
    let path = Path::new(filepath);
    if !path.exists() {
        return Err(format!("Backup file not found: {filepath}"));
    }

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid filename")?;

    let dir = remote_path.trim_end_matches('/');
    reject_unquotable_path(dir)?;
    reject_unquotable_path(filepath)?;

    let remote_file = format!("{dir}/{filename}");
    let remote_dest = format!("{username}@{host}:{remote_file}");

    tracing::info!("Uploading {filename} via SFTP to {remote_dest}");

    // Create the destination directory, then transfer - both over the SFTP
    // subsystem, in one connection.
    //
    // Both steps used to be SSH **exec** requests (`ssh host "mkdir -p ..."`, then
    // `scp`), and an sshd with `ForceCommand internal-sftp` - OpenSSH's own
    // documented way to run a chrooted, SFTP-only account - replaces whatever
    // command the client asked for with the SFTP subsystem. So the `mkdir` was
    // discarded and the upload failed for every such destination (issue #102).
    //
    // `scp` is gone rather than merely re-ordered, because it carries the same
    // defect on exactly the hosts that are hardest to notice: OpenSSH 9.0 switched
    // scp to the SFTP protocol, so a modern agent host transfers fine and only the
    // `mkdir` fails, while an agent on RHEL 8 or Ubuntu 20.04 still speaks legacy
    // `scp -t` and would keep failing after a mkdir-only fix. Measured both ways
    // s339 against a chrooted sshd: default scp exit 0, `scp -O` exit 1.
    //
    // Nothing created the directory at all before s289; that fix is preserved here,
    // one component at a time - see `sftp_mkdir_script` for why it cannot be one call.
    let mut script = sftp_mkdir_script(dir);
    script.push_str(&format!(
        "put {} {}\n",
        sftp_quote(filepath),
        sftp_quote(&remote_file)
    ));

    let mut cmd_args = sftp_opts(port, password, key_path);
    cmd_args.push("-b".into());
    cmd_args.push("-".into());
    cmd_args.push(format!("{username}@{host}"));

    let output = run_sftp(
        "sftp",
        cmd_args,
        password,
        key_path,
        600,
        "Upload",
        Some(&script),
    )
    .await?;

    if !output.status.success() {
        return Err(format!("SFTP upload failed: {}", command_detail(&output)));
    }

    tracing::info!("SFTP upload complete: {filename}");
    Ok(remote_dest)
}

/// Test S3 access by performing the operation an upload performs.
///
/// # Why this writes instead of HEADing
///
/// The test used to `HEAD` the bucket root, while an upload `PUT`s an object into
/// `path_prefix`. Those need different permissions and different paths, so a
/// read-only key, a key scoped to another prefix, and a bucket that answers 301 all
/// reported "S3 connection successful" and then failed - or silently did nothing -
/// at the first real backup. A test that connects differently from the upload is a
/// test of nothing; s289 measured a green Test against a destination whose bucket
/// stayed empty through a full policy run.
///
/// So: PUT a tiny probe object where the backups will go, then delete it. The probe
/// is removed on every path, including when the delete fails (it is reported, not
/// swallowed, because a destination that accumulates probes is worth knowing about).
pub async fn test_s3(
    bucket: &str,
    region: &str,
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
    path_prefix: &str,
) -> Result<(), String> {
    let prefix = path_prefix.trim_matches('/');
    let probe_name = format!(".dockpanel-write-probe-{:016x}", rand::random::<u64>());
    let key = if prefix.is_empty() {
        probe_name.clone()
    } else {
        format!("{prefix}/{probe_name}")
    };
    let url = format!("{endpoint}/{bucket}/{key}");

    // Write credentials to a temp file so they don't appear in process listing
    let config_guard = s3_credentials_file("test", access_key, secret_key)?;

    let sigv4 = format!("aws:amz:{region}:s3");
    let (code, body) = s3_curl(
        vec![
            "--aws-sigv4".into(),
            sigv4.clone(),
            "-K".into(),
            config_guard.path.clone(),
            "-X".into(),
            "PUT".into(),
            "-H".into(),
            "Content-Type: text/plain".into(),
            "--data-binary".into(),
            "dockpanel write probe".into(),
            url.clone(),
        ],
        15,
        "Connection test",
    )
    .await?;

    if !s3_ok(code) {
        drop(config_guard);
        return Err(format!("S3 connection test failed: {}", s3_detail(code, &body)));
    }

    // Clean up the probe. Reported rather than ignored: a destination we can write
    // but not delete cannot enforce retention either, and the operator should hear
    // it here rather than from a storage bill.
    let (del_code, del_body) = s3_curl(
        vec![
            "--aws-sigv4".into(),
            sigv4,
            "-K".into(),
            config_guard.path.clone(),
            "-X".into(),
            "DELETE".into(),
            url,
        ],
        15,
        "Connection test cleanup",
    )
    .await?;

    drop(config_guard);

    if !s3_ok(del_code) && del_code != 404 {
        return Err(format!(
            "S3 write succeeded but the test object could not be removed ({}) - \
             retention will not be able to delete old backups either",
            s3_detail(del_code, &del_body)
        ));
    }

    Ok(())
}

/// Test SFTP access by doing what an upload does.
///
/// Connecting and running `exit` proved only that the credential authenticates. It
/// never touched `remote_path`, so a destination whose directory did not exist -
/// including the `/backups` default, which exists on almost no server - reported
/// "SFTP connection successful" and then failed every real upload with
/// *"No such file or directory"* (measured s289). The test now creates the
/// directory and writes a probe file into it, which is exactly the sequence
/// `upload_sftp` performs.
pub async fn test_sftp(
    host: &str,
    port: u16,
    username: &str,
    password: Option<&str>,
    key_path: Option<&str>,
    remote_path: &str,
) -> Result<(), String> {
    let dir = remote_path.trim_end_matches('/');
    reject_unquotable_path(dir)?;

    // Create the directory, write a probe, remove it - the three things an upload
    // does, over the same transport an upload uses. Testing over a DIFFERENT
    // transport is how issue #102 stayed invisible from the panel: the test and the
    // upload both spoke SSH exec, so a server that refuses exec failed both, but a
    // test that had spoken sftp while uploads spoke scp would have been green over a
    // broken destination - the s289 defect this function was written to end.
    //
    // A local file is required: `put /dev/null` is refused outright ("not a regular
    // file", measured s339), so the probe is a real zero-byte file in the agent's
    // own tmp. `PrivateTmp=yes` makes that namespace private to the unit and the
    // sftp child inherits it.
    let probe_local = std::env::temp_dir().join(format!(
        ".dockpanel-sftp-probe-{}-{}",
        std::process::id(),
        PROBE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let probe_local_str = probe_local.to_string_lossy().to_string();

    let script = if dir.is_empty() {
        // No path to probe, so this proves only that the SFTP subsystem opens -
        // which is still more than an auth handshake proves.
        "pwd\n".to_string()
    } else {
        tokio::fs::write(&probe_local, b"")
            .await
            .map_err(|e| format!("Could not stage a local probe file: {e}"))?;
        let remote_probe = format!("{dir}/.dockpanel-write-probe");
        format!(
            "{}put {} {}\nrm {}\n",
            sftp_mkdir_script(dir),
            sftp_quote(&probe_local_str),
            sftp_quote(&remote_probe),
            sftp_quote(&remote_probe)
        )
    };

    let mut cmd_args = sftp_opts(port, password, key_path);
    cmd_args.push("-b".into());
    cmd_args.push("-".into());
    cmd_args.push(format!("{username}@{host}"));

    let output = run_sftp(
        "sftp",
        cmd_args,
        password,
        key_path,
        20,
        "Connection test",
        Some(&script),
    )
    .await;

    // Removed on every path, including the error ones - a probe left in the agent's
    // tmp for each failed Test Connection is a slow leak nobody would look for.
    let _ = tokio::fs::remove_file(&probe_local).await;

    let output = output?;

    if output.status.success() {
        Ok(())
    } else {
        // Authentication failures and permission failures read very differently to
        // an operator, and the raw output distinguishes them - so pass it through
        // rather than collapsing both into "connection failed".
        Err(format!("SFTP test failed: {}", command_detail(&output)))
    }
}

// ─── Listing, download, delete and retention (S3 and SFTP) ──────────────────

/// One object at a remote destination, as `/backups/list` reports it.
///
/// `key` is the full identifier the destination knows the object by (the
/// bucket-relative key for S3, the remote path for SFTP) and is what
/// `/backups/download` and `/backups/delete` take back verbatim. `modified` is
/// RFC 3339 in UTC for S3; SFTP's `ls` gives only a minute- or day-precision
/// local date without a year for recent files, so it is reported as `None`
/// rather than as a guess.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RemoteObject {
    pub name: String,
    pub key: String,
    pub size: u64,
    pub modified: Option<String>,
}

/// Where `/backups/download` writes. Under `/var/backups/dockpanel`, which the
/// agent unit already lists in `ReadWritePaths`.
pub const RESTORE_INBOX: &str = "/var/backups/dockpanel/restore-inbox";

/// Largest object `/backups/download` accepts (50 GiB).
pub const DOWNLOAD_MAX_BYTES: u64 = 50 * 1024 * 1024 * 1024;

/// Wall-clock budget of one download transfer. Three times the upload budget
/// (600s), because a restore usually runs over a slower path than the nightly
/// push and nothing is waiting on it but the operator. A caller must give its own
/// HTTP request more than this, or it stops waiting before the agent does.
pub const DOWNLOAD_TIMEOUT_SECS: u64 = 1800;

/// Prefix of the error a download returns when the object is over
/// [`DOWNLOAD_MAX_BYTES`], so the route can answer 413 rather than 5xx.
pub const DOWNLOAD_TOO_LARGE: &str = "Remote object is larger than the download limit";

/// Upper bound on ListObjectsV2 pages (1000 keys each by default), so a
/// misbehaving endpoint cannot keep the agent paging forever.
const S3_LIST_MAX_PAGES: usize = 10_000;

/// The key prefix every object of an S3 destination lives under: the configured
/// `path_prefix` without surrounding slashes, plus one `/`, or nothing.
/// Same derivation `upload_s3` uses to build the URL.
pub fn s3_key_prefix(path_prefix: &str) -> String {
    let p = path_prefix.trim_matches('/');
    if p.is_empty() {
        String::new()
    } else {
        format!("{p}/")
    }
}

/// The remote directory of an SFTP destination, as `upload_sftp` derives it.
/// Objects are `<dir>/<name>`, so the key prefix is `format!("{dir}/")`.
pub fn sftp_dir(remote_path: &str) -> String {
    remote_path.trim_end_matches('/').to_string()
}

/// Percent-encode by SigV4's rules: unreserved characters kept, everything else
/// `%XX` in uppercase. Already-encoded input is NOT what this expects.
///
/// Done here rather than left to curl because curl's own query canonicalisation
/// changed across releases (7.88 on Debian 12 signs the query as written, 8.x
/// re-encodes it): a query that is already canonical - encoded this way and with
/// its parameters in sorted order - signs identically under both.
fn aws_uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') || (keep_slash && c == '/') {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// URL of one object, each path segment encoded.
fn s3_object_url(endpoint: &str, bucket: &str, key: &str) -> String {
    format!("{endpoint}/{bucket}/{}", aws_uri_encode(key, true))
}

/// URL of one ListObjectsV2 page. Parameters are emitted in sorted order (the
/// SigV4 canonical order) and encoded; `delimiter=/` restricts the listing to
/// the direct children of `prefix`, which is what both backends can promise.
fn s3_list_url(endpoint: &str, bucket: &str, prefix: &str, token: Option<&str>, max_keys: Option<u32>) -> String {
    let mut q: Vec<String> = Vec::new();
    if let Some(t) = token {
        q.push(format!("continuation-token={}", aws_uri_encode(t, false)));
    }
    q.push("delimiter=%2F".into());
    q.push("list-type=2".into());
    if let Some(m) = max_keys {
        q.push(format!("max-keys={m}"));
    }
    if !prefix.is_empty() {
        q.push(format!("prefix={}", aws_uri_encode(prefix, false)));
    }
    format!("{endpoint}/{bucket}/?{}", q.join("&"))
}

/// Decode the five XML entities and numeric character references.
fn xml_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let Some(end) = tail.find(';') else {
            out.push_str(tail);
            return out;
        };
        let ent = &tail[1..end];
        let decoded = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32)
            }
            _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32),
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &tail[end + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Text of the first `<tag>...</tag>` in `s`, undecoded.
fn xml_text<'a>(s: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = s.find(&open)? + open.len();
    let len = s[start..].find(&close)?;
    Some(&s[start..start + len])
}

/// One parsed ListObjectsV2 page.
#[derive(Debug, PartialEq, Eq)]
struct S3ListPage {
    /// `(key, size, modified)` of each `<Contents>` entry, keys decoded.
    objects: Vec<(String, u64, Option<String>)>,
    /// Set only when the page says `IsTruncated=true`.
    next_token: Option<String>,
}

/// Parse a ListObjectsV2 body.
///
/// Keys are XML-escaped in the body (`&amp;`), so they are decoded here: an
/// undecoded key would not round-trip into download or delete. A truncated page
/// without a continuation token is an error, not the end of the listing - the
/// old parser stopped at the first 1000 keys without noticing there were more.
fn parse_list_objects_v2(body: &str) -> Result<S3ListPage, String> {
    if !body.contains("<ListBucketResult") {
        let excerpt: String = redact_s3_body(body).chars().take(200).collect();
        return Err(format!("S3 list returned an unexpected body: {excerpt}"));
    }
    let mut objects = Vec::new();
    let mut rest = body;
    while let Some(i) = rest.find("<Contents>") {
        let after = &rest[i + "<Contents>".len()..];
        let end = after
            .find("</Contents>")
            .ok_or("S3 list body has an unterminated <Contents> element")?;
        let block = &after[..end];
        let key = xml_text(block, "Key").ok_or("S3 list entry has no <Key>")?;
        let size: u64 = xml_text(block, "Size")
            .ok_or("S3 list entry has no <Size>")?
            .trim()
            .parse()
            .map_err(|_| "S3 list entry has an invalid <Size>".to_string())?;
        let modified = xml_text(block, "LastModified").and_then(|m| {
            chrono::DateTime::parse_from_rfc3339(m.trim())
                .ok()
                .map(|d| d.with_timezone(&chrono::Utc).to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        });
        objects.push((xml_unescape(key), size, modified));
        rest = &after[end + "</Contents>".len()..];
    }
    let truncated = xml_text(body, "IsTruncated").map(|t| t.trim() == "true").unwrap_or(false);
    let next_token = if truncated {
        let t = xml_text(body, "NextContinuationToken")
            .map(xml_unescape)
            .filter(|t| !t.is_empty())
            .ok_or("S3 list is truncated but carries no NextContinuationToken")?;
        Some(t)
    } else {
        None
    };
    Ok(S3ListPage { objects, next_token })
}

/// List the objects directly under `prefix` (a raw key prefix: the
/// destination's `s3_key_prefix` plus any sub-path or name start), following
/// every continuation token. `max_keys` is the page size (S3's default, 1000,
/// when `None`); a lab run sets it low to force pagination with a few objects.
/// Keys ending in `/` (folder placeholders) are skipped.
pub async fn list_s3(
    bucket: &str,
    region: &str,
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
    prefix: &str,
    max_keys: Option<u32>,
) -> Result<Vec<RemoteObject>, String> {
    // Credentials in a 0600 file for curl's -K, never in argv.
    let config_guard = s3_credentials_file("list", access_key, secret_key)?;
    let sigv4 = format!("aws:amz:{region}:s3");

    let mut out: Vec<RemoteObject> = Vec::new();
    let mut token: Option<String> = None;
    let mut seen_tokens = std::collections::HashSet::new();

    for _ in 0..S3_LIST_MAX_PAGES {
        let url = s3_list_url(endpoint, bucket, prefix, token.as_deref(), max_keys);
        let (code, body) = s3_curl(
            vec![
                "--aws-sigv4".into(),
                sigv4.clone(),
                "-K".into(),
                config_guard.path.clone(),
                url,
            ],
            30,
            "List",
        )
        .await?;

        if !s3_ok(code) {
            return Err(format!("S3 list failed: {}", s3_detail(code, &body)));
        }

        let page = parse_list_objects_v2(&body)?;
        for (key, size, modified) in page.objects {
            let name = key.rsplit('/').next().unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            out.push(RemoteObject { name, key, size, modified });
        }
        match page.next_token {
            None => return Ok(out),
            Some(t) => {
                // A server that hands back a token it already gave would loop
                // until the page cap; say so instead.
                if !seen_tokens.insert(t.clone()) {
                    return Err("S3 list returned the same continuation token twice".to_string());
                }
                token = Some(t);
            }
        }
    }
    Err(format!("S3 list did not finish within {S3_LIST_MAX_PAGES} pages"))
}

/// Delete a file from S3.
pub async fn delete_s3(
    bucket: &str,
    region: &str,
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
    key: &str,
) -> Result<(), String> {
    // Encoded per segment: a key listed back from the bucket may hold characters
    // (space, `+`, `&`) that a raw URL would send as something else.
    let url = s3_object_url(endpoint, bucket, key);

    // Write credentials to a temp file so they don't appear in process listing
    let config_guard = s3_credentials_file("delete", access_key, secret_key)?;

    let (code, body) = s3_curl(
        vec![
            "--aws-sigv4".into(),
            format!("aws:amz:{region}:s3"),
            "-K".into(),
            config_guard.path.clone(),
            "-X".into(),
            "DELETE".into(),
            url,
        ],
        15,
        "Delete",
    )
    .await?;

    drop(config_guard);

    // S3 answers 204 for a delete, and 404 for an object already gone - both mean
    // "it is not there", which is what the caller asked for.
    if s3_ok(code) || code == 404 {
        Ok(())
    } else {
        Err(format!("S3 delete failed: {}", s3_detail(code, &body)))
    }
}

/// GET one object into `dest` (a file the caller already created at 0600).
///
/// On a non-2xx the file holds S3's error body instead of the object; a bounded
/// excerpt of it becomes the error, and the caller's guard removes the file.
pub async fn download_s3(
    bucket: &str,
    region: &str,
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
    key: &str,
    dest: &Path,
) -> Result<(), String> {
    let url = s3_object_url(endpoint, bucket, key);
    let dest_str = dest.to_str().ok_or("Invalid download path")?.to_string();
    let config_guard = s3_credentials_file("download", access_key, secret_key)?;

    tracing::info!("Downloading s3 object {key} into {dest_str}");

    // --max-filesize refuses up front when the server sends Content-Length (and
    // curl 8.4+ also aborts mid-transfer); the size check below covers older curl.
    let (code, _) = s3_curl(
        vec![
            "--aws-sigv4".into(),
            format!("aws:amz:{region}:s3"),
            "-K".into(),
            config_guard.path.clone(),
            "--max-filesize".into(),
            DOWNLOAD_MAX_BYTES.to_string(),
            "-o".into(),
            dest_str,
            url,
        ],
        DOWNLOAD_TIMEOUT_SECS,
        "Download",
    )
    .await
    .map_err(|e| {
        if e.contains("exit status: 63") || e.contains("(63)") {
            format!("{DOWNLOAD_TOO_LARGE} ({DOWNLOAD_MAX_BYTES} bytes)")
        } else {
            e
        }
    })?;

    drop(config_guard);

    if !s3_ok(code) {
        let excerpt = read_excerpt(dest, 2048);
        return Err(format!("S3 download failed: {}", s3_detail(code, &excerpt)));
    }
    let size = std::fs::metadata(dest)
        .map_err(|e| format!("Downloaded file is missing: {e}"))?
        .len();
    if size > DOWNLOAD_MAX_BYTES {
        return Err(format!("{DOWNLOAD_TOO_LARGE} ({DOWNLOAD_MAX_BYTES} bytes)"));
    }
    Ok(())
}

/// First `max` bytes of a file, lossily decoded, for an error message.
fn read_excerpt(path: &Path, max: usize) -> String {
    use std::io::Read;
    let mut buf = vec![0u8; max];
    match std::fs::File::open(path).and_then(|mut f| f.read(&mut buf)) {
        Ok(n) => String::from_utf8_lossy(&buf[..n]).to_string(),
        Err(_) => String::new(),
    }
}

/// Parse the stdout of an `sftp -b` batch that ran `ls -ln <dir>`.
///
/// Measured against OpenSSH 9.2 (Debian 12) with `sftp -b -`, the output is the
/// echoed command line, then one line per entry:
///
/// ```text
/// sftp> ls -ln "/home/bk/backups"
/// -rw-r--r--    ? bk       bk              3 Nov 19 14:38 /home/bk/backups/site.com-20261119-030000.tar.gz
/// -rw-r--r--    ? bk       bk              2 Jan  2  2024 /home/bk/backups/old.tar.gz
/// drwxr-xr-x    ? bk       bk           4096 Nov 19 14:38 /home/bk/backups/sub
/// ```
///
/// Eight whitespace-separated fields (mode, links, owner, group, size, month,
/// day, time-or-year), then the path as sftp joined it, spaces included. Only
/// regular files (`-` mode) are kept. The key is rebuilt from `dir` and the
/// basename rather than taken from the printed path, so a relative or oddly
/// joined echo cannot move an object outside the destination.
pub fn parse_sftp_ls(stdout: &str, dir: &str) -> Vec<RemoteObject> {
    let mut out = Vec::new();
    for raw in stdout.lines() {
        let line = raw.trim_end_matches('\r');
        if !line.starts_with('-') {
            continue;
        }
        let mut rest = line;
        let mut fields: Vec<&str> = Vec::with_capacity(8);
        for _ in 0..8 {
            rest = rest.trim_start();
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            if end == 0 {
                break;
            }
            fields.push(&rest[..end]);
            rest = &rest[end..];
        }
        if fields.len() != 8 {
            continue;
        }
        let Ok(size) = fields[4].parse::<u64>() else { continue };
        let path = rest.trim_start();
        let name = path.rsplit('/').next().unwrap_or("");
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        out.push(RemoteObject {
            name: name.to_string(),
            key: format!("{dir}/{name}"),
            size,
            modified: None,
        });
    }
    out
}

/// Run one sftp batch against an SFTP destination.
async fn sftp_batch(
    host: &str,
    port: u16,
    username: &str,
    password: Option<&str>,
    key_path: Option<&str>,
    script: &str,
    timeout_secs: u64,
    label: &str,
) -> Result<std::process::Output, String> {
    let mut cmd_args = sftp_opts(port, password, key_path);
    cmd_args.push("-b".into());
    cmd_args.push("-".into());
    cmd_args.push(format!("{username}@{host}"));
    run_sftp("sftp", cmd_args, password, key_path, timeout_secs, label, Some(script)).await
}

/// List the regular files directly in `dir` on an SFTP destination.
///
/// A directory that does not exist yet lists as empty, like an S3 prefix with
/// nothing under it: a fresh destination has no backups, which is not an error.
pub async fn list_sftp(
    host: &str,
    port: u16,
    username: &str,
    password: Option<&str>,
    key_path: Option<&str>,
    dir: &str,
) -> Result<Vec<RemoteObject>, String> {
    reject_unquotable_path(dir)?;
    let target = if dir.is_empty() { "/" } else { dir };
    let script = format!("ls -ln {}\n", sftp_quote(target));
    let output = sftp_batch(host, port, username, password, key_path, &script, 60, "List").await?;
    if !output.status.success() {
        let detail = command_detail(&output);
        if detail.contains("Can't ls:") && detail.contains("not found") {
            return Ok(Vec::new());
        }
        return Err(format!("SFTP list failed: {detail}"));
    }
    Ok(parse_sftp_ls(&String::from_utf8_lossy(&output.stdout), dir))
}

/// Download one remote file into `dest` (a file the caller already created at
/// 0600; `get` writes into it in place, measured to keep the mode).
///
/// The size is read first so an oversized object is refused before any byte
/// moves, and compared after so a transfer cut short is not accepted.
pub async fn download_sftp(
    host: &str,
    port: u16,
    username: &str,
    password: Option<&str>,
    key_path: Option<&str>,
    remote: &str,
    dest: &Path,
) -> Result<(), String> {
    reject_unquotable_path(remote)?;
    let dest_str = dest.to_str().ok_or("Invalid download path")?;
    reject_unquotable_path(dest_str)?;

    let stat = sftp_batch(
        host, port, username, password, key_path,
        &format!("ls -ln {}\n", sftp_quote(remote)),
        60,
        "Download",
    )
    .await?;
    if !stat.status.success() {
        return Err(format!("SFTP download failed: {}", command_detail(&stat)));
    }
    let name = remote.rsplit('/').next().unwrap_or("");
    let expected = parse_sftp_ls(&String::from_utf8_lossy(&stat.stdout), "")
        .into_iter()
        .find(|o| o.name == name)
        .map(|o| o.size)
        .ok_or_else(|| format!("SFTP download failed: {remote} is not a regular file"))?;
    if expected > DOWNLOAD_MAX_BYTES {
        return Err(format!("{DOWNLOAD_TOO_LARGE} ({DOWNLOAD_MAX_BYTES} bytes)"));
    }

    tracing::info!("Downloading {remote} via SFTP into {dest_str}");
    let output = sftp_batch(
        host, port, username, password, key_path,
        &format!("get {} {}\n", sftp_quote(remote), sftp_quote(dest_str)),
        DOWNLOAD_TIMEOUT_SECS,
        "Download",
    )
    .await?;
    if !output.status.success() {
        return Err(format!("SFTP download failed: {}", command_detail(&output)));
    }
    let got = std::fs::metadata(dest)
        .map_err(|e| format!("Downloaded file is missing: {e}"))?
        .len();
    if got != expected {
        return Err(format!(
            "SFTP download is incomplete: received {got} bytes, the remote file has {expected}"
        ));
    }
    Ok(())
}

/// Delete one remote file. A file already gone counts as deleted, as a 404 does
/// for S3.
pub async fn delete_sftp(
    host: &str,
    port: u16,
    username: &str,
    password: Option<&str>,
    key_path: Option<&str>,
    remote: &str,
) -> Result<(), String> {
    reject_unquotable_path(remote)?;
    let script = format!("rm {}\n", sftp_quote(remote));
    let output = sftp_batch(host, port, username, password, key_path, &script, 30, "Delete").await?;
    if output.status.success() {
        return Ok(());
    }
    let detail = command_detail(&output);
    if detail.contains("No such file or directory") {
        return Ok(());
    }
    Err(format!("SFTP delete failed: {detail}"))
}

// ─── Validation (pure, unit-tested) ─────────────────────────────────────────

/// `target_name` of a download: `^[A-Za-z0-9._-]+$`, no `..`, at most 255 bytes.
/// The charset alone already excludes `/`, so the name cannot be absolute or
/// reach outside the inbox.
pub fn validate_target_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 255 {
        return Err("target_name must be 1 to 255 characters".to_string());
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return Err("target_name may contain only letters, digits, '.', '_' and '-'".to_string());
    }
    if name == "." || name.contains("..") {
        return Err("target_name may not contain '..'".to_string());
    }
    Ok(())
}

/// The optional `prefix` of `/backups/list`: relative to the destination's base,
/// letters, digits, `.`, `_`, `-` and `/`, no leading `/`, no empty, `.` or `..`
/// segment. A trailing `/` addresses a sub-directory; text after the last `/`
/// filters names by their start.
pub fn validate_list_prefix(p: &str) -> Result<(), String> {
    if p.len() > 512 {
        return Err("prefix is too long".to_string());
    }
    if !p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/')) {
        return Err("prefix may contain only letters, digits, '.', '_', '-' and '/'".to_string());
    }
    if p.starts_with('/') {
        return Err("prefix must be relative to the destination".to_string());
    }
    let segs: Vec<&str> = p.split('/').collect();
    for (i, s) in segs.iter().enumerate() {
        let last = i == segs.len() - 1;
        if (s.is_empty() && !last) || *s == "." || *s == ".." {
            return Err("prefix may not contain empty, '.' or '..' segments".to_string());
        }
    }
    Ok(())
}

/// A `key` given to download or delete must sit under the destination's
/// configured prefix (`key_prefix`, ending in `/` unless empty) and be a plain
/// path below it: no `.`/`..`/empty segment, no control character, and none of
/// `\ " * ? [ ]` (sftp's batch parser treats them specially). Every key that
/// `/backups/list` returns for the same destination passes.
pub fn validate_key_under(key: &str, key_prefix: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > 1024 {
        return Err("key must be 1 to 1024 characters".to_string());
    }
    if key.chars().any(|c| c.is_control() || matches!(c, '\\' | '"' | '*' | '?' | '[' | ']')) {
        return Err("key contains a character that is not allowed".to_string());
    }
    let Some(rest) = key.strip_prefix(key_prefix) else {
        return Err("key is outside the destination's configured prefix".to_string());
    };
    if rest.is_empty() || rest.split('/').any(|s| s.is_empty() || s == "." || s == "..") {
        return Err("key must name an object below the destination's prefix, without '.' or '..' segments".to_string());
    }
    Ok(())
}

/// `name_prefix` of `/backups/prune` (or the one derived from `domain`):
/// non-empty, no `/`, no `..`, no control character.
pub fn validate_name_prefix(p: &str) -> Result<(), String> {
    if p.is_empty() {
        return Err("name_prefix may not be empty".to_string());
    }
    if p.len() > 255 {
        return Err("name_prefix is too long".to_string());
    }
    if p.contains('/') || p.contains("..") || p.contains('\\') || p.chars().any(|c| c.is_control()) {
        return Err("name_prefix may not contain '/', '..', '\\' or control characters".to_string());
    }
    Ok(())
}

/// `suffixes` of `/backups/prune`: at least one, each non-empty, under the same
/// rules as `name_prefix`.
pub fn validate_suffixes(suffixes: &[String]) -> Result<(), String> {
    if suffixes.is_empty() {
        return Err("suffixes may not be empty".to_string());
    }
    for s in suffixes {
        if s.is_empty() || s.len() > 64 || s.contains('/') || s.contains("..") || s.contains('\\')
            || s.chars().any(|c| c.is_control())
        {
            return Err("each suffix must be 1 to 64 characters without '/', '..', '\\' or control characters".to_string());
        }
    }
    Ok(())
}

/// Whether retention may delete the object named `name`.
///
/// It must start with `prefix`, end with one of `suffixes`, and what lies
/// between - taken AFTER removing the prefix, so prefix and suffix cannot
/// overlap - must be non-empty and only `[A-Za-z0-9._-]`. Anything else is never
/// deleted: a name with a `/`, a name whose start only resembles the prefix
/// (`site.comx-...` for `site.com-`), a name without a listed suffix.
///
/// Known limit, inherited from the domain-keyed prune: a prefix ending in `-`
/// also matches a longer name that continues with safe characters (`a.com-`
/// matches `a.com-old.org-20261119-030000.tar.gz`). A caller that needs to tell
/// such names apart passes a `name_prefix` that ends where the variable part
/// begins and is unique to its resource.
pub fn prune_name_matches(name: &str, prefix: &str, suffixes: &[String]) -> bool {
    if name.contains('/') || prefix.is_empty() {
        return false;
    }
    let Some(rest) = name.strip_prefix(prefix) else { return false };
    suffixes.iter().any(|suf| {
        if suf.is_empty() {
            return false;
        }
        match rest.strip_suffix(suf.as_str()) {
            Some(mid) => {
                !mid.is_empty()
                    && mid.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            }
            None => false,
        }
    })
}

/// Split the matching objects into `(kept, to_delete)`: newest `retention`
/// kept, newest meaning greatest name. Backup names carry a fixed-width
/// `%Y%m%d-%H%M%S` stamp after a fixed prefix, so name order is time order, and
/// it is the same on S3 and SFTP (SFTP has no reliable mtime, see
/// [`RemoteObject`]). Objects that do not match are in neither list.
///
/// `site_stamp_only` is set for the legacy, domain-keyed request: the middle
/// must then be exactly the `%Y%m%d-%H%M%S` stamp `backups.rs` writes, which
/// closes the limit described on [`prune_name_matches`] for site archives
/// (`a.com-` no longer reaches `a.com-old.org-...`).
pub fn select_for_prune(
    objects: Vec<RemoteObject>,
    prefix: &str,
    suffixes: &[String],
    retention: usize,
    site_stamp_only: bool,
) -> (Vec<RemoteObject>, Vec<RemoteObject>) {
    let mut matched: Vec<RemoteObject> = objects
        .into_iter()
        .filter(|o| prune_name_matches(&o.name, prefix, suffixes))
        .filter(|o| !site_stamp_only || has_site_stamp(&o.name, prefix, suffixes))
        .collect();
    matched.sort_by(|a, b| b.name.cmp(&a.name).then_with(|| b.key.cmp(&a.key)));
    let to_delete = if matched.len() > retention { matched.split_off(retention) } else { Vec::new() };
    (matched, to_delete)
}

/// Whether the part of `name` between `prefix` and one of `suffixes` is a
/// `YYYYMMDD-HHMMSS` stamp.
fn has_site_stamp(name: &str, prefix: &str, suffixes: &[String]) -> bool {
    let Some(rest) = name.strip_prefix(prefix) else { return false };
    suffixes.iter().any(|suf| {
        rest.strip_suffix(suf.as_str()).is_some_and(|mid| {
            let b = mid.as_bytes();
            b.len() == 15
                && b[8] == b'-'
                && b.iter().enumerate().all(|(i, c)| i == 8 || c.is_ascii_digit())
        })
    })
}

// ─── Restore inbox (local side of a download) ───────────────────────────────

/// Create `inbox` at 0700 if absent and refuse it if it is not a real directory
/// (a symlink there would redirect every download).
pub fn prepare_inbox(inbox: &Path) -> Result<(), String> {
    std::fs::create_dir_all(inbox).map_err(|e| format!("Cannot create {}: {e}", inbox.display()))?;
    let meta = std::fs::symlink_metadata(inbox).map_err(|e| format!("Cannot stat {}: {e}", inbox.display()))?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(format!("{} is not a directory", inbox.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(inbox, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Cannot set the mode of {}: {e}", inbox.display()))?;
    }
    Ok(())
}

/// A partial download: an empty 0600 file in the inbox, removed on drop unless
/// [`finalize_download`] renamed it into place.
pub struct PartFile {
    pub path: std::path::PathBuf,
    armed: bool,
}

impl Drop for PartFile {
    fn drop(&mut self) {
        if self.armed {
            std::fs::remove_file(&self.path).ok();
        }
    }
}

/// Create the hidden partial file for `target` (already validated) in `inbox`.
pub fn create_part_file(inbox: &Path, target: &str) -> Result<PartFile, String> {
    let path = inbox.join(format!(".{target}.part-{:016x}", rand::random::<u64>()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(&path).map_err(|e| format!("Cannot create {}: {e}", path.display()))?;
    Ok(PartFile { path, armed: true })
}

/// What `/backups/download` reports.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Downloaded {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// Hash the finished partial file (streamed, off the async runtime: archives can
/// be far larger than the unit's `MemoryMax`), force 0600, rename it to
/// `<inbox>/<target>`.
pub async fn finalize_download(mut part: PartFile, inbox: &Path, target: &str) -> Result<Downloaded, String> {
    let p = part.path.clone();
    let (size, sha256) = tokio::task::spawn_blocking(move || -> Result<(u64, String), String> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("Cannot set the mode of the download: {e}"))?;
        }
        let mut f = std::fs::File::open(&p).map_err(|e| format!("Cannot read the download: {e}"))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1024 * 1024];
        let mut size = 0u64;
        loop {
            let n = f.read(&mut buf).map_err(|e| format!("Cannot read the download: {e}"))?;
            if n == 0 {
                break;
            }
            size += n as u64;
            hasher.update(&buf[..n]);
        }
        Ok((size, hex::encode(hasher.finalize())))
    })
    .await
    .map_err(|e| format!("Hashing the download failed: {e}"))??;

    let final_path = inbox.join(target);
    std::fs::rename(&part.path, &final_path)
        .map_err(|e| format!("Cannot move the download into place: {e}"))?;
    part.armed = false;
    Ok(Downloaded { path: final_path.to_string_lossy().to_string(), size, sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shell escaping this replaced was correct FOR A SHELL. sftp's batch
    /// parser is not one, and the failure it produces is silent: measured s339,
    /// an unquoted `put local /backups/my dir/f.tgz` wrote to `/backups/my`
    /// under the SOURCE filename and exited 0.
    #[test]
    fn quotes_paths_a_batch_parser_would_otherwise_split() {
        assert_eq!(sftp_quote("/backups"), "\"/backups\"");
        assert_eq!(sftp_quote("/my backups"), "\"/my backups\"");
        // Single quotes are literal inside double quotes - the shell form had to
        // escape these and the batch form must not.
        assert_eq!(sftp_quote("/od'brien"), "\"/od'brien\"");
        // These two are the only characters that need escaping.
        assert_eq!(sftp_quote("/say\"hi"), "\"/say\\\"hi\"");
        assert_eq!(sftp_quote("/back\\slash"), "\"/back\\\\slash\"");
        // Glob metacharacters survive literally, so a real directory named with
        // one is still addressed rather than expanded.
        assert_eq!(sftp_quote("/we*ird?"), "\"/we*ird?\"");
    }

    /// `sftp` has no `mkdir -p`, so every ancestor is created in its own command,
    /// shallowest first, each prefixed with `-` because a `mkdir` of an existing
    /// directory FAILS and would abort the rest of the batch.
    #[test]
    fn mkdir_script_creates_every_ancestor_shallowest_first() {
        assert_eq!(
            sftp_mkdir_script("/srv/backups/dockpanel"),
            "-mkdir \"/srv\"\n-mkdir \"/srv/backups\"\n-mkdir \"/srv/backups/dockpanel\"\n"
        );
        assert_eq!(sftp_mkdir_script("/backups"), "-mkdir \"/backups\"\n");
        // A relative path must not acquire a leading slash.
        assert_eq!(
            sftp_mkdir_script("backups/nightly"),
            "-mkdir \"backups\"\n-mkdir \"backups/nightly\"\n"
        );
        assert_eq!(sftp_mkdir_script(""), "");
        // Every line carries the ignore-failure prefix; one that did not would
        // abort the batch on an already-provisioned destination.
        for line in sftp_mkdir_script("/a/b/c").lines() {
            assert!(line.starts_with("-mkdir "), "unprefixed mkdir: {line}");
        }
    }

    /// A newline in a batch script STARTS A NEW COMMAND. `remote_path` arrives
    /// from the request body with no validation upstream, so this is the only
    /// place that can refuse one.
    #[test]
    fn rejects_a_remote_path_that_would_append_a_second_command() {
        assert!(reject_unquotable_path("/backups").is_ok());
        assert!(reject_unquotable_path("/my backups").is_ok());
        assert!(reject_unquotable_path("/backups\nput /etc/shadow /pub/x").is_err());
        assert!(reject_unquotable_path("/backups\rrm /pub/x").is_err());
    }

    /// `sftp -b` sets BatchMode itself, and BatchMode disables the password auth
    /// `sshpass` exists to answer - the s288 defect, reachable a second way.
    #[test]
    fn batchmode_is_turned_off_for_password_auth_and_on_for_keys() {
        let pw = sftp_opts(22, Some("secret"), None);
        assert!(
            pw.windows(2).any(|w| w[0] == "-o" && w[1] == "BatchMode=no"),
            "password auth must disable BatchMode explicitly: {pw:?}"
        );
        let key = sftp_opts(22, None, Some("/etc/dockpanel/id"));
        assert!(
            key.windows(2).any(|w| w[0] == "-o" && w[1] == "BatchMode=yes"),
            "key auth must keep BatchMode on: {key:?}"
        );
        // sftp takes -P for the port; -p would be "preserve times".
        assert!(pw.windows(2).any(|w| w[0] == "-P" && w[1] == "22"));
    }

    /// Reading only stderr is what made issue #102 unreadable: `internal-sftp`
    /// refuses an exec request on STDOUT, leaving stderr holding nothing but
    /// ssh's known-hosts banner.
    #[test]
    fn detail_reports_a_refusal_that_arrived_on_stdout() {
        use std::os::unix::process::ExitStatusExt;
        let only_stdout = std::process::Output {
            status: std::process::ExitStatus::from_raw(256),
            stdout: b"This service allows sftp connections only.".to_vec(),
            stderr: Vec::new(),
        };
        assert!(command_detail(&only_stdout).contains("sftp connections only"));

        let neither = std::process::Output {
            status: std::process::ExitStatus::from_raw(256),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        assert_eq!(command_detail(&neither), "no output from sftp");

        let both = std::process::Output {
            status: std::process::ExitStatus::from_raw(256),
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
        };
        assert_eq!(command_detail(&both), "err | out");
    }

    // ── listing, prune, download (no network) ──────────────────────────────

    /// First page of a ListObjectsV2 answer with `max-keys=2`: truncated, with a
    /// token, an XML-escaped key, a sub-"directory" under CommonPrefixes, and a
    /// folder placeholder key.
    const S3_PAGE_1: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix>backups/</Prefix><KeyCount>3</KeyCount><MaxKeys>2</MaxKeys><Delimiter>/</Delimiter><IsTruncated>true</IsTruncated><Contents><Key>backups/a&amp;b.tar.gz</Key><LastModified>2026-11-18T03:30:01.000Z</LastModified><ETag>&quot;x&quot;</ETag><Size>12</Size><StorageClass>STANDARD</StorageClass></Contents><Contents><Key>backups/</Key><LastModified>2026-11-18T03:30:01.000Z</LastModified><Size>0</Size></Contents><CommonPrefixes><Prefix>backups/cyberhunter-dr/</Prefix></CommonPrefixes><NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken></ListBucketResult>"#;

    const S3_PAGE_2: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix>backups/</Prefix><ContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</ContinuationToken><KeyCount>1</KeyCount><MaxKeys>2</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>backups/site.com-20261119-030000.tar.gz</Key><LastModified>2026-11-19T03:00:05.123Z</LastModified><Size>5368709120</Size></Contents></ListBucketResult>"#;

    #[test]
    fn list_objects_v2_pages_follow_the_continuation_token() {
        let p1 = parse_list_objects_v2(S3_PAGE_1).unwrap();
        assert_eq!(p1.next_token.as_deref(), Some("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM="));
        assert_eq!(p1.objects.len(), 2);
        // Decoded, or the key would not round-trip into download/delete.
        assert_eq!(p1.objects[0].0, "backups/a&b.tar.gz");
        assert_eq!(p1.objects[0].1, 12);
        assert_eq!(p1.objects[0].2.as_deref(), Some("2026-11-18T03:30:01Z"));
        // CommonPrefixes are not objects.
        assert!(!p1.objects.iter().any(|o| o.0.contains("cyberhunter-dr")));

        let p2 = parse_list_objects_v2(S3_PAGE_2).unwrap();
        assert_eq!(p2.next_token, None);
        assert_eq!(p2.objects, vec![(
            "backups/site.com-20261119-030000.tar.gz".to_string(),
            5_368_709_120,
            Some("2026-11-19T03:00:05Z".to_string())
        )]);
    }

    #[test]
    fn a_truncated_page_without_a_token_is_an_error_not_the_end() {
        let body = "<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>k</Key><Size>1</Size></Contents></ListBucketResult>";
        assert!(parse_list_objects_v2(body).is_err());
        // An error document is not an empty listing either.
        assert!(parse_list_objects_v2("<Error><Code>AccessDenied</Code></Error>").is_err());
        let empty = "<ListBucketResult><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>";
        assert_eq!(parse_list_objects_v2(empty).unwrap(), S3ListPage { objects: vec![], next_token: None });
    }

    /// The query is emitted already canonical: sorted parameters, every value
    /// encoded, so the token's `/`, `+` and `=` cannot be signed one way and sent
    /// another.
    #[test]
    fn list_url_is_sorted_and_encoded() {
        let u = s3_list_url("https://s3.example", "b", "backups/db-", Some("a+b/c="), Some(2));
        assert_eq!(
            u,
            "https://s3.example/b/?continuation-token=a%2Bb%2Fc%3D&delimiter=%2F&list-type=2&max-keys=2&prefix=backups%2Fdb-"
        );
        assert_eq!(s3_list_url("https://e", "b", "", None, None), "https://e/b/?delimiter=%2F&list-type=2");
        assert_eq!(s3_object_url("https://e", "b", "backups/a&b c.tar.gz"), "https://e/b/backups/a%26b%20c.tar.gz");
    }

    #[test]
    fn xml_entities_are_decoded() {
        assert_eq!(xml_unescape("a&amp;b&lt;c&gt;&quot;&apos;&#65;&#x42;"), "a&b<c>\"'AB");
        assert_eq!(xml_unescape("no entity & here"), "no entity & here");
    }

    #[test]
    fn s3_error_bodies_lose_their_credential_echoes() {
        let body = "<Error><Code>SignatureDoesNotMatch</Code><AWSAccessKeyId>AKIAEXAMPLE</AWSAccessKeyId><StringToSign>AWS4 secret-ish</StringToSign></Error>";
        let d = s3_detail(403, body);
        assert!(!d.contains("AKIAEXAMPLE"), "{d}");
        assert!(!d.contains("secret-ish"), "{d}");
        assert!(d.contains("SignatureDoesNotMatch"));
    }

    #[test]
    fn curl_config_values_are_escaped() {
        assert_eq!(curl_config_quote("ak:s\"k\\x").unwrap(), "\"ak:s\\\"k\\\\x\"");
        assert!(curl_config_quote("ak:sk\nurl = http://evil").is_err());
    }

    /// Captured from OpenSSH 9.2 `sftp -b -` (Debian 12) against a real sshd.
    const SFTP_LS: &str = "sftp> ls -ln \"/home/bk/backups\"
-rw-r--r--    ? bk       bk              2 Nov 19 14:38 /home/bk/backups/a1
-rw-r--r--    ? bk       bk              2 Jan  2  2024 /home/bk/backups/site.com-20261118-030000.tar.gz
-rw-r--r--    ? bk       bk              3 Nov 19 14:38 /home/bk/backups/site.com-20261119-030000.tar.gz
drwxr-xr-x    ? bk       bk           4096 Nov 19 14:38 /home/bk/backups/sub
-rw-r--r--    ? bk       bk              2 Nov 19 14:38 /home/bk/backups/with space.txt
";

    #[test]
    fn sftp_listing_is_parsed_from_the_measured_format() {
        let objs = parse_sftp_ls(SFTP_LS, "/home/bk/backups");
        let names: Vec<&str> = objs.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(
            names,
            ["a1", "site.com-20261118-030000.tar.gz", "site.com-20261119-030000.tar.gz", "with space.txt"]
        );
        assert_eq!(objs[2].size, 3);
        assert_eq!(objs[2].key, "/home/bk/backups/site.com-20261119-030000.tar.gz");
        assert_eq!(objs[0].modified, None);
        // The key is rebuilt from the destination dir, not taken from the echo.
        let rel = parse_sftp_ls("-rw-r--r--    ? u g 5 Nov 19 14:38 backups/x.tar.gz\n", "/srv/b");
        assert_eq!(rel[0].key, "/srv/b/x.tar.gz");
        assert!(parse_sftp_ls("sftp> ls -ln \"/x\"\n", "/x").is_empty());
    }

    fn obj(name: &str) -> RemoteObject {
        RemoteObject { name: name.into(), key: format!("backups/{name}"), size: 1, modified: None }
    }

    #[test]
    fn prune_never_selects_a_name_that_does_not_match() {
        let tgz = vec![".tar.gz".to_string()];
        let p = "site.com-";
        assert!(prune_name_matches("site.com-20261119-030000.tar.gz", p, &tgz));
        // A path, even one whose basename would match.
        assert!(!prune_name_matches("site.com-evil/../x.tar.gz", p, &tgz));
        assert!(!prune_name_matches("site.com-evil/../x", p, &tgz));
        // Suffix absent, or another suffix.
        assert!(!prune_name_matches("site.com-20261119-030000.tar", p, &tgz));
        assert!(!prune_name_matches("site.com-20261119-030000.tar.gz.age", p, &tgz));
        // Another prefix sharing the start.
        assert!(!prune_name_matches("site.comx-20261119-030000.tar.gz", p, &tgz));
        assert!(!prune_name_matches("site.co-20261119-030000.tar.gz", p, &tgz));
        assert!(!prune_name_matches("xsite.com-20261119-030000.tar.gz", p, &tgz));
        // Nothing between prefix and suffix, or characters outside the set.
        assert!(!prune_name_matches("site.com-.tar.gz", p, &tgz));
        assert!(!prune_name_matches("site.com-2026 1119.tar.gz", p, &tgz));
        assert!(!prune_name_matches("site.com-a*b.tar.gz", p, &tgz));
        // Prefix and suffix may not overlap.
        assert!(!prune_name_matches("ab", "ab", &["b".to_string()]));
        // Several suffixes.
        let dr = vec![".tar.gz.age".to_string(), ".manifest.json".to_string()];
        assert!(prune_name_matches("cyberhunter-dr-20261119T033000Z.manifest.json", "cyberhunter-dr-", &dr));
        assert!(!prune_name_matches("cyberhunter-dr-20261119T033000Z.tar.gz", "cyberhunter-dr-", &dr));
    }

    #[test]
    fn prune_keeps_the_newest_n_and_touches_nothing_else() {
        let tgz = vec![".tar.gz".to_string()];
        let objects = vec![
            obj("site.com-20261117-030000.tar.gz"),
            obj("site.com-20261119-030000.tar.gz"),
            obj("site.com-20261118-030000.tar.gz"),
            obj("site.com-old.org-20261101-030000.tar.gz"),
            obj("other.com-20261101-030000.tar.gz"),
            obj("site.com-20261101-030000.sql.gz"),
        ];
        let (kept, del) = select_for_prune(objects.clone(), "site.com-", &tgz, 2, true);
        let k: Vec<&str> = kept.iter().map(|o| o.name.as_str()).collect();
        let d: Vec<&str> = del.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(k, ["site.com-20261119-030000.tar.gz", "site.com-20261118-030000.tar.gz"]);
        // The legacy (domain) request no longer reaches another site whose name
        // merely starts with this one.
        assert_eq!(d, ["site.com-20261117-030000.tar.gz"]);

        // Generic request: the charset rule alone, so that longer name matches.
        let (_, del_generic) = select_for_prune(objects.clone(), "site.com-", &tgz, 2, false);
        assert_eq!(del_generic.len(), 2);

        // Retention larger than the set deletes nothing.
        let (kept_all, none) = select_for_prune(objects, "site.com-", &tgz, 10, true);
        assert_eq!(kept_all.len(), 3);
        assert!(none.is_empty());
    }

    #[test]
    fn target_name_validation() {
        for ok in ["cyberhunter-dr-20261119.tar.gz.age", "a", "a.b_c-d", ".hidden"] {
            assert!(validate_target_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", ".", "..", "a..b", "../x", "/etc/passwd", "a/b", "a b", "a\nb", "é", &"x".repeat(256)] {
            assert!(validate_target_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn key_validation_keeps_keys_under_the_destination_prefix() {
        assert!(validate_key_under("backups/x.tar.gz", "backups/").is_ok());
        assert!(validate_key_under("backups/cyberhunter-dr/id/x.age", "backups/").is_ok());
        assert!(validate_key_under("x.tar.gz", "").is_ok());
        assert!(validate_key_under("/home/bk/backups/with space.txt", "/home/bk/backups/").is_ok());
        // Same start, other directory.
        assert!(validate_key_under("backups-old/x", "backups/").is_err());
        assert!(validate_key_under("/backupsx/f", "/backups/").is_err());
        // Escapes and degenerate keys.
        assert!(validate_key_under("backups/../etc/x", "backups/").is_err());
        assert!(validate_key_under("backups/./x", "backups/").is_err());
        assert!(validate_key_under("backups/", "backups/").is_err());
        assert!(validate_key_under("backups//x", "backups/").is_err());
        assert!(validate_key_under("/x", "").is_err());
        assert!(validate_key_under("/backups/a\nrm /x", "/backups/").is_err());
        assert!(validate_key_under("/backups/a*", "/backups/").is_err());
        assert!(validate_key_under("/backups/a\"b", "/backups/").is_err());
    }

    #[test]
    fn list_prefix_validation() {
        for ok in ["", "cyberhunter-dr/", "cyberhunter-dr/abc/", "db-", "cyberhunter-dr/abc/cyberhunter-dr-"] {
            assert!(validate_list_prefix(ok).is_ok(), "{ok}");
        }
        for bad in ["/abs", "a//b", "../x", "a/../b", "./a", "a b", "a\nb", "a*"] {
            assert!(validate_list_prefix(bad).is_err(), "{bad:?}");
        }
    }

    /// Every key the listing builds passes the key check of the same
    /// destination, so list -> download/delete round-trips.
    #[test]
    fn listed_keys_round_trip_into_the_key_check() {
        for o in parse_sftp_ls(SFTP_LS, &sftp_dir("/home/bk/backups/")) {
            assert!(validate_key_under(&o.key, &format!("{}/", sftp_dir("/home/bk/backups/"))).is_ok(), "{}", o.key);
        }
        let p = s3_key_prefix("/backups/");
        for (k, _, _) in parse_list_objects_v2(S3_PAGE_2).unwrap().objects {
            assert!(validate_key_under(&k, &p).is_ok(), "{k}");
        }
    }

    #[tokio::test]
    async fn download_lands_at_0600_in_a_0700_inbox_and_cleans_up_on_failure() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("dp-inbox-test-{:016x}", rand::random::<u64>()));
        let inbox = root.join("restore-inbox");
        prepare_inbox(&inbox).unwrap();
        assert_eq!(std::fs::metadata(&inbox).unwrap().permissions().mode() & 0o777, 0o700);

        // Success: partial file renamed, mode 0600, hash and size reported.
        let part = create_part_file(&inbox, "x.tar.gz").unwrap();
        assert_eq!(std::fs::metadata(&part.path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::write(&part.path, b"abc").unwrap();
        let d = finalize_download(part, &inbox, "x.tar.gz").await.unwrap();
        assert_eq!(d.size, 3);
        assert_eq!(d.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(d.path, inbox.join("x.tar.gz").to_string_lossy());
        assert_eq!(std::fs::metadata(&d.path).unwrap().permissions().mode() & 0o777, 0o600);

        // Failure: dropping the partial file without finalising removes it.
        let part = create_part_file(&inbox, "y.tar.gz").unwrap();
        let p = part.path.clone();
        drop(part);
        assert!(!p.exists());
        let left: Vec<_> = std::fs::read_dir(&inbox).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left, vec![std::ffi::OsString::from("x.tar.gz")]);

        // A symlink in place of the inbox is refused.
        let link = root.join("link-inbox");
        std::os::unix::fs::symlink(&inbox, &link).unwrap();
        assert!(prepare_inbox(&link).is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn credential_files_are_created_0600_and_removed_on_drop() {
        use std::os::unix::fs::PermissionsExt;
        let g = TempFileGuard::create_kind("sftp", "pass", "pw\n").unwrap();
        let path = g.path.clone();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "pw\n");
        drop(g);
        assert!(!std::path::Path::new(&path).exists());
    }

    /// List, download, prune-style delete against a real sshd, password auth
    /// (so through `sshpass -f`). Same opt-in as the test below:
    /// `DOCKPANEL_SFTP_LAB=user:password@host:port:/remote/path`, `--ignored`.
    #[tokio::test]
    #[ignore = "needs an sshd; set DOCKPANEL_SFTP_LAB and run with --ignored"]
    async fn lab_sftp_list_download_delete() {
        let spec = std::env::var("DOCKPANEL_SFTP_LAB")
            .expect("DOCKPANEL_SFTP_LAB must be set to run this test (user:password@host:port:/remote/path)");
        let (creds, rest) = spec.split_once('@').expect("user:pass@host:port:path");
        let (user, pass) = creds.split_once(':').expect("user:pass");
        let parts: Vec<&str> = rest.splitn(3, ':').collect();
        let (host, port, path) = (parts[0], parts[1].parse::<u16>().unwrap(), parts[2]);
        let dir = sftp_dir(path);

        // Two archives and a bystander, uploaded through the real upload path.
        let stage = std::env::temp_dir().join(format!("dp-lab-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&stage).unwrap();
        for (n, body) in [
            ("lab.com-20261118-030000.tar.gz", "old"),
            ("lab.com-20261119-030000.tar.gz", "newest"),
            ("lab.com-notes.txt", "keep me"),
        ] {
            let f = stage.join(n);
            std::fs::write(&f, body).unwrap();
            upload_sftp(f.to_str().unwrap(), host, port, user, Some(pass), None, path).await.unwrap();
        }

        let listed = list_sftp(host, port, user, Some(pass), None, &dir).await.unwrap();
        let newest = listed.iter().find(|o| o.name == "lab.com-20261119-030000.tar.gz").expect("listed");
        assert_eq!(newest.size, 6);
        assert_eq!(newest.key, format!("{dir}/lab.com-20261119-030000.tar.gz"));

        // An absent directory lists as empty.
        assert!(list_sftp(host, port, user, Some(pass), None, &format!("{dir}/nope-{:x}", rand::random::<u32>()))
            .await
            .unwrap()
            .is_empty());

        // Download into a scratch inbox, then hash.
        let inbox = stage.join("inbox");
        prepare_inbox(&inbox).unwrap();
        let part = create_part_file(&inbox, "got.tar.gz").unwrap();
        download_sftp(host, port, user, Some(pass), None, &newest.key, &part.path).await.unwrap();
        let d = finalize_download(part, &inbox, "got.tar.gz").await.unwrap();
        assert_eq!(std::fs::read_to_string(&d.path).unwrap(), "newest");
        assert_eq!(d.size, 6);

        // Retention 1 over the listing: only the older archive goes.
        let suffixes = vec![".tar.gz".to_string()];
        let (_, del) = select_for_prune(listed, "lab.com-", &suffixes, 1, true);
        assert_eq!(del.len(), 1);
        for o in &del {
            delete_sftp(host, port, user, Some(pass), None, &o.key).await.unwrap();
        }
        let after: Vec<String> = list_sftp(host, port, user, Some(pass), None, &dir)
            .await
            .unwrap()
            .into_iter()
            .map(|o| o.name)
            .collect();
        assert!(!after.contains(&"lab.com-20261118-030000.tar.gz".to_string()), "{after:?}");
        assert!(after.contains(&"lab.com-20261119-030000.tar.gz".to_string()));
        assert!(after.contains(&"lab.com-notes.txt".to_string()));
        // Deleting what is already gone is not an error.
        delete_sftp(host, port, user, Some(pass), None, &del[0].key).await.unwrap();
        // A wrong password fails loudly.
        assert!(list_sftp(host, port, user, Some("wrong"), None, &dir).await.is_err());
        std::fs::remove_dir_all(&stage).ok();
    }

    /// End-to-end against a real sshd running `ForceCommand internal-sftp`.
    ///
    /// Opt-in because it needs that server: export
    /// `DOCKPANEL_SFTP_LAB=user:password@host:port:/remote/path` and run
    /// `cargo test -- --ignored`. Run s339 against a chrooted Debian sshd in a
    /// container. CI is unaffected because the test is `#[ignore]`d, not because
    /// it quietly returns - that distinction is the whole point of the note below.
    ///
    /// v2.95.1 shipped a reverted transport partly because this test used to
    /// return early when the variable was unset: a run that executed NOTHING
    /// printed the same `ok` as a run that proved the transport, and the summary
    /// line counted it as a pass. Two changes remove that state:
    ///
    /// - `#[ignore]` puts it in the summary's `N ignored` column, which is a
    ///   counted, visible state rather than a silent pass.
    /// - the variable is now `expect`ed rather than matched, so running it
    ///   (`cargo test -- --ignored`) without a lab PANICS instead of passing
    ///   vacuously. A test that cannot run must not be able to report success.
    ///
    /// Treat the transport arms in `backup-lands-pin-e2e.sh` as the CI-side
    /// guard; this is the deeper check you run by hand when touching the
    /// transport, and if you are touching it, set the variable.
    #[tokio::test]
    #[ignore = "needs an sshd running ForceCommand internal-sftp; set DOCKPANEL_SFTP_LAB and run with --ignored"]
    async fn lab_upload_and_test_survive_forcecommand() {
        let spec = std::env::var("DOCKPANEL_SFTP_LAB").expect(
            "DOCKPANEL_SFTP_LAB must be set to run this test \
             (user:password@host:port:/remote/path). It is #[ignore]d by default; \
             being asked to run means a lab was expected, so an unset variable is \
             a configuration error, not a reason to pass.",
        );
        let (creds, rest) = spec.split_once('@').expect("user:pass@host:port:path");
        let (user, pass) = creds.split_once(':').expect("user:pass");
        let parts: Vec<&str> = rest.splitn(3, ':').collect();
        let (host, port, path) = (parts[0], parts[1].parse::<u16>().unwrap(), parts[2]);

        test_sftp(host, port, user, Some(pass), None, path)
            .await
            .expect("Test Connection must succeed through ForceCommand internal-sftp");

        let local = std::env::temp_dir().join("dockpanel-sftp-lab-upload.txt");
        tokio::fs::write(&local, b"s339").await.unwrap();
        let dest = upload_sftp(
            local.to_str().unwrap(),
            host,
            port,
            user,
            Some(pass),
            None,
            path,
        )
        .await
        .expect("upload must succeed through ForceCommand internal-sftp");
        assert!(dest.contains("dockpanel-sftp-lab-upload.txt"));
        let _ = tokio::fs::remove_file(&local).await;

        // A path that cannot exist must still FAIL - otherwise the arms above only
        // prove the happy direction, and a function that always returns Ok would
        // pass every one of them.
        let err = test_sftp(host, port, user, Some(pass), None, "/proc/nope")
            .await
            .expect_err("an uncreatable remote path must fail");
        assert!(!err.is_empty());
    }
}
