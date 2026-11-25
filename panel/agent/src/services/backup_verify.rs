use crate::safe_cmd::{safe_command, DockerEnvFile};

#[derive(serde::Serialize)]
pub struct VerificationResult {
    pub passed: bool,
    pub checks_run: i32,
    pub checks_passed: i32,
    pub details: Vec<VerificationCheck>,
    pub duration_ms: u64,
}

#[derive(serde::Serialize)]
pub struct VerificationCheck {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

/// A site backup counts as verified only if every CRITICAL check passed. `has_entry_point`
/// is informational (a valid non-web backup legitimately has no index.*) and must not gate
/// the verdict. The previous `checks_passed >= checks_run - 1` slack certified a corrupt,
/// non-extractable archive as passed=true whenever `extract_success` was the single failing
/// check (only 2 checks run in that case) - the lesson-#51 EOF-as-success trap re-introduced
/// in the verify safety net itself. Extracted so the decision is unit-testable.
fn site_backup_passed(checks: &[VerificationCheck]) -> bool {
    checks.iter().all(|c| c.name == "has_entry_point" || c.passed)
}

/// Verify a site backup: extract to temp dir, check file count and structure.
pub async fn verify_site_backup(domain: &str, filename: &str) -> Result<VerificationResult, String> {
    let start = std::time::Instant::now();
    let mut checks = Vec::new();

    let backup_path = format!("/var/backups/dockpanel/{domain}/{filename}");
    if !std::path::Path::new(&backup_path).exists() {
        return Err("Backup file not found".to_string());
    }

    // Check 1: File exists and has reasonable size
    let meta = std::fs::metadata(&backup_path)
        .map_err(|e| format!("Cannot read file: {e}"))?;
    checks.push(VerificationCheck {
        name: "file_exists".into(),
        passed: meta.len() > 100,
        message: format!("Backup file size: {} bytes", meta.len()),
    });

    // Check 2: Extract to temp dir and verify contents
    let temp_dir = format!("/tmp/dockpanel-verify-{}", uuid::Uuid::new_v4());
    std::fs::create_dir_all(&temp_dir).map_err(|e| format!("Temp dir: {e}"))?;

    let extract_ok = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        safe_command("tar")
            .args(["xzf", &backup_path, "-C", &temp_dir, "--no-same-owner", "--no-same-permissions"])
            .output(),
    )
    .await
    .map(|r| r.map(|o| o.status.success()).unwrap_or(false))
    .unwrap_or(false);

    checks.push(VerificationCheck {
        name: "extract_success".into(),
        passed: extract_ok,
        message: if extract_ok { "Archive extracts cleanly".into() } else { "Failed to extract archive".into() },
    });

    // Check 3: Count files in extracted directory
    if extract_ok {
        let count_output = safe_command("find")
            .args([&temp_dir, "-type", "f"])
            .output()
            .await;
        let file_count = count_output
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
            .unwrap_or(0);

        checks.push(VerificationCheck {
            name: "file_count".into(),
            passed: file_count > 0,
            message: format!("{file_count} files extracted"),
        });

        // Check 4: Look for common web files (index.php/html, wp-config.php, etc.)
        let has_index = std::path::Path::new(&format!("{temp_dir}/index.php")).exists()
            || std::path::Path::new(&format!("{temp_dir}/index.html")).exists()
            || std::path::Path::new(&format!("{temp_dir}/public/index.html")).exists()
            || std::path::Path::new(&format!("{temp_dir}/public/index.php")).exists();

        checks.push(VerificationCheck {
            name: "has_entry_point".into(),
            passed: has_index,
            message: if has_index { "Entry point found (index.php/html)".into() } else { "No index file found (may be expected for non-web backups)".into() },
        });
    }

    // Cleanup temp dir
    std::fs::remove_dir_all(&temp_dir).ok();

    let checks_run = checks.len() as i32;
    let checks_passed = checks.iter().filter(|c| c.passed).count() as i32;
    let passed = site_backup_passed(&checks);

    Ok(VerificationResult {
        passed,
        checks_run,
        checks_passed,
        details: checks,
        duration_ms: start.elapsed().as_millis() as u64,
    })
}

/// Validate a resource name (database, app, container, etc.).
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
}

// ── Scratch engine containers ───────────────────────────────────────────────

/// Name prefixes of the throwaway containers verify and drill start, and only
/// they: nothing else on a host is named like this.
///
/// `mariadb:11` and `postgres:16-alpine` declare a `VOLUME` for their data
/// directory, so each of these containers gets an ANONYMOUS volume, which a
/// plain `docker rm -f` leaves behind. In production that was one 12-168 MB
/// volume per database verification, four ticks a day: 7.5 GB in five days.
pub(crate) const SCRATCH_CONTAINER_PREFIXES: [&str; 2] = ["dockpanel-verify-", "dockpanel-drill-"];

/// Name prefix of the named scratch volumes the volume drill creates.
pub(crate) const SCRATCH_VOLUME_PREFIX: &str = "dockpanel-drill-vol-";

/// `docker` arguments that remove a scratch container together with its
/// anonymous volumes (`-v`): see [`SCRATCH_CONTAINER_PREFIXES`].
pub(crate) fn scratch_rm_args(container_name: &str) -> [&str; 4] {
    ["rm", "-f", "-v", container_name]
}

/// Best-effort removal of one scratch container and its anonymous volumes.
pub(crate) async fn remove_scratch_container(container_name: &str) {
    let _ = safe_command("docker")
        .args(scratch_rm_args(container_name))
        .output()
        .await;
}

/// The names in `listing` (one per line, as `docker ps --format {{.Names}}`
/// or `docker volume ls -q` print them) that are one of ours: a known prefix
/// followed by a non-empty `[A-Za-z0-9-]` suffix (the agent appends a UUID
/// slice). Anything else, a user's container included, is left alone.
pub(crate) fn scratch_names(listing: &str, prefixes: &[&str]) -> Vec<String> {
    listing
        .lines()
        .map(|l| l.trim().trim_start_matches('/'))
        .filter(|name| {
            prefixes.iter().any(|p| {
                name.strip_prefix(p).is_some_and(|rest| {
                    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                })
            })
        })
        .map(String::from)
        .collect()
}

/// Stdout of a `docker` listing command, or `None` when Docker cannot answer
/// (not installed, not running yet): nothing to sweep then.
async fn docker_listing(args: &[&str]) -> Option<String> {
    match safe_command("docker").args(args).output().await {
        Ok(o) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).to_string()),
        _ => None,
    }
}

/// Remove the scratch containers (with their anonymous volumes) and scratch
/// volumes an interrupted verify or drill left behind. Called once at startup,
/// before the agent serves anything, so none of them can belong to a check in
/// progress. Returns `(removed, failed)`.
///
/// It cannot reach an anonymous volume whose container is already gone: such a
/// volume carries nothing that ties it to verify, and telling it apart from a
/// user's would be a guess.
pub async fn sweep_scratch_leftovers() -> (usize, usize) {
    let mut removed = 0;
    let mut failed = 0;

    if let Some(out) = docker_listing(&["ps", "-a", "--format", "{{.Names}}"]).await {
        for name in scratch_names(&out, &SCRATCH_CONTAINER_PREFIXES) {
            match safe_command("docker").args(scratch_rm_args(&name)).output().await {
                Ok(o) if o.status.success() => removed += 1,
                _ => {
                    failed += 1;
                    tracing::error!("Failed to remove leftover scratch container {name}");
                }
            }
        }
    }
    if let Some(out) = docker_listing(&["volume", "ls", "-q"]).await {
        for name in scratch_names(&out, &[SCRATCH_VOLUME_PREFIX]) {
            match safe_command("docker").args(["volume", "rm", "-f", &name]).output().await {
                Ok(o) if o.status.success() => removed += 1,
                _ => {
                    failed += 1;
                    tracing::error!("Failed to remove leftover scratch volume {name}");
                }
            }
        }
    }
    (removed, failed)
}

// ── Encrypted dumps ─────────────────────────────────────────────────────────

/// A dump ready for `zcat`: the stored file, or a decrypted copy of it (a
/// hidden `.part` next to it, removed when this is dropped and swept at
/// startup after a crash).
pub(crate) struct ReadableDump {
    pub path: std::path::PathBuf,
    /// For a `.enc`: what the integrity check found, reported as a check.
    pub integrity: Option<String>,
    _plain: Option<crate::services::volume_backup::PlainTemp>,
}

/// Why a dump could not be opened.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DumpOpenError {
    /// The FILE's fault: tampered with, truncated, or the wrong passphrase.
    /// A failed `integrity` check, not an error.
    Integrity(String),
    /// The caller's or the host's: no key, I/O, openssl, no space.
    Other(String),
}

/// Open `{dir}/{filename}` for the restore. A plain `.sql.gz` is read as is.
/// An encrypted `.sql.gz.enc` (a policy with Encrypt on) needs `key`: its
/// integrity tag is checked, then it is decrypted to a temporary in the same
/// directory. Piping the `.enc` itself to `zcat`, as verify used to, can only
/// fail, so every encrypted database was reported "verification failed".
///
/// An untagged file (encrypted before the integrity fix) is decrypted
/// unauthenticated, as the real restore (`routes/database_backup.rs`) does:
/// refusing it here would fail a dump that restore accepts. Its contents are
/// still checked by gzip's CRC and the restore itself.
pub(crate) async fn open_dump(
    dir: &std::path::Path,
    filename: &str,
    key: Option<&str>,
) -> Result<ReadableDump, DumpOpenError> {
    use crate::services::encryption;

    let src = dir.join(filename);
    if !filename.ends_with(".enc") {
        return Ok(ReadableDump { path: src, integrity: None, _plain: None });
    }
    let key = key
        .filter(|k| !k.is_empty())
        .ok_or_else(|| DumpOpenError::Other("Encryption key required for encrypted backup".into()))?;
    let classify = |e: String| {
        if encryption::is_content_error(&e) { DumpOpenError::Integrity(e) } else { DumpOpenError::Other(e) }
    };

    let note = match encryption::verify_file(&src, key).await.map_err(classify)? {
        encryption::TagStatus::Verified => "Integrity tag matches the passphrase; dump decrypted",
        encryption::TagStatus::Legacy => {
            "No integrity tag (encrypted before the integrity fix); dump decrypted, contents checked by the restore"
        }
    };
    let len = std::fs::metadata(&src).map(|m| m.len()).unwrap_or(0);
    crate::services::volume_backup::check_space(dir, len, "the decrypted dump")
        .map_err(|e| DumpOpenError::Other(e.to_string()))?;
    // Short and hidden, like `volume_backup::decrypted_copy`: never listed as a
    // dump, never pruned, removed by `backups::remove_stale_partials` at startup.
    let plain = crate::services::volume_backup::PlainTemp {
        path: dir.join(format!(".dec-{:016x}.part", rand::random::<u64>())),
    };
    encryption::decrypt_file(&src, &plain.path, key).await.map_err(classify)?;
    Ok(ReadableDump { path: plain.path.clone(), integrity: Some(note.to_string()), _plain: Some(plain) })
}

/// Verify a database backup by restoring to a temporary container.
///
/// An encrypted dump (`.enc`) needs `encryption_key`: see [`open_dump`]. A
/// wrong tag (tampered file or wrong passphrase) is a failed `integrity`
/// check, not an error.
pub async fn verify_db_backup(
    db_type: &str,
    db_name: &str,
    filename: &str,
    encryption_key: Option<&str>,
) -> Result<VerificationResult, String> {
    let start = std::time::Instant::now();
    let mut checks = Vec::new();

    if !is_valid_name(db_name) {
        return Err("Invalid database name".to_string());
    }
    if !is_valid_name(filename) {
        return Err("Invalid filename".to_string());
    }

    let dir = std::path::PathBuf::from(format!("/var/backups/dockpanel/databases/{db_name}"));
    let backup_path = dir.join(filename);
    if !backup_path.exists() {
        return Err("Backup file not found".to_string());
    }

    // Check 1: File size
    let meta = std::fs::metadata(&backup_path)
        .map_err(|e| format!("Cannot read file: {e}"))?;
    checks.push(VerificationCheck {
        name: "file_exists".into(),
        passed: meta.len() > 30,
        message: format!("Dump file size: {} bytes", meta.len()),
    });

    // Before any container exists, so no exit path below can skip its cleanup.
    let dump = match open_dump(&dir, filename, encryption_key).await {
        Ok(d) => d,
        Err(DumpOpenError::Integrity(m)) => {
            checks.push(VerificationCheck { name: "integrity".into(), passed: false, message: m });
            let checks_run = checks.len() as i32;
            let checks_passed = checks.iter().filter(|c| c.passed).count() as i32;
            return Ok(VerificationResult {
                passed: false,
                checks_run,
                checks_passed,
                details: checks,
                duration_ms: start.elapsed().as_millis() as u64,
            });
        }
        Err(DumpOpenError::Other(m)) => return Err(m),
    };
    if let Some(note) = &dump.integrity {
        checks.push(VerificationCheck { name: "integrity".into(), passed: true, message: note.clone() });
    }

    let container_name = format!("dockpanel-verify-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let test_password = "verify_test_pass_12345";

    // Check 2: Spin up temporary database container and restore
    let restore_ok = match db_type {
        "mysql" | "mariadb" => verify_mysql_restore(&dump.path, &container_name, db_name, test_password, &mut checks).await,
        "postgres" | "postgresql" => verify_postgres_restore(&dump.path, &container_name, db_name, test_password, &mut checks).await,
        _ => {
            checks.push(VerificationCheck {
                name: "restore".into(),
                passed: false,
                message: format!("Unsupported DB type for verification: {db_type}"),
            });
            false
        }
    };

    // Cleanup: remove the temporary container AND its anonymous data volume.
    remove_scratch_container(&container_name).await;
    drop(dump);

    let checks_run = checks.len() as i32;
    let checks_passed = checks.iter().filter(|c| c.passed).count() as i32;

    Ok(VerificationResult {
        passed: restore_ok && checks_passed == checks_run,
        checks_run,
        checks_passed,
        details: checks,
        duration_ms: start.elapsed().as_millis() as u64,
    })
}

async fn verify_mysql_restore(
    backup_path: &std::path::Path,
    container_name: &str,
    db_name: &str,
    password: &str,
    checks: &mut Vec<VerificationCheck>,
) -> bool {
    // Start temp MySQL container. Bootstrap credential via --env-file, not
    // `-e KEY=value`: see `DockerEnvFile`.
    let run_env_file = match DockerEnvFile::new(&[
        ("MYSQL_DATABASE", db_name),
        ("MYSQL_ROOT_PASSWORD", password),
    ]) {
        Ok(f) => f,
        Err(e) => {
            checks.push(VerificationCheck {
                name: "temp_container".into(),
                passed: false,
                message: format!("Failed to prepare credentials: {e}"),
            });
            return false;
        }
    };
    let start_ok = safe_command("docker")
        .arg("run").arg("-d").arg("--name").arg(container_name)
        .arg("--env-file").arg(run_env_file.path())
        .args(["--memory=256m", "mariadb:11"])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !start_ok {
        checks.push(VerificationCheck {
            name: "temp_container".into(),
            passed: false,
            message: "Failed to start temporary MySQL container".into(),
        });
        return false;
    }

    let exec_env_file = match DockerEnvFile::new(&[("MYSQL_PWD", password)]) {
        Ok(f) => f,
        Err(e) => {
            checks.push(VerificationCheck {
                name: "temp_container".into(),
                passed: false,
                message: format!("Failed to prepare credentials: {e}"),
            });
            return false;
        }
    };

    // Wait for MySQL to be ready (up to 40s)
    let mut ready = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let check = safe_command("docker")
            .arg("exec").arg("--env-file").arg(exec_env_file.path())
            .args([container_name, "mariadb", "-u", "root", "-e", "SELECT 1"])
            .output()
            .await;
        if check.map(|o| o.status.success()).unwrap_or(false) {
            ready = true;
            break;
        }
    }

    checks.push(VerificationCheck {
        name: "temp_container".into(),
        passed: ready,
        message: if ready { "Temporary MySQL container ready".into() } else { "MySQL container failed to start within 40s".into() },
    });

    if !ready {
        return false;
    }

    // Restore the dump using direct process piping (no shell interpolation)
    let zcat_child = safe_command("zcat")
        .arg(backup_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();

    let restore_ok = match zcat_child {
        Ok(mut zcat) => {
            let zcat_stdout = zcat.stdout.take();
            match zcat_stdout {
                Some(stdout) => {
                    let docker_ok = tokio::time::timeout(
                        std::time::Duration::from_secs(120),
                        safe_command("docker")
                            .arg("exec").arg("-i")
                            .arg("--env-file").arg(exec_env_file.path())
                            .args([container_name, "mariadb", "-u", "root", db_name])
                            .stdin(stdout.into_owned_fd().unwrap())
                            .output(),
                    )
                    .await
                    .map(|r| r.map(|o| o.status.success()).unwrap_or(false))
                    .unwrap_or(false);
                    // A truncated/corrupt .gz makes zcat exit non-zero while mariadb can read
                    // a clean EOF at a statement boundary and exit 0 (lesson #51 EOF-as-success).
                    // Require the decompressor to have succeeded too - mirrors the hardened
                    // database_backup.rs::restore_mysql. Without it the verify safety net
                    // certifies a corrupt backup as passed.
                    // Bound the decompressor wait: safe_command sets no kill_on_drop, so a
                    // timed-out (dropped) docker future leaves docker orphaned holding zcat's
                    // pipe read-end - an UNbounded zcat.wait() could then hang the task forever.
                    // zcat exits ~instantly on every non-hang path (docker drained the stream on
                    // success; zcat already errored on truncation), so 5s is ample headroom.
                    let zcat_ok = tokio::time::timeout(std::time::Duration::from_secs(5), zcat.wait())
                        .await.ok().and_then(|r| r.ok()).map(|s| s.success()).unwrap_or(false);
                    docker_ok && zcat_ok
                }
                None => false,
            }
        }
        Err(_) => false,
    };

    checks.push(VerificationCheck {
        name: "restore_dump".into(),
        passed: restore_ok,
        message: if restore_ok { "Dump restored successfully".into() } else { "Failed to restore dump".into() },
    });

    if !restore_ok {
        return false;
    }

    // Verify: count tables
    let table_count = safe_command("docker")
        .arg("exec").arg("--env-file").arg(exec_env_file.path())
        .args([
            container_name, "mariadb", "-u", "root", db_name,
            "-e", "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()",
            "--batch", "--skip-column-names",
        ])
        .output()
        .await
        .map(|o| {
            String::from_utf8_lossy(&o.stdout).trim().parse::<i32>().unwrap_or(0)
        })
        .unwrap_or(0);

    checks.push(VerificationCheck {
        name: "table_count".into(),
        passed: table_count > 0,
        message: format!("{table_count} tables found after restore"),
    });

    table_count > 0
}

async fn verify_postgres_restore(
    backup_path: &std::path::Path,
    container_name: &str,
    db_name: &str,
    password: &str,
    checks: &mut Vec<VerificationCheck>,
) -> bool {
    // Start temp PostgreSQL container. Bootstrap credential via --env-file,
    // not `-e KEY=value`: see `DockerEnvFile`.
    let run_env_file = match DockerEnvFile::new(&[
        ("POSTGRES_DB", db_name),
        ("POSTGRES_USER", "verify"),
        ("POSTGRES_PASSWORD", password),
    ]) {
        Ok(f) => f,
        Err(e) => {
            checks.push(VerificationCheck {
                name: "temp_container".into(),
                passed: false,
                message: format!("Failed to prepare credentials: {e}"),
            });
            return false;
        }
    };
    let start_ok = safe_command("docker")
        .arg("run").arg("-d").arg("--name").arg(container_name)
        .arg("--env-file").arg(run_env_file.path())
        .args(["--memory=256m", "postgres:16-alpine"])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !start_ok {
        checks.push(VerificationCheck {
            name: "temp_container".into(),
            passed: false,
            message: "Failed to start temporary PostgreSQL container".into(),
        });
        return false;
    }

    let exec_env_file = match DockerEnvFile::new(&[("PGPASSWORD", password)]) {
        Ok(f) => f,
        Err(e) => {
            checks.push(VerificationCheck {
                name: "temp_container".into(),
                passed: false,
                message: format!("Failed to prepare credentials: {e}"),
            });
            return false;
        }
    };

    // Wait for PostgreSQL to be ready (up to 30s)
    let mut ready = false;
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let check = safe_command("docker")
            .arg("exec").arg("--env-file").arg(exec_env_file.path())
            .args([container_name, "psql", "-U", "verify", "-d", db_name, "-c", "SELECT 1"])
            .output()
            .await;
        if check.map(|o| o.status.success()).unwrap_or(false) {
            ready = true;
            break;
        }
    }

    checks.push(VerificationCheck {
        name: "temp_container".into(),
        passed: ready,
        message: if ready { "Temporary PostgreSQL container ready".into() } else { "PostgreSQL container failed to start within 30s".into() },
    });

    if !ready {
        return false;
    }

    // Restore the dump using direct process piping (no shell interpolation)
    let zcat_child = safe_command("zcat")
        .arg(backup_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();

    let restore_ok = match zcat_child {
        Ok(mut zcat) => {
            let zcat_stdout = zcat.stdout.take();
            match zcat_stdout {
                Some(stdout) => {
                    let docker_ok = tokio::time::timeout(
                        std::time::Duration::from_secs(120),
                        safe_command("docker")
                            .arg("exec").arg("-i")
                            .arg("--env-file").arg(exec_env_file.path())
                            .args([
                                container_name,
                                "psql", "-U", "verify", "-d", db_name, "--quiet",
                                // Without these, psql reports success for a dump
                                // whose statements failed, and leaves the partial
                                // result behind - so a truncated backup that still
                                // produced *some* tables passes the table-count
                                // check below and is reported "verified" (lesson
                                // #51). The dumps restored here are written by
                                // database_backup.rs with --no-owner --no-acl and
                                // no --clean, so there are no DROP statements to
                                // fail spuriously against this fresh scratch DB.
                                "-v", "ON_ERROR_STOP=1", "--single-transaction",
                            ])
                            .stdin(stdout.into_owned_fd().unwrap())
                            .output(),
                    )
                    .await
                    .map(|r| r.map(|o| o.status.success()).unwrap_or(false))
                    .unwrap_or(false);
                    // ON_ERROR_STOP+single-transaction catch a mid-statement truncation, but a
                    // .gz cut on a clean statement boundary still lets psql see EOF and COMMIT
                    // the partial prefix (exit 0). Require the decompressor to have succeeded
                    // too (lesson #51) - mirrors database_backup.rs::restore_postgres.
                    // Bound the decompressor wait: safe_command sets no kill_on_drop, so a
                    // timed-out (dropped) docker future leaves docker orphaned holding zcat's
                    // pipe read-end - an UNbounded zcat.wait() could then hang the task forever.
                    // zcat exits ~instantly on every non-hang path (docker drained the stream on
                    // success; zcat already errored on truncation), so 5s is ample headroom.
                    let zcat_ok = tokio::time::timeout(std::time::Duration::from_secs(5), zcat.wait())
                        .await.ok().and_then(|r| r.ok()).map(|s| s.success()).unwrap_or(false);
                    docker_ok && zcat_ok
                }
                None => false,
            }
        }
        Err(_) => false,
    };

    checks.push(VerificationCheck {
        name: "restore_dump".into(),
        passed: restore_ok,
        message: if restore_ok { "Dump restored successfully".into() } else { "Failed to restore dump".into() },
    });

    if !restore_ok {
        return false;
    }

    // Verify: count tables
    let table_count = safe_command("docker")
        .arg("exec").arg("--env-file").arg(exec_env_file.path())
        .args([
            container_name, "psql", "-U", "verify", "-d", db_name,
            "-t", "-c", "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'",
        ])
        .output()
        .await
        .map(|o| {
            String::from_utf8_lossy(&o.stdout).trim().parse::<i32>().unwrap_or(0)
        })
        .unwrap_or(0);

    checks.push(VerificationCheck {
        name: "table_count".into(),
        passed: table_count > 0,
        message: format!("{table_count} tables found after restore"),
    });

    table_count > 0
}

/// Verify a volume backup: extract to temp dir, check contents.
///
/// An encrypted archive (`.tar.gz.enc`) needs `encryption_key`: its integrity
/// tag is checked and it is decrypted to a hidden temporary in the same
/// directory (removed afterwards) before `tar` reads it. A wrong tag (tampered
/// file or wrong passphrase) is a failed `integrity` check, not an error.
pub async fn verify_volume_backup(
    container_name: &str,
    filename: &str,
    encryption_key: Option<&str>,
) -> Result<VerificationResult, String> {
    let start = std::time::Instant::now();
    let mut checks = Vec::new();

    if !crate::services::backup_targets::is_valid_owner_name(container_name) {
        return Err("Invalid container name".to_string());
    }
    if !crate::services::volume_backup::is_safe_filename(filename) {
        return Err("Invalid filename".to_string());
    }

    let dir = std::path::PathBuf::from(format!("/var/backups/dockpanel/volumes/{container_name}"));
    let stored_path = format!("/var/backups/dockpanel/volumes/{container_name}/{filename}");
    if !std::path::Path::new(&stored_path).exists() {
        return Err("Backup file not found".to_string());
    }

    let archive = match crate::services::volume_backup::readable_archive(&dir, filename, encryption_key).await {
        Ok(a) => {
            if filename.ends_with(".enc") {
                checks.push(VerificationCheck {
                    name: "integrity".into(),
                    passed: true,
                    message: "Integrity tag matches the passphrase; archive decrypted".into(),
                });
            }
            a
        }
        Err(crate::services::volume_backup::VbError::Integrity(m)) => {
            checks.push(VerificationCheck { name: "integrity".into(), passed: false, message: m });
            return Ok(VerificationResult {
                passed: false,
                checks_run: 1,
                checks_passed: 0,
                details: checks,
                duration_ms: start.elapsed().as_millis() as u64,
            });
        }
        Err(e) => return Err(e.to_string()),
    };
    let backup_path = dir.join(&archive.name).to_string_lossy().to_string();

    // Check 1: File size
    let meta = std::fs::metadata(&backup_path)
        .map_err(|e| format!("Cannot read file: {e}"))?;
    checks.push(VerificationCheck {
        name: "file_exists".into(),
        passed: meta.len() > 50,
        message: format!("Volume backup size: {} bytes", meta.len()),
    });
    let extract_timeout = crate::services::volume_backup::archive_timeout(meta.len())
        .min(std::time::Duration::from_secs(3600))
        .max(std::time::Duration::from_secs(120));

    // Check 2: Extract to temp dir
    let temp_dir = format!("/tmp/dockpanel-verify-{}", uuid::Uuid::new_v4());
    std::fs::create_dir_all(&temp_dir).map_err(|e| format!("Temp dir: {e}"))?;

    let extract_ok = tokio::time::timeout(
        extract_timeout,
        safe_command("tar")
            .args(["xzf", &backup_path, "-C", &temp_dir, "--no-same-owner", "--no-same-permissions"])
            .output(),
    )
    .await
    .map(|r| r.map(|o| o.status.success()).unwrap_or(false))
    .unwrap_or(false);

    checks.push(VerificationCheck {
        name: "extract_success".into(),
        passed: extract_ok,
        message: if extract_ok { "Archive extracts cleanly".into() } else { "Failed to extract archive".into() },
    });

    // Check 3: Count files
    if extract_ok {
        let count_output = safe_command("find")
            .args([&temp_dir, "-type", "f"])
            .output()
            .await;
        let file_count = count_output
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
            .unwrap_or(0);

        checks.push(VerificationCheck {
            name: "file_count".into(),
            passed: file_count > 0,
            message: format!("{file_count} files in volume backup"),
        });
    }

    // Cleanup
    std::fs::remove_dir_all(&temp_dir).ok();
    drop(archive);

    let checks_run = checks.len() as i32;
    let checks_passed = checks.iter().filter(|c| c.passed).count() as i32;

    Ok(VerificationResult {
        passed: checks_passed == checks_run,
        checks_run,
        checks_passed,
        details: checks,
        duration_ms: start.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chk(name: &str, passed: bool) -> VerificationCheck {
        VerificationCheck { name: name.into(), passed, message: String::new() }
    }

    // s248: the site-backup verify verdict must treat extract_success + file_count as
    // CRITICAL and has_entry_point as informational. The old `checks_passed >= checks_run - 1`
    // slack certified a corrupt, non-extractable archive as passed (lesson #51 in the safety net).
    #[test]
    fn site_backup_fails_when_extract_fails() {
        // Corrupt archive: file present (>100B) but tar extract fails → only 2 checks run.
        let checks = vec![chk("file_exists", true), chk("extract_success", false)];
        assert!(!site_backup_passed(&checks), "a non-extractable archive must NOT pass verify");
    }

    #[test]
    fn site_backup_fails_on_empty_archive() {
        // Extract succeeds but zero files → file_count is a critical failure.
        let checks = vec![
            chk("file_exists", true),
            chk("extract_success", true),
            chk("file_count", false),
            chk("has_entry_point", false),
        ];
        assert!(!site_backup_passed(&checks));
    }

    #[test]
    fn site_backup_passes_when_only_entry_point_missing() {
        // A valid non-web backup (no index.*) must still pass - has_entry_point is informational.
        let checks = vec![
            chk("file_exists", true),
            chk("extract_success", true),
            chk("file_count", true),
            chk("has_entry_point", false),
        ];
        assert!(site_backup_passed(&checks));
    }

    // ── Scratch containers: the anonymous-volume leak ──────────────────────

    #[test]
    fn scratch_rm_removes_anonymous_volumes() {
        // Without -v every mariadb/postgres verify left its data volume behind
        // (51 orphans, 7.5 GB in five days on a production box).
        let args = scratch_rm_args("dockpanel-verify-1a2b3c4d");
        assert_eq!(args, ["rm", "-f", "-v", "dockpanel-verify-1a2b3c4d"]);
    }

    #[test]
    fn scratch_names_keeps_only_ours() {
        let listing = "dockpanel-verify-1a2b3c4d\n\
                       /dockpanel-drill-db-9f8e7d6c\n\
                       dockpanel-drill-0011aabb\n\
                       wordpress-db\n\
                       dockpanel-postgres\n\
                       dockpanel-verify-\n\
                       dockpanel-verify-x;rm\n\
                       my-dockpanel-verify-1234\n\
                       \n";
        assert_eq!(
            scratch_names(listing, &SCRATCH_CONTAINER_PREFIXES),
            vec!["dockpanel-verify-1a2b3c4d", "dockpanel-drill-db-9f8e7d6c", "dockpanel-drill-0011aabb"],
        );
        let volumes = "dockpanel-drill-vol-1a2b3c4d\nwordpress_data\n4f1c0e2d9a\n";
        assert_eq!(scratch_names(volumes, &[SCRATCH_VOLUME_PREFIX]), vec!["dockpanel-drill-vol-1a2b3c4d"]);
    }

    // ── Encrypted dumps ────────────────────────────────────────────────────

    /// Test-only passphrase, the one the committed fixtures were made with.
    const FIXTURE_PASS: &str = "fixture-test-passphrase-not-a-secret";
    const FIXTURE_PLAIN: &[u8] = include_bytes!("../../tests/fixtures/encryption/plain.txt");
    const FIXTURE_CURRENT: &[u8] = include_bytes!("../../tests/fixtures/encryption/current.sql.enc");
    const FIXTURE_LEGACY: &[u8] = include_bytes!("../../tests/fixtures/encryption/legacy.sql.enc");

    /// A unique scratch directory, removed on drop.
    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn with(name: &str, bytes: &[u8]) -> Self {
            let p = std::env::temp_dir().join(format!("dp-verify-test-{:016x}", rand::random::<u64>()));
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join(name), bytes).unwrap();
            Scratch(p)
        }
        fn entries(&self) -> Vec<String> {
            let mut v: Vec<String> = std::fs::read_dir(&self.0)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
                .collect();
            v.sort();
            v
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const DUMP: &str = "app-20261125-044300.sql.gz.enc";

    #[tokio::test]
    async fn open_dump_reads_a_plain_dump_in_place() {
        let s = Scratch::with("app-20261125-044300.sql.gz", b"not really gzip");
        let d = open_dump(&s.0, "app-20261125-044300.sql.gz", None).await.unwrap();
        assert_eq!(d.path, s.0.join("app-20261125-044300.sql.gz"));
        assert!(d.integrity.is_none());
        drop(d);
        assert_eq!(s.entries(), vec!["app-20261125-044300.sql.gz"]);
    }

    #[tokio::test]
    async fn open_dump_decrypts_an_encrypted_dump_to_a_hidden_temporary() {
        let s = Scratch::with(DUMP, FIXTURE_CURRENT);
        let d = open_dump(&s.0, DUMP, Some(FIXTURE_PASS)).await.unwrap();
        let name = d.path.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with(".dec-") && name.ends_with(".part"), "{name}");
        assert_eq!(d.path.parent().unwrap(), s.0.as_path());
        assert_eq!(std::fs::read(&d.path).unwrap(), FIXTURE_PLAIN, "zcat must read the plaintext, not the .enc");
        assert!(d.integrity.as_deref().unwrap().starts_with("Integrity tag matches"));
        drop(d);
        assert_eq!(s.entries(), vec![DUMP], "the decrypted copy must not outlive the verification");
    }

    #[tokio::test]
    async fn open_dump_wrong_key_is_a_failed_integrity_check() {
        let s = Scratch::with(DUMP, FIXTURE_CURRENT);
        let e = open_dump(&s.0, DUMP, Some("not-the-passphrase")).await.err().unwrap();
        assert!(matches!(e, DumpOpenError::Integrity(ref m) if m.starts_with("Backup integrity check failed")), "{e:?}");
        assert_eq!(s.entries(), vec![DUMP]);
    }

    #[tokio::test]
    async fn open_dump_tampered_file_is_a_failed_integrity_check() {
        let mut bytes = FIXTURE_CURRENT.to_vec();
        bytes[40] ^= 0x01;
        let s = Scratch::with(DUMP, &bytes);
        let e = open_dump(&s.0, DUMP, Some(FIXTURE_PASS)).await.err().unwrap();
        assert!(matches!(e, DumpOpenError::Integrity(_)), "{e:?}");
        assert_eq!(s.entries(), vec![DUMP]);
    }

    #[tokio::test]
    async fn open_dump_without_key_is_refused_not_verified() {
        let s = Scratch::with(DUMP, FIXTURE_CURRENT);
        for key in [None, Some("")] {
            let e = open_dump(&s.0, DUMP, key).await.err().unwrap();
            assert_eq!(e, DumpOpenError::Other("Encryption key required for encrypted backup".into()));
        }
    }

    #[tokio::test]
    async fn open_dump_accepts_a_legacy_untagged_dump_like_restore_does() {
        let s = Scratch::with(DUMP, FIXTURE_LEGACY);
        let d = open_dump(&s.0, DUMP, Some(FIXTURE_PASS)).await.unwrap();
        assert_eq!(std::fs::read(&d.path).unwrap(), FIXTURE_PLAIN);
        assert!(d.integrity.as_deref().unwrap().starts_with("No integrity tag"));
        drop(d);
        assert_eq!(s.entries(), vec![DUMP]);
    }

    #[test]
    fn site_backup_passes_all_critical() {
        let checks = vec![
            chk("file_exists", true),
            chk("extract_success", true),
            chk("file_count", true),
            chk("has_entry_point", true),
        ];
        assert!(site_backup_passed(&checks));
    }
}
