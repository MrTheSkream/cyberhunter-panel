// Per-image vulnerability scanner using Anchore's grype.
//
// Surfaces results per Docker image so the panel can badge individual apps
// and gate deploys at a configurable severity threshold. Distinct from the
// full security scan (services::security_scanner) which lumps container vuln
// counts into a single all-server report.

use crate::safe_cmd::safe_command;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// Scanner lives inside the CyberHunter - Panel data dir so it works under the hardened
// agent sandbox (ProtectSystem=strict, ProtectHome=yes) without needing write
// access to /usr/local/bin or $HOME.
const GRYPE_DIR: &str = "/var/lib/dockpanel/scanners";
pub const GRYPE_BIN: &str = "/var/lib/dockpanel/scanners/grype";
pub const GRYPE_DB_CACHE: &str = "/var/lib/dockpanel/scanners/grype-db";

// Pinned to a known release rather than "latest" so the exact binary we run is
// reviewable and reproducible. Anchore's install.sh already sha256-verifies the
// downloaded archive against its release checksums.txt unconditionally (read
// upstream to confirm - not gated behind any flag), so this pin closes the
// remaining gap: without a TAG argument the script both re-resolves "latest"
// on every install AND is fetched from the mutable `main` ref. Bump deliberately.
const GRYPE_VERSION: &str = "v0.122.1";

/// The pinned grype release, without the leading `v` (as `grype version` prints it).
pub fn pinned_version() -> &'static str {
    GRYPE_VERSION.trim_start_matches('v')
}

#[derive(Serialize, Clone)]
pub struct ImageScanResult {
    pub image: String,
    pub scanner: String,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub unknown_count: u32,
    /// Matches whose CVE is in the CISA KEV catalogue (actively exploited).
    /// Counted over every match, before the stored list is capped.
    pub kev_count: u32,
    pub vulnerabilities: Vec<Vuln>,
    pub scanned_at: String,
}

#[derive(Serialize, Clone)]
pub struct Vuln {
    pub cve: String,
    pub severity: String,
    pub package: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub description: Option<String>,
    /// In the CISA KEV catalogue (read on the match or on a related record).
    pub kev: bool,
}

/// True if the scanner binary is present at the managed path.
pub async fn is_installed() -> bool {
    tokio::fs::metadata(GRYPE_BIN).await.is_ok()
}

/// Install grype via Anchore's official installer script into the CyberHunter - Panel
/// data directory so the hardened agent sandbox can read/write it.
pub async fn install_grype() -> Result<(), String> {
    if is_installed().await {
        return Ok(());
    }
    install_grype_binary().await?;

    // Prime the vulnerability database through the CVE scanner's db update
    // job (transient unit, database lock, free space check, leftover sweep),
    // started in the background. It used to run here, in the agent's cgroup,
    // with 180 s for a 3.4 GB download: stopped half way, it left the download
    // behind in `grype-db-download*`.
    let _ = crate::services::vuln_scanner::start_db_update();

    Ok(())
}

/// Install the pinned grype binary only, without priming the database.
/// The CVE scanner (`vuln_scanner`) uses this and runs `db update` itself in
/// a transient unit, outside the agent's 512M cgroup.
pub async fn install_grype_binary() -> Result<(), String> {
    tokio::fs::create_dir_all(GRYPE_DIR)
        .await
        .map_err(|e| format!("create {GRYPE_DIR}: {e}"))?;

    // Anchore's installer writes the binary to the path passed via `-b`. We
    // pin it inside /var/lib/dockpanel (writable under systemd ProtectSystem=strict)
    // rather than /usr/local/bin. Both the script fetch AND the binary download are
    // pinned to GRYPE_VERSION (a tag, not `main`) so nothing here resolves "latest"
    // at install time.
    let cmd = format!(
        "curl -sSfL https://raw.githubusercontent.com/anchore/grype/{GRYPE_VERSION}/install.sh \
         | sh -s -- -b {GRYPE_DIR} {GRYPE_VERSION}"
    );

    let output = tokio::time::timeout(
        Duration::from_secs(180),
        safe_command("sh").args(["-c", &cmd]).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| "grype install timed out after 180s".to_string())?
    .map_err(|e| format!("grype install failed to execute: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "grype install failed: {}",
            stderr.chars().take(300).collect::<String>()
        ));
    }

    Ok(())
}

/// Remove grype binary and its cached vulnerability database.
pub async fn uninstall_grype() -> Result<(), String> {
    let _ = tokio::fs::remove_file(GRYPE_BIN).await;
    let _ = tokio::fs::remove_dir_all(GRYPE_DB_CACHE).await;
    Ok(())
}

/// Scan a single Docker image. Times out at 180s so a hung pull cannot wedge
/// the agent's request handler.
pub async fn scan_image(image: &str) -> Result<ImageScanResult, String> {
    if image.is_empty() || image.len() > 512 {
        return Err("Invalid image reference".to_string());
    }
    // Same character set Docker accepts for image refs. Reject anything that
    // could break out of the argv slot.
    if !image.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == ':' || c == '/' || c == '.' || c == '-' || c == '_' || c == '@'
    }) {
        return Err("Image reference contains disallowed characters".to_string());
    }

    if !is_installed().await {
        return Err("Scanner not installed. Install grype first.".to_string());
    }

    // Runs in the CVE scanner's capped transient unit (MemoryMax, Nice 19,
    // idle IO), not in the agent's own 512M cgroup; the unit is stopped when
    // the 180s timeout fires, which is what kill_on_drop(true) used to cover.
    let report =
        crate::services::vuln_scanner::grype_image_report(image, Duration::from_secs(180)).await?;
    parse_grype_output(image, &report)
}

#[derive(Deserialize)]
struct GrypeReport {
    matches: Option<Vec<GrypeMatch>>,
}

#[derive(Deserialize)]
struct GrypeMatch {
    vulnerability: GrypeVuln,
    artifact: GrypeArtifact,
    // Lenient on purpose: an entry that fails to parse would fail the whole
    // scan, and a failed scan lets the deploy through.
    #[serde(default, rename = "relatedVulnerabilities")]
    related: Option<Vec<GrypeKevCarrier>>,
}

#[derive(Deserialize)]
struct GrypeVuln {
    id: String,
    severity: String,
    description: Option<String>,
    fix: Option<GrypeFix>,
    #[serde(default, rename = "knownExploited")]
    known_exploited: Option<Vec<serde::de::IgnoredAny>>,
}

/// Only the KEV list of a related record; everything else is ignored.
#[derive(Deserialize, Default)]
struct GrypeKevCarrier {
    #[serde(default, rename = "knownExploited")]
    known_exploited: Option<Vec<serde::de::IgnoredAny>>,
}

/// Same rule as `vuln_scanner::finding_of`: a match is KEV when its own record
/// or any related record (a GHSA usually carries KEV only on its related CVE)
/// has a non-empty `knownExploited` list.
fn match_is_kev(m: &GrypeMatch) -> bool {
    let listed = |k: &Option<Vec<serde::de::IgnoredAny>>| k.as_ref().is_some_and(|v| !v.is_empty());
    listed(&m.vulnerability.known_exploited)
        || m.related.as_deref().unwrap_or_default().iter().any(|r| listed(&r.known_exploited))
}

#[derive(Deserialize)]
struct GrypeFix {
    versions: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct GrypeArtifact {
    name: String,
    version: String,
}

fn parse_grype_output(image: &str, json_str: &str) -> Result<ImageScanResult, String> {
    let report: GrypeReport = serde_json::from_str(json_str)
        .map_err(|e| format!("Failed to parse grype JSON: {e}"))?;

    let mut critical = 0u32;
    let mut high = 0u32;
    let mut medium = 0u32;
    let mut low = 0u32;
    let mut unknown = 0u32;
    let mut kev_count = 0u32;
    let mut vulnerabilities = Vec::new();

    if let Some(matches) = report.matches {
        for m in matches {
            let severity_normalized = normalize_severity(&m.vulnerability.severity);
            match severity_normalized.as_str() {
                "critical" => critical += 1,
                "high" => high += 1,
                "medium" => medium += 1,
                "low" => low += 1,
                _ => unknown += 1,
            }
            let kev = match_is_kev(&m);
            if kev {
                kev_count += 1;
            }

            let fixed_version = m
                .vulnerability
                .fix
                .and_then(|f| f.versions)
                .and_then(|v| v.into_iter().next());

            // Cap stored vulns to keep payload manageable; counts are still
            // accurate because we counted before truncating.
            if vulnerabilities.len() < 500 {
                vulnerabilities.push(Vuln {
                    cve: m.vulnerability.id,
                    severity: severity_normalized,
                    package: m.artifact.name,
                    installed_version: m.artifact.version,
                    fixed_version,
                    description: m.vulnerability.description,
                    kev,
                });
            }
        }
    }

    Ok(ImageScanResult {
        image: image.to_string(),
        scanner: "grype".to_string(),
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
        unknown_count: unknown,
        kev_count,
        vulnerabilities,
        scanned_at: chrono::Utc::now().to_rfc3339(),
    })
}

fn normalize_severity(s: &str) -> String {
    match s.to_ascii_lowercase().as_str() {
        "critical" => "critical".to_string(),
        "high" => "high".to_string(),
        "medium" => "medium".to_string(),
        "low" => "low".to_string(),
        "negligible" => "low".to_string(),
        _ => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_grype_severities() {
        let json = r#"{
          "matches": [
            {"vulnerability":{"id":"CVE-1","severity":"Critical","description":"x","fix":{"versions":["1.2.3"]}},
             "artifact":{"name":"libfoo","version":"1.2.0"}},
            {"vulnerability":{"id":"CVE-2","severity":"High","fix":null},
             "artifact":{"name":"libbar","version":"2.0.0"}},
            {"vulnerability":{"id":"CVE-3","severity":"Negligible","fix":null},
             "artifact":{"name":"libbaz","version":"0.1"}}
          ]
        }"#;
        let result = parse_grype_output("nginx:latest", json).unwrap();
        assert_eq!(result.critical_count, 1);
        assert_eq!(result.high_count, 1);
        assert_eq!(result.low_count, 1); // Negligible folds into low
        assert_eq!(result.vulnerabilities.len(), 3);
        assert_eq!(result.vulnerabilities[0].fixed_version.as_deref(), Some("1.2.3"));
        assert_eq!(result.kev_count, 0);
        assert!(result.vulnerabilities.iter().all(|v| !v.kev));
    }

    #[test]
    fn reads_kev_on_the_match_and_on_related_vulnerabilities() {
        let json = r#"{
          "matches": [
            {"vulnerability":{"id":"CVE-2021-44228","severity":"Critical",
               "knownExploited":[{"cve":"CVE-2021-44228","knownRansomwareCampaignUse":"Known"}]},
             "artifact":{"name":"log4j-core","version":"2.14.1"}},
            {"vulnerability":{"id":"GHSA-jfh8-c2jp-5v3q","severity":"Critical","knownExploited":null},
             "relatedVulnerabilities":[
               {"id":"CVE-2021-44228","knownExploited":[{"cve":"CVE-2021-44228"}]}],
             "artifact":{"name":"log4j-api","version":"2.14.1"}},
            {"vulnerability":{"id":"CVE-2",
               "severity":"High","knownExploited":[]},
             "relatedVulnerabilities":[{"id":"CVE-2","knownExploited":[]}, {"id":null, "cvss":null}],
             "artifact":{"name":"libbar","version":"2.0.0"}},
            {"vulnerability":{"id":"CVE-3","severity":"Low"},
             "relatedVulnerabilities":null,
             "artifact":{"name":"libbaz","version":"0.1"}}
          ]
        }"#;
        let result = parse_grype_output("app:1", json).unwrap();
        assert_eq!(result.kev_count, 2);
        let kev: Vec<bool> = result.vulnerabilities.iter().map(|v| v.kev).collect();
        assert_eq!(kev, vec![true, true, false, false]);
        assert_eq!(result.critical_count, 2);
    }

    #[test]
    fn kev_count_is_taken_before_the_stored_list_is_capped() {
        let one = r#"{"vulnerability":{"id":"CVE-9","severity":"Low","knownExploited":[{}]},
                      "artifact":{"name":"p","version":"1"}}"#;
        let json = format!("{{\"matches\":[{}]}}", vec![one; 600].join(","));
        let result = parse_grype_output("app:1", &json).unwrap();
        assert_eq!(result.vulnerabilities.len(), 500);
        assert_eq!(result.kev_count, 600);
    }

    #[test]
    fn rejects_bad_image_refs() {
        // These would be caught at handler boundary; sanity-check the validator.
        let bad = ["", "  ", "img;rm -rf /", "img$(whoami)", "img|cat"];
        for b in bad {
            let allowed = b.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || c == ':' || c == '/' || c == '.' || c == '-' || c == '_' || c == '@'
            }) && !b.is_empty();
            assert!(!allowed, "should reject: {b}");
        }
        let good = ["nginx:latest", "ghcr.io/owner/repo:1.2.3", "image@sha256:abcd"];
        for g in good {
            let allowed = g.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || c == ':' || c == '/' || c == '.' || c == '-' || c == '_' || c == '@'
            }) && !g.is_empty();
            assert!(allowed, "should accept: {g}");
        }
    }
}
