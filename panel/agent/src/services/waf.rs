//! OWASP CRS layout resolution for the WAF (ModSecurity3).
//!
//! Two CRS layouts reach `/etc/modsecurity/crs` in practice:
//!
//! - **GitHub CRS v4** (our own download): the whole release lives in the
//!   directory, rules included, at `/etc/modsecurity/crs/rules/*.conf`.
//! - **Debian/Ubuntu `modsecurity-crs`** (pulled in as a Recommends of
//!   `libmodsecurity3`; 3.3.5 on Ubuntu 24.04): `/etc/modsecurity/crs` only
//!   holds `crs-setup.conf` and the two exclusion files, the rules live in
//!   `/usr/share/modsecurity-crs/rules`. A per-site file that blindly includes
//!   `/etc/modsecurity/crs/rules/*.conf` then fails `nginx -t` with
//!   "Not able to open file".
//!
//! The functions here take their directories as arguments so the layout logic
//! is unit-testable without touching the real filesystem paths.

use std::path::{Path, PathBuf};

/// Where the panel expects `crs-setup.conf` (both layouts put it here).
pub const CRS_DIR: &str = "/etc/modsecurity/crs";
/// Where the Debian/Ubuntu `modsecurity-crs` package puts the rules.
pub const DISTRO_RULES_DIR: &str = "/usr/share/modsecurity-crs/rules";

/// Exclusion files the Debian package moves out of `rules/` into `CRS_DIR`.
/// They must be loaded before and after the rules respectively.
const EXCLUSION_BEFORE: &str = "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf";
const EXCLUSION_AFTER: &str = "RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf";

/// True when `dir` is a readable directory holding at least one `*.conf`
/// file. A dangling symlink or an empty directory is not usable: an
/// `Include dir/*.conf` that matches nothing fails `nginx -t`.
fn has_conf_files(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries.flatten().any(|e| {
                e.path().extension().is_some_and(|x| x == "conf")
                    && e.path().is_file()
            })
        })
        .unwrap_or(false)
}

/// The rules directory to include, or `None` when no usable CRS is present.
///
/// `<crs_dir>/rules` wins over the distro directory so that a v4 download is
/// never paired with rules of another release: `crs-setup.conf` and the rules
/// must come from the same CRS version. Requires `<crs_dir>/crs-setup.conf`.
pub fn resolve_rules_dir(crs_dir: &Path, distro_rules_dir: &Path) -> Option<PathBuf> {
    if !crs_dir.join("crs-setup.conf").is_file() {
        return None;
    }
    [crs_dir.join("rules"), distro_rules_dir.to_path_buf()]
        .into_iter()
        .find(|d| has_conf_files(d))
}

/// The ModSecurity directives loading the CRS, or a comment when none is
/// usable. Plain `Include` only (ModSecurity3 has no `IncludeOptional`), so
/// every file named here is checked to exist first.
pub fn render_crs_include(crs_dir: &Path, distro_rules_dir: &Path) -> String {
    let Some(rules) = resolve_rules_dir(crs_dir, distro_rules_dir) else {
        return "# OWASP CRS not found - basic protection only".to_string();
    };
    // An exclusion file kept beside crs-setup.conf (Debian layout) is
    // included unless the rules directory already ships one of that name,
    // which would load it twice.
    let exclusion = |name: &str| {
        let p = crs_dir.join(name);
        (p.is_file() && !rules.join(name).is_file()).then(|| format!("Include {}", p.display()))
    };
    let mut lines = vec![format!("Include {}", crs_dir.join("crs-setup.conf").display())];
    lines.extend(exclusion(EXCLUSION_BEFORE));
    lines.push(format!("Include {}/*.conf", rules.display()));
    lines.extend(exclusion(EXCLUSION_AFTER));
    lines.join("\n")
}

/// Make `<crs_dir>/rules` point at the distro rules when the distro layout is
/// in use, so the CRS looks the same on disk whichever way it arrived.
/// Idempotent: does nothing when `<crs_dir>/rules` already exists (a real
/// directory, our own earlier symlink, or one an admin made) or when the
/// distro rules are absent. Replaces only a dangling symlink.

pub fn link_distro_rules(crs_dir: &Path, distro_rules_dir: &Path) -> std::io::Result<bool> {
    let link = crs_dir.join("rules");
    if !crs_dir.join("crs-setup.conf").is_file() || !has_conf_files(distro_rules_dir) {
        return Ok(false);
    }
    match std::fs::symlink_metadata(&link) {
        Ok(m) if m.file_type().is_symlink() && !link.exists() => std::fs::remove_file(&link)?,
        Ok(_) => return Ok(false),
        Err(_) => {}
    }
    std::os::unix::fs::symlink(distro_rules_dir, &link)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Self {
            let d = std::env::temp_dir().join(format!("dp-waf-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&d).unwrap();
            Tmp(d)
        }
        fn crs(&self) -> PathBuf { self.0.join("etc-crs") }
        fn distro(&self) -> PathBuf { self.0.join("usr-share-rules") }
    }
    impl Drop for Tmp {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    fn touch(p: &Path) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, "# x\n").unwrap();
    }

    /// Ubuntu 24.04 `modsecurity-crs` 3.3.5 layout.
    fn apt_layout(t: &Tmp) {
        touch(&t.crs().join("crs-setup.conf"));
        touch(&t.crs().join(EXCLUSION_BEFORE));
        touch(&t.crs().join(EXCLUSION_AFTER));
        touch(&t.distro().join("REQUEST-901-INITIALIZATION.conf"));
        touch(&t.distro().join("crawlers-user-agents.data"));
    }

    /// GitHub CRS v4 tarball layout (exclusions ship as `.example`).
    fn v4_layout(t: &Tmp) {
        touch(&t.crs().join("crs-setup.conf"));
        touch(&t.crs().join("rules/REQUEST-901-INITIALIZATION.conf"));
        touch(&t.crs().join("rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example"));
    }

    #[test]
    fn apt_layout_includes_distro_rules_and_exclusions_in_order() {
        let t = Tmp::new();
        apt_layout(&t);
        assert_eq!(resolve_rules_dir(&t.crs(), &t.distro()), Some(t.distro()));
        let out = render_crs_include(&t.crs(), &t.distro());
        let expected = format!(
            "Include {c}/crs-setup.conf\nInclude {c}/{EXCLUSION_BEFORE}\nInclude {d}/*.conf\nInclude {c}/{EXCLUSION_AFTER}",
            c = t.crs().display(), d = t.distro().display()
        );
        assert_eq!(out, expected);
        assert!(!out.contains("etc-crs/rules"), "must not include the missing rules dir: {out}");
    }

    #[test]
    fn v4_layout_includes_its_own_rules() {
        let t = Tmp::new();
        v4_layout(&t);
        let out = render_crs_include(&t.crs(), &t.distro());
        assert_eq!(out, format!(
            "Include {c}/crs-setup.conf\nInclude {c}/rules/*.conf",
            c = t.crs().display()
        ));
    }

    #[test]
    fn crs_dir_rules_win_over_distro_rules() {
        let t = Tmp::new();
        v4_layout(&t);
        touch(&t.distro().join("REQUEST-901-INITIALIZATION.conf"));
        assert_eq!(resolve_rules_dir(&t.crs(), &t.distro()), Some(t.crs().join("rules")));
    }

    #[test]
    fn setup_without_any_rules_is_not_usable() {
        let t = Tmp::new();
        touch(&t.crs().join("crs-setup.conf"));
        assert_eq!(resolve_rules_dir(&t.crs(), &t.distro()), None);
        assert!(render_crs_include(&t.crs(), &t.distro()).starts_with('#'));
    }

    #[test]
    fn rules_without_setup_are_not_usable() {
        let t = Tmp::new();
        touch(&t.distro().join("REQUEST-901-INITIALIZATION.conf"));
        assert_eq!(resolve_rules_dir(&t.crs(), &t.distro()), None);
    }

    #[test]
    fn empty_rules_dir_falls_through_to_distro() {
        let t = Tmp::new();
        apt_layout(&t);
        fs::create_dir_all(t.crs().join("rules")).unwrap();
        touch(&t.crs().join("rules/only-data.data"));
        assert_eq!(resolve_rules_dir(&t.crs(), &t.distro()), Some(t.distro()));
    }

    #[test]
    fn manual_symlink_to_distro_rules_is_used_without_double_exclusions() {
        let t = Tmp::new();
        apt_layout(&t);
        std::os::unix::fs::symlink(t.distro(), t.crs().join("rules")).unwrap();
        let out = render_crs_include(&t.crs(), &t.distro());
        assert!(out.contains(&format!("Include {}/rules/*.conf", t.crs().display())), "{out}");
        assert_eq!(out.matches(EXCLUSION_BEFORE).count(), 1, "{out}");
    }

    #[test]
    fn dangling_symlink_falls_through_and_is_replaced() {
        let t = Tmp::new();
        apt_layout(&t);
        std::os::unix::fs::symlink(t.0.join("gone"), t.crs().join("rules")).unwrap();
        assert_eq!(resolve_rules_dir(&t.crs(), &t.distro()), Some(t.distro()));
        assert!(link_distro_rules(&t.crs(), &t.distro()).unwrap());
        assert_eq!(fs::read_link(t.crs().join("rules")).unwrap(), t.distro());
    }

    #[test]
    fn exclusion_also_in_rules_dir_is_not_included_twice() {
        let t = Tmp::new();
        apt_layout(&t);
        touch(&t.distro().join(EXCLUSION_BEFORE));
        // The rules glob already loads it; the /etc copy must not be added too.
        let out = render_crs_include(&t.crs(), &t.distro());
        assert!(!out.contains(EXCLUSION_BEFORE), "{out}");
        assert!(out.contains(&format!("Include {}/*.conf", t.distro().display())), "{out}");
        assert!(out.contains(EXCLUSION_AFTER), "{out}");
    }

    #[test]
    fn link_distro_rules_is_idempotent() {
        let t = Tmp::new();
        apt_layout(&t);
        assert!(link_distro_rules(&t.crs(), &t.distro()).unwrap());
        assert!(!link_distro_rules(&t.crs(), &t.distro()).unwrap());
        assert_eq!(resolve_rules_dir(&t.crs(), &t.distro()), Some(t.crs().join("rules")));
    }

    #[test]
    fn link_distro_rules_leaves_a_real_rules_dir_alone() {
        let t = Tmp::new();
        v4_layout(&t);
        touch(&t.distro().join("REQUEST-901-INITIALIZATION.conf"));
        assert!(!link_distro_rules(&t.crs(), &t.distro()).unwrap());
        assert!(!fs::symlink_metadata(t.crs().join("rules")).unwrap().file_type().is_symlink());
    }

    #[test]
    fn link_distro_rules_skips_without_distro_rules() {
        let t = Tmp::new();
        touch(&t.crs().join("crs-setup.conf"));
        assert!(!link_distro_rules(&t.crs(), &t.distro()).unwrap());
        assert!(fs::symlink_metadata(t.crs().join("rules")).is_err());
    }
}
